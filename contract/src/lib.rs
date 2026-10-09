//! Stellar → NEAR light client (POC).
//!
//! # Sparse verification
//!
//! A *span* of ledger headers is authenticated by ONE quorum certificate at the tail
//! instead of one per ledger. The certificate is a set of validator signatures over
//! `xdr(networkID, ENVELOPE_TYPE_SCP, statement)`, where the statement externalizes the
//! tail's `StellarValue`. That value commits to `txSetHash`, and the tail's transaction
//! set commits to `previousLedgerHash` — which pins the header before the tail, and that
//! header pins the one before it, transitively back to the stored head. One certificate
//! therefore authenticates an entire span (~428 B per intermediate ledger).
//!
//! The tail transaction set is *optional*:
//! - present → the span is pinned immediately (`pinned_seq` reports through which ledger);
//! - absent → the span is provisional. The head still advances and later spans still
//!   chain to it, and the chain gets pinned by any later span that does bring a set.
//!   Claims can never be provisional: proving inclusion needs the set, so claims carry it.
//!
//! # Storage discipline
//!
//! Payloads (headers, transaction sets, envelopes) are calldata only — verified in
//! memory, never written to state. State holds just the chain head and the trust
//! configuration. Recording a proven transaction as settled is the consuming
//! application's business (a bridge built on this light client), not the light
//! client's.
//!
//! The trust set is deliberately configuration, not consensus: Stellar has no on-chain
//! validator set. Operators pin node ids and a threshold here.

#[cfg(test)]
mod tests;

use std::io::Cursor;

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, require, AccountId, PanicOnDefault};

use stellar_xdr::{
    EnvelopeType, GeneralizedTransactionSet, Hash, LedgerHeader, Limited, Limits, PublicKey,
    ReadXdr, ScpEnvelope, ScpStatementPledges, Signature, StellarValue, TransactionEnvelope,
    TransactionPhase, TransactionSet, TxSetComponent, Value, WriteXdr,
};

// --------------------------------------------------------------- JSON call arguments

/// A span of consecutive ledgers plus the evidence authenticating its tail.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SpanProof {
    /// XDR `LedgerHeader` for each ledger `head_seq + 1 ..= tail_seq`, ascending.
    pub headers: Vec<Base64VecU8>,
    /// XDR `ScpEnvelope`s forming the quorum certificate for the tail ledger.
    pub tail_envelopes: Vec<Base64VecU8>,
    /// XDR transaction set of the tail ledger. Optional: it is what pins the chain.
    pub tail_tx_set_xdr: Option<Base64VecU8>,
    /// Inclusion claims to prove against the tail's transaction set.
    pub tx_claims: Vec<TxClaim>,
}

/// Claim that `tx_envelope_xdr` is the transaction at `tx_index` of the set.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TxClaim {
    pub tx_envelope_xdr: Base64VecU8,
    pub tx_index: u32,
}

// ------------------------------------------------------------------ raw (Borsh) args

/// Same as [`SpanProof`] but Borsh-encoded: call arguments are raw bytes on NEAR, so a
/// Borsh entry point skips both base64 (1.33x) and JSON parsing. ~27% smaller calldata.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SpanProofRaw {
    pub headers: Vec<Vec<u8>>,
    pub tail_envelopes: Vec<Vec<u8>>,
    pub tail_tx_set: Option<Vec<u8>>,
    pub tx_claims: Vec<TxClaimRaw>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct TxClaimRaw {
    pub tx_envelope: Vec<u8>,
    pub tx_index: u32,
}

// -------------------------------------------------------------------------- results

/// What was proven about one span.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SpanEvidence {
    pub tail_seq: u32,
    pub tail_hash: Base64VecU8,
    /// Ledger through which the chain is pinned by signed bytes, if the tail set was
    /// verified. The tail header itself is pinned by the next span that brings a set.
    pub pinned_seq: Option<u32>,
    /// Distinct trusted signers whose signatures were verified.
    pub quorum_signers: u32,
    /// sha256(tx envelope) per proven claim — returned, never stored.
    pub claimed_tx_ids: Vec<Base64VecU8>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct HeadView {
    pub ledger_seq: u32,
    pub header_hash: Base64VecU8,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TrustView {
    pub trusted_nodes: Vec<Base64VecU8>,
    pub threshold: u32,
    pub max_protocol_version: u32,
}

/// Outcome of verifying one RISC Zero Groth16 receipt.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ReceiptEvidence {
    pub verified: bool,
    pub claim_digest: Base64VecU8,
    pub control_root: Base64VecU8,
}

/// The RISC Zero wrapper build this contract accepts — readable by anyone so a
/// caller can check compatibility before submitting a receipt.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct WrapperView {
    pub control_root: Base64VecU8,
    pub bn254_control_id: Base64VecU8,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct LightClient {
    pub owner: AccountId,
    /// sha256(Stellar network passphrase) — first 32 bytes of every signed message.
    pub network_id: [u8; 32],
    pub trusted_nodes: Vec<[u8; 32]>,
    pub threshold: u32,
    pub max_protocol_version: u32,
    pub head_seq: u32,
    pub head_hash: [u8; 32],
    /// Pinned RISC Zero wrapper identity. The Groth16 verifying key belongs to
    /// RISC Zero's STARK→SNARK wrapper (universal across guest circuits for one
    /// wrapper build), so the wrapper build is what must be pinned: receipts whose
    /// `control_root` / `bn254_control_id` differ are rejected up front.
    pub control_root: [u8; 32],
    pub bn254_control_id: [u8; 32],
}

#[near]
impl LightClient {
    #[init]
    pub fn new(
        owner: AccountId,
        network_id: Base64VecU8,
        trusted_nodes: Vec<Base64VecU8>,
        threshold: u32,
        max_protocol_version: u32,
        head_seq: u32,
        head_hash: Base64VecU8,
        control_root: Base64VecU8,
        bn254_control_id: Base64VecU8,
    ) -> Self {
        require!(threshold > 0, "threshold must be positive");
        require!(
            threshold as usize <= trusted_nodes.len(),
            "threshold exceeds trust set size"
        );
        Self {
            owner,
            network_id: to32(&network_id, "network_id"),
            trusted_nodes: trusted_nodes.iter().map(|n| to32(n, "trusted node id")).collect(),
            threshold,
            max_protocol_version,
            head_seq,
            head_hash: to32(&head_hash, "head_hash"),
            control_root: to32(&control_root, "control_root"),
            bn254_control_id: to32(&bn254_control_id, "bn254_control_id"),
        }
    }

    /// Verify a span and advance the chain head to its tail.
    ///
    /// The span must start at `head_seq + 1`; intermediate ledgers cost only their
    /// header (428 B) because the tail certificate pins them transitively.
    pub fn submit_span(&mut self, span: SpanProof) -> SpanEvidence {
        let headers = slices(&span.headers);
        let envelopes = slices(&span.tail_envelopes);
        let claims: Vec<(&[u8], u32)> = span
            .tx_claims
            .iter()
            .map(|c| (c.tx_envelope_xdr.0.as_slice(), c.tx_index))
            .collect();
        let evidence = self.verify_span_core(
            self.head_seq,
            self.head_hash,
            &headers,
            &envelopes,
            span.tail_tx_set_xdr.as_ref().map(|s| s.0.as_slice()),
            &claims,
        );
        self.head_seq = evidence.tail_seq;
        self.head_hash = to32(&evidence.tail_hash, "tail hash");
        evidence
    }

    /// Same as [`submit_span`] but with Borsh-encoded arguments passed as raw call bytes
    /// — no JSON, no base64. Use this from relayers where calldata size matters.
    pub fn submit_span_raw(&mut self, #[serializer(borsh)] span: SpanProofRaw) -> SpanEvidence {
        let headers: Vec<&[u8]> = span.headers.iter().map(|h| h.as_slice()).collect();
        let envelopes: Vec<&[u8]> = span.tail_envelopes.iter().map(|e| e.as_slice()).collect();
        let claims: Vec<(&[u8], u32)> = span
            .tx_claims
            .iter()
            .map(|c| (c.tx_envelope.as_slice(), c.tx_index))
            .collect();
        let evidence = self.verify_span_core(
            self.head_seq,
            self.head_hash,
            &headers,
            &envelopes,
            span.tail_tx_set.as_deref(),
            &claims,
        );
        self.head_seq = evidence.tail_seq;
        self.head_hash = to32(&evidence.tail_hash, "tail hash");
        evidence
    }

    /// Stateless check of a span against an arbitrary starting head: what would be
    /// proven if this were submitted there. For consumers (e.g. a bridge) verifying a
    /// claim before acting on it.
    pub fn verify_span_view(
        &self,
        head_seq: u32,
        head_hash: Base64VecU8,
        span: SpanProof,
    ) -> SpanEvidence {
        let headers = slices(&span.headers);
        let envelopes = slices(&span.tail_envelopes);
        let claims: Vec<(&[u8], u32)> = span
            .tx_claims
            .iter()
            .map(|c| (c.tx_envelope_xdr.0.as_slice(), c.tx_index))
            .collect();
        self.verify_span_core(
            head_seq,
            to32(&head_hash, "head hash"),
            &headers,
            &envelopes,
            span.tail_tx_set_xdr.as_ref().map(|s| s.0.as_slice()),
            &claims,
        )
    }

    /// Owner-only trust set maintenance (Stellar validator sets change off-chain).
    pub fn update_trust(&mut self, trusted_nodes: Vec<Base64VecU8>, threshold: u32) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(threshold > 0, "threshold must be positive");
        require!(
            threshold as usize <= trusted_nodes.len(),
            "threshold exceeds trust set size"
        );
        self.trusted_nodes = trusted_nodes.iter().map(|n| to32(n, "trusted node id")).collect();
        self.threshold = threshold;
    }

    pub fn get_head(&self) -> HeadView {
        HeadView {
            ledger_seq: self.head_seq,
            header_hash: Base64VecU8(self.head_hash.to_vec()),
        }
    }

    pub fn get_trust(&self) -> TrustView {
        TrustView {
            trusted_nodes: self
                .trusted_nodes
                .iter()
                .map(|n| Base64VecU8(n.to_vec()))
                .collect(),
            threshold: self.threshold,
            max_protocol_version: self.max_protocol_version,
        }
    }

    /// Chain-walk the span, verify the tail certificate and (if supplied) the tail
    /// transaction set, then prove any claims against that set.
    #[allow(clippy::too_many_arguments)]
    fn verify_span_core(
        &self,
        start_seq: u32,
        start_hash: [u8; 32],
        headers: &[&[u8]],
        tail_envelopes: &[&[u8]],
        tail_set: Option<&[u8]>,
        claims: &[(&[u8], u32)],
    ) -> SpanEvidence {
        require!(!headers.is_empty(), "span needs at least the tail header");

        // 1) the headers form a chain from the starting head to the tail.
        let mut prev_seq = start_seq;
        let mut prev_hash = start_hash;
        let mut pinned_by_set = start_hash;
        let mut tail: Option<(LedgerHeader, [u8; 32])> = None;
        for (i, raw) in headers.iter().enumerate() {
            let header: LedgerHeader = decode(raw, "ledger header");
            require!(header.ledger_seq == prev_seq + 1, "unexpected ledger sequence");
            require!(
                header.previous_ledger_hash.0 == prev_hash,
                "header previous ledger hash mismatch"
            );
            let hash: [u8; 32] = env::sha256(raw)
                .try_into()
                .unwrap_or_else(|_| env::panic_str("sha256 output is not 32 bytes"));
            let seq = header.ledger_seq;
            if i + 1 == headers.len() {
                // `prev_hash` is the point the tail set must pin.
                pinned_by_set = prev_hash;
                tail = Some((header, hash));
            }
            prev_seq = seq;
            prev_hash = hash;
        }
        let (tail_header, tail_hash) = tail.unwrap_or_else(|| env::panic_str("no tail header"));
        require!(
            tail_header.ledger_version <= self.max_protocol_version,
            "ledger protocol version is beyond the supported maximum"
        );

        // 2) a quorum of trusted nodes externalized exactly the tail header's SCP value.
        let (signed_value, quorum_signers) = self.check_quorum(&tail_header, tail_envelopes);

        // 3) the signed value commits to the tail's transaction set ...
        let mut pinned_seq = None;
        let mut txs: Vec<TransactionEnvelope> = Vec::new();
        if let Some(set) = tail_set {
            require!(
                env::sha256(set) == signed_value.tx_set_hash.0,
                "transaction set does not hash to the signed value"
            );
            // ... and the set pins the previous header, which pins the chain backwards.
            let set_prev = if claims.is_empty() {
                tx_set_prev_hash(set)
            } else {
                let (prev, list) = parse_tx_set(set);
                txs = list;
                prev.0
            };
            require!(set_prev == pinned_by_set, "tx set previous ledger hash mismatch");
            pinned_seq = Some(prev_seq - 1);
        }

        // 4) claims need the set: inclusion cannot be proven without it.
        require!(
            claims.is_empty() || tail_set.is_some(),
            "claims require the tail transaction set"
        );
        let mut claimed_tx_ids = Vec::with_capacity(claims.len());
        for (envelope_bytes, index) in claims {
            let idx = *index as usize;
            require!(idx < txs.len(), "claimed tx index is out of range");
            let encoded = encode(&txs[idx]);
            require!(
                encoded == *envelope_bytes,
                "claimed tx envelope is not the element at that index"
            );
            claimed_tx_ids.push(Base64VecU8(env::sha256(&encoded).to_vec()));
        }

        SpanEvidence {
            tail_seq: tail_header.ledger_seq,
            tail_hash: Base64VecU8(tail_hash.to_vec()),
            pinned_seq,
            quorum_signers,
            claimed_tx_ids,
        }
    }

    /// The RISC Zero wrapper build this contract accepts — readable by anyone, so a
    /// caller can check compatibility before spending gas on a receipt.
    pub fn get_wrapper(&self) -> WrapperView {
        WrapperView {
            control_root: Base64VecU8(self.control_root.to_vec()),
            bn254_control_id: Base64VecU8(self.bn254_control_id.to_vec()),
        }
    }

    /// Would a receipt from this wrapper build be accepted? Reads nothing else and
    /// writes nothing: pure compatibility check against the pinned identity.
    pub fn is_wrapper_compatible(
        &self,
        control_root: Base64VecU8,
        bn254_control_id: Base64VecU8,
    ) -> bool {
        let Ok(control_root) = <[u8; 32]>::try_from(control_root.0.as_slice()) else {
            return false;
        };
        let Ok(bn254_control_id) = <[u8; 32]>::try_from(bn254_control_id.0.as_slice()) else {
            return false;
        };
        control_root == self.control_root && bn254_control_id == self.bn254_control_id
    }

    /// Owner-only: rotate the accepted wrapper identity. Needed because a RISC Zero
    /// wrapper upgrade changes the verifying key — without this the contract would be
    /// permanently bound to one wrapper build.
    pub fn update_wrapper(&mut self, control_root: Base64VecU8, bn254_control_id: Base64VecU8) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        self.control_root = to32(&control_root, "control_root");
        self.bn254_control_id = to32(&bn254_control_id, "bn254_control_id");
    }

    /// Verify a RISC Zero Groth16 receipt and return what it proves.
    ///
    /// Panics only on malformed input lengths; a bad proof returns
    /// `verified: false`.
    pub fn verify_receipt(
        &self,
        seal: Base64VecU8,
        control_root: Base64VecU8,
        claim_digest: Base64VecU8,
        bn254_control_id: Base64VecU8,
    ) -> ReceiptEvidence {
        let control_root = to32(&control_root, "control_root");
        let claim_digest = to32(&claim_digest, "claim_digest");
        let bn254_control_id = to32(&bn254_control_id, "bn254_control_id");
        // Reject unknown wrapper builds before touching the proof. The verifying key
        // is RISC Zero's STARK→SNARK wrapper key, so the wrapper build is the trust
        // anchor: a receipt is only meaningful if we accept that wrapper.
        require!(
            control_root == self.control_root,
            "unsupported RISC Zero wrapper: control_root not pinned"
        );
        require!(
            bn254_control_id == self.bn254_control_id,
            "unsupported RISC Zero wrapper: bn254_control_id not pinned"
        );
        let seal = seal.0;
        require!(seal.len() == 256, "seal must be 256 bytes");

        let inputs = verifier::risc0::public_inputs(control_root, claim_digest, bn254_control_id);
        let verified = match verifier::risc0::seal_to_proof(&seal) {
            Ok(proof) => {
                verifier::groth16::verify(&verifier::risc0::verifying_key(), &proof, &inputs)
            }
            Err(_) => false,
        };

        ReceiptEvidence {
            verified,
            claim_digest: Base64VecU8(claim_digest.to_vec()),
            control_root: Base64VecU8(control_root.to_vec()),
        }
    }

    /// Verify signatures of trusted nodes externalizing exactly the header's SCP value.
    /// One pass; stops as soon as the threshold is met.
    fn check_quorum(
        &self,
        header: &LedgerHeader,
        envelopes: &[&[u8]],
    ) -> (StellarValue, u32) {
        let mut counted: Vec<[u8; 32]> = Vec::new();
        let mut value: Option<StellarValue> = None;
        for raw in envelopes {
            let envelope: ScpEnvelope = decode(raw, "scp envelope");
            let statement = &envelope.statement;
            if statement.slot_index != u64::from(header.ledger_seq) {
                continue; // witness for a different slot
            }
            let ScpStatementPledges::Externalize(ext) = &statement.pledges else {
                continue; // only EXTERNALIZE finalizes a value
            };

            // The externalized value must be exactly the header's SCP value.
            let externalized: StellarValue = decode(value_bytes(&ext.commit.value), "stellar value");
            require!(
                externalized == header.scp_value,
                "externalized value differs from the header scp value"
            );
            value = Some(externalized);

            let PublicKey::PublicKeyTypeEd25519(key) = &statement.node_id.0;
            let node_id = key.0;
            if counted.contains(&node_id) {
                continue; // one vote per node
            }
            if !self.trusted_nodes.contains(&node_id) {
                continue; // not part of the pinned trust set
            }

            // stellar-core: signature = sign(xdr(networkID, ENVELOPE_TYPE_SCP, statement))
            let statement_xdr = encode(statement);
            let mut message = Vec::with_capacity(32 + 4 + statement_xdr.len());
            message.extend_from_slice(&self.network_id);
            message.extend_from_slice(&(EnvelopeType::Scp as i32).to_be_bytes());
            message.extend_from_slice(&statement_xdr);

            let signature = signature_bytes(&envelope.signature);
            require!(
                env::ed25519_verify(&signature, &message, &node_id),
                "invalid validator signature"
            );

            counted.push(node_id);
            if counted.len() as u32 >= self.threshold {
                break;
            }
        }
        let signers = counted.len() as u32;
        require!(signers >= self.threshold, "quorum threshold not met");
        let value = value.unwrap_or_else(|| env::panic_str("no externalize statement for ledger"));
        (value, signers)
    }
}

// ---------------------------------------------------------------- decoding helpers

fn slices(items: &[Base64VecU8]) -> Vec<&[u8]> {
    items.iter().map(|i| i.0.as_slice()).collect()
}

fn decode<T: ReadXdr>(bytes: &[u8], what: &str) -> T {
    let mut reader = Limited::new(Cursor::new(bytes), Limits::none());
    T::read_xdr_to_end(&mut reader)
        .unwrap_or_else(|_| env::panic_str(&format!("invalid {what} xdr")))
}

fn try_decode<T: ReadXdr>(bytes: &[u8]) -> Option<T> {
    let mut reader = Limited::new(Cursor::new(bytes), Limits::none());
    T::read_xdr_to_end(&mut reader).ok()
}

fn encode<T: WriteXdr>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = Limited::new(&mut buf, Limits::none());
    value
        .write_xdr(&mut writer)
        .unwrap_or_else(|_| env::panic_str("xdr encoding failed"));
    buf
}

/// Read `previousLedgerHash` from a transaction set without decoding the set.
///
/// ponytail: the set kind is inferred from the XDR union discriminant (4 bytes) instead
/// of parsing every transaction envelope — a 341 KiB set of ~385 envelopes reduced to a
/// 36-byte read. The sha256 check pins these bytes to the signed value and the chain
/// check pins the hash, so misreading the kind fails closed (it can only reject), with
/// the theoretical exception of a 2^-32 prefix collision. Upgrade path: [`parse_tx_set`],
/// which is exact and already used whenever claims are present.
fn tx_set_prev_hash(bytes: &[u8]) -> [u8; 32] {
    require!(bytes.len() >= 36, "transaction set is too short");
    let discriminant = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let offset = if discriminant == 1 {
        4 // GeneralizedTransactionSet: union discriminant precedes TransactionSetV1
    } else {
        0 // TransactionSet starts with the hash
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[offset..offset + 32]);
    out
}

/// Split a transaction set into its `previousLedgerHash` and its transactions.
///
/// Both encodings start with that hash: `TransactionSet` directly, and
/// `GeneralizedTransactionSet` after the union discriminant. Whichever type
/// re-encodes byte-identically is the one the network hashed.
fn parse_tx_set(bytes: &[u8]) -> (Hash, Vec<TransactionEnvelope>) {
    if let Some(set) = try_decode::<GeneralizedTransactionSet>(bytes) {
        if encode(&set) == bytes {
            let GeneralizedTransactionSet::V1(v1) = &set;
            let mut txs = Vec::new();
            for phase in v1.phases.iter() {
                match phase {
                    TransactionPhase::V0(components) => {
                        for component in components.iter() {
                            let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(component) =
                                component;
                            txs.extend(component.txs.iter().cloned());
                        }
                    }
                    TransactionPhase::V1(component) => {
                        // Parallel phase: stages of dependent-tx clusters, flattened in
                        // serialization order so indices match the set as hashed.
                        for stage in component.execution_stages.iter() {
                            for cluster in stage.0.iter() {
                                txs.extend(cluster.0.iter().cloned());
                            }
                        }
                    }
                }
            }
            return (v1.previous_ledger_hash.clone(), txs);
        }
    }
    let set: TransactionSet = decode(bytes, "transaction set");
    require!(encode(&set) == bytes, "transaction set is not canonical xdr");
    (
        set.previous_ledger_hash.clone(),
        set.txs.iter().cloned().collect(),
    )
}

fn value_bytes(value: &Value) -> &[u8] {
    value.0.as_slice()
}

fn signature_bytes(signature: &Signature) -> [u8; 64] {
    let Ok(sig) = <[u8; 64]>::try_from(signature.0.as_slice()) else {
        env::panic_str("signature is not 64 bytes")
    };
    sig
}

fn to32(value: &Base64VecU8, what: &str) -> [u8; 32] {
    let Ok(bytes) = <[u8; 32]>::try_from(value.0.as_slice()) else {
        env::panic_str(&format!("{what} must be 32 bytes"))
    };
    bytes
}
