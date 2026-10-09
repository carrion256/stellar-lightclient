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

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, require, AccountId, PanicOnDefault};

#[cfg(test)]
use std::io::Cursor;

#[cfg(test)]
use stellar_xdr::{LedgerHeader, Limited, Limits, PublicKey, ReadXdr, ScpEnvelope,
ScpStatementPledges, WriteXdr};

use verify_core::{Crypto, Error};

/// Near host functions behind `verify_core::Crypto` — the only crypto the shared
/// core needs; everything else in `verify_core::verify_span` is host-agnostic.
struct NearCrypto;

impl Crypto for NearCrypto {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        env::sha256(bytes)
            .try_into()
            .unwrap_or_else(|_| env::panic_str("sha256 output is not 32 bytes"))
    }

    fn ed25519_verify(&self, signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
        env::ed25519_verify(signature, message, public_key)
    }
}

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

/// Outcome of verifying one RISC Zero Groth16 receipt **and** the claim it proves,
/// read out of the journal the guest committed.
///
/// `verified: false` (rather than a panic) for any proof/binding failure; the
/// wrapper pinning and length rules panic exactly like [`ReceiptEvidence`]. When
/// unverified, `journal`/`claim_digest` echo the input and `end_seq`/`end_hash`/
/// `claim_ids` are zeroed — callers must branch on `verified` first.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ClaimEvidence {
    pub verified: bool,
    /// Claim digest the proof was verified against (echo of the public input).
    pub claim_digest: Base64VecU8,
    /// The guest's committed output, echoed back for the caller.
    pub journal: Base64VecU8,
    pub end_seq: u32,
    pub end_hash: Base64VecU8,
    /// sha256(tx envelope) per settled deposit, as committed by the guest.
    pub claim_ids: Vec<Base64VecU8>,
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

    /// Chain-walk, tail certificate, transaction-set pinning, and claim proofs run
    /// in `verify_core::verify_span` — the host-agnostic core shared with the guest
    /// (no private copy of this logic here). Failures map 1:1 onto the panic
    /// messages this contract has always used.
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
        let proof = verify_core::SpanProof {
            headers,
            tail_envelopes,
            tail_set,
            claims,
        };
        let trust = verify_core::Trust {
            network_id: self.network_id,
            trusted_nodes: self.trusted_nodes.clone(),
            threshold: self.threshold,
            max_protocol_version: self.max_protocol_version,
        };
        let outcome = match verify_core::verify_span(&NearCrypto, &trust, start_seq, start_hash, &proof) {
            Ok(outcome) => outcome,
            Err(error) => {
                // The core's Display prefix for every variant is exactly the
                // message this contract panicked with before the split (extra
                // context follows after " — ", appended by the core, not here).
                let message = match error {
                    Error::EmptySpan => "span needs at least the tail header",
                    Error::InvalidHeaderXdr { .. } => "invalid ledger header xdr",
                    Error::UnexpectedLedgerSeq { .. } => "unexpected ledger sequence",
                    Error::PreviousLedgerHashMismatch { .. } => "header previous ledger hash mismatch",
                    Error::ProtocolVersionExceeded { .. } => {
                        "ledger protocol version is beyond the supported maximum"
                    }
                    Error::InvalidEnvelopeXdr { .. } => "invalid scp envelope xdr",
                    Error::InvalidStellarValueXdr { .. } => "invalid stellar value xdr",
                    Error::ExternalizedValueMismatch { .. } => {
                        "externalized value differs from the header scp value"
                    }
                    Error::InvalidSignatureLength { .. } => "signature is not 64 bytes",
                    Error::InvalidValidatorSignature { .. } => "invalid validator signature",
                    Error::QuorumNotReached { .. } => "quorum threshold not met",
                    Error::NoExternalizeStatement => "no externalize statement for ledger",
                    Error::TxSetHashMismatch => "transaction set does not hash to the signed value",
                    Error::TxSetTooShort => "transaction set is too short",
                    Error::InvalidTxSetXdr => "invalid transaction set xdr",
                    Error::NonCanonicalTxSet => "transaction set is not canonical xdr",
                    Error::TxSetPreviousLedgerHashMismatch => "tx set previous ledger hash mismatch",
                    Error::ClaimsRequireTxSet => "claims require the tail transaction set",
                    Error::ClaimIndexOutOfRange { .. } => "claimed tx index is out of range",
                    Error::ClaimEnvelopeMismatch { .. } => {
                        "claimed tx envelope is not the element at that index"
                    }
                    Error::MalformedJournal(_) => "invalid epoch journal encoding",
                };
                env::panic_str(message);
            }
        };
        SpanEvidence {
            tail_seq: outcome.tail_seq,
            tail_hash: Base64VecU8(outcome.tail_hash.to_vec()),
            pinned_seq: outcome.pinned_seq,
            quorum_signers: outcome.quorum_signers,
            claimed_tx_ids: outcome
                .claim_ids
                .iter()
                .map(|id| Base64VecU8(id.to_vec()))
                .collect(),
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
        // anchor: a receipt is only meaningful if we accept that wrapper. Fail with
        // `env::panic_str` directly (not `require!`) so the reason is always a
        // `GuestPanic` message a caller can read, never a bare wasm trap.
        if control_root != self.control_root {
            // Log the reason explicitly: depending on near-sdk's panic plumbing the
            // failure surfaces as a GuestPanic message or as a bare wasm trap, and a
            // caller must always be able to tell why their receipt was refused.
            env::log_str("unsupported RISC Zero wrapper: control_root not pinned");
            env::panic_str("unsupported RISC Zero wrapper: control_root not pinned");
        }
        if bn254_control_id != self.bn254_control_id {
            env::log_str("unsupported RISC Zero wrapper: bn254_control_id not pinned");
            env::panic_str("unsupported RISC Zero wrapper: bn254_control_id not pinned");
        }
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

    /// Verify a RISC Zero Groth16 receipt **and** bind it to the claim the guest
    /// proved: the supplied `claim` bytes must digest (with
    /// `verifier::claim::claim_digest`) to the `claim_digest` public input, and the
    /// supplied `journal` must hash into the claim's output. Returns the epoch journal
    /// contents so a bridge can read the settled deposits.
    ///
    /// Panics on malformed lengths and on an unpinned wrapper (same reason strings as
    /// [`verify_receipt`]); a structurally-valid but cryptographically-bad proof
    /// returns `verified: false` rather than panicking, per [`ReceiptEvidence`].
    /// The same applies to claim/journal binding failures: a valid receipt whose
    /// claim or journal doesn't match is reported via `verified: false`, never as a
    /// panic, so the evidence value itself is the verdict.
    pub fn verify_claim(
        &self,
        seal: Base64VecU8,
        control_root: Base64VecU8,
        claim_digest: Base64VecU8,
        bn254_control_id: Base64VecU8,
        claim: Base64VecU8,
        journal: Base64VecU8,
    ) -> ClaimEvidence {
        // 1) digest conversion.
        let control_root = to32(&control_root, "control_root");
        let claim_digest = to32(&claim_digest, "claim_digest");
        let bn254_control_id = to32(&bn254_control_id, "bn254_control_id");
        let seal = seal.0;

        // 2) wrapper pinning — identical rejection to verify_receipt, same strings.
        // The wrapper build is the trust anchor, so unknown wrappers are refused
        // before any payload length is even inspected.
        if control_root != self.control_root {
            env::log_str("unsupported RISC Zero wrapper: control_root not pinned");
            env::panic_str("unsupported RISC Zero wrapper: control_root not pinned");
        }
        if bn254_control_id != self.bn254_control_id {
            env::log_str("unsupported RISC Zero wrapper: bn254_control_id not pinned");
            env::panic_str("unsupported RISC Zero wrapper: bn254_control_id not pinned");
        }

        // 3) malformed lengths panic; nothing else in this call is a caller error.
        require!(seal.len() == 256, "seal must be 256 bytes");
        require!(
            claim.0.len() == 104,
            "receipt claim must be 104 bytes (see verifier::claim::ReceiptClaim)"
        );

        // 4) Groth16 — a bad proof is reported, not thrown.
        let inputs = verifier::risc0::public_inputs(control_root, claim_digest, bn254_control_id);
        let verified = match verifier::risc0::seal_to_proof(&seal) {
            Ok(proof) => {
                verifier::groth16::verify(&verifier::risc0::verifying_key(), &proof, &inputs)
            }
            Err(_) => false,
        };

        // 5) the claim bytes must digest to the claim_digest public input.
        let claim = verifier::claim::ReceiptClaim::decode(&claim.0)
            .unwrap_or_else(|e| env::panic_str(&e));
        let verified = verified && claim_digest == verifier::claim::claim_digest(&claim);

        // 6) the journal must hash into the claim's output (risc0 `Output` tagged
        // digest over `journal_digest(journal)` + empty assumptions).
        let verified = verified
            && claim.output == Some(verifier::claim::ok_output_digest(&journal.0));

        // 7) decode the journal so the evidence always reports what it claims.
        // A decode failure panics only when `verified == true`: the journal is
        // cryptographically bound then, so it is a caller/encoding error. An
        // unverified journal is unbound input and must never panic; it yields
        // empty epoch fields instead.
        let epoch = match verify_core::decode_journal(&journal.0) {
            Ok(epoch) => Some(epoch),
            Err(error) => {
                if verified {
                    env::panic_str(&error.to_string())
                } else {
                    None
                }
            }
        };
        ClaimEvidence {
            verified,
            claim_digest: Base64VecU8(claim_digest.to_vec()),
            journal: Base64VecU8(journal.0),
            end_seq: epoch.as_ref().map_or(0, |epoch| epoch.end_seq),
            end_hash: Base64VecU8(
                epoch
                    .as_ref()
                    .map_or_else(Vec::new, |epoch| epoch.end_hash.to_vec()),
            ),
            claim_ids: epoch.map_or_else(Vec::new, |epoch| {
                epoch
                    .claim_ids
                    .iter()
                    .map(|id| Base64VecU8(id.to_vec()))
                    .collect()
            }),
        }
    }

}

// ---------------------------------------------------------------- decoding helpers

fn slices(items: &[Base64VecU8]) -> Vec<&[u8]> {
    items.iter().map(|i| i.0.as_slice()).collect()
}

// Test fixture codec: the tests forge/tamper XDR payloads with these. The span
// verification logic itself lives in `verify_core`; production code no longer
// parses XDR at all.
#[cfg(test)]
fn decode<T: ReadXdr>(bytes: &[u8], what: &str) -> T {
    let mut reader = Limited::new(Cursor::new(bytes), Limits::none());
    T::read_xdr_to_end(&mut reader)
        .unwrap_or_else(|_| env::panic_str(&format!("invalid {what} xdr")))
}

#[cfg(test)]
fn encode<T: WriteXdr>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = Limited::new(&mut buf, Limits::none());
    value
        .write_xdr(&mut writer)
        .unwrap_or_else(|_| env::panic_str("xdr encoding failed"));
    buf
}

fn to32(value: &Base64VecU8, what: &str) -> [u8; 32] {
    let Ok(bytes) = <[u8; 32]>::try_from(value.0.as_slice()) else {
        env::panic_str(&format!("{what} must be 32 bytes"))
    };
    bytes
}
