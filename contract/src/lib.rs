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
//! The tail transaction set *pins* the chain: its signed `previousLedgerHash`
//! authenticates the ledger before the tail. The contract's stored head is
//! exactly that authenticated checkpoint — never the tail header's own hash,
//! which the signed bytes do not cover (storing it would let a forged tail
//! poison the chain). Mutable submission therefore requires the tail set;
//! spans without one are *provisional* — viewable via `verify_span_view`,
//! never stored, and claims can never be provisional since proving inclusion
//! needs the set.
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

use verify_core::Crypto;

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
#[derive(Clone, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SpanProof {
    /// The authenticated predecessor header for single-header spans carrying
    /// claims: the header XDR for ledger `head_seq` itself, which must match
    /// the stored checkpoint. Optional for multi-header spans, whose
    /// predecessor is the penultimate (authenticated) span header.
    pub start_header: Option<Base64VecU8>,
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TxClaim {
    pub tx_envelope_xdr: Base64VecU8,
    pub tx_index: u32,
}

// ------------------------------------------------------------------ raw (Borsh) args

/// Same as [`SpanProof`] but Borsh-encoded: call arguments are raw bytes on NEAR, so a
/// Borsh entry point skips both base64 (1.33x) and JSON parsing. ~27% smaller calldata.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct SpanProofRaw {
    /// Authenticated predecessor header (see [`SpanProof::start_header`]).
    /// Borsh field order is part of the wire format — this must stay first.
    pub start_header: Option<Vec<u8>>,
    pub headers: Vec<Vec<u8>>,
    pub tail_envelopes: Vec<Vec<u8>>,
    pub tail_tx_set: Option<Vec<u8>>,
    pub tx_claims: Vec<TxClaimRaw>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
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
    /// The checkpoint authenticated by the tail's signed transaction set: the
    /// ledger *before* the tail, pinned by signed bytes. `None` for provisional
    /// spans, which can be viewed but never submitted.
    pub authenticated_head: Option<HeadView>,
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

/// Outcome of verifying one RISC Zero Groth16 receipt **and** binding it to
/// this contract's epoch policy.
///
/// `verified: false` (rather than a panic) for any proof or binding failure;
/// the wrapper pinning and length rules panic exactly like
/// [`ReceiptEvidence`]. When unverified, the epoch fields
/// (`end_seq`/`end_hash`/`claim_ids`) are zeroed — invalid evidence exposes
/// nothing — and callers must branch on `verified` first.
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
    /// Transaction envelope inclusion IDs: sha256(tx envelope) per proven
    /// claim, as committed by the guest. The light client proves inclusion of
    /// envelope bytes in the tail set; it proves nothing about the operation
    /// inside.
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
    /// The epoch guest program whose successful claims `verify_claim` accepts.
    /// This is the `pre` image ID of the canonical success claim; receipts
    /// produced by any other guest program are refused at claim binding —
    /// before Groth16 — because the wrapper key itself is universal.
    pub epoch_image_id: [u8; 32],
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
        epoch_image_id: Base64VecU8,
    ) -> Self {
        let this = Self {
            owner,
            network_id: to32(&network_id, "network_id"),
            trusted_nodes: trusted_nodes.iter().map(|n| to32(n, "trusted node id")).collect(),
            threshold,
            max_protocol_version,
            head_seq,
            head_hash: to32(&head_hash, "head_hash"),
            control_root: to32(&control_root, "control_root"),
            bn254_control_id: to32(&bn254_control_id, "bn254_control_id"),
            epoch_image_id: to32(&epoch_image_id, "epoch_image_id"),
        };
        // The shared trust validator rejects impossible thresholds and
        // duplicated node ids — a duplicated id can never contribute to quorum,
        // so accepting one would strand the contract with a trust set that can
        // never satisfy its own threshold.
        if let Err(error) = verify_core::validate_trust(&this.trust()) {
            env::panic_str(&error.to_string());
        }
        // A non-canonical wrapper identity can never verify anything — refuse
        // it at the configuration boundary rather than on every later receipt.
        require_valid_wrapper(this.control_root, this.bn254_control_id);
        this
    }

    /// Verify a span and advance the chain head to the checkpoint *authenticated*
    /// by its signed tail transaction set.
    ///
    /// The span must start at `head_seq + 1`; intermediate ledgers cost only their
    /// header (428 B) because the tail certificate pins them transitively.
    /// Intermediate ledgers never become the head: the stored head is the ledger
    /// pinned *through* signed bytes, so a tampered tail header cannot poison the
    /// chain (its own hash is never stored).
    pub fn submit_span(&mut self, span: SpanProof) -> SpanEvidence {
        let headers = slices(&span.headers);
        let envelopes = slices(&span.tail_envelopes);
        let claims: Vec<(&[u8], u32)> = span
            .tx_claims
            .iter()
            .map(|c| (c.tx_envelope_xdr.0.as_slice(), c.tx_index))
            .collect();
        let evidence = self.verify_span_core(
            span.start_header.as_ref().map(|h| h.0.as_slice()),
            self.head_seq,
            self.head_hash,
            &headers,
            &envelopes,
            span.tail_tx_set_xdr.as_ref().map(|s| s.0.as_slice()),
            &claims,
        );
        self.persist_authenticated_head(&evidence);
        evidence
    }

    /// Persist the tail-authenticated predecessor checkpoint. `evidence` is the
    /// output of a core-verified span; `authenticated_head` is `None` only for
    /// provisional spans, which by policy may be *viewed* but never stored.
    fn persist_authenticated_head(&mut self, evidence: &SpanEvidence) {
        let head = evidence
            .authenticated_head
            .as_ref()
            .unwrap_or_else(|| env::panic_str("span submission requires the tail transaction set"));
        self.head_seq = head.ledger_seq;
        self.head_hash = to32(&head.header_hash, "authenticated head hash");
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
            span.start_header.as_deref(),
            self.head_seq,
            self.head_hash,
            &headers,
            &envelopes,
            span.tail_tx_set.as_deref(),
            &claims,
        );
        self.persist_authenticated_head(&evidence);
        evidence
    }

    /// Stateless check of a span against an arbitrary starting checkpoint:
    /// what would be proven if this were submitted there.
    ///
    /// The view has no pinning requirement — provisional spans (no tail
    /// transaction set) can be checked and returned here, they just can never
    /// be submitted (see [`submit_span`]).
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
            span.start_header.as_ref().map(|h| h.0.as_slice()),
            head_seq,
            to32(&head_hash, "head hash"),
            &headers,
            &envelopes,
            span.tail_tx_set_xdr.as_ref().map(|s| s.0.as_slice()),
            &claims,
        )
    }

    /// Owner-only trust set maintenance (Stellar validator sets change off-chain).
    /// Validated with the same shared helper submissions use, so a duplicated
    /// node id or an impossible threshold can never be stored.
    pub fn update_trust(&mut self, trusted_nodes: Vec<Base64VecU8>, threshold: u32) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        let candidate = verify_core::Trust {
            network_id: self.network_id,
            trusted_nodes: trusted_nodes.iter().map(|n| to32(n, "trusted node id")).collect(),
            threshold,
            max_protocol_version: self.max_protocol_version,
        };
        if let Err(error) = verify_core::validate_trust(&candidate) {
            env::panic_str(&error.to_string());
        }
        self.trusted_nodes = candidate.trusted_nodes;
        self.threshold = threshold;
    }

    /// The epoch guest image whose claims `verify_claim` accepts.
    pub fn get_epoch_image(&self) -> Base64VecU8 {
        Base64VecU8(self.epoch_image_id.to_vec())
    }

    /// Owner-only: rotate the accepted epoch guest image (e.g. after a guest
    /// program upgrade). Receipts from any other image stay unverified.
    pub fn update_epoch_image_id(&mut self, epoch_image_id: Base64VecU8) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        self.epoch_image_id = to32(&epoch_image_id, "epoch_image_id");
    }

    /// Owner-only: change the supported protocol ceiling. Validated through
    /// the same shared trust helper submissions use, so the configuration can
    /// never be left in a state `verify_core` rejects.
    pub fn update_max_protocol_version(&mut self, max_protocol_version: u32) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        let candidate = verify_core::Trust {
            max_protocol_version,
            ..self.trust()
        };
        if let Err(error) = verify_core::validate_trust(&candidate) {
            env::panic_str(&error.to_string());
        }
        self.max_protocol_version = max_protocol_version;
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
    /// (no private copy of this logic here). Failures panic with the core's
    /// `Display` text, whose prefix is exactly the message this contract has
    /// always used (positional context follows after " — ").
    #[allow(clippy::too_many_arguments)]
    fn verify_span_core(
        &self,
        start_header: Option<&[u8]>,
        start_seq: u32,
        start_hash: [u8; 32],
        headers: &[&[u8]],
        tail_envelopes: &[&[u8]],
        tail_set: Option<&[u8]>,
        claims: &[(&[u8], u32)],
    ) -> SpanEvidence {
        let proof = verify_core::SpanProof {
            start_header,
            headers,
            tail_envelopes,
            tail_set,
            claims,
        };
        let outcome =
            match verify_core::verify_span(&NearCrypto, &self.trust(), start_seq, start_hash, &proof)
        {
            Ok(outcome) => outcome,
            Err(error) => env::panic_str(&error.to_string()),
        };
        SpanEvidence {
            tail_seq: outcome.tail_seq,
            tail_hash: Base64VecU8(outcome.tail_hash.to_vec()),
            authenticated_head: outcome.authenticated_head.map(|head| HeadView {
                ledger_seq: head.seq,
                header_hash: Base64VecU8(head.hash.to_vec()),
            }),
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
    ///
    /// The identity is checked at the configuration boundary: a `bn254_control_id`
    /// that is not a canonical BN254 scalar can never verify a Groth16 receipt, so
    /// pinning one would strand the contract on a permanently impossible wrapper.
    pub fn update_wrapper(&mut self, control_root: Base64VecU8, bn254_control_id: Base64VecU8) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        let control_root = to32(&control_root, "control_root");
        let bn254_control_id = to32(&bn254_control_id, "bn254_control_id");
        require_valid_wrapper(control_root, bn254_control_id);
        self.control_root = control_root;
        self.bn254_control_id = bn254_control_id;
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
        let verified = match (verifier::risc0::seal_to_proof(&seal), inputs) {
            (Ok(proof), Ok(inputs)) => {
                verifier::groth16::verify(&verifier::risc0::verifying_key(), &proof, &inputs)
            }
            _ => false,
        };

        ReceiptEvidence {
            verified,
            claim_digest: Base64VecU8(claim_digest.to_vec()),
            control_root: Base64VecU8(control_root.to_vec()),
        }
    }

    /// Verify a RISC Zero Groth16 receipt **and** bind it to this contract's
    /// epoch policy *before* any pairing work: the supplied `journal` must
    /// decode, commit to the current trust policy, start at the stored
    /// checkpoint, describe a coherent epoch, and `claim_digest` must equal the
    /// digest of the canonical *success* claim for the configured epoch guest
    /// image. Callers no longer supply claim bytes — the contract derives the
    /// expected claim itself, so the proof is checked against this contract's
    /// own image and policy, not against anything the caller claims.
    ///
    /// Panics on malformed lengths and on an unpinned wrapper (same reason
    /// strings as [`verify_receipt`]). Any failure — bad proof, wrong image,
    /// wrong policy, stale or incoherent checkpoint — reports `verified: false`
    /// with zeroed epoch fields; invalid evidence exposes nothing.
    pub fn verify_claim(
        &self,
        seal: Base64VecU8,
        control_root: Base64VecU8,
        claim_digest: Base64VecU8,
        bn254_control_id: Base64VecU8,
        journal: Base64VecU8,
    ) -> ClaimEvidence {
        // 1) digest conversion.
        let control_root = to32(&control_root, "control_root");
        let claim_digest = to32(&claim_digest, "claim_digest");
        let bn254_control_id = to32(&bn254_control_id, "bn254_control_id");
        let seal = seal.0;
        let journal = journal.0;

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

        // 4) cheap bindings first, Groth16 last: the journal can only be
        // accepted if it could have come from the configured guest image under
        // the current policy and checkpoint. A receipt proving *any* execution
        // is worthless here — only the configured image's success claim counts.
        let unverified = |journal| ClaimEvidence {
            verified: false,
            claim_digest: Base64VecU8(claim_digest.to_vec()),
            journal: Base64VecU8(journal),
            end_seq: 0,
            end_hash: Base64VecU8(Vec::new()),
            claim_ids: Vec::new(),
        };
        let Some(epoch) = self.bind_epoch(&journal, claim_digest) else {
            return unverified(journal);
        };

        // 5) Groth16 — a bad proof is reported, not thrown. Unknown scalar
        // public inputs are not verifiable either, and never panic.
        let verified = match verifier::risc0::public_inputs(control_root, claim_digest, bn254_control_id) {
            Err(_) => false,
            Ok(inputs) => match verifier::risc0::seal_to_proof(&seal) {
                Ok(proof) => verifier::groth16::verify(&verifier::risc0::verifying_key(), &proof, &inputs),
                Err(_) => false,
            },
        };
        if !verified {
            return unverified(journal);
        }

        ClaimEvidence {
            verified,
            claim_digest: Base64VecU8(claim_digest.to_vec()),
            journal: Base64VecU8(journal),
            end_seq: epoch.end_seq,
            end_hash: Base64VecU8(epoch.end_hash.to_vec()),
            claim_ids: epoch
                .claim_ids
                .iter()
                .map(|id| Base64VecU8(id.to_vec()))
                .collect(),
        }
    }

    fn trust(&self) -> verify_core::Trust {
        verify_core::Trust {
            network_id: self.network_id,
            trusted_nodes: self.trusted_nodes.clone(),
            threshold: self.threshold,
            max_protocol_version: self.max_protocol_version,
        }
    }

    /// The non-cryptographic bindings a journal must satisfy for this contract
    /// to treat a receipt over it as candidate evidence: canonical v1 decode,
    /// the current trust policy digest, the stored checkpoint as the epoch
    /// start, and a coherent epoch end. Returns the decoded journal only when
    /// every binding holds *and* the claimed claim digest equals the digest of
    /// the canonical success claim for the configured epoch image.
    fn bind_epoch(&self, journal: &[u8], claimed_digest: [u8; 32]) -> Option<verify_core::EpochJournal> {
        let epoch = verify_core::decode_journal(journal).ok()?;
        let Ok(policy) = verify_core::trust_digest(&NearCrypto, &self.trust()) else {
            return None;
        };
        if epoch.policy_digest != policy {
            return None;
        }
        if epoch.start_seq != self.head_seq || epoch.start_hash != self.head_hash {
            return None;
        }
        // Coherent epoch: time moves forward, and an epoch that doesn't move
        // must still agree with itself.
        if epoch.end_seq < epoch.start_seq
            || (epoch.end_seq == epoch.start_seq && epoch.end_hash != epoch.start_hash)
        {
            return None;
        }
        let expected = verifier::claim::claim_digest(&verifier::claim::ok_claim(self.epoch_image_id, journal));
        (expected == claimed_digest).then_some(epoch)
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

/// Canonicality gate for the pinned wrapper identity. The Groth16 public
/// inputs are field elements: a `bn254_control_id` that is not canonically
/// below the BN254 scalar-field modulus can never verify — pinning one would
/// strand the contract on a permanently impossible wrapper, so callers of
/// `new`/`update_wrapper` are refused here rather than on every later receipt.
/// Reuses the verifier's strict input derivation; no separate crypto.
fn require_valid_wrapper(control_root: [u8; 32], bn254_control_id: [u8; 32]) {
    if verifier::risc0::public_inputs(control_root, [0u8; 32], bn254_control_id).is_err() {
        env::panic_str("bn254_control_id is not a canonical BN254 scalar");
    }
}
