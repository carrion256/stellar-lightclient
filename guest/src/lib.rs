//! RISC Zero guest for the Stellar light-client epoch path.
//!
//! Verifies a whole epoch of ledger closes + deposit claims with the shared
//! [`verify_core::verify_span`] (one quorum certificate per span, chain-pinned
//! through each span's tail transaction set) and commits a compact
//! [`verify_core::EpochJournal`]. Off-chain, the relayer builds an [`EpochInput`],
//! `run_epoch_bytes` deserializes it — in-guest the zkVM runs this same code,
//! so the journal the NEAR contract checks was produced by the same
//! verification path.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use verify_core::{
    encode_journal, verify_span, Crypto, EpochJournal, Error, SpanProof, Trust,
};

/// The guest's [`Crypto`] backend: real SHA-256 and ed25519, no shortcuts.
/// Malformed keys or signatures fail closed (`false`) — verification never
/// panics on attacker-controlled input.
pub struct Sha256Dalek;

impl Crypto for Sha256Dalek {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn ed25519_verify(&self, signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let sig = Signature::from_bytes(signature);
        key.verify_strict(message, &sig).is_ok()
    }
}

/// One span: headers, the tail's quorum certificates, the tail's transaction
/// set (if pinned), and claims against that set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpanInput {
    pub headers: Vec<Vec<u8>>,
    pub tail_envelopes: Vec<Vec<u8>>,
    pub tail_set: Option<Vec<u8>>,
    pub claims: Vec<(Vec<u8>, u32)>,
}

/// Everything the guest needs to attest an epoch. Field order is the relayer
/// contract: `trust`, `start_seq`, `start_hash`, `spans`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochInput {
    pub trust: Trust,
    pub start_seq: u32,
    pub start_hash: [u8; 32],
    pub spans: Vec<SpanInput>,
}

/// Verifies every span in order, chaining each span's start from the previous
/// outcome, and returns the journal for the whole epoch. Claim ids accumulate
/// across all spans; a zero-span epoch is valid and yields a start==end journal.
pub fn run_epoch(input: &EpochInput) -> Result<EpochJournal, Error> {
    run_epoch_with(&Sha256Dalek, input)
}

/// Same as [`run_epoch`] with an injectable crypto backend (for testing).
pub fn run_epoch_with<C: Crypto>(crypto: &C, input: &EpochInput) -> Result<EpochJournal, Error> {
    let mut start_seq = input.start_seq;
    let mut start_hash = input.start_hash;
    let mut claim_ids = Vec::new();

    for span in &input.spans {
        let headers: Vec<&[u8]> = span.headers.iter().map(|h| h.as_slice()).collect();
        let tail_envelopes: Vec<&[u8]> = span
            .tail_envelopes
            .iter()
            .map(|e| e.as_slice())
            .collect();
        let claims: Vec<(&[u8], u32)> = span
            .claims
            .iter()
            .map(|(c, i)| (c.as_slice(), *i))
            .collect();

        let proof = SpanProof {
            headers: &headers,
            tail_envelopes: &tail_envelopes,
            tail_set: span.tail_set.as_deref(),
            claims: &claims,
        };
        let outcome = verify_span(crypto, &input.trust, start_seq, start_hash, &proof)?;

        claim_ids.extend_from_slice(&outcome.claim_ids);
        start_seq = outcome.tail_seq;
        start_hash = outcome.tail_hash;
    }

    Ok(EpochJournal {
        start_seq: input.start_seq,
        start_hash: input.start_hash,
        end_seq: start_seq,
        end_hash: start_hash,
        claim_ids,
    })
}

/// zkVM entry helper: deserialize the [`EpochInput`], run the epoch, return
/// the journal bytes for commitment.
pub fn run_epoch_bytes(input_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let input: EpochInput =
        bincode::deserialize(input_bytes).map_err(|e| format!("invalid epoch input: {e}"))?;
    let journal = run_epoch(&input).map_err(|e| format!("epoch verification failed: {e}"))?;
    Ok(encode_journal(&journal))
}
