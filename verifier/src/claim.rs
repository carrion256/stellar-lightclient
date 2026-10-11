//! RISC Zero receipt-claim handling for NEAR.
//!
//! The digest derivation — `ReceiptClaim`, `journal_digest`,
//! `ok_output_digest`, `claim_digest`, `ok_claim` — is chain-agnostic and
//! lives in [`groth16_core::claim`] (with all of its RISC Zero source
//! citations). This module keeps this crate's original signatures by
//! supplying the NEAR [`NearOps`] provider internally: every call hashes
//! through `near_sdk::env::sha256`, exactly as before.

use crate::ops::NearOps;

pub use groth16_core::claim::ReceiptClaim;

/// [`groth16_core::claim::journal_digest`] with the NEAR provider.
pub fn journal_digest(journal: &[u8]) -> [u8; 32] {
    groth16_core::claim::journal_digest(&NearOps, journal)
}

/// [`groth16_core::claim::ok_output_digest`] with the NEAR provider.
pub fn ok_output_digest(journal: &[u8]) -> [u8; 32] {
    groth16_core::claim::ok_output_digest(&NearOps, journal)
}

/// [`groth16_core::claim::claim_digest`] with the NEAR provider.
pub fn claim_digest(claim: &ReceiptClaim) -> [u8; 32] {
    groth16_core::claim::claim_digest(&NearOps, claim)
}

/// [`groth16_core::claim::ok_claim`] with the NEAR provider.
pub fn ok_claim(image_id: [u8; 32], journal: &[u8]) -> ReceiptClaim {
    groth16_core::claim::ok_claim(&NearOps, image_id, journal)
}
