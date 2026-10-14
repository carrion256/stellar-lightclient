//! RISC Zero-specific glue for NEAR: pinned verifying key, seal parsing,
//! and claim public-input derivation.
//!
//! The implementation — the pinned risc0-groth16 3.0.5 constants, strict raw
//! seal parsing, and digest splitting — is chain-agnostic and lives in
//! [`groth16_core::risc0`] (with all of its risc0-groth16 source citations).
//! This module keeps this crate's original signatures, supplying the NEAR
//! [`NearOps`] provider inside `verify`.

use crate::ops::NearOps;
use groth16_core::bn254::Fr;

pub use groth16_core::risc0::{
    pinned_vk_unchecked, public_inputs, seal_to_proof, verifying_key, CheckedProof,
    RISC0_BN254_CONTROL_ID, RISC0_CONTROL_ROOT,
};

/// [`groth16_core::risc0::verify`] with the NEAR provider: Groth16-verify a
/// decoded seal against the pinned RISC Zero verifying key, skipping the
/// per-call VK point re-validation — the key is a compile-time constant
/// whose unchecked construction is asserted equal to the fully checked
/// [`verifying_key()`] in `tests/risc0_verify.rs` — and the proof-side point
/// checks [`seal_to_proof`] already enforced (the [`CheckedProof`] type).
pub fn verify(proof: &CheckedProof, public_inputs: &[Fr; 5]) -> bool {
    groth16_core::risc0::verify(&NearOps, proof, public_inputs)
}
