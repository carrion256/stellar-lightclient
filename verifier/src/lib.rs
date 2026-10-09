//! RISC Zero Groth16 verification for NEAR.
//!
//! RISC Zero receipts are Groth16 proofs over BN254. This crate verifies them on
//! NEAR by driving the curve arithmetic through the chain's `alt_bn128` host
//! functions (`env::alt_bn128_g1_multiexp`, `env::alt_bn128_pairing_check`) instead
//! of running a pure-Rust pairing implementation inside the contract.
//!
//! Layout:
//! - [`bn128`] — BN254 primitives over the host functions (encoding layer).
//! - [`groth16`] — the verification equation over those primitives.
//! - [`risc0`] — the pinned RISC Zero verifying key, seal parsing, and claim
//!   public-input derivation.
//!
//! RISC Zero only — this project never uses SP1.

pub mod bn128;
pub mod groth16;
pub mod claim;
pub mod risc0;

pub use bn128::{Fr, G1, G2};
pub use groth16::{Proof, VerifyingKey};
