//! RISC Zero Groth16 verification for NEAR.
//!
//! RISC Zero receipts are Groth16 proofs over BN254. This crate verifies them on
//! NEAR by driving the curve arithmetic through the chain's `alt_bn128` host
//! functions (`env::alt_bn128_g1_multiexp`, `env::alt_bn128_pairing_check`) instead
//! of running a pure-Rust pairing implementation inside the contract.
//!
//! The proof system, seal parsing, and claim derivation are chain-agnostic and
//! live in [`groth16_core`]; this crate is the NEAR adapter over it.
//!
//! Layout:
//! - [`ops`] — [`ops::NearOps`]: the NEAR provider for the chain seam.
//! - [`bn128`] — BN254 point aliases and the two free host operations.
//! - [`groth16`] — the verification equation (`groth16_core::groth16`).
//! - [`claim`] — RISC Zero receipt-claim digests (`groth16_core::claim`).
//! - [`risc0`] — the pinned RISC Zero verifying key, seal parsing, and claim
//!   public-input derivation (`groth16_core::risc0`).
//!
//! RISC Zero only — this project never uses SP1.

pub mod bn128;
pub mod claim;
pub mod groth16;
pub mod ops;
pub mod risc0;

pub use bn128::{Fr, G1, G2};
pub use groth16::{Proof, VerifyingKey};
