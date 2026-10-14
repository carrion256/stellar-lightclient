#![cfg_attr(not(test), no_std)]
//! Host-agnostic Groth16 verification over BN254.
//!
//! This crate holds everything about verifying a Groth16 proof that does not
//! depend on which chain is doing the verifying. The NEAR contract and the
//! Soroban contract both build on it, each supplying a provider over
//! [`ProofOps`] — three host operations, and nothing else.
//!
//! # Layout
//!
//! - [`ops`] — the [`ProofOps`] trait: the whole chain seam.
//! - [`bn254`] — arkworks point types and a pure-Rust [`ProofOps`] reference.
//!   Wire encoding is deliberately *not* here: each chain's byte order belongs
//!   to that chain's provider.
//! - [`groth16`] — the verification equation over [`ProofOps`].
//! - [`claim`] — RISC Zero `ReceiptClaim` digest derivation.
//! - [`risc0`] — the pinned RISC Zero verifying key and seal parsing.
//!
//! # The verification equation
//!
//! Following ark-groth16 0.5.0, `src/groth16/verifier.rs:49-64`:
//!
//! ```text
//! e(A, B) · e(π_l, −γ) · e(C, −δ) == e(α, β)
//! where π_l = IC[0] + Σ_i x_i · IC[i+1]
//! ```
//!
//! Both sides are folded into a **single** multi-pairing check by moving
//! `e(α, β)` across, and `π_l` is evaluated with a **single** multi-scalar
//! multiplication. So a whole verification is one [`ProofOps::g1_multiexp`] and
//! one [`ProofOps::pairing_check`].
//!
//! # Trust
//!
//! `verify` is total for any well-typed input: every point is checked on-curve
//! and in the prime-order subgroup *before* the host is touched. That matters
//! because the NEAR and Soroban hosts both **abort** on a malformed point —
//! without the guards a bad proof would turn into a panicking transaction
//! instead of a `false`.
//!
//! RISC Zero only — this project never uses SP1.

pub mod bn254;
pub mod claim;
pub mod groth16;
pub mod ops;
pub mod risc0;

extern crate alloc;

pub use bn254::{Fr, G1, G2};
pub use groth16::{Proof, VerifyingKey};
pub use ops::{HostChecksG2Subgroup, ProofOps};
