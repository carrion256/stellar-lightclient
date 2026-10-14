//! The operations a Groth16 verifier needs from its host.
//!
//! This trait is the **entire** chain seam. Everything else in this crate — the
//! BN254 wire encoding, the verification equation, RISC Zero seal parsing and
//! claim derivation — is host-agnostic and shared verbatim between the NEAR and
//! Soroban deployments. A chain provides a thin adapter over exactly these
//! three operations:
//!
//! | op | NEAR | Soroban |
//! |---|---|---|
//! | [`ProofOps::sha256`] | `env::sha256` | `crypto::sha256` |
//! | [`ProofOps::g1_multiexp`] | `env::alt_bn128_g1_multiexp` | `Bn254::g1_msm` |
//! | [`ProofOps::pairing_check`] | `env::alt_bn128_pairing_check` | `Bn254::pairing_check` |
//!
//! The two curve operations are deliberately the *only* group arithmetic in the
//! trait. Groth16 verification is one multi-scalar multiplication and one
//! multi-pairing check — see [`crate::groth16`] — so a provider never has to
//! understand the proof system, and the proof system never has to know which
//! chain it is running on.
//!
//! The point types are arkworks affine points, not provider types. Each
//! provider owns *how* it encodes them for its host: NEAR uses 32-byte
//! little-endian coordinates, Soroban uses Ethereum-compatible 32-byte
//! big-endian. That difference is why the seam is here rather than in the
//! shared code.

use crate::bn254::{Fr, G1, G2};

/// Host operations required to verify a Groth16 proof.
pub trait ProofOps {
    /// SHA-256. Used for RISC Zero claim/journal digests.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// Multi-scalar multiplication in G1: `Σ points[i] · scalars[i]`.
    ///
    /// `points.len()` must equal `scalars.len()`. Providers normalize the empty
    /// case to the identity before touching the host.
    ///
    /// That normalization is **load-bearing on Soroban**, where `pairing_check`
    /// panics on an empty vector, and **defensive on NEAR**, whose
    /// `alt_bn128_*` already returns the identity for an empty buffer —
    /// established by deleting the early return and re-running the suite rather
    /// than assumed. Either way `groth16_core::groth16::verify` never calls this
    /// with an empty slice.
    fn g1_multiexp(&self, points: &[G1], scalars: &[Fr]) -> G1;

    /// Multi-pairing product check: `∏ e(pairs[i].0, pairs[i].1) == 1`.
    ///
    /// Providers normalize the empty case to `true` before touching the host.
    /// Same split as [`ProofOps::g1_multiexp`]: Soroban's `Bn254::pairing_check`
    /// *panics* on an empty or mismatched vector, NEAR's returns `true` on its
    /// own. `groth16_core::groth16::verify` never calls this with an empty or
    /// mismatched slice.
    fn pairing_check(&self, pairs: &[(G1, G2)]) -> bool;
}

/// Marker for a [`ProofOps`] provider whose [`pairing_check`](ProofOps::pairing_check)
/// validates **every** G2 operand itself — canonical field elements, on the
/// curve, *and* in the prime-order subgroup — and aborts the transaction on
/// one that is not (rather than, say, only checking the curve equation).
///
/// That guarantee is what lets a verifier hand the host a G2 point whose
/// subgroup membership it has *not* checked: the host's check is the
/// soundness backstop, so a wrong-subgroup point can never reach a `true`
/// verdict, it can only abort. The price is the failure mode — such an input
/// traps instead of returning `false` — which is why the unchecked path
/// ([`crate::risc0::verify_host_checked`]) is only reachable through this
/// trait and the fully checked [`crate::risc0::verify`] stays total.
///
/// Implement it only after reading the host's G2 deserializer, never on
/// inference. Soroban qualifies (citations at its impl); do **not** implement
/// it for a provider whose pairing accepts unvalidated G2 points.
pub trait HostChecksG2Subgroup: ProofOps {}
