//! BN254 affine types and a pure-Rust [`ProofOps`] reference.
//!
//! What lives here is chain-agnostic on purpose. The arkworks point types and
//! a reference provider are shared by every deployment; **wire encoding is
//! not**, because each chain demands a different byte order. NEAR wants
//! 32-byte little-endian coordinates, Soroban wants Ethereum-compatible
//! big-endian with the G2 coefficients swapped. Each provider owns its own
//! codec — `verifier/src/bn128.rs` for NEAR, `stellar-verifier/src/ops.rs` for
//! Soroban — so this crate knows neither.

use crate::ops::ProofOps;
use alloc::vec::Vec;
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::One;
use sha2::{Digest, Sha256};

/// BN254 scalar field element.
pub type Fr = ark_bn254::Fr;
/// BN254 G1 affine point (`ark_bn254::G1Affine`).
pub type G1 = ark_bn254::G1Affine;
/// BN254 G2 affine point (`ark_bn254::G2Affine`).
pub type G2 = ark_bn254::G2Affine;

/// Bytes in one BN254 field element.
///
/// These three describe the **point and seal layout**, which is shared: a
/// Groth16 seal is `a(G1) ‖ b(G2) ‖ c(G1)` = 256 bytes on every chain, and
/// [`crate::risc0`] parses exactly that. They live here rather than in a
/// provider for that reason. What does *not* belong here is any chain's buffer
/// framing — NEAR packs `[(G1, scalar)]` and `[(G1, G2)]` batches whose
/// element sizes are NEAR's alone, and those stay in `verifier/src/bn128.rs`.
pub const SCALAR_SIZE: usize = 32;
/// Bytes in one uncompressed G1 point: two field elements.
pub const G1_SIZE: usize = 2 * SCALAR_SIZE;
/// Bytes in one uncompressed G2 point: four field elements.
pub const G2_SIZE: usize = 4 * SCALAR_SIZE;
/// Bytes in a Groth16 seal: `a(G1) ‖ b(G2) ‖ c(G1)`. This is the RISC Zero
/// `Seal::SIZE` and the wire length of any Groth16 proof in this format.
pub const SEAL_SIZE: usize = G1_SIZE + G2_SIZE + G1_SIZE;

/// Pure-Rust [`ProofOps`] provider: `sha2` for SHA-256 and arkworks
/// ([`VariableBaseMSM`] / [`Pairing`]) for the curve operations — no chain
/// host involved. This is what this crate's own tests run through, and any
/// off-chain consumer can reuse it as-is. It is also the reference the two
/// chain providers are checked against.
///
/// Semantics match [`crate::ops::ProofOps`]: a length-mismatched multiexp is
/// a programming error (panic), an empty multiexp returns the identity, an
/// empty pairing check returns `true`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeOps;

impl ProofOps for NativeOps {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn g1_multiexp(&self, points: &[G1], scalars: &[Fr]) -> G1 {
        if points.len() != scalars.len() {
            // Programming error, same as the NEAR provider.
            panic!(
                "g1_multiexp: points/scalars length mismatch ({} vs {})",
                points.len(),
                scalars.len()
            );
        }
        if points.is_empty() {
            return G1::identity();
        }
        ark_bn254::G1Projective::msm_unchecked(points, scalars).into_affine()
    }

    fn pairing_check(&self, pairs: &[(G1, G2)]) -> bool {
        if pairs.is_empty() {
            return true;
        }
        let (g1s, g2s): (Vec<G1>, Vec<G2>) = pairs.iter().copied().unzip();
        ark_bn254::Bn254::multi_pairing(g1s, g2s).0.is_one()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    /// `NativeOps` must do real curve arithmetic — if it were a stub, every
    /// "parity" test in this workspace would be comparing a provider against
    /// nothing.
    #[test]
    fn native_msm_is_real_arithmetic() {
        let g = G1::generator();
        let got = NativeOps.g1_multiexp(&[g, g], &[Fr::from(3u64), Fr::from(5u64)]);
        assert_eq!(got, (g * Fr::from(8u64)).into_affine());
    }

    /// The empty-product conventions the trait pins on providers.
    #[test]
    fn native_ops_normalize_degenerate_input() {
        assert_eq!(NativeOps.g1_multiexp(&[], &[]), G1::identity());
        assert!(NativeOps.pairing_check(&[]));
    }

    #[test]
    #[should_panic(expected = "length mismatch")]
    fn native_msm_rejects_length_mismatch() {
        let _ = NativeOps.g1_multiexp(&[G1::generator()], &[]);
    }

    /// A real pairing product: `e(g1, g2)` and `e(g1, -g2)` multiply to the
    /// identity, so the check must hold — proving `pairing_check` is not
    /// hardcoded to `true`.
    #[test]
    fn native_pairing_check_is_real_arithmetic() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        assert!(NativeOps.pairing_check(&[(g1, g2), (g1, -g2)]));
        assert!(!NativeOps.pairing_check(&[(g1, g2)]));
    }
}
