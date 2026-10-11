//! BN254 primitives over NEAR's `alt_bn128` host functions.
//!
//! Encoding is the crux: arkworks exposes field elements via `into_bigint()`
//! (limbs of `u64`), while NEAR's host functions demand 32-byte
//! **little-endian** values. The host-side parsers/encoders are in
//! near-vm-runner `runtime/near-vm-runner/src/logic/alt_bn128.rs`
//! (`decode_g1`, `decode_g2`, `encode_g1`, `decode_u256`):
//!
//! * `G1` = uncompressed affine `(x, y)`, each coordinate 32-byte LE, 64 B.
//!   The identity is 64 zero bytes (`decode_g1`: `x == 0 && y == 0`).
//! * `G2` = `(x.c0, x.c1, y.c0, y.c1)` — each 32-byte LE, 128 B total
//!   (`decode_g2` splits `raw` into `x`, `y`; `decode_fq2` then splits into
//!   `(real, imaginary) == (c0, c1)`).
//! * Invalid encodings (not canonical / not on curve / not in subgroup /
//!   wrong buffer length) **abort** the host call — the contract traps, it
//!   does not receive `false`.
//!
//! The arkworks types and the little-endian encoding itself live in
//! [`groth16_core::bn254`]; the host calls live in [`NearOps`]
//! ([`crate::ops`]). This module keeps this crate's original surface: the
//! point aliases plus the two free host operations.

use crate::ops::NearOps;
use groth16_core::ProofOps;

pub use groth16_core::bn254::{Fr, G1, G2};

/// Weighted G1 sum `Σ scalars[i] · points[i]`, computed by NEAR's
/// `alt_bn128_g1_multiexp` host function.
///
/// Emits `[(G1 64 B, scalar 32 B)]` — 96 bytes per element (points encoded
/// `(x, y)`, scalars 32-byte LE, both little-endian), and decodes the
/// 64-byte result back to affine coordinates.
///
/// Empty input returns the identity without touching the host.
pub fn g1_multiexp(points: &[G1], scalars: &[Fr]) -> G1 {
    NearOps.g1_multiexp(points, scalars)
}

/// Multi-pairing product `∏ e(p_i, q_i) == 1` check, computed by NEAR's
/// `alt_bn128_pairing_check` host function.
///
/// Emits `[(G1 64 B, G2 128 B)]` — 192 bytes per element. G2 points are
/// encoded `(x.c0, x.c1, y.c0, y.c1)` (32-byte LE each), matching the host
/// `decode_g2` layout.
///
/// Empty input returns `true` (empty pairing product is the identity),
/// without touching the host.
pub fn pairing_check(pairs: &[(G1, G2)]) -> bool {
    NearOps.pairing_check(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fq;
    use groth16_core::bn254::{
        fq_from_le, fq_to_le, g1_from_bytes, g1_to_bytes, g2_to_bytes, G1_MULTIEXP_ELEMENT_SIZE,
        G1_SIZE, G2_SIZE, PAIRING_CHECK_ELEMENT_SIZE,
    };

    #[test]
    fn fq_roundtrip_and_le_layout() {
        let x = Fq::from(0xdead_beef_1234_5678u64);
        let bytes = fq_to_le(&x);
        assert_eq!(fq_from_le(&bytes), x);
        // Little-endian: low 64-bit limb in bytes 0..8.
        assert_eq!(&bytes[..8], &0xdead_beef_1234_5678u64.to_le_bytes());
        assert!(bytes[8..].iter().all(|&b| b == 0));
    }

    #[test]
    fn g1_encode_layout() {
        // Point (1, 2): x at bytes 0..32, y at bytes 32..64, LE.
        let p = G1::new_unchecked(Fq::from(1u64), Fq::from(2u64));
        let b = g1_to_bytes(&p);
        assert_eq!(b[0], 1);
        assert_eq!(b[32], 2);
        assert_eq!(g1_from_bytes(&b), p);
    }

    #[test]
    fn g1_identity_roundtrip() {
        let b = g1_to_bytes(&G1::identity());
        assert_eq!(b, [0u8; G1_SIZE]);
        assert!(g1_from_bytes(&b).infinity);
    }

    #[test]
    fn g2_encode_layout() {
        let p = G2::new_unchecked(
            ark_bn254::Fq2 {
                c0: Fq::from(1u64),
                c1: Fq::from(2u64),
            },
            ark_bn254::Fq2 {
                c0: Fq::from(3u64),
                c1: Fq::from(4u64),
            },
        );
        let b = g2_to_bytes(&p);
        assert_eq!(b[0], 1); // x.c0
        assert_eq!(b[32], 2); // x.c1
        assert_eq!(b[64], 3); // y.c0
        assert_eq!(b[96], 4); // y.c1
        assert_eq!(b.len(), G2_SIZE);
    }

    #[test]
    fn g2_identity_encodes_zero() {
        assert_eq!(g2_to_bytes(&G2::identity()), [0u8; G2_SIZE]);
    }

    #[test]
    fn empty_multiline_lengths() {
        // Byte-layout constants the host validates against.
        assert_eq!(G1_MULTIEXP_ELEMENT_SIZE, 96);
        assert_eq!(PAIRING_CHECK_ELEMENT_SIZE, 192);
    }
}
