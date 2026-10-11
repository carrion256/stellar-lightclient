//! The NEAR provider for [`groth16_core::ProofOps`]: `near_sdk::env` SHA-256
//! and the `alt_bn128_*` host functions behind the chain-agnostic seam.
//!
//! The little-endian wire encoding (and its size constants) comes from
//! [`groth16_core::bn254`]; this module only adds the host calls. Behaviour
//! matches the crate's historical one exactly: a length-mismatched multiexp
//! panics (programming error, not malformed input), empty input never touches
//! the host (identity / `true`), and the host's multiexp result is decoded as
//! strictly 64 bytes.

use crate::bn128::{
    fr_to_le, g1_from_bytes, g1_to_bytes, g2_to_bytes, Fr, G1, G2,
    G1_MULTIEXP_ELEMENT_SIZE, PAIRING_CHECK_ELEMENT_SIZE,
};
use groth16_core::ProofOps;

/// NEAR provider for the Groth16 verification seam.
#[derive(Debug, Clone, Copy, Default)]
pub struct NearOps;

impl ProofOps for NearOps {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        near_sdk::env::sha256(data).try_into().unwrap()
    }

    /// Weighted G1 sum `Σ scalars[i] · points[i]`, computed by NEAR's
    /// `alt_bn128_g1_multiexp` host function.
    ///
    /// Emits `[(G1 64 B, scalar 32 B)]` — 96 bytes per element (points encoded
    /// `(x, y)`, scalars 32-byte LE, both little-endian), and decodes the
    /// 64-byte result back to affine coordinates.
    ///
    /// Empty input returns the identity without touching the host.
    fn g1_multiexp(&self, points: &[G1], scalars: &[Fr]) -> G1 {
        if points.len() != scalars.len() {
            // Programming error, not malformed input: callers are internal and
            // the host would abort on a malformed buffer anyway.
            panic!(
                "g1_multiexp: points/scalars length mismatch ({} vs {})",
                points.len(),
                scalars.len()
            );
        }
        if points.is_empty() {
            return G1::identity();
        }
        let mut buf = Vec::with_capacity(points.len() * G1_MULTIEXP_ELEMENT_SIZE);
        for (p, s) in points.iter().zip(scalars.iter()) {
            buf.extend_from_slice(&g1_to_bytes(p));
            buf.extend_from_slice(&fr_to_le(s));
        }
        let result = near_sdk::env::alt_bn128_g1_multiexp(&buf);
        // The host returns exactly 64 bytes on success; anything else means the
        // host misbehaved and aborting is the correct outcome.
        g1_from_bytes(&result)
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
    fn pairing_check(&self, pairs: &[(G1, G2)]) -> bool {
        if pairs.is_empty() {
            return true;
        }
        let mut buf = Vec::with_capacity(pairs.len() * PAIRING_CHECK_ELEMENT_SIZE);
        for (p, q) in pairs {
            buf.extend_from_slice(&g1_to_bytes(p));
            buf.extend_from_slice(&g2_to_bytes(q));
        }
        near_sdk::env::alt_bn128_pairing_check(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, CurveGroup};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    /// `ProofOps`'s empty-input obligation for the NEAR provider.
    ///
    /// An earlier version tried to prove the stronger "never touches the host"
    /// by omitting `testing_env!`, relying on `near_sdk::env` panicking without
    /// a mock chain. It does not: `alt_bn128_*` returns normally in this
    /// configuration, so a clean return proves nothing about whether the host
    /// was called. The control case that would have made it falsifiable — a
    /// non-empty multiexp, which must touch the host — also returned without
    /// panicking, which is how the premise failed.
    ///
    /// So this pins the observable, not the mechanism: empty input yields the
    /// identity and `true`. The "no host call" half is enforced by construction
    /// (both paths return before any `env::*`) and is not testable here.
    #[test]
    fn empty_input_normalizes_to_identity_and_true() {
        testing_env!(VMContextBuilder::new().build());
        assert_eq!(NearOps.g1_multiexp(&[], &[]), G1::identity());
        assert!(NearOps.pairing_check(&[]));
    }

    /// A length-mismatched multiexp is a programming error, not malformed
    /// input: it must panic rather than quietly return a wrong point.
    #[test]
    #[should_panic(expected = "length mismatch")]
    fn multiexp_length_mismatch_panics() {
        let _ = NearOps.g1_multiexp(&[G1::generator()], &[]);
    }

    /// Non-empty input does reach the host, so these need the mock chain — and
    /// they confirm the provider does real curve arithmetic rather than being a
    /// stub that would make every cross-backend comparison vacuous.
    #[test]
    fn multiexp_does_real_host_arithmetic() {
        testing_env!(VMContextBuilder::new().build());
        let g = G1::generator();
        let got = NearOps.g1_multiexp(&[g, g], &[Fr::from(3u64), Fr::from(5u64)]);
        assert_eq!(got, (g * Fr::from(8u64)).into_affine());
    }

    #[test]
    fn pairing_check_does_real_host_arithmetic() {
        testing_env!(VMContextBuilder::new().build());
        let g1 = G1::generator();
        let g2 = G2::generator();
        // e(g1, g2) · e(g1, −g2) is the identity; e(g1, g2) alone is not.
        assert!(NearOps.pairing_check(&[(g1, g2), (g1, -g2)]));
        assert!(!NearOps.pairing_check(&[(g1, g2)]));
    }
}
