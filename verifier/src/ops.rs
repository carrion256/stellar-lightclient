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
