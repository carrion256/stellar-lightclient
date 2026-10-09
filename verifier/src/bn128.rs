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

use ark_bn254::Fq;
use ark_ff::{BigInt, PrimeField};

/// BN254 scalar field element.
pub type Fr = ark_bn254::Fr;
/// BN254 G1 affine point (`ark_bn254::G1Affine`).
pub type G1 = ark_bn254::G1Affine;
/// BN254 G2 affine point (`ark_bn254::G2Affine`).
pub type G2 = ark_bn254::G2Affine;

const SCALAR_SIZE: usize = 32;
const G1_SIZE: usize = 2 * SCALAR_SIZE;
const G2_SIZE: usize = 4 * SCALAR_SIZE;
const G1_MULTIEXP_ELEMENT_SIZE: usize = G1_SIZE + SCALAR_SIZE; // 96
const PAIRING_CHECK_ELEMENT_SIZE: usize = G1_SIZE + G2_SIZE; // 192

/// Encode a base-field element as 32-byte little-endian, exactly the
/// `decode_u256` format (`u128::from_le_bytes` on the lo/hi halves) the host
/// parser uses.
fn fq_to_le(x: &Fq) -> [u8; SCALAR_SIZE] {
    let limbs = x.into_bigint().0; // [u64; 4], canonical representative
    let mut out = [0u8; SCALAR_SIZE];
    for (i, limb) in limbs.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Encode a scalar-field element as 32-byte little-endian.
fn fr_to_le(x: &Fr) -> [u8; SCALAR_SIZE] {
    let limbs = x.into_bigint().0;
    let mut out = [0u8; SCALAR_SIZE];
    for (i, limb) in limbs.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Decode a 32-byte little-endian base-field element produced by
/// [`fq_to_le`]. The host only ever emits canonical values (`into_bigint`
/// of a valid field element is below the modulus), so the `None` arm is
/// unreachable; fall back to zero rather than panic.
fn fq_from_le(b: &[u8]) -> Fq {
    assert!(b.len() >= SCALAR_SIZE);
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&b[i * 8..(i + 1) * 8]);
        *limb = u64::from_le_bytes(chunk);
    }
    Fq::from_bigint(BigInt(limbs)).unwrap_or_default()
}

/// Encode `p` as `(x, y)`, 64 B, each 32-byte LE. The identity (or the
/// host-encoded all-zero buffer) becomes 64 zero bytes, which the host
/// decodes back to the identity per `decode_g1`.
fn g1_to_bytes(p: &G1) -> [u8; G1_SIZE] {
    let mut out = [0u8; G1_SIZE];
    out[..SCALAR_SIZE].copy_from_slice(&fq_to_le(&p.x));
    out[SCALAR_SIZE..].copy_from_slice(&fq_to_le(&p.y));
    out
}

/// Decode a 64-byte G1 buffer. All-zero input decodes to the identity,
/// matching the host's `decode_g1` convention.
fn g1_from_bytes(b: &[u8]) -> G1 {
    assert!(b.len() == G1_SIZE);
    if b.iter().all(|&byte| byte == 0) {
        return G1::identity();
    }
    G1::new_unchecked(
        fq_from_le(&b[..SCALAR_SIZE]),
        fq_from_le(&b[SCALAR_SIZE..G1_SIZE]),
    )
}

/// Encode `p` as `(x.c0, x.c1, y.c0, y.c1)`, 128 B, each 32-byte LE — the
/// host `decode_g2`/`decode_fq2` layout (real then imaginary coefficient,
/// no EVM-style coordinate swapping).
fn g2_to_bytes(p: &G2) -> [u8; G2_SIZE] {
    let mut out = [0u8; G2_SIZE];
    out[..SCALAR_SIZE].copy_from_slice(&fq_to_le(&p.x.c0));
    out[SCALAR_SIZE..2 * SCALAR_SIZE].copy_from_slice(&fq_to_le(&p.x.c1));
    out[2 * SCALAR_SIZE..3 * SCALAR_SIZE].copy_from_slice(&fq_to_le(&p.y.c0));
    out[3 * SCALAR_SIZE..].copy_from_slice(&fq_to_le(&p.y.c1));
    out
}

/// Weighted G1 sum `Σ scalars[i] · points[i]`, computed by NEAR's
/// `alt_bn128_g1_multiexp` host function.
///
/// Emits `[(G1 64 B, scalar 32 B)]` — 96 bytes per element (points encoded
/// `(x, y)`, scalars 32-byte LE, both little-endian), and decodes the
/// 64-byte result back to affine coordinates.
///
/// Empty input returns the identity without touching the host.
pub fn g1_multiexp(points: &[G1], scalars: &[Fr]) -> G1 {
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
pub fn pairing_check(pairs: &[(G1, G2)]) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

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
