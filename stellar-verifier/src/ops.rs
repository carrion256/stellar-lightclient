//! The Soroban [`ProofOps`] provider over Stellar's native BN254 host
//! functions (CAP-0074 / Protocol 25 "X-Ray"): `Bn254::g1_msm`,
//! `Bn254::pairing_check`, and `crypto::sha256`.
//!
//! # Wire encoding
//!
//! Everything is Ethereum-compatible big-endian, exactly what the host
//! demands. All citations are to `soroban-sdk` 28.0.0 `src/crypto/bn254.rs`:
//!
//! * **G1** (`Bn254G1Affine` serialization docs, lines 36-42): the 64 bytes
//!   are `be_bytes(X) || be_bytes(Y)`, each coordinate a 32-byte big-endian
//!   `Bn254Fp`; the point at infinity is 64 zero bytes; the flag bits
//!   (0x80/0x40 of the first byte) must be unset; points must be on the
//!   curve (no subgroup check required for G1).
//! * **G2** (`Bn254G2Affine` serialization docs, lines 56-65), verbatim:
//!   "`be_bytes(X) || be_bytes(Y)` where each coordinate is an Fp2 element
//!   (64 bytes) - Fp2 element encoding: `be_bytes(c1) || be_bytes(c0)`".
//!   So the wire order is `x.c1 || x.c0 || y.c1 || y.c0` — the **Ethereum**
//!   order. This is the *reverse* coefficient order (and big-endian, not
//!   little-endian) from the NEAR provider's layout in
//!   `groth16-core/src/bn254.rs` (`x.c0 || x.c1 || y.c0 || y.c1`, LE).
//!   A swapped coefficient order does not trap — it feeds the host a
//!   different point and proofs silently fail, which is why the exact order
//!   is pinned here by citation and by the byte-level unit tests below, and
//!   end-to-end by the fixture test in [`crate::tests`] (a wrong order makes
//!   the host pairing reject a valid proof).
//! * **Fr** (`Bn254Fr` docs, lines 70-77): a 32-byte big-endian U256.
//!
//! The SDK's `from_bytes` constructors validate nothing (lines 110-124); the
//! host **traps** on malformed bytes when a value reaches a host function
//! (lines 30-34). So this module's decoders enforce canonical field elements
//! (round-trip re-encode; also rejects the0x80/0x40 flag bits, since
//! `p < 2^254 < 0x80…`), and the on-curve/subgroup guards stay in
//! `groth16_core::groth16::verify`, which runs them *before* any host call.
//!
//! Total-ness follows the contract in `groth16-core/src/ops.rs`: an empty
//! multi-scalar multiplication returns the identity without a host call, an
//! empty pairing check returns `true` without a host call (the host's
//! `pairing_check` panics on empty vectors, bn254.rs:433-434), and a
//! points/scalars length mismatch is a programming error (`panic!`).

use ark_bn254::{Fq, Fq2};
use ark_ff::PrimeField;
use groth16_core::{Fr, G1, G2, ProofOps};
use soroban_sdk::crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine};
use soroban_sdk::{Bytes, BytesN, Env, Vec as HostVec};

/// Wire sizes come from the shared point layout in `groth16_core::bn254`,
/// which both chains agree on (`a(G1) ‖ b(G2) ‖ c(G1)` is 256 bytes
/// everywhere). Only the *byte order* differs, and that is what the functions
/// below implement.
pub(crate) use groth16_core::bn254::{G1_SIZE, G2_SIZE, SCALAR_SIZE};

/// 32-byte big-endian encoding of a `BigInt<4>` given as its little-endian
/// `u64` limbs (limb `i` covers wire bytes `8i..8i+8`, least-significant
/// first; the reversal produces big-endian).
fn be32_from_limbs(limbs: &[u64]) -> [u8; SCALAR_SIZE] {
    let mut le = [0u8; SCALAR_SIZE];
    for (i, w) in limbs.iter().take(4).enumerate() {
        le[8 * i..8 * i + 8].copy_from_slice(&w.to_le_bytes());
    }
    le.reverse();
    le
}

/// Borrow `b[start..start + N]` as a fixed-size array, or `None` if out of
/// range. Keeps every wire read total (no panics on short buffers).
fn at<const N: usize>(b: &[u8], start: usize) -> Option<&[u8; N]> {
    b.get(start..start.checked_add(N)?)?.try_into().ok()
}

/// Decode a canonical base-field element: interpret the 32 bytes as a
/// big-endian integer and require it to be `< p`. A non-canonical input
/// (or one with the host's0x80/0x40 flag bits set — unreachable for
/// canonical values since `p < 2^254`) reduces to a different value and
/// fails the round-trip comparison.
fn fq_from_wire(b: &[u8; SCALAR_SIZE]) -> Option<Fq> {
    let mut le = *b;
    le.reverse();
    let v = Fq::from_le_bytes_mod_order(&le);
    (be32_from_limbs(&v.into_bigint().0) == *b).then_some(v)
}

/// Decode a canonical scalar-field element, same round-trip rule as
/// [`fq_from_wire`] against `r`. Non-canonical scalars are rejected, never
/// silently reduced (matching the NEAR provider's strictness and
/// `groth16_core::risc0::public_inputs`' documented error path).
pub(crate) fn fr_from_wire(b: &[u8; SCALAR_SIZE]) -> Option<Fr> {
    let mut le = *b;
    le.reverse();
    let v = Fr::from_le_bytes_mod_order(&le);
    (fr_to_wire(&v) == *b).then_some(v)
}

/// Encode a scalar as 32-byte big-endian.
pub(crate) fn fr_to_wire(fr: &Fr) -> [u8; SCALAR_SIZE] {
    be32_from_limbs(&fr.into_bigint().0)
}

/// Encode a G1 point as `be_bytes(X) || be_bytes(Y)`; the identity becomes
/// 64 zero bytes (the host's infinity encoding).
pub(crate) fn g1_to_wire(p: &G1) -> [u8; G1_SIZE] {
    if p.infinity {
        return [0u8; G1_SIZE];
    }
    let mut out = [0u8; G1_SIZE];
    out[..SCALAR_SIZE].copy_from_slice(&be32_from_limbs(&p.x.into_bigint().0));
    out[SCALAR_SIZE..].copy_from_slice(&be32_from_limbs(&p.y.into_bigint().0));
    out
}

/// Decode a G1 point from `be_bytes(X) || be_bytes(Y)`. All-zero input is
/// the identity; otherwise field elements must be canonical. On-curve and
/// subgroup checks are deliberately *not* done here — they run in
/// `groth16_core::groth16::verify` before any host call, keeping the entry point
/// total for adversarial input.
pub(crate) fn g1_from_wire(b: &[u8; G1_SIZE]) -> Option<G1> {
    if *b == [0u8; G1_SIZE] {
        return Some(G1::identity());
    }
    let x = fq_from_wire(at::<SCALAR_SIZE>(b, 0)?)?;
    let y = fq_from_wire(at::<SCALAR_SIZE>(b, SCALAR_SIZE)?)?;
    Some(G1::new_unchecked(x, y))
}

/// Encode a G2 point as `be_bytes(X) || be_bytes(Y)` with each Fp2
/// coordinate `be_bytes(c1) || be_bytes(c0)` — c1 (imaginary) first, the
/// Ethereum order quoted in the module docs; the identity becomes 128 zero
/// bytes.
pub(crate) fn g2_to_wire(p: &G2) -> [u8; G2_SIZE] {
    if p.infinity {
        return [0u8; G2_SIZE];
    }
    let mut out = [0u8; G2_SIZE];
    out[0..SCALAR_SIZE].copy_from_slice(&be32_from_limbs(&p.x.c1.into_bigint().0));
    out[SCALAR_SIZE..2 * SCALAR_SIZE]
        .copy_from_slice(&be32_from_limbs(&p.x.c0.into_bigint().0));
    out[2 * SCALAR_SIZE..3 * SCALAR_SIZE]
        .copy_from_slice(&be32_from_limbs(&p.y.c1.into_bigint().0));
    out[3 * SCALAR_SIZE..].copy_from_slice(&be32_from_limbs(&p.y.c0.into_bigint().0));
    out
}

/// Decode a G2 point; wire order `x.c1 || x.c0 || y.c1 || y.c0` (Ethereum),
/// canonical field elements required, all-zero input is the identity.
/// On-curve/subgroup checks run in `groth16_core::groth16::verify`.
pub(crate) fn g2_from_wire(b: &[u8; G2_SIZE]) -> Option<G2> {
    if *b == [0u8; G2_SIZE] {
        return Some(G2::identity());
    }
    let x_c1 = fq_from_wire(at::<SCALAR_SIZE>(b, 0)?)?;
    let x_c0 = fq_from_wire(at::<SCALAR_SIZE>(b, SCALAR_SIZE)?)?;
    let y_c1 = fq_from_wire(at::<SCALAR_SIZE>(b, 2 * SCALAR_SIZE)?)?;
    let y_c0 = fq_from_wire(at::<SCALAR_SIZE>(b, 3 * SCALAR_SIZE)?)?;
    Some(G2::new_unchecked(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1)))
}

/// Read `N` bytes from `b` at `at`, or `None` if the buffer is too short.
pub(crate) fn take<const N: usize>(b: &Bytes, at: u32) -> Option<[u8; N]> {
    let end = at.checked_add(N as u32)?;
    if b.len() < end {
        return None;
    }
    let mut out = [0u8; N];
    b.slice(at..end).copy_into_slice(&mut out);
    Some(out)
}

/// [`ProofOps`] over the Soroban host's BN254 functions.
pub struct SorobanBn254 {
    env: Env,
}

impl SorobanBn254 {
    pub fn new(env: &Env) -> Self {
        Self {
            env: env.clone(),
        }
    }
}

impl ProofOps for SorobanBn254 {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        // `crypto::sha256` from the ops table = the SHA-256 host function
        // behind `Env::crypto()`.
        self.env
            .crypto()
            .sha256(&Bytes::from_slice(&self.env, data))
            .to_array()
    }

    fn g1_multiexp(&self, points: &[G1], scalars: &[Fr]) -> G1 {
        // Total-ness contract (groth16-core/src/ops.rs): equal lengths are a
        // programming error to uphold; empty returns the identity without
        // touching the host.
        assert_eq!(
            points.len(),
            scalars.len(),
            "g1_multiexp: points.len() must equal scalars.len()"
        );
        if points.is_empty() {
            return G1::identity();
        }
        let env = &self.env;
        let mut vp = HostVec::new(env);
        let mut vs = HostVec::new(env);
        for (p, s) in points.iter().zip(scalars.iter()) {
            vp.push_back(Bn254G1Affine::from_array(env, &g1_to_wire(p)));
            vs.push_back(Bn254Fr::from_bytes(BytesN::from_array(
                env,
                &fr_to_wire(s),
            )));
        }
        let out = env.crypto().bn254().g1_msm(vp, vs);
        // Host output is canonical, so the None arm is unreachable; fall
        // back to the identity rather than trap (mirrors groth16-core's
        // unreachable-decode precedent).
        g1_from_wire(&out.to_array()).unwrap_or(G1::identity())
    }

    fn pairing_check(&self, pairs: &[(G1, G2)]) -> bool {
        // Empty pairing = empty product = identity → true, no host call
        // (the host panics on empty vectors; bn254.rs:433-434).
        if pairs.is_empty() {
            return true;
        }
        let env = &self.env;
        let mut vp1 = HostVec::new(env);
        let mut vp2 = HostVec::new(env);
        for (p, q) in pairs {
            vp1.push_back(Bn254G1Affine::from_array(env, &g1_to_wire(p)));
            vp2.push_back(Bn254G2Affine::from_array(env, &g2_to_wire(q)));
        }
        env.crypto().bn254().pairing_check(vp1, vp2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fq;

    fn env() -> Env {
        Env::default()
    }

    /// The G1 generator (1, 2) pins big-endian `X || Y` byte order exactly.
    #[test]
    fn g1_wire_is_bigendian_x_then_y() {
        let g = G1::new_unchecked(Fq::from(1u64), Fq::from(2u64));
        let mut expected = [0u8; 64];
        expected[31] = 1;
        expected[63] = 2;
        assert_eq!(g1_to_wire(&g), expected);
        assert_eq!(g1_from_wire(&expected), Some(g));
    }

    /// A G2 point with distinct c0/c1 values pins the Ethereum Fp2 order
    /// `x.c1 || x.c0 || y.c1 || y.c0` exactly (the reverse of NEAR's).
    #[test]
    fn g2_wire_is_ethereum_c1_c0_order() {
        let p = G2::new_unchecked(Fq2::new(Fq::from(1u64), Fq::from(2u64)), Fq2::new(Fq::from(3u64), Fq::from(4u64)));
        let mut expected = [0u8; 128];
        expected[31] = 2; // x.c1
        expected[63] = 1; // x.c0
        expected[95] = 4; // y.c1
        expected[127] = 3; // y.c0
        assert_eq!(g2_to_wire(&p), expected);
        assert_eq!(g2_from_wire(&expected), Some(p));
    }

    #[test]
    fn fr_wire_is_bigendian() {
        let fr = Fr::from(9u64);
        let mut expected = [0u8; 32];
        expected[31] = 9;
        assert_eq!(fr_to_wire(&fr), expected);
        assert_eq!(fr_from_wire(&expected), Some(fr));
    }

    /// The host encodes the identity as all-zero bytes; both directions.
    #[test]
    fn identity_roundtrips_as_all_zero_bytes() {
        assert_eq!(g1_to_wire(&G1::identity()), [0u8; 64]);
        assert_eq!(g1_from_wire(&[0u8; 64]), Some(G1::identity()));
        assert_eq!(g2_to_wire(&G2::identity()), [0u8; 128]);
        assert_eq!(g2_from_wire(&[0u8; 128]), Some(G2::identity()));
    }

    /// Non-canonical scalars (≥ r) are rejected, never silently reduced.
    /// r as big-endian, quoted from the SDK (bn254.rs:71-72).
    #[test]
    fn non_canonical_scalars_are_rejected() {
        let r: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x01,
        ];
        assert_eq!(fr_from_wire(&r), None);
        assert_eq!(fr_from_wire(&[0xff; 32]), None);
        // r - 1 is canonical and round-trips.
        let mut rm1 = r;
        rm1[31] = 0;
        let fr = fr_from_wire(&rm1).expect("r - 1 is canonical");
        assert_eq!(fr_to_wire(&fr), rm1);
    }

    /// The0x80/0x40 flag bits (bn254.rs:40) are unreachable for canonical
    /// field elements (`p < 2^254`), so the canonicality check rejects them.
    #[test]
    fn flag_bits_are_rejected() {
        let mut g = g1_to_wire(&G1::new_unchecked(Fq::from(1u64), Fq::from(2u64)));
        g[0] |= 0x80;
        assert_eq!(g1_from_wire(&g), None);
        let mut p = g2_to_wire(&G2::new_unchecked(
            Fq2::new(Fq::from(1u64), Fq::from(2u64)),
            Fq2::new(Fq::from(3u64), Fq::from(4u64)),
        ));
        p[0] |= 0x40;
        assert_eq!(g2_from_wire(&p), None);
    }

    /// Empty multiexp returns the identity without a host call; the host's
    /// g1_msm on empty input is not part of the contract, so a regression
    /// here would surface as a trap in these tests.
    #[test]
    fn empty_multiexp_is_identity() {
        let ops = SorobanBn254::new(&env());
        assert_eq!(ops.g1_multiexp(&[], &[]), G1::identity());
    }

    /// Empty pairing is the empty product: true, no host call (the host
    /// panics on empty vectors).
    #[test]
    fn empty_pairing_is_true() {
        let ops = SorobanBn254::new(&env());
        assert!(ops.pairing_check(&[]));
    }

    #[test]
    #[should_panic(expected = "g1_multiexp: points.len() must equal scalars.len()")]
    fn multiexp_length_mismatch_panics() {
        let ops = SorobanBn254::new(&env());
        let _ = ops.g1_multiexp(&[G1::identity()], &[]);
    }
}
