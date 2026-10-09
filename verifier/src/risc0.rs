//! RISC Zero-specific glue: pinned Groth16 verifying key, seal parsing,
//! and claim public-input derivation.
//!
//! Every byte-handling routine here mirrors `risc0-groth16` 3.0.5 exactly
//! (`src/verifier.rs`, `src/lib.rs`, `src/types.rs`); citations are inline.
//! Verifying key transcription is checked in `tests/risc0_verify.rs` against
//! `risc0_groth16::verifying_key()` via the crate's tagged digest.

use crate::bn128::{Fr, G1, G2};
use crate::groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;

// ---------------------------------------------------------------------------
// Pinned RISC Zero verifying key.
// Transcribed (decimal, verbatim) from
// risc0-groth16-3.0.5/src/verifier.rs:36-76.
// The 6 IC points imply 5 public inputs, matching `public_inputs` below.
// ---------------------------------------------------------------------------
const ALPHA_X: &str =
    "20491192805390485299153009773594534940189261866228447918068658471970481763042";
const ALPHA_Y: &str =
    "9383485363053290200918347156157836566562967994039712273449902621266178545958";
const BETA_X1: &str =
    "4252822878758300859123897981450591353533073413197771768651442665752259397132";
const BETA_X2: &str =
    "6375614351688725206403948262868962793625744043794305715222011528459656738731";
const BETA_Y1: &str =
    "21847035105528745403288232691147584728191162732299865338377159692350059136679";
const BETA_Y2: &str =
    "10505242626370262277552901082094356697409835680220590971873171140371331206856";
const GAMMA_X1: &str =
    "11559732032986387107991004021392285783925812861821192530917403151452391805634";
const GAMMA_X2: &str =
    "10857046999023057135944570762232829481370756359578518086990519993285655852781";
const GAMMA_Y1: &str =
    "4082367875863433681332203403145435568316851327593401208105741076214120093531";
const GAMMA_Y2: &str =
    "8495653923123431417604973247489272438418190587263600148770280649306958101930";
const DELTA_X1: &str =
    "1668323501672964604911431804142266013250380587483576094566949227275849579036";
const DELTA_X2: &str =
    "12043754404802191763554326994664886008979042643626290185762540825416902247219";
const DELTA_Y1: &str =
    "7710631539206257456743780535472368339139328733484942210876916214502466455394";
const DELTA_Y2: &str =
    "13740680757317479711909903993315946540841369848973133181051452051592786724563";
const IC0_X: &str = "8446592859352799428420270221449902464741693648963397251242447530457567083492";
const IC0_Y: &str = "1064796367193003797175961162477173481551615790032213185848276823815288302804";
const IC1_X: &str = "3179835575189816632597428042194253779818690147323192973511715175294048485951";
const IC1_Y: &str = "20895841676865356752879376687052266198216014795822152491318012491767775979074";
const IC2_X: &str = "5332723250224941161709478398807683311971555792614491788690328996478511465287";
const IC2_Y: &str = "21199491073419440416471372042641226693637837098357067793586556692319371762571";
const IC3_X: &str = "12457994489566736295787256452575216703923664299075106359829199968023158780583";
const IC3_Y: &str = "19706766271952591897761291684837117091856807401404423804318744964752784280790";
const IC4_X: &str = "19617808913178163826953378459323299110911217259216006187355745713323154132237";
const IC4_Y: &str = "21663537384585072695701846972542344484111393047775983928357046779215877070466";
const IC5_X: &str = "6834578911681792552110317589222010969491336870276623105249474534788043166867";
const IC5_Y: &str = "15060583660288623605191393599883223885678013570733629274538391874953353488393";

/// The pinned RISC Zero Groth16 verifying key (6 IC points → 5 public inputs).
pub fn verifying_key() -> VerifyingKey {
    // Constants are valid by construction; a transcription error is caught by
    // the digest cross-check in tests/risc0_verify.rs.
    VerifyingKey {
        alpha_g1: g1_from_be([ALPHA_X, ALPHA_Y]).expect("pinned ALPHA is a G1 point"),
        beta_g2: g2_from_be([[BETA_X1, BETA_X2], [BETA_Y1, BETA_Y2]])
            .expect("pinned BETA is a G2 point"),
        gamma_g2: g2_from_be([[GAMMA_X1, GAMMA_X2], [GAMMA_Y1, GAMMA_Y2]])
            .expect("pinned GAMMA is a G2 point"),
        delta_g2: g2_from_be([[DELTA_X1, DELTA_X2], [DELTA_Y1, DELTA_Y2]])
            .expect("pinned DELTA is a G2 point"),
        ic: [IC0_X, IC1_X, IC2_X, IC3_X, IC4_X, IC5_X]
            .into_iter()
            .zip([IC0_Y, IC1_Y, IC2_Y, IC3_Y, IC4_Y, IC5_Y].into_iter())
            .map(|(x, y)| g1_from_be([x, y]).expect("pinned IC point"))
            .collect(),
    }
}

/// Decode a raw 256-byte RISC Zero seal into a [`Proof`].
///
/// Layout (risc0-groth16-3.0.5/src/types.rs:69-103 `Seal::decode`):
/// - `a`: bytes 0..64, G1 as `(x_BE, y_BE)`.
/// - `b`: bytes 64..192, G2 — **coordinate-swapped**: the raw quad is
///   `(x.c1, x.c0, y.c1, y.c0)`, consumed by `g2_from_bytes` in source order
///   `elem[0][1], elem[0][0], elem[1][1], elem[1][0]`
///   (risc0-groth16-3.0.5/src/lib.rs:118-132; swap introduced in
///   src/types.rs:117-120). We un-swap here so `Proof.b` is the real G2 point.
/// - `c`: bytes 192..256, G1 as `(x_BE, y_BE)`.
pub fn seal_to_proof(seal: &[u8]) -> Result<Proof, String> {
    // Seal::SIZE == 256; the source returns an error, so do the same.
    if seal.len() != 256 {
        return Err(format!("invalid seal length: expected 256, got {}", seal.len()));
    }
    // Split into 32-byte big-endian field elements exactly as Seal::decode does
    // (types.rs:80-100): a = [e0, e1], b = [[e2, e3], [e4, e5]], c = [e6, e7].
    let e = |i: usize| &seal[i * 32..(i + 1) * 32];
    Ok(Proof {
        a: g1_from_be_raw([e(0), e(1)]).map_err(|_| "seal a: invalid G1 point")?,
        b: g2_from_be_raw([[e(2), e(3)], [e(4), e(5)]])
            .map_err(|_| "seal b: invalid G2 point")?,
        c: g1_from_be_raw([e(6), e(7)]).map_err(|_| "seal c: invalid G1 point")?,
    })
}

/// Claim public inputs: `[ctrl_hi, ctrl_lo, claim_hi, claim_lo,
/// bn254_control_id_rev]`, each an [`Fr`].
///
/// Digest splitting replicates `split_digest`
/// (risc0-groth16-3.0.5/src/verifier.rs:302-310): the digest bytes are
/// reversed, the reversed buffer is split at 16 bytes, and each 16-byte half
/// is interpreted as a big-endian integer (`from_u256_hex` left-pads, then
/// `fr_from_bytes` (verifier.rs:318-323) reverses to arkworks' little-endian
/// deserialization). Net effect: half values are `u128::from_le_bytes` of the
/// *original* digest halves — each < 2^128, far below the scalar modulus, so
/// `Fr::from(u128)` is exact and canonical.
///
/// The fifth input is `bn254_control_id` with its bytes reversed, parsed as a
/// big-endian u256 into `Fr` (risc0-groth16-3.0.5/src/verifier.rs:104-105).
pub fn public_inputs(
    control_root: [u8; 32],
    claim_digest: [u8; 32],
    bn254_control_id: [u8; 32],
) -> [Fr; 5] {
    let (a0, a1) = split_digest(control_root);
    let (c0, c1) = split_digest(claim_digest);
    let mut id_be = bn254_control_id;
    id_be.reverse(); // verifier.rs:104 — reverse the digest bytes
    let id_bn254_fr = fr_from_be(&id_be);
    // Order pinned by verifier.rs:107 `new_inner(&seal, &[a0, a1, c0, c1, id_bn254_fr], ..)`.
    [a0, a1, c0, c1, id_bn254_fr]
}

/// `split_digest` equivalent: returns `(hi, lo)` — the two scalar halves of a
/// digest, as produced by the source path above (first element ← original
/// digest bytes 0..16, second ← bytes 16..32).
fn split_digest(d: [u8; 32]) -> (Fr, Fr) {
    let half = |b: &[u8]| Fr::from(u128::from_le_bytes(b.try_into().unwrap()));
    (half(&d[..16]), half(&d[16..]))
}

/// `fr_from_bytes` equivalent for a 32-byte big-endian value
/// (risc0-groth16-3.0.5/src/verifier.rs:318-323). Non-canonical values
/// (≥ scalar modulus) are an error in the source; since our signature cannot
/// return an error, they map to `Fr::ZERO`, which makes Groth16 verification
/// fail closed — no legitimate scalar equals 0 here, and `seal_to_proof` +
/// `verify` still reject any crafted seal.
fn fr_from_be(bytes: &[u8; 32]) -> Fr {
    let mut le = *bytes;
    le.reverse(); // arkworks CanonicalDeserialize reads little-endian
    Fr::deserialize_uncompressed(le.as_slice())
        .ok()
        .unwrap_or(Fr::from(0u64))
}

/// `from_u256` for a decimal string (risc0-groth16-3.0.5/src/lib.rs:135-147):
/// u256 decimal → 32-byte big-endian. Returns `None` on overflow; our pinned
/// constants are in range.
fn u256_dec_to_be32(s: &str) -> Option<[u8; 32]> {
    let mut limbs = [0u64; 4]; // little-endian 64-bit limbs
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        let mut carry = (b - b'0') as u64;
        for limb in limbs.iter_mut() {
            let t = u128::from(*limb) * 10 + u128::from(carry);
            *limb = t as u64;
            carry = (t >> 64) as u64;
        }
        if carry != 0 {
            return None; // > u256::MAX
        }
    }
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        // limb 0 is least significant → last 8 bytes of the BE array.
        out[24 - i * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
    }
    Some(out)
}

/// G1 decode replicating `g1_from_bytes`
/// (risc0-groth16-3.0.5/src/lib.rs:103-115): buffer `x.rev ‖ y.rev` (both
/// halves little-endian), then `deserialize_uncompressed` (canonical +
/// on-curve checks included).
fn g1_from_be_raw(elem: [&[u8]; 2]) -> Result<G1, ()> {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(elem[0]);
    buf[..32].reverse();
    buf[32..].copy_from_slice(elem[1]);
    buf[32..].reverse();
    G1::deserialize_uncompressed(buf.as_slice()).map_err(|_| ())
}

/// G2 decode replicating `g2_from_bytes`
/// (risc0-groth16-3.0.5/src/lib.rs:118-132): buffer is built in the order
/// `elem[0][1] ‖ elem[0][0] ‖ elem[1][1] ‖ elem[1][0]`, each chunk reversed.
/// With the source's swap (types.rs:117-120) this yields the *real* G2 point
/// `(x = Fq2(c0 = elem[0][1], c1 = elem[0][0]), y = Fq2(elem[1][1], elem[1][0]))`.
fn g2_from_be_raw(elem: [[&[u8]; 2]; 2]) -> Result<G2, ()> {
    let mut buf = [0u8; 128];
    for (i, src) in [elem[0][1], elem[0][0], elem[1][1], elem[1][0]]
        .iter()
        .enumerate()
    {
        buf[i * 32..(i + 1) * 32].copy_from_slice(src);
        buf[i * 32..(i + 1) * 32].reverse();
    }
    G2::deserialize_uncompressed(buf.as_slice()).map_err(|_| ())
}

/// VK construction: decimal constant → BE bytes → the same `g?_from_bytes`
/// path the source's `try_verifying_key` uses
/// (risc0-groth16-3.0.5/src/verifier.rs:269-299).
fn g1_from_be(xs: [&str; 2]) -> Result<G1, String> {
    g1_from_be_raw([
        &u256_dec_to_be32(xs[0]).ok_or("ALPHA/IC x out of range")?,
        &u256_dec_to_be32(xs[1]).ok_or("ALPHA/IC y out of range")?,
    ])
    .map_err(|_| "g1 point invalid".to_string())
}

fn g2_from_be(ys: [[&str; 2]; 2]) -> Result<G2, String> {
    g2_from_be_raw([
        [
            &u256_dec_to_be32(ys[0][0]).ok_or("G2 e00 out of range")?,
            &u256_dec_to_be32(ys[0][1]).ok_or("G2 e01 out of range")?,
        ],
        [
            &u256_dec_to_be32(ys[1][0]).ok_or("G2 e10 out of range")?,
            &u256_dec_to_be32(ys[1][1]).ok_or("G2 e11 out of range")?,
        ],
    ])
    .map_err(|_| "g2 point invalid".to_string())
}
