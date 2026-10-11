//! Groth16 verification for Stellar/Soroban over the native BN254 host
//! functions (CAP-0074 / Protocol 25 "X-Ray").
//!
//! The verification equation, the shape/degeneracy guards, and every
//! on-curve/prime-order-subgroup check live in `groth16_core::groth16::verify`; this
//! crate supplies the Soroban [`ProofOps`] provider (see [`ops`]) and the
//! wire-format decoding. Nothing about Groth16 is re-implemented here.
//!
//! # Wire format
//!
//! All arguments are Ethereum-compatible **big-endian** `Bytes`; point and
//! scalar encodings are the Soroban host's own formats (citations and the G2
//! coefficient order — `x.c1 || x.c0 || y.c1 || y.c0` — are in [`ops`]).
//!
//! * `proof` — exactly 256 bytes:
//!   `a (G1, 64) || b (G2, 128) || c (G1, 64)`, i.e. byte-for-byte the
//!   Groth16-seal layout of a RISC Zero seal.
//! * `verifying_key` — `448 + 64·k` bytes, `k ≥ 0`:
//!   `alpha_g1 (64) || beta_g2 (128) || gamma_g2 (128) || delta_g2 (128) ||
//!   ic[0] … ic[k−1] (64 each)`. `k = 0` decodes to an empty IC list, which
//!   `groth16_core::groth16::verify` rejects as `false`.
//! * `public_inputs` — `32·n` bytes, one canonical big-endian scalar each.
//!
//! # Totality
//!
//! [`StellarVerifier::verify`] and [`StellarVerifier::verify_risc0_receipt`]
//! never trap on adversarial input:
//!
//! * decoding enforces lengths and canonical field elements only — any
//!   malformed buffer returns `false` (the host's flag bits 0x80/0x40 and
//!   non-canonical coordinates/scalars are rejected here);
//! * every point's on-curve/subgroup check runs inside
//!   `groth16_core::groth16::verify` *before* any host call — both the NEAR and the
//!   Soroban host **abort** on a malformed point, so those pre-checks are
//!   what keep this entry point total. That is exactly why the entry point
//!   calls `verify` and never `verify_trusted_vk`.
//!
//! `verify_risc0_receipt` follows the pinned-RISC-Zero path
//! (`groth16_core::risc0::verify`, which uses `verify_trusted_vk` against
//! the pinned key whose transcription is cross-checked by groth16-core's
//! tests); all proof-side guards still apply, so it is total as well.
//!
//! soroban-sdk 28 refuses `wasm32-unknown-unknown` on Rust ≥ 1.82 (its
//! build.rs panics: use `wasm32v1-none`, a no-std target), so this crate is
//! `no_std` + `alloc` outside of tests.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use groth16_core::{Fr, Proof, VerifyingKey};
use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env};

mod ops;

use ops::{fr_from_wire, g1_from_wire, g2_from_wire, take, G1_SIZE, G2_SIZE, SCALAR_SIZE};
use groth16_core::bn254::SEAL_SIZE;

#[cfg(test)]
mod tests;

/// `alpha_g1 || beta_g2 || gamma_g2 || delta_g2`.
const VK_HEADER_LEN: usize = G1_SIZE + 3 * G2_SIZE; // 448
/// `a || b || c`. This is the Groth16 proof wire format and the RISC Zero
/// `Seal::SIZE` simultaneously — the same 256 bytes on both chains — so it
/// comes from the shared layout rather than being re-derived here.
const PROOF_LEN: usize = SEAL_SIZE;

/// Decode the verifying-key wire format; `None` on any length or
/// canonicality violation (points may be off-curve here — the pre-checks
/// run in `groth16_core::groth16::verify`).
fn decode_vk(b: &Bytes) -> Option<VerifyingKey> {
    let len = b.len() as usize;
    if len < VK_HEADER_LEN || (len - VK_HEADER_LEN) % G1_SIZE != 0 {
        return None;
    }
    let mut at = 0u32;
    let alpha_g1 = g1_from_wire(&take(b, at)?)?;
    at += G1_SIZE as u32;
    let beta_g2 = g2_from_wire(&take(b, at)?)?;
    at += G2_SIZE as u32;
    let gamma_g2 = g2_from_wire(&take(b, at)?)?;
    at += G2_SIZE as u32;
    let delta_g2 = g2_from_wire(&take(b, at)?)?;
    at += G2_SIZE as u32;
    let mut ic = Vec::new();
    while (at as usize) < len {
        ic.push(g1_from_wire(&take(b, at)?)?);
        at += G1_SIZE as u32;
    }
    Some(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}

/// Decode `a (G1) || b (G2) || c (G1)`; exact length required.
fn decode_proof(b: &Bytes) -> Option<Proof> {
    if b.len() as usize != PROOF_LEN {
        return None;
    }
    Some(Proof {
        a: g1_from_wire(&take(b, 0)?)?,
        b: g2_from_wire(&take(b, G1_SIZE as u32)?)?,
        c: g1_from_wire(&take(b, (G1_SIZE + G2_SIZE) as u32)?)?,
    })
}

/// Decode `32·n` bytes of canonical big-endian public inputs.
fn decode_inputs(b: &Bytes) -> Option<Vec<Fr>> {
    if b.len() % (SCALAR_SIZE as u32) != 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut at = 0u32;
    while at < b.len() {
        out.push(fr_from_wire(&take(b, at)?)?);
        at += SCALAR_SIZE as u32;
    }
    Some(out)
}

#[contract]
pub struct StellarVerifier;

#[contractimpl]
impl StellarVerifier {
    /// Verifies a Groth16 proof (`a`, `b`, `c`) against `verifying_key` and
    /// `public_inputs`, all in the wire formats documented at the crate
    /// root. Returns `false` for malformed bytes, wrong shapes, or an
    /// invalid proof; never traps.
    pub fn verify(env: Env, verifying_key: Bytes, proof: Bytes, public_inputs: Bytes) -> bool {
        let (Some(vk), Some(proof), Some(inputs)) = (
            decode_vk(&verifying_key),
            decode_proof(&proof),
            decode_inputs(&public_inputs),
        ) else {
            return false;
        };
        let ops = ops::SorobanBn254::new(&env);
        groth16_core::groth16::verify(&ops, &vk, &proof, &inputs)
    }

    /// Verifies a RISC Zero 3.0 receipt end-to-end: derives the `ok()`
    /// `ReceiptClaim` digest for (`image_id`, `journal`) through
    /// `groth16_core::claim`, folds it with `control_root` and
    /// `bn254_control_id` into the five Groth16 public inputs
    /// (`groth16_core::risc0::public_inputs`), and checks `seal` against the
    /// pinned RISC Zero verifying key.
    ///
    /// Wire formats:
    /// * `image_id`, `control_root`, `bn254_control_id` — 32-byte digests
    ///   exactly as upstream/`testdata/risc0_receipt_fixture.json` define
    ///   them; `bn254_control_id`'s risc0-groth16 byte reversal happens
    ///   inside `public_inputs`, not in the arguments.
    /// * `journal` — the raw journal bytes.
    /// * `seal` — the 256-byte Ethereum-format Groth16 seal
    ///   (`a (64) || b (128) || c (64)`, big-endian), byte-for-byte the
    ///   fixture's `seal` field (minus the transaction `selector`).
    ///
    /// `control_root` and `bn254_control_id` are part of the *statement* being
    /// proven, not a trust knob: both feed the five Groth16 public inputs, so a
    /// wrong value simply fails to verify rather than widening what is accepted.
    ///
    /// This contract stores no wrapper identity and therefore supplies **no
    /// reference values** to compare against — unlike the NEAR deployment, which
    /// exposes `get_wrapper` / `is_wrapper_compatible` for exactly this. A caller
    /// that wants "this receipt came from RISC Zero release X" must pin both
    /// against X at integration time. `AGENTS.md` records where those constants
    /// come from and when they must be re-pinned (any *verification* crate bump).
    ///
    /// Malformed input returns `false`; never traps.
    pub fn verify_risc0_receipt(
        env: Env,
        image_id: BytesN<32>,
        journal: Bytes,
        seal: Bytes,
        control_root: BytesN<32>,
        bn254_control_id: BytesN<32>,
    ) -> bool {
        let ops = ops::SorobanBn254::new(&env);
        let journal: Vec<u8> = journal.iter().collect();
        let claim = groth16_core::claim::ok_claim(&ops, image_id.to_array(), &journal);
        let digest = groth16_core::claim::claim_digest(&ops, &claim);
        let Ok(public_inputs) = groth16_core::risc0::public_inputs(
            control_root.to_array(),
            digest,
            bn254_control_id.to_array(),
        ) else {
            return false;
        };
        let Ok(seal) = <[u8; SEAL_SIZE]>::try_from(seal) else {
            return false;
        };
        let Ok(proof) = groth16_core::risc0::seal_to_proof(&seal) else {
            return false;
        };
        groth16_core::risc0::verify(&ops, &proof, &public_inputs)
    }
}
