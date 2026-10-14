//! Fixture-driven tests for the contract, mirroring the NEAR verifier's
//! fixture handling (`verifier/tests/risc0_verify.rs`).
//!
//! These run against the real Soroban test host (`Env::default()` with the
//! `testutils` feature): `soroban-env-host` implements the BN254 host
//! functions natively via arkworks, so `g1_msm` and `pairing_check` below
//! exercise the actual host path, not a mock. The G2 coefficient order of
//! `ops` is proven end-to-end by the fixture: a valid proof only verifies
//! if the host receives the points in the Ethereum order the host expects.

use crate::ops::{fr_to_wire, g1_to_wire, g2_to_wire, SorobanBn254};
use crate::StellarVerifier;
use ark_serialize::CanonicalDeserialize;
use groth16_core::bn254::NativeOps;
use groth16_core::groth16::verify;
use groth16_core::{Fr, G1, G2, ProofOps};
use serde_json::Value;
use soroban_sdk::{Bytes, BytesN, Env};
use std::path::Path;

/// `testdata/groth16_fixture.json` is produced by `tools/groth16-fixture`
/// (arkworks reference). Panics loudly if absent — never silently skip.
fn groth16_fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/groth16_fixture.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing Groth16 fixture at {} — generate it with tools/groth16-fixture ({e})",
            path.display()
        )
    });
    serde_json::from_str(&raw).expect("fixture must be valid JSON")
}

/// `testdata/risc0_receipt_fixture.json` is a genuine upstream RISC Zero 3.0
/// receipt (source URLs recorded in the file).
fn risc0_fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/risc0_receipt_fixture.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("missing RISC Zero fixture at {} ({e})", path.display())
    });
    serde_json::from_str(&raw).expect("fixture must be valid JSON")
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("fixture values are hex strings")).expect("valid hex")
}

/// The fixture's points are arkworks uncompressed serialization (little-
/// endian coordinates, flag bits in the final byte) — parse with arkworks,
/// then re-encode to this contract's big-endian wire format.
fn parse_g1(raw: &[u8]) -> G1 {
    G1::deserialize_uncompressed(raw).expect("G1: bad point in fixture")
}

fn parse_g2(raw: &[u8]) -> G2 {
    G2::deserialize_uncompressed(raw).expect("G2: bad point in fixture")
}

fn parse_fr(raw: &[u8]) -> Fr {
    Fr::deserialize_uncompressed(raw).expect("Fr: bad scalar in fixture")
}

fn g1_of(v: &Value) -> G1 {
    parse_g1(&hex_bytes(v))
}

fn g2_of(v: &Value) -> G2 {
    parse_g2(&hex_bytes(v))
}

/// VK wire: `alpha_g1 || beta_g2 || gamma_g2 || delta_g2 || ic[]`.
fn wire_vk(f: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&g1_to_wire(&g1_of(&f["vk"]["alpha_g1"])));
    out.extend_from_slice(&g2_to_wire(&g2_of(&f["vk"]["beta_g2"])));
    out.extend_from_slice(&g2_to_wire(&g2_of(&f["vk"]["gamma_g2"])));
    out.extend_from_slice(&g2_to_wire(&g2_of(&f["vk"]["delta_g2"])));
    for ic in f["vk"]["gamma_abc_g1"].as_array().expect("ic list") {
        out.extend_from_slice(&g1_to_wire(&g1_of(ic)));
    }
    out
}

/// Proof wire: `a || b || c`.
fn wire_proof(p: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&g1_to_wire(&g1_of(&p["a"])));
    out.extend_from_slice(&g2_to_wire(&g2_of(&p["b"])));
    out.extend_from_slice(&g1_to_wire(&g1_of(&p["c"])));
    out
}

/// Public-input wire: 32-byte big-endian scalars (fixture hex is LE).
fn wire_inputs(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    for x in v.as_array().expect("public inputs list") {
        out.extend_from_slice(&fr_to_wire(&parse_fr(&hex_bytes(x))));
    }
    out
}

fn call_verify(env: &Env, vk: &[u8], proof: &[u8], inputs: &[u8]) -> bool {
    StellarVerifier::verify(
        env.clone(),
        Bytes::from_slice(env, vk),
        Bytes::from_slice(env, proof),
        Bytes::from_slice(env, inputs),
    )
}

/// The toy fixture's proof verifies through the REAL Soroban host BN254
/// functions: decode -> codecs -> groth16_core::groth16::verify -> Bn254::g1_msm /
/// Bn254::pairing_check. This is also the end-to-end G2-order proof: a
/// wrong coefficient order hands the host different points and this
/// assertion fails.
#[test]
fn groth16_fixture_verifies_on_the_soroban_host() {
    let env = Env::default();
    let f = groth16_fixture();
    assert!(
        call_verify(&env, &wire_vk(&f), &wire_proof(&f["proof"]), &wire_inputs(&f["public_inputs"])),
        "valid fixture proof must verify on the Soroban host"
    );
    // The toy Groth16 circuit's cost. The real RISC Zero receipt is measured
    // separately in `risc0_receipt_verifies_end_to_end` — different program,
    // different number. Soroban meters cpu insns and memory separately from
    // NEAR's gas, so neither figure is comparable to `submit_span`'s Tgas.
    let b = env.cost_estimate().budget();
    println!(
        "soroban verify: {} cpu insns, {} mem bytes",
        b.cpu_instruction_cost(),
        b.memory_bytes_cost(),
    );
}

/// The toy-circuit fixture decoded into the shared core's structured types.
/// Both the native-parity test and the cross-backend equivalence test need
/// exactly this, so it lives in one place.
fn structured_fixture() -> (groth16_core::VerifyingKey, groth16_core::Proof, Vec<Fr>) {
    let f = groth16_fixture();
    let vk = groth16_core::VerifyingKey {
        alpha_g1: g1_of(&f["vk"]["alpha_g1"]),
        beta_g2: g2_of(&f["vk"]["beta_g2"]),
        gamma_g2: g2_of(&f["vk"]["gamma_g2"]),
        delta_g2: g2_of(&f["vk"]["delta_g2"]),
        ic: f["vk"]["gamma_abc_g1"]
            .as_array()
            .expect("ic list")
            .iter()
            .map(|p| g1_of(p))
            .collect(),
    };
    let proof = groth16_core::Proof {
        a: g1_of(&f["proof"]["a"]),
        b: g2_of(&f["proof"]["b"]),
        c: g1_of(&f["proof"]["c"]),
    };
    let inputs: Vec<Fr> = f["public_inputs"]
        .as_array()
        .expect("public inputs list")
        .iter()
        .map(|x| parse_fr(&hex_bytes(x)))
        .collect();
    (vk, proof, inputs)
}

/// Provider-independent cross-check: the same fixture also verifies with
/// groth16-core's pure-Rust ops, so a failure of the host test above is a
/// Soroban-provider problem, not a fixture/core problem.
#[test]
fn fixture_verifies_with_native_ops() {
    let (vk, proof, inputs) = structured_fixture();
    assert!(verify(&NativeOps, &vk, &proof, &inputs));
}

/// Host MSM cross-check against pure arkworks arithmetic: the provider's
/// Fr/G1 wire encodings must give the host the same points and scalars
/// arkworks sees. (α·3 + α·5 = α·8.)
#[test]
fn host_msm_matches_arkworks() {
    let env = Env::default();
    let f = groth16_fixture();
    let alpha = g1_of(&f["vk"]["alpha_g1"]);
    let ops = SorobanBn254::new(&env);
    let host = ops.g1_multiexp(&[alpha, alpha], &[Fr::from(3u64), Fr::from(5u64)]);
    let expected = alpha * Fr::from(8u64);
    assert_eq!(host, expected);
}

/// Cross-backend verdict equivalence — the test that catches a provider whose
/// *encoding* is wrong while every per-backend suite still passes.
///
/// The same logical proof is verified twice: once through the contract's full
/// wire path (decode big-endian bytes → Soroban host `g1_msm`/`pairing_check`),
/// once through the pure-arkworks `NativeOps` reference. They must agree on
/// every case, positive and negative. A wrong G2 coefficient order
/// (`x.c1||x.c0||y.c1||y.c0` vs NEAR's `x.c0||x.c1||y.c0||y.c1`) is exactly the
/// bug this catches: the host call succeeds and simply fails to verify, which
/// reads as a bad proof rather than a bad port. Neither backend's own suite
/// finds it, because each is internally consistent.
#[test]
fn wire_path_and_native_reference_agree_on_every_verdict() {
    let f = groth16_fixture();
    let vk_wire = wire_vk(&f);
    let proof_wire = wire_proof(&f["proof"]);
    let inputs_wire = wire_inputs(&f["public_inputs"]);
    let (vk, proof, inputs) = structured_fixture();

    // Cases must be well-formed on *both* paths. A bit-flipped proof is
    // off-curve and cannot be represented as an arkworks point at all, so it
    // cannot be a cross-backend case — that one belongs to
    // `tampered_wire_proof_returns_false_without_trapping`, which covers the
    // host-side trap guard. Here we want inputs where both backends can
    // compute a verdict and must reach the *same* one.
    let mut bad_inputs: Vec<Fr> = inputs.clone();
    bad_inputs[0] += Fr::from(1u64);
    let bad_inputs_wire: Vec<u8> = bad_inputs
        .iter()
        .flat_map(|x| fr_to_wire(x).to_vec())
        .collect();

    // A well-formed but wrong verifying key: swap one IC point for alpha. The
    // host path must see the corrupted bytes too, so patch the wire at the
    // documented offset — `alpha_g1(64) || beta_g2(128) || gamma_g2(128) ||
    // delta_g2(128) || ic[]`, hence ic[1] begins at 448 + 64.
    let mut bad_vk = vk.clone();
    bad_vk.ic[1] = vk.alpha_g1;
    let mut bad_vk_wire = vk_wire.clone();
    let ic1_at = 448 + 64;
    bad_vk_wire[ic1_at..ic1_at + 64].copy_from_slice(&g1_to_wire(&vk.alpha_g1));

    // Swapped A and C: a well-formed proof with the two G1 slots exchanged.
    // Exercises the G1 wire codec in two different positions of the same
    // buffer, which a per-point unit test cannot.
    let swapped = groth16_core::Proof {
        a: proof.c,
        b: proof.b,
        c: proof.a,
    };
    let mut swapped_wire = proof_wire.clone();
    // A is bytes 0..64, C is bytes 192..256 of the 256-byte proof wire.
    let (head, tail) = swapped_wire.split_at_mut(192);
    let mut a_block = [0u8; 64];
    a_block.copy_from_slice(&head[..64]);
    head[..64].copy_from_slice(&tail[..64]);
    tail[..64].copy_from_slice(&a_block);

    // Each case carries its *expected* verdict, so agreement alone cannot pass:
    // two backends that both wrongly accept a negative would otherwise satisfy
    // `via_host == via_native`. Cases must be well-formed on both paths — a
    // bit-flipped proof coordinate is off-curve and cannot be an arkworks point
    // at all, so it cannot be a cross-backend case. That one belongs to
    // `tampered_wire_proof_returns_false_without_trapping`.
    let cases: Vec<(
        &str,
        bool,                        // expected verdict on both paths
        &Vec<u8>,                    // vk wire for the host path
        &groth16_core::VerifyingKey, // vk for the native path
        &Vec<u8>,                    // proof wire for the host path
        &groth16_core::Proof,        // proof for the native path
        &[u8],                       // inputs wire for the host path
        &[Fr],                       // inputs for the native path
    )> = vec![
        ("valid", true, &vk_wire, &vk, &proof_wire, &proof, &inputs_wire, &inputs),
        (
            "wrong public input",
            false,
            &vk_wire,
            &vk,
            &proof_wire,
            &proof,
            &bad_inputs_wire,
            &bad_inputs,
        ),
        (
            "corrupted verifying key",
            false,
            &bad_vk_wire,
            &bad_vk,
            &proof_wire,
            &proof,
            &inputs_wire,
            &inputs,
        ),
        (
            "swapped A and C",
            false,
            &vk_wire,
            &vk,
            &swapped_wire,
            &swapped,
            &inputs_wire,
            &inputs,
        ),
    ];

    for (name, expected, vk_w, vk_c, proof_w, proof_c, in_w, native_inputs) in cases {
        let env = Env::default();
        let via_host = call_verify(&env, vk_w, proof_w, in_w);
        let via_native = groth16_core::groth16::verify(&NativeOps, vk_c, proof_c, native_inputs);
        assert_eq!(via_host, expected, "host path got the wrong verdict for case: {name}");
        assert_eq!(via_native, expected, "native path got the wrong verdict for case: {name}");
        assert_eq!(
            via_host, via_native,
            "wire path and native reference disagree on case: {name}"
        );
    }
}

/// A single flipped bit in a proof coordinate (off-curve) must come back
/// `false` from the entry point — not trap. This is the guard that keeps
/// the Soroban host from aborting on a malformed point.
#[test]
fn tampered_wire_proof_returns_false_without_trapping() {
    let env = Env::default();
    let f = groth16_fixture();
    let vk = wire_vk(&f);
    let mut proof = wire_proof(&f["proof"]);
    let inputs = wire_inputs(&f["public_inputs"]);
    proof[63] ^= 0x01; // flip a low bit of a's y -> canonical but off-curve
    assert!(!call_verify(&env, &vk, &proof, &inputs));
}

#[test]
fn wrong_public_inputs_are_rejected() {
    let env = Env::default();
    let f = groth16_fixture();
    assert!(!call_verify(
        &env,
        &wire_vk(&f),
        &wire_proof(&f["proof"]),
        &wire_inputs(&f["wrong_public_inputs"]),
    ));
}

/// Malformed lengths decode to `false`, never panic (every `take` is
/// bounds-checked before slicing).
#[test]
fn malformed_lengths_are_rejected() {
    let env = Env::default();
    let f = groth16_fixture();
    let vk = wire_vk(&f);
    let proof = wire_proof(&f["proof"]);
    let inputs = wire_inputs(&f["public_inputs"]);
    // Empty buffers.
    assert!(!call_verify(&env, &[], &[], &[]));
    // VK one byte short (fails the 448 + 64k shape).
    assert!(!call_verify(&env, &vk[..vk.len() - 1], &proof, &inputs));
    // VK header only with a non-integral IC tail (drop half an IC point).
    assert!(!call_verify(&env, &vk[..vk.len() - 32], &proof, &inputs));
    // Proof truncated and proof overlong.
    assert!(!call_verify(&env, &vk, &proof[..proof.len() - 1], &inputs));
    assert!(!call_verify(&env, &vk, &proof, &inputs[..inputs.len() - 1]));
    // Public inputs not a multiple of 32.
    assert!(!call_verify(&env, &vk, &proof, &[0u8; 33]));
}

/// A non-canonical public-input scalar (exactly r, the scalar modulus,
/// big-endian — quoted from soroban-sdk bn254.rs:71-72) is rejected rather
/// than silently reduced.
#[test]
fn non_canonical_public_input_is_rejected() {
    let env = Env::default();
    let f = groth16_fixture();
    let mut r = [0u8; 32];
    r.copy_from_slice(
        &hex::decode(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        )
        .unwrap(),
    );
    let _ = &mut r;
    assert!(!call_verify(&env, &wire_vk(&f), &wire_proof(&f["proof"]), &r));
}

/// `ProofOps::sha256` maps onto the host SHA-256: NIST vector for "abc".
#[test]
fn sha256_matches_the_nist_vector() {
    let env = Env::default();
    let ops = SorobanBn254::new(&env);
    assert_eq!(
        ops.sha256(b"abc"),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}

/// End-to-end RISC Zero receipt verification on the Soroban host: claim
/// digest derivation (host SHA-256) + public-input folding + the pinned
/// key's Groth16 check (host MSM + pairing).
#[test]
fn risc0_receipt_verifies_end_to_end() {
    let env = Env::default();
    let f = risc0_fixture();
    let result = StellarVerifier::verify_risc0_receipt(
        env.clone(),
        BytesN::from_array(&env, &hex_bytes(&f["image_id"]).try_into().unwrap()),
        Bytes::from_slice(&env, &hex_bytes(&f["journal"])),
        Bytes::from_slice(&env, &hex_bytes(&f["seal"])),
        BytesN::from_array(&env, &hex_bytes(&f["control_root"]).try_into().unwrap()),
        BytesN::from_array(&env, &hex_bytes(&f["bn254_control_id"]).try_into().unwrap()),
    );
    assert!(result, "upstream RISC Zero receipt must verify");
    // The real RISC Zero receipt's cost — not the toy Groth16 circuit's, which
    // is a different number and a different program.
    let b = env.cost_estimate().budget();
    println!(
        "soroban verify_risc0_receipt: {} cpu insns, {} mem bytes",
        b.cpu_instruction_cost(),
        b.memory_bytes_cost(),
    );
}

/// A receipt with a different journal must be rejected (the claim digest
/// changes, so the folded public inputs no longer match the seal).
#[test]
fn risc0_receipt_with_wrong_journal_is_rejected() {
    let env = Env::default();
    let f = risc0_fixture();
    let result = StellarVerifier::verify_risc0_receipt(
        env.clone(),
        BytesN::from_array(&env, &hex_bytes(&f["image_id"]).try_into().unwrap()),
        Bytes::from_slice(&env, b"a different journal"),
        Bytes::from_slice(&env, &hex_bytes(&f["seal"])),
        BytesN::from_array(&env, &hex_bytes(&f["control_root"]).try_into().unwrap()),
        BytesN::from_array(&env, &hex_bytes(&f["bn254_control_id"]).try_into().unwrap()),
    );
    assert!(!result);
}

/// A malformed seal must return `false`, never trap. The length conversion to
/// `[u8; SEAL_SIZE]` is where a wrong-sized seal would surface as a panic if it
/// were unwrapped instead of matched, so pin the boundary on both sides.
#[test]
fn risc0_receipt_rejects_malformed_seals_without_trapping() {
    let env = Env::default();
    let f = risc0_fixture();
    let seal = hex_bytes(&f["seal"]);
    let call = |seal_bytes: &[u8]| {
        StellarVerifier::verify_risc0_receipt(
            env.clone(),
            BytesN::from_array(&env, &hex_bytes(&f["image_id"]).try_into().unwrap()),
            Bytes::from_slice(&env, &hex_bytes(&f["journal"])),
            Bytes::from_slice(&env, seal_bytes),
            BytesN::from_array(&env, &hex_bytes(&f["control_root"]).try_into().unwrap()),
            BytesN::from_array(&env, &hex_bytes(&f["bn254_control_id"]).try_into().unwrap()),
        )
    };

    // Length boundaries: one short and one long.
    assert!(!call(&seal[..seal.len() - 1]), "truncated seal must be rejected");
    let mut overlong = seal.clone();
    overlong.push(0);
    assert!(!call(&overlong), "overlong seal must be rejected");

    // Right length, wrong contents: a flipped coordinate byte must not verify.
    let mut tampered = seal.clone();
    tampered[0] ^= 0x01;
    assert!(!call(&tampered), "tampered seal must be rejected");

    // And the untouched seal still verifies, so the negatives are rejections
    // and not a test that only ever sees `false`.
    assert!(call(&seal), "the genuine seal must still verify");
}

/// `control_root` and `bn254_control_id` are part of the statement, not
/// decoration: both feed the five Groth16 public inputs. A receipt proven under
/// one wrapper identity must not verify under another — that binding is what
/// makes "this receipt came from RISC Zero release X" meaningful rather than
/// "some RISC Zero receipt verifies".
///
/// Every other test in this file supplies the *correct* pair, so without this
/// the two parameters were never exercised as anything but constants.
#[test]
fn risc0_receipt_binds_the_wrapper_identity() {
    let env = Env::default();
    let f = risc0_fixture();
    let call = |control_root: [u8; 32], bn254_control_id: [u8; 32]| {
        StellarVerifier::verify_risc0_receipt(
            env.clone(),
            BytesN::from_array(&env, &hex_bytes(&f["image_id"]).try_into().unwrap()),
            Bytes::from_slice(&env, &hex_bytes(&f["journal"])),
            Bytes::from_slice(&env, &hex_bytes(&f["seal"])),
            BytesN::from_array(&env, &control_root),
            BytesN::from_array(&env, &bn254_control_id),
        )
    };

    let good_root: [u8; 32] = hex_bytes(&f["control_root"]).try_into().unwrap();
    let good_id: [u8; 32] = hex_bytes(&f["bn254_control_id"]).try_into().unwrap();

    // Positive control first: the genuine identity must verify, so the
    // rejections below are rejections rather than an always-`false` entry point.
    assert!(call(good_root, good_id), "the genuine wrapper identity must verify");

    // Each parameter is individually bound to the proof.
    let mut bad_root = good_root;
    bad_root[0] ^= 0x01;
    assert!(!call(bad_root, good_id), "control_root must be bound to the proof");

    let mut bad_id = good_id;
    bad_id[0] ^= 0x01;
    assert!(!call(good_root, bad_id), "bn254_control_id must be bound to the proof");

    // All-zero is not a wildcard or a default.
    assert!(!call([0u8; 32], [0u8; 32]), "no implicit wrapper identity");
    assert!(!call(good_root, [0u8; 32]), "zero control id is not a default");
    assert!(!call([0u8; 32], good_id), "zero control root is not a default");
}

/// The pinned entry point takes no wrapper identity: it can only ever accept
/// statements proven under the build's own pins. The fixture — a genuine
/// upstream receipt — is the ground truth for those pins, so the digest
/// equalities double as a release-drift guard: a verification-crate bump that
/// moves the pair fails here until it is deliberately re-pinned (AGENTS.md).
#[test]
fn pinned_receipt_entry_uses_the_audited_wrapper_identity() {
    let env = Env::default();
    let f = risc0_fixture();
    assert_eq!(hex_bytes(&f["control_root"]), groth16_core::risc0::RISC0_CONTROL_ROOT);
    assert_eq!(
        hex_bytes(&f["bn254_control_id"]),
        groth16_core::risc0::RISC0_BN254_CONTROL_ID
    );
    assert!(
        StellarVerifier::verify_risc0_receipt_pinned(
            env.clone(),
            BytesN::from_array(&env, &hex_bytes(&f["image_id"]).try_into().unwrap()),
            Bytes::from_slice(&env, &hex_bytes(&f["journal"])),
            Bytes::from_slice(&env, &hex_bytes(&f["seal"])),
        ),
        "the genuine receipt must verify through the pinned entry"
    );
}

/// The pinned path fails closed on attacker-shaped input exactly like the
/// generic one — pinning the constants does not pin the statement open.
#[test]
fn pinned_receipt_rejects_tampering() {
    let env = Env::default();
    let f = risc0_fixture();
    let image: [u8; 32] = hex_bytes(&f["image_id"]).try_into().unwrap();
    let seal = hex_bytes(&f["seal"]);
    let journal = hex_bytes(&f["journal"]);
    let mut tampered = seal.clone();
    tampered[0] ^= 0x01;
    assert!(
        !StellarVerifier::verify_risc0_receipt_pinned(
            env.clone(),
            BytesN::from_array(&env, &image),
            Bytes::from_slice(&env, &journal),
            Bytes::from_slice(&env, &tampered),
        ),
        "tampered seal must be rejected through the pinned entry"
    );
    assert!(
        !StellarVerifier::verify_risc0_receipt_pinned(
            env.clone(),
            BytesN::from_array(&env, &image),
            Bytes::from_slice(&env, b"a different journal"),
            Bytes::from_slice(&env, &seal),
        ),
        "wrong journal must be rejected through the pinned entry"
    );
}
