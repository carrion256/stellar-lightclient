//! Cross-checks for the RISC Zero verifier layer:
//!
//! 1. Math cross-check against an arkworks-generated Groth16 fixture.
//! 2. Verifying-key transcription check via risc0-groth16's tagged digest.
//! 3. Seal parsing (length errors, round-trip through `seal_to_proof`).
//! 4. Public-input derivation (`split_digest` + control-id byte reversal).

use ark_bn254::Fq;
use ark_ff::{BigInt, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use risc0_binfmt::Digestible; // dev-dep: see report — not re-exported by risc0_groth16
use risc0_zkp::core::digest::Digest;
use risc0_zkp::core::hash::sha::{cpu::Impl, Sha256};
use serde_json::Value;
use std::path::Path;
use verifier::bn128::{Fr, G1, G2};
use verifier::groth16::{self, Proof, VerifyingKey};
use verifier::risc0;

// ---------------------------------------------------------------- fixtures

/// `testdata/groth16_fixture.json` is produced by `tools/groth16-fixture`
/// (arkworks reference). Panics loudly if absent — we must never silently skip.
fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/groth16_fixture.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing Groth16 fixture at {} — generate it with tools/groth16-fixture ({e})",
            path.display()
        )
    });
    serde_json::from_str(&raw).expect("fixture must be valid JSON")
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string").trim();
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex decode")
}

// Fixture hex is raw arkworks `CanonicalSerialize::serialize_uncompressed`
// output (LE-wire; confirmed by the generator agent: seed 42, field elements
// little-endian, G2 = x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1). `deserialize_uncompressed`
// is flag-aware: the top 2 bits of the encoding's last byte are SWFlags
// (PointAtInfinity=0x40, YIsNegative=0x80 — ark-ec serialization_flags.rs),
// and the wire format is byte-identical between arkworks 0.4 and 0.5.
fn parse_g1(raw: &[u8]) -> G1 {
    G1::deserialize_uncompressed(raw).expect("G1: bad point in fixture")
}

fn parse_g2(raw: &[u8]) -> G2 {
    G2::deserialize_uncompressed(raw).expect("G2: bad point in fixture")
}

fn parse_fr(raw: &[u8]) -> Fr {
    Fr::deserialize_uncompressed(raw).expect("Fr: invalid scalar")
}

/// The fixture's tampered proof has `tampered_proof.a` = `proof.a` XOR 0x01
/// in the final byte (the swflag byte) — the flipped y is off-curve, so a
/// canonical parser rejects it outright. The reference verifier does not
/// pre-check; it feeds the unchecked point into the pairing check, which
/// rejects it. Mirror that: parse strictly first, then strip the swflag bits
/// and construct unchecked so `!verify` is reachable.
fn parse_g1_maybe_tampered(raw: &[u8]) -> G1 {
    if let Ok(p) = G1::deserialize_uncompressed(raw) {
        return p;
    }
    let mut b = raw.to_vec();
    let last = b.len() - 1;
    b[last] &= 0x3F; // strip swflags (top 2 bits), keep the raw y data
    G1::new_unchecked(
        Fq::deserialize_uncompressed(&b[0..32]).expect("tampered G1 x chunk"),
        Fq::deserialize_uncompressed(&b[32..64]).expect("tampered G1 y chunk"),
    )
}

// ------------------------------------------------------------ group 1: math

#[test]
fn math_matches_arkworks_fixture() {
    // `groth16::verify` hits near_sdk host functions; they need a mocked chain.
    testing_env!(VMContextBuilder::new().build());
    let f = fixture();

    let g1 = |v: &Value| parse_g1(&hex_bytes(v));
    let g2 = |v: &Value| parse_g2(&hex_bytes(v));
    let fr = |v: &Value| parse_fr(&hex_bytes(v));

    let vk = VerifyingKey {
        alpha_g1: g1(&f["vk"]["alpha_g1"]),
        beta_g2: g2(&f["vk"]["beta_g2"]),
        gamma_g2: g2(&f["vk"]["gamma_g2"]),
        delta_g2: g2(&f["vk"]["delta_g2"]),
        ic: f["vk"]["gamma_abc_g1"]
            .as_array()
            .expect("vk.gamma_abc_g1 array")
            .iter()
            .map(g1)
            .collect(),
    };
    let proof_of = |p: &Value| Proof {
        a: g1(&p["a"]),
        b: g2(&p["b"]),
        c: g1(&p["c"]),
    };
    let proof = proof_of(&f["proof"]);
    let inputs: Vec<Fr> = f["public_inputs"]
        .as_array()
        .expect("public_inputs array")
        .iter()
        .map(fr)
        .collect();

    // One Groth16 verification = 4-pair pairing check + one multiexp. Measure the
    // real host-gas cost: the near mock delegates alt_bn128_* to nearcore VMLogic,
    // so this is the cost a transaction would pay.
    let before = near_sdk::env::used_gas().as_gas();
    assert!(
        groth16::verify(&vk, &proof, &inputs),
        "valid fixture proof must verify"
    );
    let spent = near_sdk::env::used_gas().as_gas() - before;
    println!(
        "groth16 verify: {} Tgas host gas (4-pair pairing_check + 1 multiexp)",
        spent / 1_000_000_000_000
    );

    // tampered_proof.a differs from proof.a in the swflag byte only: off-curve,
    // canonical-parse rejected, unchecked-constructed — pairing check rejects.
    let tampered = Proof {
        a: parse_g1_maybe_tampered(&hex_bytes(&f["tampered_proof"]["a"])),
        b: g2(&f["tampered_proof"]["b"]),
        c: g1(&f["tampered_proof"]["c"]),
    };
    assert!(
        !groth16::verify(&vk, &tampered, &inputs),
        "tampered proof must not verify"
    );

    let wrong_inputs: Vec<Fr> = f["wrong_public_inputs"]
        .as_array()
        .expect("wrong_public_inputs array")
        .iter()
        .map(fr)
        .collect();
    assert!(
        !groth16::verify(&vk, &proof, &wrong_inputs),
        "wrong public inputs must not verify"
    );
}

// ------------------------------------------------- group 2: vk digest check

/// Mirror of risc0_binfmt::tagged_struct (risc0-binfmt-3.0.5/src/hash.rs:69-88)
/// — replicated so the check does not depend on private helpers.
fn tagged_struct(tag: &str, down: &[Digest], data: &[u32]) -> Digest {
    let tag_digest = *Impl::hash_bytes(tag.as_bytes());
    let mut all = Vec::new();
    all.extend_from_slice(tag_digest.as_bytes());
    for d in down {
        all.extend_from_slice(d.as_ref());
    }
    for w in data {
        all.extend_from_slice(&w.to_le_bytes());
    }
    all.extend_from_slice(&(down.len() as u16).to_le_bytes());
    *Impl::hash_bytes(&all)
}

/// Mirror of tagged_iter (hash.rs:94-101): right fold with tagged_struct.
fn tagged_iter(tag: &str, iter: impl DoubleEndedIterator<Item = Digest>) -> Digest {
    iter.rfold(Digest::ZERO, |acc, el| {
        tagged_struct(tag, &[el, acc], &[])
    })
}

/// Mirror of hash_point (risc0-groth16-3.0.5/src/verifier.rs:204-212):
/// y ‖ x uncompressed bytes, whole buffer reversed, sha256.
fn hash_g1(p: &G1) -> Digest {
    let mut buf = Vec::new();
    p.y.serialize_uncompressed(&mut buf).unwrap();
    p.x.serialize_uncompressed(&mut buf).unwrap();
    buf.reverse();
    *Impl::hash_bytes(&buf)
}

fn hash_g2(p: &G2) -> Digest {
    let mut buf = Vec::new();
    p.y.serialize_uncompressed(&mut buf).unwrap();
    p.x.serialize_uncompressed(&mut buf).unwrap();
    buf.reverse();
    *Impl::hash_bytes(&buf)
}

#[test]
fn vk_digest_matches_risc0_reference() {
    let vk = risc0::verifying_key();
    assert_eq!(vk.ic.len(), 6, "risc0 vk has 6 IC points (5 public inputs)");

    let ours = tagged_struct(
        "risc0_groth16.VerifyingKey",
        &[
            hash_g1(&vk.alpha_g1),
            hash_g2(&vk.beta_g2),
            hash_g2(&vk.gamma_g2),
            hash_g2(&vk.delta_g2),
            tagged_iter(
                "risc0_groth16.VerifyingKey.IC",
                vk.ic.iter().map(hash_g1),
            ),
        ],
        &[],
    );

    assert_eq!(
        ours,
        risc0_groth16::verifying_key().digest::<Impl>(),
        "pinned VK transcription does not match risc0_groth16::verifying_key()"
    );
}

// ------------------------------------------------ group 2b: unchecked pinned vk

/// The fast-path key (`risc0::verify`) must be point-for-point the same key
/// the checked constructor produces — this is what makes skipping the
/// VK-side on-curve/subgroup re-validation sound.
#[test]
fn pinned_vk_unchecked_matches_checked() {
    let checked = risc0::verifying_key();
    let unchecked = risc0::pinned_vk_unchecked();
    assert_eq!(
        format!("{:?}", unchecked.alpha_g1),
        format!("{:?}", checked.alpha_g1),
        "alpha_g1 must match"
    );
    assert_eq!(
        format!("{:?}", unchecked.beta_g2),
        format!("{:?}", checked.beta_g2),
        "beta_g2 must match"
    );
    assert_eq!(
        format!("{:?}", unchecked.gamma_g2),
        format!("{:?}", checked.gamma_g2),
        "gamma_g2 must match"
    );
    assert_eq!(
        format!("{:?}", unchecked.delta_g2),
        format!("{:?}", checked.delta_g2),
        "delta_g2 must match"
    );
    assert_eq!(unchecked.ic.len(), checked.ic.len(), "ic length must match");
    for (i, (u, c)) in unchecked.ic.iter().zip(checked.ic.iter()).enumerate() {
        assert_eq!(
            format!("{:?}", u),
            format!("{:?}", c),
            "ic[{i}] must match"
        );
    }
}

// ---------------------------------------------------- group 3: seal parsing

#[test]
fn seal_wrong_length_is_error() {
    assert!(risc0::seal_to_proof(&[0u8; 255]).is_err());
    assert!(risc0::seal_to_proof(&[0u8; 257]).is_err());
    assert!(risc0::seal_to_proof(&[]).is_err());
    // Right length, off-curve junk: still an error, never a panic.
    assert!(risc0::seal_to_proof(&[0u8; 256]).is_err());
}

/// Serialize a G1 point into the seal layout: x, y big-endian, 32 bytes each.
fn encode_g1_into(p: &G1, out: &mut [u8]) {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let mut tmp = Vec::new();
    p.x.serialize_uncompressed(&mut tmp).unwrap();
    x.copy_from_slice(&tmp);
    tmp.clear();
    p.y.serialize_uncompressed(&mut tmp).unwrap();
    y.copy_from_slice(&tmp);
    x.reverse();
    y.reverse();
    out[..32].copy_from_slice(&x);
    out[32..].copy_from_slice(&y);
}

/// Serialize a G2 point into the seal layout: the G2 coordinate swap —
/// raw quad is `x.c1, x.c0, y.c1, y.c0` (risc0-groth16 src/types.rs:117-120).
fn encode_g2_into(p: &G2, out: &mut [u8]) {
    let mut c = [[0u8; 32]; 4];
    let mut tmp = Vec::new();
    p.x.c1.serialize_uncompressed(&mut tmp).unwrap();
    c[0].copy_from_slice(&tmp);
    tmp.clear();
    p.x.c0.serialize_uncompressed(&mut tmp).unwrap();
    c[1].copy_from_slice(&tmp);
    tmp.clear();
    p.y.c1.serialize_uncompressed(&mut tmp).unwrap();
    c[2].copy_from_slice(&tmp);
    tmp.clear();
    p.y.c0.serialize_uncompressed(&mut tmp).unwrap();
    c[3].copy_from_slice(&tmp);
    for (i, chunk) in c.iter_mut().enumerate() {
        chunk.reverse();
        out[i * 32..(i + 1) * 32].copy_from_slice(chunk);
    }
}

#[test]
fn seal_round_trips_through_parse() {
    // A well-formed 256-byte seal built from the pinned VK's real points.
    let vk = risc0::verifying_key();
    let mut seal = vec![0u8; 256];
    encode_g1_into(&vk.alpha_g1, &mut seal[0..64]);
    encode_g2_into(&vk.beta_g2, &mut seal[64..192]);
    encode_g1_into(&vk.ic[5], &mut seal[192..256]);

    let proof = risc0::seal_to_proof(&seal).expect("well-formed seal must parse");
    assert_eq!(proof.a, vk.alpha_g1);
    assert_eq!(proof.b, vk.beta_g2);
    assert_eq!(proof.c, vk.ic[5]);
}

// ---------------------------------------------- group 4: public-input vectors

#[test]
fn public_inputs_match_hand_vectors() {
    // Independent ground truths, derived directly from the `split_digest`
    // definition in risc0-groth16-3.0.5/src/verifier.rs:302-310 (reversed
    // buffer, split at 16, each half BE → Fr): for digest d, first half =
    // u128::from_be_bytes(d_reversed[16..]) = u128::from_le_bytes(d[..16]),
    // second = u128::from_le_bytes(d[16..]).
    let ctrl: [u8; 32] = core::array::from_fn(|i| i as u8);
    let claim: [u8; 32] = core::array::from_fn(|i| 255 - i as u8);
    let id: [u8; 32] = core::array::from_fn(|i| i as u8);

    let ins = risc0::public_inputs(ctrl, claim, id).expect("canonical inputs");

    // ctrl_hi: d[..16] little-endian  → 0x0f0e…0100
    assert_eq!(ins[0], Fr::from(0x0f0e0d0c0b0a09080706050403020100u128));
    // ctrl_lo: d[16..] little-endian  → 0x1f1e…1110
    assert_eq!(ins[1], Fr::from(0x1f1e1d1c1b1a19181716151413121110u128));
    // claim_hi
    assert_eq!(ins[2], Fr::from(0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeffu128));
    // claim_lo
    assert_eq!(ins[3], Fr::from(0xe0e1e2e3e4e5e6e7e8e9eaebecedeeefu128));

    // Fifth element: byte-reversed id parsed big-endian (verifier.rs:104-105).
    let reversed = Fr::from_bigint(BigInt([
        0x0706050403020100u64,
        0x0f0e0d0c0b0a0908u64,
        0x1716151413121110u64,
        0x1f1e1d1c1b1a1918u64,
    ]))
    .expect("reversed id is canonical");
    assert_eq!(ins[4], reversed);

    // The input is non-palindromic: the un-reversed parse differs, proving the
    // byte reversal is actually applied.
    let unreversed = Fr::from_bigint(BigInt([
        0x18191a1b1c1d1e1fu64,
        0x1011121314151617u64,
        0x08090a0b0c0d0e0fu64,
        0x0001020304050607u64,
    ]))
    .expect("unreversed id is canonical");
    assert_ne!(ins[4], unreversed);
}

// ------------------------------------------- group 5: strict raw encoding

/// Scalar-field modulus (canonical big-endian) — the strict parse boundary.
/// `Fq::MODULUS` is 2^254 + …, so every scalar is < 2^254 and `into_bigint()`
/// leaves the top two bits zero; reversing the top byte can never collide
/// with the SWFlag bit positions (0x40/0x80 of the LE last byte).
fn fq_modulus_be() -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, limb) in Fq::MODULUS.0.iter().enumerate() {
        b[24 - i * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
    }
    b
}

#[test]
fn seal_rejects_swflag_bits_in_raw_coordinates() {
    let vk = risc0::verifying_key();
    let mut seal = vec![0u8; 256];
    encode_g1_into(&vk.alpha_g1, &mut seal[0..64]);
    encode_g2_into(&vk.beta_g2, &mut seal[64..192]);
    encode_g1_into(&vk.ic[5], &mut seal[192..256]);

    // Byte 32 = first G1 y coordinate, its top byte (BE): raw format carries
    // no SWFlags, so the 0x80/0x40 bits are malformed — the old flag-aware
    // decoder silently stripped them and returned the *valid* original point.
    let mut s = seal.clone();
    s[32] |= 0x80;
    assert!(risc0::seal_to_proof(&s).is_err(), "YIsNegative bit must reject");
    let mut s = seal.clone();
    s[32] |= 0x40;
    assert!(risc0::seal_to_proof(&s).is_err(), "PointAtInfinity bit must reject");
    // G2 x.c1: raw quad word 0 → seal byte 64.
    let mut s = seal.clone();
    s[64] |= 0x80;
    assert!(risc0::seal_to_proof(&s).is_err(), "G2 flag bit must reject");
    // c's y coordinate, byte 224.
    let mut s = seal.clone();
    s[224] |= 0x80;
    assert!(risc0::seal_to_proof(&s).is_err(), "c flag bit must reject");

    // The untouched seal still parses — rejections are discriminating.
    risc0::seal_to_proof(&seal).expect("clean seal still parses");
}

#[test]
fn seal_rejects_coordinates_at_or_above_modulus() {
    let vk = risc0::verifying_key();
    let q = fq_modulus_be();

    // x ≡ modulus inside an otherwise-valid a encoding: the canonical
    // decoder rejects before any curve math.
    let mut s = vec![0u8; 256];
    encode_g1_into(&vk.alpha_g1, &mut s[0..64]);
    s[..32].copy_from_slice(&q);
    assert!(risc0::seal_to_proof(&s).is_err(), "a.x = q");

    // y ≡ modulus in the same valid encoding.
    let mut s = vec![0u8; 256];
    encode_g1_into(&vk.alpha_g1, &mut s[0..64]);
    s[32..64].copy_from_slice(&q);
    assert!(risc0::seal_to_proof(&s).is_err(), "a.y = q");

    // G2 x.c1 word ≡ modulus inside an otherwise-valid b encoding.
    let mut s = vec![0u8; 256];
    encode_g1_into(&vk.alpha_g1, &mut s[0..64]);
    encode_g2_into(&vk.beta_g2, &mut s[64..192]);
    s[64..96].copy_from_slice(&q);
    assert!(risc0::seal_to_proof(&s).is_err(), "b word = q");

    // q − 1 is a legitimate canonical encoding; the decoder alone must
    // accept it (checked below in LE), while the point built from it is
    // off-curve and the strict decode rejects that.
    let mut qm1_be = q;
    *qm1_be.last_mut().unwrap() -= 1;
    let mut s = vec![0u8; 256];
    encode_g1_into(&vk.alpha_g1, &mut s[0..64]);
    s[..32].copy_from_slice(&qm1_be);
    assert!(risc0::seal_to_proof(&s).is_err(), "q−1 is off-curve");
    let mut qm1_le = qm1_be;
    qm1_le.reverse();
    assert!(
        Fq::deserialize_uncompressed(qm1_le.as_slice()).is_ok(),
        "q−1 is canonical to the decoder"
    );
}

#[test]
fn public_inputs_enforce_scalar_modulus_boundary() {
    let ctrl = [0u8; 32];
    let claim = [0u8; 32];

    // Scalar modulus of the curve field (Fr), big-endian — never Fq's.
    let mut r_be = [0u8; 32];
    for (i, limb) in <Fr as PrimeField>::MODULUS.0.iter().enumerate() {
        r_be[24 - i * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
    }

    // Largest canonical control id: parse value r − 1. public_inputs reverses
    // the supplied bytes and parses them BE, so supply reverse(r − 1); the
    // decoded value must be exactly r − 1 — canonical boundary passes.
    let mut rm1 = r_be;
    *rm1.last_mut().unwrap() -= 1;
    let mut id_valid = rm1;
    id_valid.reverse();
    let ins = risc0::public_inputs(ctrl, claim, id_valid).expect("r−1 is canonical");
    let r_minus_one = Fr::from_bigint({
        let mut b = <Fr as PrimeField>::MODULUS;
        b.0[0] -= 1;
        b
    })
    .expect("r−1 is canonical");
    assert_eq!(ins[4], r_minus_one);

    // id parses to r: Err, and never the zero scalar or any reduction.
    let mut id_r = r_be;
    id_r.reverse();
    assert!(risc0::public_inputs(ctrl, claim, id_r).is_err());

    // id parses to r + 1: Err.
    let mut id_rp1 = r_be;
    *id_rp1.last_mut().unwrap() += 1;
    id_rp1.reverse();
    assert!(risc0::public_inputs(ctrl, claim, id_rp1).is_err());
}

// ----------------------------------------- group 6: total verify() on junk

// Deterministic search for a genuine on-curve G2 point *outside* the
// prime-order subgroup: candidates (x, y=0) built via
// `G2::get_point_from_x_unchecked`; skip the identity (0,0); return the
// first hit. No synthetic r-scalar multiplication: r·B is the identity
// (r is the prime-order group order), not a coset element.
fn wrong_subgroup_g2() -> G2 {
    for i in 1u64..64 {
        let p = G2::get_point_from_x_unchecked(
            ark_bn254::Fq2::new(Fq::from(i), Fq::from(0u64)),
            false,
        );
        if let Some(p) = p {
            if !p.infinity && p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve()
            {
                return p;
            }
        }
    }
    panic!("deterministic wrong-subgroup G2 search failed");
}

#[test]
fn verify_rejects_wrong_subgroup_g2_in_proof_without_host_trap() {
    testing_env!(VMContextBuilder::new().build());
    let vk = risc0::verifying_key(); // on-curve, in-subgroup by VK digest check

    // The unchecked G2 reaches verify() directly; without the subgroup
    // guard the host pairing_check would abort on it.
    let proof = Proof {
        a: vk.alpha_g1,
        b: wrong_subgroup_g2(),
        c: vk.ic[5],
    };
    assert!(proof.b.is_on_curve());
    assert!(
        !proof.b.is_in_correct_subgroup_assuming_on_curve(),
        "search must return a cofactor-coset point"
    );
    assert!(!groth16::verify(&vk, &proof, &[Fr::from(0u64); 5]));
}

#[test]
fn verify_rejects_wrong_subgroup_g2_in_vk_without_host_trap() {
    // Same defect class in the *verifying key* exercises the vk-side guard;
    // sharing one bad point between proof and vk would make the guard
    // checks indistinguishable.
    testing_env!(VMContextBuilder::new().build());
    let vk = risc0::verifying_key();
    let mut vk_bad = vk.clone();
    vk_bad.beta_g2 = wrong_subgroup_g2();

    let proof = Proof {
        a: vk.alpha_g1,
        b: vk.beta_g2,
        c: vk.ic[5],
    };
    assert!(!groth16::verify(&vk_bad, &proof, &[Fr::from(0u64); 5]));
}

#[test]
fn ok_claim_digest_matches_risc0_reference() {
    use risc0_binfmt::Digestible;
    use risc0_zkp::core::digest::Digest;
    use risc0_zkvm::ReceiptClaim; // dev-dep: vendored 3.0.6; ReceiptClaim::ok
                                  // shape identical to the 3.0.5 source claim.rs
                                  // cites (receipt.rs:77-95, 326-341)

    testing_env!(VMContextBuilder::new().build());

    let journal = b"epoch-journal-bytes";
    let image: [u8; 32] = core::array::from_fn(|i| i as u8);
    let ours = verifier::claim::claim_digest(&verifier::claim::ok_claim(image, journal));
    let reference: [u8; 32] = ReceiptClaim::ok(Digest::from(image), journal.to_vec())
        .digest::<Impl>()
        .as_bytes()
        .try_into()
        .unwrap();

    assert_eq!(ours, reference);

    // Discriminating: a different journal or image must diverge.
    let other = verifier::claim::claim_digest(&verifier::claim::ok_claim(image, b"other"));
    assert_ne!(ours, other);
    let other = verifier::claim::claim_digest(&verifier::claim::ok_claim([9u8; 32], journal));
    assert_ne!(ours, other);
}

#[test]
fn genuine_risc0_receipt_verifies_and_binds_public_inputs() {
    testing_env!(VMContextBuilder::new().build());
    // Upstream bootstrap-groth16 receipt, not a locally generated toy VK.
    // The fixture records immutable source URLs and wire transformations.
    let f: Value = serde_json::from_str(include_str!(
        "../../testdata/risc0_receipt_fixture.json"
    )).unwrap();
    let word = |key: &str| -> [u8; 32] { hex_bytes(&f[key]).try_into().unwrap() };
    let journal = hex_bytes(&f["journal"]);
    let claim = verifier::claim::claim_digest(&verifier::claim::ok_claim(
        word("image_id"), &journal,
    ));
    assert_eq!(claim, word("claim_digest"));
    let inputs = risc0::public_inputs(
        word("control_root"), claim, word("bn254_control_id"),
    ).unwrap();
    let seal = hex_bytes(&f["seal"]);
    let proof = risc0::seal_to_proof(&seal).unwrap();
    let vk = risc0::verifying_key();
    assert!(groth16::verify(&vk, &proof, &inputs));

    // Fast path (shared contract): the unchecked pinned VK must agree with
    // the checked path — true for the genuine proof, false once an input is
    // altered (same input-binding property, checked through `risc0::verify`).
    assert!(risc0::verify(&proof, &inputs), "fast path verifies");
    let mut altered = inputs;
    altered[0] += Fr::from(1u64);
    assert!(!risc0::verify(&proof, &altered), "fast path binds inputs");
    for index in 0..inputs.len() {
        let mut altered = inputs;
        altered[index] += Fr::from(1u64);
        assert!(!groth16::verify(&vk, &proof, &altered), "input {index} is bound");
    }
    let mut malformed = seal;
    malformed[32] |= 0x80;
    assert!(risc0::seal_to_proof(&malformed).is_err());
}
