use std::env;
use std::fs;
use std::path::PathBuf;

use ark_bn254::{Bn254, Fq, Fr, G1Affine};
use ark_groth16::{prepare_verifying_key, Groth16, Proof};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use serde_json::json;

/// x * x = y over ark_bn254::Fr: one private witness `x`, one public input `y`.
#[derive(Clone)]
struct SquareCircuit {
    x: Fr,
    y: Fr,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| Ok(self.x))?;
        let y = cs.new_input_variable(|| Ok(self.y))?;
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + y)?;
        Ok(())
    }
}

fn enc<T: CanonicalSerialize>(v: &T) -> String {
    let mut buf = Vec::new();
    v.serialize_uncompressed(&mut buf).unwrap();
    hex::encode(&buf)
}

fn main() {
    let mut out = PathBuf::from("testdata/groth16_fixture.json");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                out = PathBuf::from(args.next().expect("--out requires a value"));
            }
            other => panic!(
                "unknown argument: {other} (usage: groth16-fixture [--out <path>])"
            ),
        }
    }

    // Deterministic: one seeded RNG drives setup and proving; the same seed
    // and crate versions reproduce the fixture byte-for-byte.
    let mut rng = StdRng::seed_from_u64(42);
    let public_y = Fr::from(9u64);
    let circuit = SquareCircuit {
        x: Fr::from(3u64),
        y: public_y,
    };

    let params =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
            .expect("setup failed");
    let proof =
        Groth16::<Bn254>::prove(&params, circuit.clone(), &mut rng).expect("prove failed");

    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = [public_y];

    // Self-check 1: the reference verifier must accept the good proof.
    let accepted = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .expect("verification errored on the good proof");
    assert!(accepted, "reference verifier REJECTED the good proof");

    // Self-check 2: the fixture tampering rule — flip the last byte of the
    // serialized `a` — must make the reference verifier reject.
    //
    // The G1 uncompressed wire carries flag bits in the top 2 bits of its
    // final byte (arkworks embeds the y-sign / infinity flag there); the
    // tampered wire is therefore rejected by any canonical parser *and* we
    // additionally exercise the pairing check on the unchecked off-curve
    // point so the reference verifier's math rejects it too.
    let mut a_bytes = Vec::new();
    proof.a.serialize_uncompressed(&mut a_bytes).unwrap();
    assert!(
        <G1Affine as CanonicalDeserialize>::deserialize_uncompressed(&a_bytes[..]).is_ok(),
        "fixture proof.a is not a valid G1 encoding"
    );
    let tamper_idx = a_bytes.len() - 1;
    a_bytes[tamper_idx] ^= 0x01;
    // Strip the encoding's flag bits (top 2 bits of the final byte) to get
    // plain coordinate bytes for the unchecked tampered point.
    let mut raw = a_bytes.clone();
    raw[tamper_idx] &= 0x3f;
    let tampered_a = G1Affine::new_unchecked(
        <Fq as CanonicalDeserialize>::deserialize_uncompressed(&raw[..32]).unwrap(),
        <Fq as CanonicalDeserialize>::deserialize_uncompressed(&raw[32..]).unwrap(),
    );
    let tampered_proof = Proof {
        a: tampered_a,
        b: proof.b,
        c: proof.c,
    };
    let tampered_accepted = Groth16::<Bn254>::verify_proof(&pvk, &tampered_proof, &public_inputs);
    assert!(
        !matches!(tampered_accepted, Ok(true)),
        "reference verifier ACCEPTED the tampered proof"
    );

    let vk = &params.vk;
    let fixture = json! {
        {
            "curve": "bn254",
            "arkworks_version": "0.4.x",
            "vk": {
                "alpha_g1": enc(&vk.alpha_g1),
                "beta_g2": enc(&vk.beta_g2),
                "gamma_g2": enc(&vk.gamma_g2),
                "delta_g2": enc(&vk.delta_g2),
                "gamma_abc_g1": vk.gamma_abc_g1.iter().map(enc).collect::<Vec<_>>(),
            },
            "proof": {
                "a": enc(&proof.a),
                "b": enc(&proof.b),
                "c": enc(&proof.c),
            },
            "public_inputs": [enc(&public_y)],
            "tampered_proof": {
                "a": hex::encode(&a_bytes),
                "b": enc(&proof.b),
                "c": enc(&proof.c),
            },
            "wrong_public_inputs": [enc(&Fr::from(10u64))],
        }
    };

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).expect("cannot create output directory");
        }
    }
    fs::write(&out, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("cannot write fixture");

    println!("curve: bn254 | circuit: x*x = y (witness x=3, public y=9)");
    println!(
        "serialized proof sizes (uncompressed): a = {} bytes, b = {} bytes, c = {} bytes",
        enc(&proof.a).len() / 2,
        enc(&proof.b).len() / 2,
        enc(&proof.c).len() / 2,
    );
    println!("public input y = Fr(9) = 0x{}", enc(&public_y));
    println!("gamma_abc_g1 entries: {}", vk.gamma_abc_g1.len());
    println!("self-check 1 (good proof accepted by arkworks reference): PASS");
    println!("self-check 2 (tampered proof rejected by reference): PASS");
    println!("fixture written to {}", out.display());
}
