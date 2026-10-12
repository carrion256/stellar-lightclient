//! Real-fixture epoch tests: two consecutive mainnet closes, chained with an
//! anchored transaction-envelope inclusion claim. No transaction execution or
//! deposit settlement is implied by an inclusion ID.

use std::io::Cursor;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;
use stellar_xdr::{
    LedgerHeader, Limited, Limits, PublicKey, ReadXdr, ScpEnvelope, ScpStatementPledges,
    TransactionResultSet, WriteXdr,
};
use verify_core::{trust_digest, tx_contents_hash, validate_trust, Crypto, Error, Trust};

use guest::{run_epoch, EpochInput, Sha256Dalek, SpanInput};
use verify_core::{decode_journal, encode_journal};

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../testdata/fixture.json");

fn fixture() -> Value {
    let raw = std::fs::read_to_string(FIXTURE_PATH)
        .expect("testdata/fixture.json missing — run: cargo run -p xtask -- fetch-fixture");
    serde_json::from_str(&raw).expect("fixture is not valid json")
}

fn b64(value: &Value) -> Vec<u8> {
    STANDARD
        .decode(value.as_str().expect("expected base64 string"))
        .expect("invalid base64 in fixture")
}

fn b64_32(value: &Value) -> [u8; 32] {
    b64(value).try_into().expect("expected 32 bytes")
}

fn b64_list(value: &Value) -> Vec<Vec<u8>> {
    value
        .as_array()
        .expect("expected array")
        .iter()
        .map(b64)
        .collect()
}

fn decode<T: ReadXdr>(bytes: &[u8]) -> T {
    let mut reader = Limited::new(Cursor::new(bytes), Limits::none());
    T::read_xdr_to_end(&mut reader).expect("invalid xdr in fixture")
}

/// Threshold computation mirrors `contract/src/tests.rs::trust_set_and_externalizers`:
/// distinct node ids whose envelopes externalize the tail's slot.
fn trust_set_and_externalizers(tail: &Value) -> (Vec<[u8; 32]>, u32) {
    let trust: Vec<[u8; 32]> = b64_list(&tail["distinct_signers_b64"])
        .into_iter()
        .map(|node| node.try_into().expect("32-byte node id"))
        .collect();
    let header: LedgerHeader = decode(&b64(&tail["header_xdr_b64"]));
    let mut externalizers: Vec<[u8; 32]> = Vec::new();
    for raw in b64_list(&tail["scp_envelopes_b64"]) {
        let envelope: ScpEnvelope = decode(&raw);
        if envelope.statement.slot_index != u64::from(header.ledger_seq) {
            continue;
        }
        let ScpStatementPledges::Externalize(_) = envelope.statement.pledges else {
            continue;
        };
        let PublicKey::PublicKeyTypeEd25519(key) = &envelope.statement.node_id.0;
        if !externalizers.contains(&key.0) {
            externalizers.push(key.0);
        }
    }
    (trust, externalizers.len() as u32)
}

fn network_id(fixture: &Value) -> [u8; 32] {
    Sha256Dalek.sha256(fixture["network_passphrase"].as_str().unwrap().as_bytes())
}

/// The two-closes-per-epoch shape. Span 0 = close[0], span 1 = close[1], and
/// `run_epoch` chains span 1 off span 0's outcome.
fn epoch_input(fixture: &Value) -> EpochInput {
    let closes = fixture["closes"].as_array().unwrap();
    assert_eq!(closes.len(), 2, "fixture must carry two closes for the epoch test");
    let first = &closes[0];
    let tail = &closes[1];

    let (trusted_nodes, threshold) = trust_set_and_externalizers(tail);
    let trust = Trust {
        network_id: network_id(fixture),
        trusted_nodes,
        threshold,
        max_protocol_version: 99,
    };

    // Claims need authenticated predecessor context: span 0 has no header for
    // its start ledger in the fixture, so it carries none; span 1's predecessor
    // is literally the first close and is supplied as the anchor.
    let spans = closes
        .iter()
        .enumerate()
        .map(|(index, close)| SpanInput {
            start_header: if index == 0 {
                None
            } else {
                Some(b64(&closes[index - 1]["header_xdr_b64"]))
            },
            headers: vec![b64(&close["header_xdr_b64"])],
            tail_envelopes: b64_list(&close["scp_envelopes_b64"]),
            tail_set: Some(b64(&close["tx_set_xdr_b64"])),
            claims: if index == 0 {
                vec![]
            } else {
                vec![(
                    b64(&close["tx_envelope_xdr_b64"]),
                    close["tx_index"].as_u64().unwrap() as u32,
                )]
            },
            outcome_claims: vec![],
            tail_results: None,
        })
        .collect();

    EpochInput {
        trust,
        start_seq: first["ledger_seq"].as_u64().unwrap() as u32 - 1,
        start_hash: b64_32(&first["tx_set_previous_ledger_hash_b64"]),
        spans,
    }
}

#[test]
fn real_mainnet_epoch_verifies_and_chains() {
    let fixture = fixture();
    let closes = fixture["closes"].as_array().unwrap();
    let input = epoch_input(&fixture);

    let journal = run_epoch(&input).expect("real mainnet epoch must verify");

    assert_eq!(journal.start_seq, closes[0]["ledger_seq"].as_u64().unwrap() as u32 - 1);
    // The journal commits the latest *authenticated* checkpoint: both spans
    // pinned through their predecessor, i.e. the first close — never the
    // unauthenticated tail (the second close).
    assert_eq!(journal.end_seq, closes[0]["ledger_seq"].as_u64().unwrap() as u32);
    assert_eq!(journal.start_hash, b64_32(&closes[0]["tx_set_previous_ledger_hash_b64"]));
    assert_eq!(journal.end_hash, b64_32(&closes[0]["header_hash_b64"]));

    let expected_claims: Vec<[u8; 32]> = vec![Sha256Dalek.sha256(
        &b64(&closes[1]["tx_envelope_xdr_b64"]),
    )];
    assert_eq!(journal.claim_ids, expected_claims, "one claim id per anchored span");
    assert_eq!(journal.claim_ids.len(), 1);
    assert_eq!(journal.policy_digest, trust_digest(&Sha256Dalek, &input.trust).unwrap());

    let bytes = encode_journal(&journal);
    let decoded = decode_journal(&bytes).expect("journal round-trip");
    assert_eq!(decoded, journal);
}

#[test]
fn tampered_signature_fails() {
    let fixture = fixture();
    let mut input = epoch_input(&fixture);

    // Corrupt the signature on the first certificate (signature is the trailing
    // 64 bytes of the envelope XDR); decoding still succeeds, verification fails.
    let sig = &mut input.spans[0].tail_envelopes[0];
    let last = sig.len() - 1;
    sig[last] ^= 0xff;

    assert!(run_epoch(&input).is_err(), "tampered certificate must not verify");
}

#[test]
fn claim_at_wrong_index_fails() {
    let fixture = fixture();
    let mut input = epoch_input(&fixture);
    // Claim the anchored envelope at a slot it does not occupy.
    input.spans[1].claims[0].1 += 1;

    assert!(run_epoch(&input).is_err(), "claim at a wrong index must fail");
}

#[test]
fn second_span_broken_chain_link_fails() {
    let fixture = fixture();
    let mut input = epoch_input(&fixture);

    // LedgerHeader XDR layout: u32 ledgerVersion then previousLedgerHash, so
    // the previous-hash occupies bytes 4..36. Tampering it breaks span 1's
    // chain to span 0's tail without changing the signature itself.
    input.spans[1].headers[0][4] ^= 0xff;

    assert!(run_epoch(&input).is_err(), "broken chain link must fail");
}

#[test]
fn single_header_claim_without_anchor_fails() {
    let fixture = fixture();
    let mut input = epoch_input(&fixture);

    // The fixture carries no header for span 0's start ledger; claiming
    // against it anyway must fail closed on the missing predecessor.
    let first = &fixture["closes"][0];
    input.spans[0].claims = vec![(
        b64(&first["tx_envelope_xdr_b64"]),
        first["tx_index"].as_u64().unwrap() as u32,
    )];

    let err = run_epoch(&input).err().expect("unanchored single-header claim must fail");
    assert_eq!(err, Error::ClaimsRequirePredecessor);
}

#[test]
fn empty_epoch_validates_trust_and_commits_the_start_checkpoint() {
    let fixture = fixture();
    let mut input = epoch_input(&fixture);
    input.spans = vec![];

    let journal = run_epoch(&input).expect("empty epoch with valid trust is valid");
    assert_eq!(journal.start_seq, input.start_seq);
    assert_eq!(journal.end_seq, input.start_seq);
    assert_eq!(journal.end_hash, input.start_hash);
    assert!(journal.claim_ids.is_empty());
    assert_eq!(journal.policy_digest, trust_digest(&Sha256Dalek, &input.trust).unwrap());

    // Zero-span epochs validate trust too: an attacker-supplied threshold 0
    // is rejected before any journal is committed.
    let mut zero = input.clone();
    zero.trust.threshold = 0;
    let err = run_epoch(&zero).err().expect("invalid trust must fail closed");
    assert_eq!(err, Error::InvalidTrust("threshold outside trusted node count"));

    let mut dup = input.clone();
    dup.trust.trusted_nodes.push(dup.trust.trusted_nodes[0]);
    assert_eq!(run_epoch(&dup).err(), Some(Error::InvalidTrust("duplicate trusted node")));
    assert!(validate_trust(&input.trust).is_ok());
}

#[test]
fn attacker_trust_produces_a_different_policy_digest() {
    let fixture = fixture();
    let input = epoch_input(&fixture);
    let ours = trust_digest(&Sha256Dalek, &input.trust).unwrap();

    // Same shape, attacker keys: the policy digest must diverge so the
    // contract can pin its own configuration against the journal.
    let attacker = Trust {
        network_id: input.trust.network_id,
        trusted_nodes: vec![[9u8; 32]; 1],
        threshold: 1,
        max_protocol_version: input.trust.max_protocol_version,
    };
    assert!(validate_trust(&attacker).is_ok(), "attacker policy is well-formed");
    let theirs = trust_digest(&Sha256Dalek, &attacker).unwrap();
    assert_ne!(ours, theirs);

    // Order of nodes does not change the digest; it binds the *set*.
    let mut shuffled = input.trust.clone();
    shuffled.trusted_nodes.reverse();
    assert_eq!(trust_digest(&Sha256Dalek, &shuffled).unwrap(), ours);
}

#[test]
fn encoded_epoch_input_is_bounded_and_rejects_trailing_bytes() {
    let fixture = fixture();
    let input = epoch_input(&fixture);
    let bytes = bincode::serialize(&input).unwrap();
    let journal = decode_journal(&guest::run_epoch_bytes(&bytes).unwrap()).unwrap();
    assert_eq!(journal.end_hash, b64_32(&fixture["closes"][0]["header_hash_b64"]));
    assert_eq!(journal.claim_ids, vec![Sha256Dalek.sha256(
        &b64(&fixture["closes"][1]["tx_envelope_xdr_b64"]),
    )]);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(guest::run_epoch_bytes(&trailing).is_err());
    assert!(guest::run_epoch_bytes(&bytes[..bytes.len() - 1]).is_err());

    // Fixed-int bincode: the trust's node count follows its 32-byte network ID.
    let mut oversized = bytes;
    oversized[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(guest::run_epoch_bytes(&oversized).is_err());
}

/// Execute the built guest ELF in the zkVM and report the cycle breakdown, and
/// assert the accelerated and fallback paths compute the same journal.
///
/// Requires the ELF at `target/riscv32im-risc0-zkvm-elf/release/guest`; build it
/// first with the rustup/risc0 toolchain command in AGENTS.md. `#[ignore]`d so
/// the default suite does not depend on that artifact. Needs `r0vm` on PATH —
/// `nix shell nixpkgs#cargo-risczero` provides it; the `risc0` rustup toolchain
/// does not.
///
/// # Measured baseline
///
/// Real fixture epoch (2 spans, 30 envelopes at threshold 30, 319 KB set):
///
/// ```text
/// 2 spans, 1 claim     73,097,352 cycles  (~80 segments)
/// 2 spans, no claims   60,730,164
/// 1 span,  no claim    30,589,574
///   -> parse_tx_set    12,367,188   16.9% of total, 29% of the span carrying it
/// ```
///
/// `parse_tx_set` is a **per-span constant**: it decodes every transaction in
/// the set to serve any claim, so ~12.4M is paid whether there is one claim or
/// many. Its share therefore moves with claim density, and the benefit of a
/// cheaper parse is per span, not per claim.
///
/// What that 16.9% is *not*: it is not "the largest unaccelerated term". The
/// 60.7M with no claims contains generic rv32im work too — bincode
/// deserialisation of an `EpochInput` carrying both sets and all 30 envelopes,
/// plus the XDR decode of those envelopes and headers per span. None of that is
/// attributed yet, and if the input decode turns out to dominate, the lever is
/// the input format rather than a parsing walk. The one-span figure bounds the
/// one-off input cost at well under 1M cycles, which argues against that — but
/// it is an inference from two numbers, not a direct measurement.
///
/// Also measured: whether the precompile swap does anything at all. Same ELF
/// build procedure, same input, twice — once with RISC Zero's accelerated
/// `sha2`/`ed25519-dalek` forks, once with the crates.io originals:
///
/// ```text
///                          accelerated    crates.io    ratio
/// 2 spans, 1 claim          73,097,352   246,278,025   3.37x
/// 2 spans, no claims        60,730,164   233,851,843   3.85x
/// parse_tx_set              12,367,188    12,426,182   ~unchanged
/// ```
///
/// `parse_tx_set` is not crypto and must not move between the two builds — its
/// staying within 0.5% is the control that says the comparison is
/// apples-to-apples. The 3.4-3.9x on the epoch as a whole is the evidence for
/// the `perf(guest)` commit.
///
/// What that also says: the accelerated build still spends ~30M cycles per span
/// on work that is not `parse_tx_set`, and only part of it is crypto. Splitting
/// that remainder is the next question — not whether the precompiles work,
/// which they do.
#[test]
#[ignore]
fn zkvm_cycle_breakdown() {
    use risc0_binfmt::ProgramBinary;
    use risc0_zkos_v1compat::V1COMPAT_ELF;
    use risc0_zkvm::{default_executor, ExecutorEnv};

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf_path = root.join("target/riscv32im-risc0-zkvm-elf/release/guest");
    let user_elf = std::fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("build the guest ELF first ({elf_path:?}): {e}"));

    // RISC Zero 3 requires the user ELF to be packaged with the V1COMPAT
    // kernel before execution — `execute` takes the encoded `ProgramBinary`,
    // not the bare ELF.
    let encoded = ProgramBinary::new(&user_elf, V1COMPAT_ELF).encode();

    // Two runs of the identical program: the full epoch, and the same epoch with
    // every inclusion claim removed. Claims are what force `parse_tx_set` —
    // without them `verify_span` only peeks at the set header — so the delta is
    // that parse's cycle cost. In the guest there is no precompile for XDR, so
    // this is the unaccelerated term that the ed25519/sha256 swaps leave behind.
    let run = |input: &guest::EpochInput| -> u64 {
        let payload = bincode::serialize(input).unwrap();
        let env = ExecutorEnv::builder()
            .write(&payload.len())
            .unwrap()
            .write_slice(&payload)
            .build()
            .unwrap();
        let session = default_executor().execute(env, &encoded).unwrap();
        // The swap to RISC Zero's precompile forks must not change what the
        // guest computes. `run_epoch_bytes` uses the same code natively, where
        // those crates fall back to the generic implementations, so identical
        // journals are the proof that the accelerated and fallback paths agree
        // — in the environment that actually gets proven, which is the one the
        // native suite cannot see.
        let native = guest::run_epoch_bytes(&payload).expect("native run");
        assert_eq!(
            native, session.journal.bytes,
            "zkVM and native journals must be byte-identical"
        );
        session.segments.iter().map(|s| s.cycles as u64).sum()
    };

    let full = epoch_input(&fixture());
    let mut no_claims = epoch_input(&fixture());
    for span in &mut no_claims.spans {
        span.claims.clear();
    }
    // One span instead of two separates the per-span cost (signatures, set
    // hash, tx-set parse) from what is paid once — chiefly bincode
    // deserialisation of the input, which itself grows with the input, so the
    // split is approximate rather than exact.
    let mut one_span = epoch_input(&fixture());
    one_span.spans.truncate(1);

    let with_claims = run(&full);
    let without = run(&no_claims);
    let single = run(&one_span);
    // Fixture asymmetry to keep in mind: span 0 carries no inclusion claim and
    // span 1 carries one, so "1 span" and "marginal 2nd span" are not like for
    // like. What is comparable:
    //   span 1 with claims    = with_claims - single
    //   span 1 without claims = without - single
    // and their difference is the parse, which is also what
    // with_claims - without measures directly.
    eprintln!(
        "zkvm cycles (80 segments for the full epoch):\n  2 spans, 1 claim:     {with_claims}\n  2 spans, no claims:   {without}\n  1 span,  (no claim):  {single}\n  -> parse_tx_set:      {} ({:.1}% of total; {:.0}% of the span carrying the claim)\n  -> second span cost:  {} (incl. its parse)\n  -> input + first span: {single}",
        with_claims.saturating_sub(without),
        100.0 * (with_claims.saturating_sub(without)) as f64 / with_claims as f64,
        100.0 * (with_claims.saturating_sub(without)) as f64
            / (with_claims.saturating_sub(single)) as f64,
        with_claims.saturating_sub(single)
    );
}

#[test]
fn outcome_claims_land_in_the_journal() {
    let fixture = fixture();
    let mut input = epoch_input(&fixture);
    let closes = fixture["closes"].as_array().unwrap();
    let first = &closes[0];

    // Span 1's authenticated head is close[0], supplied there as `start_header`,
    // so the result set that may commit outcomes is close[0]'s.
    let results = b64(&first["results_xdr_b64"]);
    let envelope = b64(&first["tx_envelope_xdr_b64"]);
    let want = tx_contents_hash(&Sha256Dalek, network_id(&fixture), &envelope).unwrap();
    let set: TransactionResultSet = decode(&results);
    let pair = set
        .results
        .iter()
        .find(|r| r.transaction_hash.0 == want)
        .expect("head result set has the highlighted row");
    let mut pair_bytes = Vec::new();
    pair.write_xdr(&mut Limited::new(&mut pair_bytes, Limits::none())).unwrap();

    input.spans[1].outcome_claims = vec![(envelope, pair_bytes.clone())];
    input.spans[1].tail_results = Some(results);

    let journal = run_epoch(&input).expect("epoch with an outcome claim verifies");
    assert_eq!(journal.outcome_digests, vec![Sha256Dalek.sha256(&pair_bytes)]);
    // A result row implies inclusion, so no extra claim id is manufactured.
    assert_eq!(journal.claim_ids.len(), input.spans[1].claims.len());
}
