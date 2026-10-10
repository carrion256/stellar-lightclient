//! Contract tests driven by real Stellar mainnet data.
//!
//! `testdata/fixture.json` is produced by `cargo run -p xtask -- fetch-fixture`, which
//! pulls an SCP/ledger/transactions checkpoint from a public history archive and
//! asserts every published hash matches the re-encoded XDR. So the signatures checked
//! here are real validator signatures over real ledger closes.
//!
//! The suite is only meaningful if signature verification is real:
//! `tampered_signature_is_rejected`, `tampered_node_id_is_rejected` and
//! `wrong_network_id_is_rejected` fail loudly if verification is ever vacuous.

use base64::Engine as _;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::testing_env;

use super::*;

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/fixture.json");

fn fixture() -> serde_json::Value {
    let raw = std::fs::read_to_string(FIXTURE_PATH)
        .expect("testdata/fixture.json missing — run: cargo run -p xtask -- fetch-fixture");
    serde_json::from_str(&raw).expect("fixture is not valid json")
}

fn b64(value: &serde_json::Value) -> Base64VecU8 {
    Base64VecU8(
        base64::engine::general_purpose::STANDARD
            .decode(value.as_str().expect("expected base64 string"))
            .expect("invalid base64 in fixture"),
    )
}

fn b64_list(value: &serde_json::Value) -> Vec<Base64VecU8> {
    value.as_array().expect("expected array").iter().map(b64).collect()
}

fn num(value: &serde_json::Value) -> u32 {
    value.as_u64().expect("expected number") as u32
}

const RISCV0_RECEIPT_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/risc0_receipt_fixture.json");

/// Genuine upstream RISC Zero v3.0 Groth16 receipt fixture (source-pinned).
/// The journal is a genuine zkVM journal — but not a Stellar epoch journal.
#[derive(Clone)]
struct ReceiptFixture {
    seal: Vec<u8>,
    journal: Vec<u8>,
    control_root: [u8; 32],
    bn254_control_id: [u8; 32],
    claim_digest: [u8; 32],
}

fn fixture_seal() -> ReceiptFixture {
    let raw = std::fs::read_to_string(RISCV0_RECEIPT_PATH)
        .expect("testdata/risc0_receipt_fixture.json missing");
    let json: serde_json::Value =
        serde_json::from_str(&raw).expect("receipt fixture is not valid json");
    let decode = |name: &str| -> Vec<u8> {
        let hex = json[name].as_str().expect("hex string");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    };
    let digest = |name: &str| -> [u8; 32] {
        decode(name).try_into().expect("fixture digest is 32 bytes")
    };
    ReceiptFixture {
        seal: decode("seal"),
        journal: decode("journal"),
        control_root: digest("control_root"),
        bn254_control_id: digest("bn254_control_id"),
        claim_digest: digest("claim_digest"),
    }
}

/// One-header span at `close`: its own certificate, its own tx set. Carrying
/// a claim needs an authenticated predecessor — use `sparse_span` for claims.
fn span_proof(close: &serde_json::Value, claim_index: Option<u32>) -> SpanProof {
    // Single-header span: no claim (claims need an authenticated predecessor
    // the fixture does not supply for these closes).
    assert!(claim_index.is_none(), "single-header spans cannot carry claims");
    SpanProof {
        start_header: None,
        headers: vec![b64(&close["header_xdr_b64"])],
        tail_envelopes: b64_list(&close["scp_envelopes_b64"]),
        tail_tx_set_xdr: Some(b64(&close["tx_set_xdr_b64"])),
        tx_claims: claims(close, claim_index),
    }
}

fn claims(close: &serde_json::Value, claim_index: Option<u32>) -> Vec<TxClaim> {
    match claim_index {
        Some(index) => vec![TxClaim {
            tx_envelope_xdr: b64(&close["tx_envelope_xdr_b64"]),
            tx_index: index,
        }],
        None => Vec::new(),
    }
}

/// Sparse span: both headers, but only the *tail* carries a certificate and tx set.
fn sparse_span(
    first: &serde_json::Value,
    tail: &serde_json::Value,
    with_tail_set: bool,
    claim_index: Option<u32>,
) -> SpanProof {
    SpanProof {
        // Multi-header spans authenticate their own predecessor (the
        // penultimate header), so no anchor is needed — or allowed to drift.
        start_header: None,
        headers: vec![b64(&first["header_xdr_b64"]), b64(&tail["header_xdr_b64"])],
        tail_envelopes: b64_list(&tail["scp_envelopes_b64"]),
        tail_tx_set_xdr: with_tail_set.then(|| b64(&tail["tx_set_xdr_b64"])),
        tx_claims: claims(tail, claim_index),
    }
}

/// Distinct node ids across the given closes, and how many externalized the tail.
fn trust_set_and_externalizers(tail: &serde_json::Value) -> (Vec<Base64VecU8>, u32) {
    let trust = b64_list(&tail["distinct_signers_b64"]);
    let header: LedgerHeader = decode(b64(&tail["header_xdr_b64"]).0.as_slice(), "fixture header");
    let mut externalizers: Vec<[u8; 32]> = Vec::new();
    for raw in b64_list(&tail["scp_envelopes_b64"]) {
        let envelope: ScpEnvelope = decode(raw.0.as_slice(), "fixture envelope");
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

/// Client whose chain head is the ledger right before `first`, ready to accept it.
fn client_before(
    first: &serde_json::Value,
    network_id: [u8; 32],
    trusted_nodes: Vec<Base64VecU8>,
    threshold: u32,
) -> LightClient {
    client_before_with_wrapper(first, network_id, trusted_nodes, threshold, [0x22u8; 32])
}

/// ...with the wrapper identity under test. The canonical default is pinned by
/// [`client_before`]; noncanonical ids are refused at the configuration
/// boundary, so this argument must stay canonical for happy-path tests.
fn client_before_with_wrapper(
    first: &serde_json::Value,
    network_id: [u8; 32],
    trusted_nodes: Vec<Base64VecU8>,
    threshold: u32,
    bn254_control_id: [u8; 32],
) -> LightClient {
    testing_env!(VMContextBuilder::new().build());
    LightClient::new(
        "lc.near".parse().unwrap(),
        Base64VecU8(network_id.to_vec()),
        trusted_nodes,
        threshold,
        99,
        num(&first["ledger_seq"]) - 1,
        b64(&first["tx_set_previous_ledger_hash_b64"]),
        // Pinned RISC Zero wrapper identity for the tests (canonical, below
        // the BN254 field modulus).
        Base64VecU8(vec![0x11u8; 32]),
        Base64VecU8(bn254_control_id.to_vec()),
        // Epoch guest image under test (arbitrary but fixed).
        Base64VecU8(vec![0xEEu8; 32]),
    )
}


fn network_id(fixture: &serde_json::Value) -> [u8; 32] {
    let digest = env::sha256(fixture["network_passphrase"].as_str().unwrap().as_bytes());
    digest.try_into().expect("sha256 digest is 32 bytes")
}

/// Trust set covering both fixture closes; threshold = every distinct externalizer.
fn fixture_client() -> (LightClient, serde_json::Value) {
    let f = fixture();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    let (mut trust, tail_externalizers) = trust_set_and_externalizers(&tail);
    for node in b64_list(&first["distinct_signers_b64"]) {
        if !trust.contains(&node) {
            trust.push(node);
        }
    }
    assert!(tail_externalizers > 0, "fixture has no externalize statements");
    let client = client_before(&first, network_id(&f), trust, tail_externalizers);
    (client, f)
}

#[test]
fn real_mainnet_span_verifies() {
    let (mut client, f) = fixture_client();
    let close = f["closes"][0].clone();
    let before = env::used_gas().as_gas();
    let head_before = client.get_head();
    let evidence = client.submit_span(span_proof(&close, None));
    let spent_gas = env::used_gas().as_gas() - before;
    let payload_bytes = b64(&close["tx_set_xdr_b64"]).0.len();
    println!(
        "span tail {}: {} quorum signers, tx set ≈{} KiB, host gas {} Tgas",
        evidence.tail_seq,
        evidence.quorum_signers,
        payload_bytes / 1024,
        spent_gas / 1_000_000_000_000,
    );
    assert_eq!(evidence.tail_seq, num(&close["ledger_seq"]));
    // The signed set authenticates through the ledger before the tail — for a
    // single-header span that is the stored checkpoint itself, so the head
    // does NOT advance: the unauthenticated tail is never stored.
    let head = evidence.authenticated_head.expect("tail set authenticates the predecessor");
    assert_eq!(head.ledger_seq, head_before.ledger_seq);
    assert_eq!(head.header_hash, head_before.header_hash);
    assert_eq!(client.get_head().ledger_seq, head_before.ledger_seq);
    assert!(spent_gas < 300_000_000_000_000, "span cost too much gas");
}

#[test]
fn forged_tail_hash_is_never_stored() {
    // Review repro: flip ONLY the tail header's tx_set_result_hash. The
    // certificate, the signed value and the transaction set all still check
    // out — the core accepts the span — but the tail header's own hash (now
    // forged) must never reach contract state.
    let (mut client, f) = fixture_client();
    let close = f["closes"][0].clone();
    let mut span = span_proof(&close, None);
    let mut tail: LedgerHeader = decode(span.headers[0].0.as_slice(), "header");
    tail.tx_set_result_hash.0[0] ^= 0x01;
    span.headers[0] = Base64VecU8(encode(&tail));

    let head_before = client.get_head();
    let evidence = client.submit_span(span);

    // The evidence reports the forged tail…
    assert_eq!(evidence.tail_seq, num(&close["ledger_seq"]));
    // …but state holds only the authenticated predecessor: unchanged.
    let head = evidence.authenticated_head.expect("signed set pins the predecessor");
    assert_eq!(head.ledger_seq, head_before.ledger_seq);
    assert_eq!(head.header_hash, head_before.header_hash);
    assert_eq!(client.get_head().header_hash, head_before.header_hash);
    assert_eq!(client.get_head().ledger_seq, head_before.ledger_seq);

    // And the next honest overlapping span is accepted — the forged submission
    // poisoned nothing the next honest relayer depends on.
    let first = f["closes"][0].clone();
    let tail_close = f["closes"][1].clone();
    client.submit_span(sparse_span(&first, &tail_close, true, None));
    assert_eq!(client.get_head().ledger_seq, num(&first["ledger_seq"]));
}

#[test]
fn sparse_span_verifies_with_one_certificate() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    // Two ledgers, but only the tail's certificate and tx set are transmitted. The
    // first ledger is authenticated transitively: the tail set pins its header hash.
    let evidence = client.submit_span(sparse_span(&first, &tail, true, None));
    assert_eq!(evidence.tail_seq, num(&tail["ledger_seq"]));
    // The stored head is the authenticated predecessor — the *first* header,
    // pinned through the tail's signed set — never the unauthenticated tail.
    let head = evidence.authenticated_head.expect("tail set authenticates the predecessor");
    assert_eq!(head.ledger_seq, num(&first["ledger_seq"]));
    assert_eq!(head.header_hash, b64(&first["header_hash_b64"]));
    assert_eq!(client.get_head().ledger_seq, num(&first["ledger_seq"]));
    assert_eq!(client.get_head().header_hash, b64(&first["header_hash_b64"]));
}


#[test]
fn provisional_spans_are_viewable_but_never_stored() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    let span = sparse_span(&first, &tail, false, None);
    // The view reports provisional spans with no authenticated head: pure
    // tracking stays ~37 KiB per checkpoint on the wire.
    let head = client.get_head();
    let view = client.verify_span_view(head.ledger_seq, head.header_hash, span.clone());
    assert!(view.authenticated_head.is_none(), "no tail set, no authenticated head");

    // But provisional spans can never move the stored head: the tail hash is
    // not authenticated by signed bytes, and storing it would poison the chain.
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_span(span);
    }));
    assert!(rejected.is_err(), "provisional spans must not advance the head");
    assert_eq!(client.get_head().ledger_seq, num(&first["ledger_seq"]) - 1);
}


#[test]
#[should_panic(expected = "claims require the tail transaction set")]
fn claim_without_tx_set_is_rejected() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    client.submit_span(sparse_span(&first, &tail, false, Some(0)));
}

#[test]
fn raw_borsh_entry_point_matches_json() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    let span = sparse_span(&first, &tail, true, Some(num(&tail["tx_index"])));
    let json_evidence = client.submit_span(span.clone());

    let (mut raw_client, _) = fixture_client();
    let raw = SpanProofRaw {
        start_header: None,
        headers: span
            .headers
            .iter()
            .map(|h| h.0.clone())
            .collect(),
        tail_envelopes: span
            .tail_envelopes
            .iter()
            .map(|e| e.0.clone())
            .collect(),
        tail_tx_set: span.tail_tx_set_xdr.as_ref().map(|s| s.0.clone()),
        tx_claims: vec![TxClaimRaw {
            tx_envelope: b64(&tail["tx_envelope_xdr_b64"]).0.clone(),
            tx_index: num(&tail["tx_index"]),
        }],
    };
    // Exactly the bytes a relayer would place in the call input. `start_header`
    // is the first Borsh field, so its Option tag must lead the encoding.
    let mut bytes = Vec::new();
    raw.serialize(&mut bytes).expect("borsh encode");
    assert_eq!(bytes[0], 0, "start_header=None tag must come first");
    let decoded = SpanProofRaw::try_from_slice(&bytes).expect("borsh decode");
    let raw_evidence = raw_client.submit_span_raw(decoded);

    assert_eq!(raw_evidence.tail_seq, json_evidence.tail_seq);
    assert_eq!(raw_evidence.quorum_signers, json_evidence.quorum_signers);
    assert_eq!(raw_evidence.claimed_tx_ids, json_evidence.claimed_tx_ids);
    assert_eq!(
        raw_evidence.authenticated_head.map(|h| h.ledger_seq),
        Some(num(&first["ledger_seq"]))
    );
    // Borsh call bytes for this span versus the JSON form of the same proof.
    let json_bytes = serde_json::to_string(&span).expect("json encode").len();
    println!("raw {} B vs json {json_bytes} B for the same span", bytes.len());
}


#[test]
#[should_panic(expected = "unexpected ledger sequence")]
fn out_of_order_span_is_rejected() {
    let (mut client, f) = fixture_client();
    // The tail cannot be submitted first: the span must start at head + 1.
    client.submit_span(span_proof(&f["closes"][1], None));
}

#[test]
#[should_panic(expected = "header previous ledger hash mismatch")]
fn tampered_intermediate_header_is_rejected() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    let mut span = sparse_span(&first, &tail, true, None);
    // Flip one bit inside the intermediate header's previous-ledger-hash field (bytes
    // 4..36 of the XDR): the header still decodes, so the chain walk must reject it.
    let mut header = span.headers[0].0.clone();
    header[20] ^= 0x01;
    span.headers[0] = Base64VecU8(header);
    client.submit_span(span);
}

#[test]
#[should_panic(expected = "tx set previous ledger hash mismatch")]
fn forged_header_chain_is_rejected_by_signed_set() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    let mut span = sparse_span(&first, &tail, true, None);
    // Forge a *self-consistent* chain: tamper the intermediate header and rewrite the
    // tail's previous-ledger-hash to match, so the chain walk passes. Only the signed
    // transaction set can catch this — its previousLedgerHash is inside signed bytes.
    let mut forged: LedgerHeader = decode(span.headers[0].0.as_slice(), "header");
    forged.tx_set_result_hash.0[0] ^= 0x01;
    let forged_bytes = encode(&forged);
    let forged_hash: [u8; 32] = env::sha256(&forged_bytes)
        .try_into()
        .expect("sha256 digest is 32 bytes");
    let mut tail_header: LedgerHeader = decode(span.headers[1].0.as_slice(), "header");
    tail_header.previous_ledger_hash.0 = forged_hash;
    span.headers = vec![Base64VecU8(forged_bytes), Base64VecU8(encode(&tail_header))];
    client.submit_span(span);
}

#[test]
#[should_panic(expected = "header previous ledger hash mismatch")]
fn wrong_stored_head_is_rejected() {
    let f = fixture();
    let close = f["closes"][0].clone();
    let (trust, externalizers) = trust_set_and_externalizers(&close);
    // Right sequence, wrong stored head: the chain link must reject it.
    let mut client = client_before(&close, network_id(&f), trust, externalizers);
    client.head_hash = [0u8; 32];
    client.submit_span(span_proof(&close, None));
}

#[test]
#[should_panic(expected = "invalid validator signature")]
fn tampered_signature_is_rejected() {
    let (mut client, f) = fixture_client();
    let mut span = span_proof(&f["closes"][0], None);
    // Flip one bit of an envelope's signature; everything else stays valid.
    let mut envelope = span.tail_envelopes[0].0.clone();
    let last = envelope.len() - 1;
    envelope[last] ^= 0x01;
    span.tail_envelopes[0] = Base64VecU8(envelope);
    client.submit_span(span);
}

#[test]
#[should_panic(expected = "invalid validator signature")]
fn tampered_node_id_is_rejected() {
    let (mut client, f) = fixture_client();
    let mut span = span_proof(&f["closes"][0], None);
    // Rebind a statement to a *different trusted* node's key: the signature was made by
    // the original key over the original statement, so verification must fail. A
    // vacuous verifier would accept this — the panic is the evidence the crypto is live.
    let envelopes: Vec<ScpEnvelope> = span
        .tail_envelopes
        .iter()
        .map(|raw| decode(raw.0.as_slice(), "envelope"))
        .collect();
    let externalizers: Vec<usize> = envelopes
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.statement.pledges, ScpStatementPledges::Externalize(_)))
        .map(|(i, _)| i)
        .collect();
    assert!(externalizers.len() > 1, "fixture needs two externalize statements");
    let (i, j) = (externalizers[0], externalizers[1]);
    let mut tampered = envelopes[i].clone();
    tampered.statement.node_id = envelopes[j].statement.node_id.clone();
    span.tail_envelopes[i] = Base64VecU8(encode(&tampered));
    client.submit_span(span);
}

#[test]
#[should_panic(expected = "invalid validator signature")]
fn wrong_network_id_is_rejected() {
    let f = fixture();
    let close = f["closes"][0].clone();
    let (trust, externalizers) = trust_set_and_externalizers(&close);
    // Same trust set and threshold, different network id: signatures must not transfer.
    let mut other = network_id(&f);
    other[0] ^= 0x01;
    let mut client = client_before(&close, other, trust, externalizers);
    client.submit_span(span_proof(&close, None));
}

#[test]
#[should_panic(expected = "quorum threshold not met")]
fn insufficient_quorum_is_rejected() {
    let f = fixture();
    let close = f["closes"][0].clone();
    let (mut trust, externalizers) = trust_set_and_externalizers(&close);
    // A node that exists in the trust set but never signed cannot help reach quorum.
    trust.push(Base64VecU8(vec![0xAAu8; 32]));
    let mut client = client_before(&close, network_id(&f), trust, externalizers + 1);
    client.submit_span(span_proof(&close, None));
}

#[test]
fn claim_is_proven() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    let claim_index = num(&tail["tx_index"]);
    // Claims need an authenticated predecessor: the two-header sparse span
    // carries its own (the first header, pinned by the tail's signed set).
    let tx_id = Base64VecU8(env::sha256(b64(&tail["tx_envelope_xdr_b64"]).0.as_slice()).to_vec());

    let evidence = client.submit_span(sparse_span(&first, &tail, true, Some(claim_index)));
    assert_eq!(evidence.claimed_tx_ids.as_slice(), std::slice::from_ref(&tx_id));
    // And no transaction record is kept: proving is this contract's job,
    // settling is the consuming application's. Storage discipline (payloads are
    // calldata only) is asserted where `state_write` actually runs — the
    // sandbox e2e tests; the native mock never persists it.
}


#[test]
#[should_panic(expected = "not the element at that index")]
fn wrong_claim_index_is_rejected() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    let claimed = num(&tail["tx_index"]);
    assert!(num(&tail["tx_count"]) > 1, "fixture needs at least two transactions");
    // Claim the fixture's transaction at a different index. The sparse span
    // carries the authenticated predecessor the claim needs.
    let wrong = if claimed == 0 { 1 } else { 0 };
    client.submit_span(sparse_span(&first, &tail, true, Some(wrong)));
}

// ------------------------------------------------ group 5: wrapper pinning

#[test]
fn wrapper_info_reports_pinned_identity() {
    let (client, _f) = fixture_client();
    let wrapper = client.get_wrapper();
    assert_eq!(wrapper.control_root.0, vec![0x11u8; 32]);
    assert_eq!(wrapper.bn254_control_id.0, vec![0x22u8; 32]);
    // Compatibility is checkable by anyone, without submitting anything.
    assert!(client.is_wrapper_compatible(Base64VecU8(vec![0x11; 32]), Base64VecU8(vec![0x22; 32])));
    assert!(!client.is_wrapper_compatible(Base64VecU8(vec![0x11; 32]), Base64VecU8(vec![0x23; 32])));
    assert!(!client.is_wrapper_compatible(Base64VecU8(vec![0x12; 32]), Base64VecU8(vec![0x22; 32])));
}

#[test]
#[should_panic(expected = "unsupported RISC Zero wrapper: control_root not pinned")]
fn receipt_with_wrong_control_root_is_rejected() {
    let (client, _f) = fixture_client();
    client.verify_receipt(
        Base64VecU8(vec![0u8; 256]),
        // control_root unpinned: rejected before image/journal are touched.
        Base64VecU8(vec![0x99; 32]),
        Base64VecU8(vec![0x22; 32]),
        Base64VecU8(vec![0u8; 32]),
        Base64VecU8(Vec::new()),
    );
}

#[test]
#[should_panic(expected = "unsupported RISC Zero wrapper: bn254_control_id not pinned")]
fn receipt_with_wrong_wrapper_id_is_rejected() {
    let (client, _f) = fixture_client();
    client.verify_receipt(
        Base64VecU8(vec![0u8; 256]),
        Base64VecU8(vec![0x11; 32]),
        // bn254_control_id unpinned: rejected before image/journal are touched.
        Base64VecU8(vec![0x99; 32]),
        Base64VecU8(vec![0u8; 32]),
        Base64VecU8(Vec::new()),
    );
}

#[test]
fn update_wrapper_is_owner_only() {
    let (mut client, _f) = fixture_client();
    // A non-owner cannot rotate the wrapper identity.
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("mallory.near".parse().unwrap())
            .build()
    );
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // ids stay canonical (below the BN254 field modulus): this test is
        // about authorization, not about the wrapper validity boundary.
        client.update_wrapper(Base64VecU8(vec![0x33; 32]), Base64VecU8(vec![0x12; 32]));
    }));
    assert!(rejected.is_err(), "non-owner must not rotate the wrapper");

    // The owner can, and the public view reflects the new identity.
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("lc.near".parse().unwrap())
            .build()
    );
    client.update_wrapper(Base64VecU8(vec![0x33; 32]), Base64VecU8(vec![0x12; 32]));
    let wrapper = client.get_wrapper();
    assert_eq!(wrapper.control_root.0, vec![0x33; 32]);
    assert_eq!(wrapper.bn254_control_id.0, vec![0x12; 32]);
    assert!(client.is_wrapper_compatible(Base64VecU8(vec![0x33; 32]), Base64VecU8(vec![0x12; 32])));
}


// ---------------------------------------------- group 6: epoch journal binding
//
// `bind_epoch` is the production helper `verify_claim` calls *before* any
// Groth16 work. The tests here drive that helper directly: the positive case
// proves the assertions are satisfiable, and each negative case removes one
// production guard's reason to reject — if a guard is deleted, its negative
// test starts failing. No zero-seal short-circuits: none of these calls ever
// reaches the pairing host functions.

fn policy_digest_for(client: &LightClient) -> [u8; 32] {
    verify_core::trust_digest(&NearCrypto, &client.trust()).expect("fixture trust is valid")
}

/// Journal encoding for the given start/end pair with the client's *current*
/// policy digest, or `None` to keep whatever was encoded.
fn epoch_journal(
    client: &LightClient,
    start_seq: u32,
    start_hash: [u8; 32],
    end_seq: u32,
    end_hash: [u8; 32],
) -> Vec<u8> {
    verify_core::encode_journal(&verify_core::EpochJournal {
        policy_digest: policy_digest_for(client),
        start_seq,
        start_hash,
        end_seq,
        end_hash,
        claim_ids: vec![[0x0cu8; 32], [0x0du8; 32]],
    })
}

/// A client whose head is `(100, [0x0a; 32])`, the epoch start every
/// binding test uses.
fn client_at_epoch_head() -> LightClient {
    let (mut client, _f) = fixture_client();
    client.head_seq = 100;
    client.head_hash = [0x0au8; 32];
    client
}

fn expected_claim_digest(client: &LightClient, journal: &[u8]) -> [u8; 32] {
    verifier::claim::claim_digest(&verifier::claim::ok_claim(client.epoch_image_id, journal))
}

#[test]
fn epoch_binding_accepts_matching_journal_and_digest() {
    let client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);

    let epoch = client
        .bind_epoch(&journal, expected_claim_digest(&client, &journal))
        .expect("matching journal/digest must bind");
    assert_eq!(epoch.end_seq, 528);
    assert_eq!(epoch.end_hash, [0x0bu8; 32]);
    assert_eq!(epoch.claim_ids, vec![[0x0cu8; 32], [0x0du8; 32]]);
}

#[test]
fn epoch_binding_rejects_claim_from_wrong_image() {
    let client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);
    // The receipt proves execution of a *different* guest program: the claim
    // digest binds that program's image ID, not ours. The wrapper verifying key
    // is universal, so this is the only line of defence.
    let foreign_digest =
        verifier::claim::claim_digest(&verifier::claim::ok_claim([0x77u8; 32], &journal));
    assert!(client.bind_epoch(&journal, foreign_digest).is_none());
}

#[test]
fn epoch_binding_rejects_claim_with_failing_exit() {
    let client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);
    // A receipt whose execution did not halt successfully (sys_exit != 0) has
    // a different claim digest — binding only ever matches the canonical
    // *success* claim, so failure claims cannot verify.
    let mut failed = verifier::claim::ok_claim(client.epoch_image_id, &journal);
    failed.sys_exit = 1;
    assert!(client.bind_epoch(&journal, verifier::claim::claim_digest(&failed)).is_none());
}

#[test]
fn epoch_binding_rejects_digest_not_derived_from_journal() {
    let client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);
    let mut wrong = expected_claim_digest(&client, &journal);
    wrong[0] ^= 0x01;
    assert!(client.bind_epoch(&journal, wrong).is_none());
}

#[test]
fn epoch_binding_rejects_journal_from_foreign_policy() {
    let client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);
    // Same checkpoint, valid digest math — but the journal was produced under
    // a different validator set / threshold / protocol ceiling.
    let mut foreign = verify_core::decode_journal(&journal).unwrap();
    foreign.policy_digest = [0x9eu8; 32];
    let foreign_journal = verify_core::encode_journal(&foreign);
    assert!(client
        .bind_epoch(&foreign_journal, expected_claim_digest(&client, &foreign_journal))
        .is_none());
}

#[test]
fn epoch_binding_rejects_stale_start_checkpoint() {
    // Journal claims the epoch started at the *previous* checkpoint; the
    // contract's head has moved on — exactly the replay a bridge must not
    // accept.
    let mut client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);
    client.head_seq = 99;
    assert!(client.bind_epoch(&journal, expected_claim_digest(&client, &journal)).is_none());
    // (And the fresh checkpoint binds — see the positive test above.)
}

#[test]
fn epoch_binding_rejects_incoherent_end() {
    let client = client_at_epoch_head();
    // end_seq before start_seq is nonsense no execution can produce.
    let backward = epoch_journal(&client, 100, [0x0au8; 32], 99, [0x0bu8; 32]);
    assert!(client.bind_epoch(&backward, expected_claim_digest(&client, &backward)).is_none());
    // An epoch that stays put must still agree with itself.
    let renamed = epoch_journal(&client, 100, [0x0au8; 32], 100, [0x0bu8; 32]);
    assert!(client.bind_epoch(&renamed, expected_claim_digest(&client, &renamed)).is_none());
    // Same seq *and* same hash does bind (claims can be proven in one epoch).
    let still = epoch_journal(&client, 100, [0x0au8; 32], 100, [0x0au8; 32]);
    assert!(client.bind_epoch(&still, expected_claim_digest(&client, &still)).is_some());
}

#[test]
fn epoch_binding_rejects_malformed_journal_bytes() {
    let client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);
    // Truncated journal: canonical decode fails, binding fails closed.
    assert!(client.bind_epoch(&journal[..journal.len() - 1], expected_claim_digest(&client, &journal)).is_none());
    // The upstream (genuine, non-Stellar) fixture journal is not a valid
    // EpochJournal encoding at all.
    let upstream = fixture_seal().journal;
    assert!(client.bind_epoch(&upstream, [0u8; 32]).is_none());
}

// ------------------------------------ group 7: wrapper pinning at the boundary

/// A pinned `bn254_control_id` that is not a canonical BN254 scalar can never
/// verify a Groth16 receipt — refuse it at the configuration boundary.
#[test]
#[should_panic(expected = "bn254_control_id is not a canonical BN254 scalar")]
fn init_rejects_noncanonical_wrapper_id() {
    let f = fixture();
    let close = f["closes"][0].clone();
    let (trust, externalizers) = trust_set_and_externalizers(&close);
    client_before_with_wrapper(&close, network_id(&f), trust, externalizers, [0xFFu8; 32]);
}

#[test]
#[should_panic(expected = "bn254_control_id is not a canonical BN254 scalar")]
fn update_wrapper_rejects_noncanonical_id() {
    let (mut client, _f) = fixture_client();
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("lc.near".parse().unwrap())
            .build()
    );
    client.update_wrapper(Base64VecU8(vec![0x11; 32]), Base64VecU8(vec![0xFF; 32]));
}

// ------------------------------------------- group 8: verify_claim integration

#[test]
#[should_panic(expected = "unsupported RISC Zero wrapper: control_root not pinned")]
fn verify_claim_with_wrong_control_root_is_rejected() {
    let (client, _f) = fixture_client();
    client.verify_claim(
        Base64VecU8(vec![0u8; 256]),
        Base64VecU8(vec![0x99; 32]),
        Base64VecU8(vec![0u8; 32]),
        Base64VecU8(vec![0x22; 32]),
        Base64VecU8(Vec::new()),
    );
}

#[test]
#[should_panic(expected = "unsupported RISC Zero wrapper: bn254_control_id not pinned")]
fn verify_claim_with_wrong_wrapper_id_is_rejected() {
    let (client, _f) = fixture_client();
    client.verify_claim(
        Base64VecU8(vec![0u8; 256]),
        Base64VecU8(vec![0x11; 32]),
        Base64VecU8(vec![0u8; 32]),
        Base64VecU8(vec![0x99; 32]),
        Base64VecU8(Vec::new()),
    );
}

#[test]
fn verify_claim_reports_bad_proof_with_zeroed_epoch_fields() {
    // Journal, policy, checkpoint and claim digest all bind; only the Groth16
    // proof is garbage. The evidence is reported `verified: false` with zeroed
    // epoch fields — invalid evidence exposes nothing.
    let client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);
    let digest = expected_claim_digest(&client, &journal);

    let logs_before = get_logs().len();
    let evidence = client.verify_claim(
        Base64VecU8(vec![0u8; 256]),
        Base64VecU8(vec![0x11; 32]),
        Base64VecU8(digest.to_vec()),
        Base64VecU8(vec![0x22; 32]),
        Base64VecU8(journal),
    );
    assert!(!evidence.verified, "zero seal is not a valid Groth16 proof");
    assert_eq!(evidence.claim_digest.0, digest.to_vec());
    assert_eq!(evidence.end_seq, 0);
    assert!(evidence.end_hash.0.is_empty());
    assert!(evidence.claim_ids.is_empty());
    // A Groth16 failure must not masquerade as a binding failure.
    let new_logs = &get_logs()[logs_before..];
    assert!(
        !new_logs.iter().any(|l| l.contains("claim not bound")),
        "bad proof must not log a binding mismatch: {new_logs:?}"
    );
}

#[test]
fn verify_claim_rejects_wrong_image_claim() {
    // A receipt from a foreign guest program is unverified even though its
    // journal and checkpoint would otherwise bind.
    let client = client_at_epoch_head();
    let journal = epoch_journal(&client, 100, [0x0au8; 32], 528, [0x0bu8; 32]);
    let foreign_digest =
        verifier::claim::claim_digest(&verifier::claim::ok_claim([0x77u8; 32], &journal));

    let logs_before = get_logs().len();
    let evidence = client.verify_claim(
        Base64VecU8(vec![0u8; 256]),
        Base64VecU8(vec![0x11; 32]),
        Base64VecU8(foreign_digest.to_vec()),
        Base64VecU8(vec![0x22; 32]),
        Base64VecU8(journal),
    );
    assert!(!evidence.verified, "foreign image claims must not verify");
    assert!(evidence.claim_ids.is_empty(), "unverified evidence exposes no epoch fields");
    // The refusal says so: binding failure is distinguishable from a bad proof.
    let new_logs = &get_logs()[logs_before..];
    assert!(
        new_logs.iter().any(|l| l.contains("claim not bound: image, policy, or checkpoint mismatch")),
        "binding failure must be logged, got: {new_logs:?}"
    );
}

#[test]
fn verify_claim_rejects_genuine_non_epoch_receipt() {
    // The genuine upstream RISC Zero v3.0 seal: a valid zkVM execution, but
    // of a foreign guest with a non-Stellar journal. Binding refuses it —
    // valid raw evidence is not an epoch claim.
    let fixture = fixture_seal();
    let mut client = client_at_epoch_head();
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("lc.near".parse().unwrap())
            .build()
    );
    client.update_wrapper(
        Base64VecU8(fixture.control_root.to_vec()),
        Base64VecU8(fixture.bn254_control_id.to_vec()),
    );

    let logs_before = get_logs().len();
    let evidence = client.verify_claim(
        Base64VecU8(fixture.seal),
        Base64VecU8(fixture.control_root.to_vec()),
        Base64VecU8(fixture.claim_digest.to_vec()),
        Base64VecU8(fixture.bn254_control_id.to_vec()),
        Base64VecU8(fixture.journal),
    );
    assert!(!evidence.verified, "generic zkVM execution is not an epoch claim");
    assert_eq!(evidence.end_seq, 0, "unverified evidence exposes no epoch fields");
    assert!(evidence.claim_ids.is_empty());
    let new_logs = &get_logs()[logs_before..];
    assert!(
        new_logs.iter().any(|l| l.contains("claim not bound: image, policy, or checkpoint mismatch")),
        "non-epoch journal must be refused at binding, got: {new_logs:?}"
    );
}

// ---------------------------------------- group 9: epoch image configuration

#[test]
fn epoch_image_roundtrips_and_rotates() {
    let (mut client, _f) = fixture_client();
    assert_eq!(client.get_epoch_image().0, vec![0xEEu8; 32]);

    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("lc.near".parse().unwrap())
            .build()
    );
    client.update_epoch_image_id(Base64VecU8(vec![0x77; 32]));
    assert_eq!(client.get_epoch_image().0, vec![0x77u8; 32]);
}

#[test]
#[should_panic(expected = "owner only")]
fn epoch_image_update_is_owner_only() {
    let (mut client, _f) = fixture_client();
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("mallory.near".parse().unwrap())
            .build()
    );
    client.update_epoch_image_id(Base64VecU8(vec![0x77; 32]));
}

#[test]
fn max_protocol_version_is_owner_only_and_viewed() {
    let (mut client, _f) = fixture_client();
    assert_eq!(client.get_trust().max_protocol_version, 99);

    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("mallory.near".parse().unwrap())
            .build()
    );
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.update_max_protocol_version(21);
    }));
    assert!(rejected.is_err(), "non-owner must not change the protocol ceiling");
    assert_eq!(client.get_trust().max_protocol_version, 99);

    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("lc.near".parse().unwrap())
            .build()
    );
    client.update_max_protocol_version(21);
    assert_eq!(client.get_trust().max_protocol_version, 21);
}

#[test]
#[should_panic(expected = "invalid trust")]
fn init_rejects_duplicate_trusted_node() {
    let f = fixture();
    let close = f["closes"][0].clone();
    let (mut trust, externalizers) = trust_set_and_externalizers(&close);
    let duplicate = trust[0].clone();
    trust.push(duplicate);
    // threshold still fits the (padded) list length — only the duplicate check
    // catches this, and verify_core's quorum could never satisfy it anyway.
    client_before_with_wrapper(&close, network_id(&f), trust, externalizers + 1, [0x22u8; 32]);
}

#[test]
#[should_panic(expected = "invalid trust")]
fn update_trust_rejects_duplicate_node() {
    let (mut client, _f) = fixture_client();
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id("lc.near".parse().unwrap())
            .build()
    );
    let mut trust = client
        .trusted_nodes
        .iter()
        .map(|n| Base64VecU8(n.to_vec()))
        .collect::<Vec<_>>();
    let duplicate = trust[0].clone();
    trust.push(duplicate);
    client.update_trust(trust, client.threshold);
}
