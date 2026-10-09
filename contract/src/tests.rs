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
use near_sdk::test_utils::VMContextBuilder;
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

/// One-header span at `close`: its own certificate, its own tx set, optional claim.
fn span_proof(close: &serde_json::Value, claim_index: Option<u32>) -> SpanProof {
    SpanProof {
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
    testing_env!(VMContextBuilder::new().build());
    LightClient::new(
        "lc.near".parse().unwrap(),
        Base64VecU8(network_id.to_vec()),
        trusted_nodes,
        threshold,
        99,
        num(&first["ledger_seq"]) - 1,
        b64(&first["tx_set_previous_ledger_hash_b64"]),
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
    assert_eq!(client.get_head().ledger_seq, evidence.tail_seq);
    // The tail's tx set pins the chain through the ledger before the tail.
    assert_eq!(evidence.pinned_seq, Some(num(&close["ledger_seq"]) - 1));
    assert!(spent_gas < 300_000_000_000_000, "span cost too much gas");
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
    assert_eq!(evidence.pinned_seq, Some(num(&first["ledger_seq"])));
    assert_eq!(client.get_head().ledger_seq, evidence.tail_seq);
}

#[test]
fn span_without_tail_set_is_provisional() {
    let (mut client, f) = fixture_client();
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    // No tx set: nothing pins the chain yet, so `pinned_seq` must stay empty while the
    // head still advances. This is what makes pure tracking ~37 KiB per checkpoint.
    let evidence = client.submit_span(sparse_span(&first, &tail, false, None));
    assert_eq!(evidence.pinned_seq, None);
    assert_eq!(client.get_head().ledger_seq, num(&tail["ledger_seq"]));
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
    let close = f["closes"][0].clone();
    let json_evidence = client.submit_span(span_proof(&close, Some(num(&close["tx_index"]))));

    let (mut raw_client, _) = fixture_client();
    let raw = SpanProofRaw {
        headers: vec![b64(&close["header_xdr_b64"]).0.clone()],
        tail_envelopes: b64_list(&close["scp_envelopes_b64"])
            .into_iter()
            .map(|e| e.0)
            .collect(),
        tail_tx_set: Some(b64(&close["tx_set_xdr_b64"]).0.clone()),
        tx_claims: vec![TxClaimRaw {
            tx_envelope: b64(&close["tx_envelope_xdr_b64"]).0.clone(),
            tx_index: num(&close["tx_index"]),
        }],
    };
    // Exactly the bytes a relayer would place in the call input.
    let mut bytes = Vec::new();
    raw.serialize(&mut bytes).expect("borsh encode");
    let decoded = SpanProofRaw::try_from_slice(&bytes).expect("borsh decode");
    let raw_evidence = raw_client.submit_span_raw(decoded);

    assert_eq!(raw_evidence.tail_seq, json_evidence.tail_seq);
    assert_eq!(raw_evidence.pinned_seq, json_evidence.pinned_seq);
    assert_eq!(raw_evidence.quorum_signers, json_evidence.quorum_signers);
    assert_eq!(raw_evidence.claimed_tx_ids, json_evidence.claimed_tx_ids);
    // Borsh call bytes for this span versus the JSON form of the same proof.
    let json_bytes = serde_json::to_string(&span_proof(&close, Some(num(&close["tx_index"]))))
        .expect("json encode")
        .len();
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
fn claim_is_proven_and_payloads_are_not_stored() {
    let (mut client, f) = fixture_client();
    let close = f["closes"][0].clone();
    let claim_index = num(&close["tx_index"]);
    let tx_id = Base64VecU8(env::sha256(b64(&close["tx_envelope_xdr_b64"]).0.as_slice()).to_vec());

    let before = env::storage_usage();
    let evidence = client.submit_span(span_proof(&close, Some(claim_index)));
    let after = env::storage_usage();

    assert_eq!(evidence.claimed_tx_ids.as_slice(), std::slice::from_ref(&tx_id));
    // The span payload (headers + envelopes + tx set, hundreds of KiB) must not land in
    // state: only the chain head is written.
    let delta = u64::from(after - before);
    assert!(delta < 256, "state grew by {delta} bytes — payloads are being stored");
    // And no settlement record is kept: proving is this contract's job, settling is the
    // consuming application's.
    println!("state growth for one span: {delta} bytes");
}

#[test]
#[should_panic(expected = "not the element at that index")]
fn wrong_claim_index_is_rejected() {
    let (mut client, f) = fixture_client();
    let close = f["closes"][0].clone();
    let claimed = num(&close["tx_index"]);
    assert!(num(&close["tx_count"]) > 1, "fixture needs at least two transactions");
    // Claim the fixture's transaction at a different index.
    let wrong = if claimed == 0 { 1 } else { 0 };
    client.submit_span(span_proof(&close, Some(wrong)));
}
