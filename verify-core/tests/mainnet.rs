//! Real-data coverage: the same `testdata/fixture.json` the contract tests
//! use, verified through `verify-core` directly. The signatures checked here
//! are real validator signatures over real ledger closes, and
//! `tampered_signature` / `wrong_network_id` fail loudly if verification is
//! ever vacuous.

use base64::Engine as _;
use serde_json::Value;
use stellar_xdr::{LedgerHeader, Limited, Limits, PublicKey, ReadXdr, ScpEnvelope, ScpStatementPledges};
use std::io::Cursor;
use verify_core::{
    decode_journal, encode_journal, verify_span, Crypto, EpochJournal, Error, SpanOutcome,
    SpanProof, Trust,
};

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/fixture.json");

struct TestCrypto;

impl Crypto for TestCrypto {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let d: [u8; 32] = Sha256::digest(bytes).into();
        d
    }
    fn ed25519_verify(&self, signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};
        let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(signature) else {
            return false;
        };
        vk.verify_strict(message, &sig).is_ok()
    }
}

fn fixture() -> Value {
    let raw = std::fs::read_to_string(FIXTURE_PATH)
        .expect("testdata/fixture.json missing — run: cargo run -p xtask -- fetch-fixture");
    serde_json::from_str(&raw).expect("fixture is not valid json")
}

fn b64(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_str().expect("expected base64 string"))
        .expect("invalid base64 in fixture")
}

fn b64_list(value: &Value) -> Vec<Vec<u8>> {
    value.as_array().expect("expected array").iter().map(b64).collect()
}

fn num(value: &Value) -> u32 {
    value.as_u64().expect("expected number") as u32
}

fn decode_xdr<T: ReadXdr>(bytes: &[u8]) -> T {
    T::read_xdr_to_end(&mut Limited::new(Cursor::new(bytes), Limits::none())).unwrap()
}

fn network_id(fixture: &Value) -> [u8; 32] {
    TestCrypto.sha256(fixture["network_passphrase"].as_str().unwrap().as_bytes())
}

/// Trust set for `close` (its distinct signers) and the node ids that
/// externalized `close`'s value in its own slot.
fn trust_and_externalizers(close: &Value) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let header: LedgerHeader = decode_xdr(&b64(&close["header_xdr_b64"]));
    let mut trust: Vec<[u8; 32]> = Vec::new();
    let mut externalizers: Vec<[u8; 32]> = Vec::new();
    for raw in b64_list(&close["scp_envelopes_b64"]) {
        let envelope: ScpEnvelope = decode_xdr(&raw);
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
        if !trust.contains(&key.0) {
            trust.push(key.0);
        }
    }
    for node in b64_list(&close["distinct_signers_b64"]) {
        let node: [u8; 32] = node.as_slice().try_into().expect("32-byte node id");
        if !trust.contains(&node) {
            trust.push(node);
        }
    }
    (trust, externalizers)
}

/// The two-close sparse span: both headers, certificate and tx set only at
/// the tail, plus the tail's claim.
struct Span {
    start_seq: u32,
    start_hash: [u8; 32],
    headers: Vec<Vec<u8>>,
    tail_envelopes: Vec<Vec<u8>>,
    tail_set: Vec<u8>,
    claim_bytes: Vec<u8>,
    claim_index: u32,
    tail_seq: u32,
    tail_hash: [u8; 32],
    trust: Vec<[u8; 32]>,
    threshold: u32,
    network_id: [u8; 32],
}

fn span() -> Span {
    let f = fixture();
    let first = &f["closes"][0];
    let tail = &f["closes"][1];
    let (mut trust, externalizers) = trust_and_externalizers(tail);
    let (mut trust_first, _) = trust_and_externalizers(first);
    trust_first.retain(|n| !trust.contains(n));
    trust.extend(trust_first);
    assert!(!externalizers.is_empty(), "fixture has no externalize statements");
    Span {
        start_seq: num(&first["ledger_seq"]) - 1,
        start_hash: b64(&first["tx_set_previous_ledger_hash_b64"]).try_into().unwrap(),
        headers: vec![b64(&first["header_xdr_b64"]), b64(&tail["header_xdr_b64"])],
        tail_envelopes: b64_list(&tail["scp_envelopes_b64"]),
        tail_set: b64(&tail["tx_set_xdr_b64"]),
        claim_bytes: b64(&tail["tx_envelope_xdr_b64"]),
        claim_index: num(&tail["tx_index"]),
        tail_seq: num(&tail["ledger_seq"]),
        tail_hash: b64(&tail["header_hash_b64"]).try_into().unwrap(),
        trust,
        threshold: externalizers.len() as u32,
        network_id: network_id(&f),
    }
}

fn trust_for(s: &Span, network_id: [u8; 32]) -> Trust {
    Trust {
        network_id,
        trusted_nodes: s.trust.clone(),
        threshold: s.threshold,
        max_protocol_version: u32::MAX,
    }
}

#[test]
fn real_mainnet_sparse_span_verifies() {
    let s = span();
    let headers: Vec<&[u8]> = s.headers.iter().map(|h| h.as_slice()).collect();
    let envelopes: Vec<&[u8]> = s.tail_envelopes.iter().map(|e| e.as_slice()).collect();
    let outcome = verify_span(
        &TestCrypto,
        &trust_for(&s, s.network_id),
        s.start_seq,
        s.start_hash,
        &SpanProof {
            headers: &headers,
            tail_envelopes: &envelopes,
            tail_set: Some(&s.tail_set),
            claims: &[],
        },
    )
    .unwrap();
    assert_eq!(outcome.tail_seq, s.tail_seq);
    assert_eq!(outcome.tail_hash, s.tail_hash);
    assert_eq!(outcome.pinned_seq, Some(s.tail_seq - 1));
    assert_eq!(outcome.quorum_signers, s.threshold);
}

#[test]
fn claim_proven_against_mainnet_set() {
    let s = span();
    let headers: Vec<&[u8]> = s.headers.iter().map(|h| h.as_slice()).collect();
    let envelopes: Vec<&[u8]> = s.tail_envelopes.iter().map(|e| e.as_slice()).collect();
    let claims = &[(&s.claim_bytes[..], s.claim_index)];
    let outcome: SpanOutcome = verify_span(
        &TestCrypto,
        &trust_for(&s, s.network_id),
        s.start_seq,
        s.start_hash,
        &SpanProof {
            headers: &headers,
            tail_envelopes: &envelopes,
            tail_set: Some(&s.tail_set),
            claims,
        },
    )
    .unwrap();
    assert_eq!(outcome.claim_ids, vec![TestCrypto.sha256(&s.claim_bytes)]);
    assert_eq!(outcome.pinned_seq, Some(s.tail_seq - 1));
}

#[test]
fn tampered_mainnet_signature_rejected() {
    let s = span();
    // The signature is the final field of the envelope: flipping one bit of
    // the last byte breaks it without touching the statement.
    let mut envelopes = s.tail_envelopes.clone();
    *envelopes[0].last_mut().unwrap() ^= 0x01;
    let headers: Vec<&[u8]> = s.headers.iter().map(|h| h.as_slice()).collect();
    let envs: Vec<&[u8]> = envelopes.iter().map(|e| e.as_slice()).collect();
    let err = verify_span(
        &TestCrypto,
        &trust_for(&s, s.network_id),
        s.start_seq,
        s.start_hash,
        &SpanProof {
            headers: &headers,
            tail_envelopes: &envs,
            tail_set: Some(&s.tail_set),
            claims: &[],
        },
    )
    .unwrap_err();
    assert_eq!(err, Error::InvalidValidatorSignature { index: 0 });
}

#[test]
fn wrong_network_id_rejected() {
    let s = span();
    let headers: Vec<&[u8]> = s.headers.iter().map(|h| h.as_slice()).collect();
    let envelopes: Vec<&[u8]> = s.tail_envelopes.iter().map(|e| e.as_slice()).collect();
    let err = verify_span(
        &TestCrypto,
        &trust_for(&s, s.network_id.map(|b| !b)),
        s.start_seq,
        s.start_hash,
        &SpanProof {
            headers: &headers,
            tail_envelopes: &envelopes,
            tail_set: Some(&s.tail_set),
            claims: &[],
        },
    )
    .unwrap_err();
    assert_eq!(err, Error::InvalidValidatorSignature { index: 0 });
}

#[test]
fn prefix_fast_path_matches_full_parse_on_mainnet() {
    let s = span();
    let headers: Vec<&[u8]> = s.headers.iter().map(|h| h.as_slice()).collect();
    let envelopes: Vec<&[u8]> = s.tail_envelopes.iter().map(|e| e.as_slice()).collect();
    let trust = trust_for(&s, s.network_id);
    // Fast path (no claims): previousLedgerHash read from the 36-byte prefix.
    let fast = verify_span(
        &TestCrypto,
        &trust,
        s.start_seq,
        s.start_hash,
        &SpanProof {
            headers: &headers,
            tail_envelopes: &envelopes,
            tail_set: Some(&s.tail_set),
            claims: &[],
        },
    )
    .unwrap();
    assert_eq!(fast.pinned_seq, Some(s.tail_seq - 1));
    // Full parse (claims present): must agree on the pin.
    let claims = &[(&s.claim_bytes[..], s.claim_index)];
    let full = verify_span(
        &TestCrypto,
        &trust,
        s.start_seq,
        s.start_hash,
        &SpanProof {
            headers: &headers,
            tail_envelopes: &envelopes,
            tail_set: Some(&s.tail_set),
            claims,
        },
    )
    .unwrap();
    assert_eq!(full.pinned_seq, fast.pinned_seq);
    assert_eq!(full.tail_hash, fast.tail_hash);
    assert_eq!(full.claim_ids, vec![TestCrypto.sha256(&s.claim_bytes)]);
}

#[test]
fn journal_roundtrip_with_mainnet_ids() {
    let s = span();
    let j = EpochJournal {
        start_seq: s.start_seq,
        start_hash: s.start_hash,
        end_seq: s.tail_seq,
        end_hash: s.tail_hash,
        claim_ids: vec![TestCrypto.sha256(&s.claim_bytes)],
    };
    assert_eq!(decode_journal(&encode_journal(&j)).unwrap(), j);
}
