//! Real-fixture epoch tests: two consecutive mainnet closes, each verified as
//! one span, chained, with a deposit claim each. The negative tests pin the
//! three failure classes the contract must never accept.

use std::io::Cursor;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;
use stellar_xdr::{LedgerHeader, Limited, Limits, PublicKey, ReadXdr, ScpEnvelope, ScpStatementPledges};
use verify_core::{Crypto, Trust};

use guest::{run_epoch, EpochInput, Sha256Dalek, SpanInput};
use verify_core::{decode_journal, encode_journal};

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/fixture.json");

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

    let spans = closes
        .iter()
        .map(|close| SpanInput {
            headers: vec![b64(&close["header_xdr_b64"])],
            tail_envelopes: b64_list(&close["scp_envelopes_b64"]),
            tail_set: Some(b64(&close["tx_set_xdr_b64"])),
            claims: vec![(
                b64(&close["tx_envelope_xdr_b64"]),
                close["tx_index"].as_u64().unwrap() as u32,
            )],
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
    assert_eq!(journal.end_seq, closes[1]["ledger_seq"].as_u64().unwrap() as u32);
    assert_eq!(journal.start_hash, b64_32(&closes[0]["tx_set_previous_ledger_hash_b64"]));
    assert_eq!(journal.end_hash, b64_32(&closes[1]["header_hash_b64"]));

    let expected_claims: Vec<[u8; 32]> = closes
        .iter()
        .map(|c| Sha256Dalek.sha256(&b64(&c["tx_envelope_xdr_b64"])))
        .collect();
    assert_eq!(journal.claim_ids, expected_claims, "one claim id per close");
    assert_eq!(journal.claim_ids.len(), 2);

    let bytes = encode_journal(&journal);
    let decoded = decode_journal(&bytes).expect("journal round-trip");
    assert_eq!(decoded.start_seq, journal.start_seq);
    assert_eq!(decoded.start_hash, journal.start_hash);
    assert_eq!(decoded.end_seq, journal.end_seq);
    assert_eq!(decoded.end_hash, journal.end_hash);
    assert_eq!(decoded.claim_ids, journal.claim_ids);
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

    // Claim the envelope at a slot it does not occupy.
    input.spans[0].claims[0].1 += 1;

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
