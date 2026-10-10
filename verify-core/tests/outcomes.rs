//! Outcome proofs against real mainnet fixture data.
//!
//! Two facts these tests pin down, both established empirically against
//! `testdata/fixture.json` rather than assumed:
//!
//! * `tx_set_result_hash` is `sha256` of the whole canonical
//!   `TransactionResultSet` — vector count included;
//! * `TransactionResultPair.transaction_hash` is the network-bound contents
//!   hash, never the envelope hash that `claim_id` uses.
//!
//! And the security property the design turns on: outcomes bind to the
//! **authenticated head** header, so a fabricated tail header cannot commit a
//! fabricated result set.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, InvokeHostFunctionResult, InvokeHostFunctionSuccessPreImage, LedgerHeader, Limited,
    Limits, OperationResult, OperationResultTr, ReadXdr, TransactionResult, TransactionResultPair,
    TransactionResultResult, TransactionResultSet, VecM, WriteXdr,
};
use std::io::Cursor;

use verify_core::{
    decode_result_set, outcome_digest, soroban_success_preimage, tx_contents_hash,
    verify_outcome_claims, verify_span, Checkpoint, Crypto, Error, SpanProof, Trust,
};

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/fixture.json");

struct TestCrypto;
impl Crypto for TestCrypto {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
    fn ed25519_verify(&self, signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        vk.verify(message, &Signature::from_bytes(signature)).is_ok()
    }
}

fn fixture() -> Value {
    let raw = std::fs::read_to_string(FIXTURE_PATH).expect("testdata/fixture.json missing");
    serde_json::from_str(&raw).expect("fixture is not valid json")
}

fn b64(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().expect("expected base64 string")).expect("invalid base64")
}

fn num(value: &Value) -> u32 {
    value.as_u64().expect("expected number") as u32
}

fn decode_xdr<T: ReadXdr>(bytes: &[u8]) -> T {
    T::read_xdr_to_end(&mut Limited::new(Cursor::new(bytes), Limits::none())).unwrap()
}

fn encode_xdr<T: WriteXdr>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    value.write_xdr(&mut Limited::new(&mut buf, Limits::none())).unwrap();
    buf
}

/// The same envelope with a different transaction fee: still canonical XDR,
/// but a different contents hash.
fn variant_envelope(envelope_bytes: &[u8]) -> Vec<u8> {
    let mut env: stellar_xdr::TransactionEnvelope = decode_xdr(envelope_bytes);
    match &mut env {
        stellar_xdr::TransactionEnvelope::Tx(e) => e.tx.fee = e.tx.fee.wrapping_add(1),
        stellar_xdr::TransactionEnvelope::TxV0(e) => e.tx.fee = e.tx.fee.wrapping_add(1),
        stellar_xdr::TransactionEnvelope::TxFeeBump(e) => e.tx.fee = e.tx.fee.wrapping_add(1),
    }
    encode_xdr(&env)
}

fn network_id(f: &Value) -> [u8; 32] {
    TestCrypto.sha256(f["network_passphrase"].as_str().unwrap().as_bytes())
}

/// The two-close span `mainnet.rs` verifies: `closes[0]` is the authenticated
/// head, `closes[1]` the tail.
struct FixtureSpan {
    trust: Trust,
    start_seq: u32,
    start_hash: [u8; 32],
    headers: Vec<Vec<u8>>,
    tail_envelopes: Vec<Vec<u8>>,
    tail_set: Vec<u8>,
    /// `TransactionResultSet` of the *authenticated head* ledger.
    head_results: Vec<u8>,
    /// `TransactionResultSet` of the *tail* ledger — the one a naive design
    /// would bind to, and the one an attacker can forge a header around.
    tail_results: Vec<u8>,
    /// A real `(envelope, TransactionResultPair)` from the head ledger.
    outcome_claim: (Vec<u8>, Vec<u8>),
    tail_hash: [u8; 32],
}

fn span() -> FixtureSpan {
    let f = fixture();
    let first = &f["closes"][0];
    let tail = &f["closes"][1];
    let network_id = network_id(&f);

    let head_results = b64(&first["results_xdr_b64"]);
    let tail_results = b64(&tail["results_xdr_b64"]);
    let envelope = b64(&first["tx_envelope_xdr_b64"]);
    let set: TransactionResultSet = decode_xdr(&head_results);
    let want = tx_contents_hash(&TestCrypto, network_id, &envelope).unwrap();
    let pair = set
        .results
        .iter()
        .find(|r| r.transaction_hash.0 == want)
        .expect("fixture head result set has no row for the highlighted envelope");

    // Node ids: every distinct signer that externalized either close.
    let mut nodes: Vec<[u8; 32]> = Vec::new();
    let mut threshold = 0u32;
    for close in [first, tail] {
        threshold = threshold.max(close["signer_count"].as_u64().unwrap_or(0) as u32);
        for id in close["distinct_signers_b64"].as_array().unwrap() {
            let node: [u8; 32] = b64(id).try_into().unwrap();
            if !nodes.contains(&node) {
                nodes.push(node);
            }
        }
    }
    let trust = Trust {
        network_id,
        trusted_nodes: nodes,
        threshold,
        max_protocol_version: u32::MAX,
    };

    FixtureSpan {
        trust,
        start_seq: num(&first["ledger_seq"]) - 1,
        start_hash: b64(&first["tx_set_previous_ledger_hash_b64"]).try_into().unwrap(),
        headers: vec![b64(&first["header_xdr_b64"]), b64(&tail["header_xdr_b64"])],
        tail_envelopes: b64_list(&tail["scp_envelopes_b64"]),
        tail_set: b64(&tail["tx_set_xdr_b64"]),
        head_results,
        tail_results,
        outcome_claim: (envelope, encode_xdr(pair)),
        tail_hash: b64(&tail["header_hash_b64"]).try_into().unwrap(),
    }
}

fn b64_list(value: &Value) -> Vec<Vec<u8>> {
    value.as_array().unwrap().iter().map(b64).collect()
}

/// Run `verify_span` over the fixture span with the given outcome inputs.
fn run(
    s: &FixtureSpan,
    outcome_claims: &[(&[u8], &[u8])],
    tail_results: Option<&[u8]>,
    tail_set: Option<&[u8]>,
) -> Result<verify_core::SpanOutcome, Error> {
    let headers: Vec<&[u8]> = s.headers.iter().map(|h| h.as_slice()).collect();
    let envelopes: Vec<&[u8]> = s.tail_envelopes.iter().map(|e| e.as_slice()).collect();
    let proof = SpanProof {
        start_header: None,
        headers: &headers,
        tail_envelopes: &envelopes,
        tail_set,
        claims: &[],
        outcome_claims,
        tail_results,
    };
    verify_span(&TestCrypto, &s.trust, s.start_seq, s.start_hash, &proof)
}

// ------------------------------------------------------------------ pinned facts

#[test]
fn result_set_hash_is_plain_sha256_of_the_whole_set() {
    let f = fixture();
    for close in f["closes"].as_array().unwrap() {
        let header: LedgerHeader = decode_xdr(&b64(&close["header_xdr_b64"]));
        let results = b64(&close["results_xdr_b64"]);
        assert_eq!(
            TestCrypto.sha256(&results),
            header.tx_set_result_hash.0,
            "tx_set_result_hash == sha256(canonical TransactionResultSet)"
        );
        let set: TransactionResultSet = decode_xdr(&results);
        assert_eq!(
            set.results.len() as u32,
            num(&close["tx_count"]),
            "one result row per transaction in the set"
        );
    }
}

#[test]
fn contents_hash_is_not_the_envelope_hash() {
    // The join key trap: a verifier that compares `transaction_hash` against
    // `claim_id` fails on every real ledger and looks like a data bug.
    let s = span();
    let envelope_hash = TestCrypto.sha256(&s.outcome_claim.0);
    let contents = tx_contents_hash(&TestCrypto, s.trust.network_id, &s.outcome_claim.0).unwrap();
    assert_ne!(contents, envelope_hash, "contents hash drops the signatures");
    let pair: TransactionResultPair = decode_xdr(&s.outcome_claim.1);
    assert_eq!(pair.transaction_hash.0, contents, "result rows key on the contents hash");
    assert_ne!(pair.transaction_hash.0, envelope_hash);
}

// ------------------------------------------------------------------ happy path

#[test]
fn outcome_claim_proves_inclusion_and_outcome() {
    let s = span();
    let outcome = run(&s, &[(&s.outcome_claim.0, &s.outcome_claim.1)], Some(&s.head_results), Some(&s.tail_set))
        .expect("real outcome claim verifies");
    assert_eq!(outcome.outcome_digests.len(), 1);
    let pair: TransactionResultPair = decode_xdr(&s.outcome_claim.1);
    assert_eq!(outcome.outcome_digests[0], outcome_digest(&TestCrypto, &pair).unwrap());
    // The head is pinned exactly as the inclusion path pins it.
    assert_eq!(
        outcome.authenticated_head,
        Some(Checkpoint {
            seq: num(&fixture()["closes"][0]["ledger_seq"]),
            hash: TestCrypto.sha256(&s.headers[0]),
        })
    );
}

#[test]
fn outcome_claims_need_no_transaction_set_proof() {
    // A result row exists only for an applied transaction, so inclusion is
    // implied: a span with no tail set at all cannot carry one, but a span that
    // pins the chain proves the outcome without any `claims` entry.
    let s = span();
    let outcome = run(&s, &[(&s.outcome_claim.0, &s.outcome_claim.1)], Some(&s.head_results), Some(&s.tail_set))
        .unwrap();
    assert!(outcome.claim_ids.is_empty(), "no inclusion claim was supplied");
    assert_eq!(outcome.outcome_digests.len(), 1);
}

// ------------------------------------------------------- the forgery vector

#[test]
fn tail_ledger_results_are_refused() {
    // Supplying the *tail* ledger's result set is refused: it is committed only
    // by the provisional tail header, whose `tx_set_result_hash` the quorum
    // certificate does not cover.
    let s = span();
    let err = run(
        &s,
        &[(&s.outcome_claim.0, &s.outcome_claim.1)],
        Some(&s.tail_results),
        Some(&s.tail_set),
    )
    .unwrap_err();
    assert_eq!(err, Error::TxSetResultHashMismatch);
}

#[test]
fn forged_tail_header_cannot_commit_results() {
    // The attack: real headers, real certificate, real transaction set, and a
    // fabricated result set. Rewriting only the tail header's
    // `tx_set_result_hash` must not help.
    let s = span();
    let mut fabricated_set: TransactionResultSet = decode_xdr(&s.head_results);
    let want = tx_contents_hash(&TestCrypto, s.trust.network_id, &s.outcome_claim.0).unwrap();
    for row in fabricated_set.results.iter_mut() {
        if row.transaction_hash.0 == want {
            row.result.result = TransactionResultResult::TxSuccess(VecM::default());
        }
    }
    let fabricated = encode_xdr(&fabricated_set);

    // Craft a tail header that commits the fabrication. The span still walks:
    // the tail's own hash is never pinned inside a span.
    let mut tail_header: LedgerHeader = decode_xdr(&s.headers[1]);
    tail_header.tx_set_result_hash = Hash(TestCrypto.sha256(&fabricated));
    let forged_tail = encode_xdr(&tail_header);

    let mut headers = s.headers.clone();
    headers[1] = forged_tail;
    let envelopes: Vec<&[u8]> = s.tail_envelopes.iter().map(|e| e.as_slice()).collect();
    let hs: Vec<&[u8]> = headers.iter().map(|h| h.as_slice()).collect();
    let proof = SpanProof {
        start_header: None,
        headers: &hs,
        tail_envelopes: &envelopes,
        tail_set: Some(&s.tail_set),
        claims: &[],
        outcome_claims: &[(&s.outcome_claim.0, &s.outcome_claim.1)],
        tail_results: Some(&fabricated),
    };
    let err = verify_span(&TestCrypto, &s.trust, s.start_seq, s.start_hash, &proof).unwrap_err();
    assert_eq!(err, Error::TxSetResultHashMismatch);
}

#[test]
fn swapped_result_row_is_refused() {
    // The other half of the forgery: a real result set, but a `TxFailed`
    // re-presented as `TxSuccess`. The pair must be an element of the committed
    // set, so the swap is caught.
    let s = span();
    let want = tx_contents_hash(&TestCrypto, s.trust.network_id, &s.outcome_claim.0).unwrap();
    let forged = TransactionResultPair {
        transaction_hash: Hash(want),
        result: TransactionResult {
            fee_charged: 0,
            result: TransactionResultResult::TxSuccess(VecM::default()),
            ext: stellar_xdr::TransactionResultExt::V0,
        },
    };
    let forged_bytes = encode_xdr(&forged);
    assert_ne!(forged_bytes, s.outcome_claim.1, "test really does swap the row");
    let err = run(
        &s,
        &[(&s.outcome_claim.0, &forged_bytes)],
        Some(&s.head_results),
        Some(&s.tail_set),
    )
    .unwrap_err();
    assert_eq!(err, Error::OutcomeNotInResults { outcome: 0 });
}

// ------------------------------------------------------------------ fail closed

#[test]
fn result_for_a_different_envelope_is_refused() {
    let s = span();
    // A real, well-formed envelope whose transaction body differs: the
    // contents-hash binding must catch the mismatch. Mutating raw bytes would
    // break XDR parsing and test the wrong check.
    let other = variant_envelope(&s.outcome_claim.0);
    let err = run(&s, &[(&other, &s.outcome_claim.1)], Some(&s.head_results), Some(&s.tail_set))
        .unwrap_err();
    assert_eq!(err, Error::OutcomeTransactionHashMismatch { outcome: 0 });
}

#[test]
fn outcome_without_a_result_set_is_refused() {
    let s = span();
    let err = run(&s, &[(&s.outcome_claim.0, &s.outcome_claim.1)], None, Some(&s.tail_set))
        .unwrap_err();
    assert_eq!(err, Error::OutcomeResultsMissing);
}

#[test]
fn outcomes_without_a_pinned_head_are_refused() {
    // No tail set => nothing pins a header => there is no authenticated head to
    // bind outcomes to. Provisional spans may be viewed but never carry proof.
    let s = span();
    let err = run(&s, &[(&s.outcome_claim.0, &s.outcome_claim.1)], Some(&s.head_results), None)
        .unwrap_err();
    assert_eq!(err, Error::ResultsRequireAuthenticatedHead);
}

#[test]
fn garbage_result_set_is_refused() {
    let s = span();
    let mut junk = s.head_results.clone();
    junk[0] ^= 0x01; // vector count no longer matches the payload
    let err = run(&s, &[(&s.outcome_claim.0, &s.outcome_claim.1)], Some(&junk), Some(&s.tail_set));
    assert!(err.is_err());
}

#[test]
fn outcome_claims_are_indexed_for_diagnostics() {
    // A failure names which claim failed rather than blaming the whole span.
    let s = span();
    let other = variant_envelope(&s.outcome_claim.0);
    let err = run(
        &s,
        &[(&s.outcome_claim.0, &s.outcome_claim.1), (&other, &s.outcome_claim.1)],
        Some(&s.head_results),
        Some(&s.tail_set),
    )
    .unwrap_err();
    assert_eq!(err, Error::OutcomeTransactionHashMismatch { outcome: 1 });
}

// ------------------------------------------------------------------ soroban

fn soroban_pair(committed: [u8; 32]) -> Vec<u8> {
    let pair = TransactionResultPair {
        transaction_hash: Hash([0x11; 32]),
        result: TransactionResult {
            fee_charged: 100,
            result: TransactionResultResult::TxSuccess(VecM::try_from(vec![
                OperationResult::OpInner(OperationResultTr::InvokeHostFunction(
                    InvokeHostFunctionResult::Success(Hash(committed)),
                )),
            ])
            .unwrap()),
            ext: stellar_xdr::TransactionResultExt::V0,
        },
    };
    encode_xdr(&pair)
}

#[test]
fn soroban_preimage_is_checked_against_the_committed_hash() {
    let preimage = InvokeHostFunctionSuccessPreImage {
        return_value: stellar_xdr::ScVal::Void,
        events: VecM::default(),
    };
    let preimage_bytes = encode_xdr(&preimage);
    let committed = TestCrypto.sha256(&preimage_bytes);
    let pair = soroban_pair(committed);

    let got = soroban_success_preimage(&TestCrypto, &pair, &preimage_bytes)
        .expect("preimage matching the committed hash verifies");
    assert!(got.events.is_empty());

    // A tampered preimage is a different hash: rejected, not silently accepted.
    let mut tampered = preimage_bytes.clone();
    tampered[0] ^= 0x01;
    let err = soroban_success_preimage(&TestCrypto, &pair, &tampered).unwrap_err();
    assert_eq!(err, Error::SorobanSuccess("success preimage hash mismatch"));

    // A result with no successful invoke_host_function carries nothing to prove.
    let plain = TransactionResultPair {
        transaction_hash: Hash([0x11; 32]),
        result: TransactionResult {
            fee_charged: 100,
            result: TransactionResultResult::TxSuccess(VecM::default()),
            ext: stellar_xdr::TransactionResultExt::V0,
        },
    };
    let err = soroban_success_preimage(&TestCrypto, &encode_xdr(&plain), &preimage_bytes)
        .unwrap_err();
    assert_eq!(err, Error::SorobanSuccess("no successful invoke_host_function"));
}

#[test]
fn result_set_must_be_canonical() {
    let s = span();
    let set = decode_result_set(&s.head_results).expect("fixture result set is canonical");
    let re = encode_xdr(&set);
    assert_eq!(re, s.head_results);
    assert_eq!(TestCrypto.sha256(&re), TestCrypto.sha256(&s.head_results));
}

#[test]
fn verify_outcome_claims_returns_digests_in_claim_order() {
    let s = span();
    let set: TransactionResultSet = decode_xdr(&s.head_results);
    let digest = verify_outcome_claims(
        &TestCrypto,
        s.trust.network_id,
        &set,
        &[(&s.outcome_claim.0, &s.outcome_claim.1)],
    )
    .unwrap();
    let pair: TransactionResultPair = decode_xdr(&s.outcome_claim.1);
    assert_eq!(digest, vec![outcome_digest(&TestCrypto, &pair).unwrap()]);
}
