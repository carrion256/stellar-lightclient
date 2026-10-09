//! Synthetic coverage for verify-core: the tests build chained headers, real
//! ed25519 validator signatures (via `ed25519-dalek`), and both transaction-set
//! encodings from scratch, so every message-construction and chain-pinning
//! check below is exercised with genuine crypto.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature as DalekSignature};
use stellar_xdr::{
    BumpSequenceOp, EnvelopeType, GeneralizedTransactionSet, Hash, LedgerHeader, Limited, Limits,
    MuxedAccount, NodeId, Operation, OperationBody, PublicKey, ReadXdr, ScpBallot, ScpEnvelope,
    ScpStatement, ScpStatementExternalize, ScpStatementPledges, SequenceNumber, Signature,
    StellarValue, TransactionEnvelope, TransactionPhase, TransactionSet, TransactionSetV1,
    TransactionV1Envelope, TxSetComponent, TxSetComponentTxsMaybeDiscountedFee, Uint256, Value,
    VecM, WriteXdr,
};
use verify_core::{
    decode_journal, encode_journal, verify_span, Crypto, EpochJournal, Error, SpanOutcome,
    SpanProof, Trust,
};

// ------------------------------------------------------------------ crypto

struct TestCrypto;

impl Crypto for TestCrypto {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let d: [u8; 32] = Sha256::digest(bytes).into();
        d
    }
    fn ed25519_verify(&self, signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let Ok(sig) = DalekSignature::from_slice(signature) else {
            return false;
        };
        vk.verify_strict(message, &sig).is_ok()
    }
}

// ------------------------------------------------------------------ builders

const NETWORK_ID: [u8; 32] = [7u8; 32];
const MAX_PROTOCOL: u32 = 22;
const TRUSTED: [u8; 3] = [0, 1, 2]; // indices into `key()`
const UNTRUSTED: u8 = 9;

fn key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i.wrapping_add(1); 32])
}

fn node_id(sk: &SigningKey) -> [u8; 32] {
    sk.verifying_key().to_bytes()
}

fn encode_xdr<T: WriteXdr>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    value.write_xdr(&mut Limited::new(&mut buf, Limits::none())).unwrap();
    buf
}

fn decode_xdr<T: ReadXdr>(bytes: &[u8]) -> T {
    T::read_xdr_to_end(&mut Limited::new(std::io::Cursor::new(bytes), Limits::none())).unwrap()
}

/// Signed `ScpEnvelope` externalizing `value` for slot `seq` under `sk`.
fn envelope(sk: &SigningKey, seq: u32, value: &StellarValue) -> Vec<u8> {
    let statement = ScpStatement {
        node_id: NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(node_id(sk)))),
        slot_index: u64::from(seq),
        pledges: ScpStatementPledges::Externalize(ScpStatementExternalize {
            commit: ScpBallot {
                counter: 1,
                value: Value::try_from(encode_xdr(value)).unwrap(),
            },
            n_h: 0,
            commit_quorum_set_hash: Hash([0u8; 32]),
        }),
    };
    let statement_xdr = encode_xdr(&statement);
    // stellar-core: signature = sign(xdr(networkID, ENVELOPE_TYPE_SCP, statement))
    let mut message = Vec::with_capacity(36 + statement_xdr.len());
    message.extend_from_slice(&NETWORK_ID);
    message.extend_from_slice(&(EnvelopeType::Scp as i32).to_be_bytes());
    message.extend_from_slice(&statement_xdr);
    let signature = sk.sign(&message);
    encode_xdr(&ScpEnvelope {
        statement,
        signature: Signature::try_from(signature.to_bytes().to_vec()).unwrap(),
    })
}

fn header_bytes(seq: u32, prev: [u8; 32], value: &StellarValue, version: u32) -> Vec<u8> {
    let mut header = LedgerHeader::default();
    header.ledger_version = version;
    header.previous_ledger_hash = Hash(prev);
    header.scp_value = value.clone();
    header.ledger_seq = seq;
    encode_xdr(&header)
}

/// The two distinct tx envelope encodings used as claim payloads.
fn txs() -> (Vec<u8>, Vec<u8>) {
    let mk = |seq: i64| {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: stellar_xdr::Transaction {
                source_account: MuxedAccount::Ed25519(Uint256([1u8; 32])),
                fee: 100,
                seq_num: SequenceNumber(seq),
                cond: stellar_xdr::Preconditions::None,
                memo: stellar_xdr::Memo::None,
                operations: VecM::try_from(vec![Operation {
                    source_account: None,
                    body: OperationBody::BumpSequence(BumpSequenceOp {
                        bump_to: SequenceNumber(42),
                    }),
                }])
                .unwrap(),
                ext: stellar_xdr::TransactionExt::V0,
            },
            signatures: VecM::default(),
        })
    };
    (encode_xdr(&mk(1)), encode_xdr(&mk(2)))
}

#[derive(Clone, Copy)]
enum SetKind {
    Generalized,
    Legacy,
}

fn tx_set_bytes(prev: [u8; 32], kind: SetKind, tx0: &TransactionEnvelope, tx1: &TransactionEnvelope) -> Vec<u8> {
    match kind {
        SetKind::Generalized => {
            let component = TxSetComponentTxsMaybeDiscountedFee {
                base_fee: None,
                txs: VecM::try_from(vec![tx0.clone(), tx1.clone()]).unwrap(),
            };
            encode_xdr(&GeneralizedTransactionSet::V1(TransactionSetV1 {
                previous_ledger_hash: Hash(prev),
                phases: VecM::try_from(vec![TransactionPhase::V0(
                    VecM::try_from(vec![TxSetComponent::TxsetCompTxsMaybeDiscountedFee(component)]).unwrap(),
                )])
                .unwrap(),
            }))
        }
        SetKind::Legacy => encode_xdr(&TransactionSet {
            previous_ledger_hash: Hash(prev),
            txs: VecM::try_from(vec![tx0.clone(), tx1.clone()]).unwrap(),
        }),
    }
}

/// Chained span `start_seq + 1 ..= tail_seq`, its quorum certificate, and its
/// tail transaction set pinning the header before the tail.
struct Chain {
    start_seq: u32,
    start_hash: [u8; 32],
    headers: Vec<Vec<u8>>,
    tail_seq: u32,
    tail_value: StellarValue,
    tail_set: Vec<u8>,
    tx0: Vec<u8>,
    tx1: Vec<u8>,
    envelopes: Vec<Vec<u8>>,
    trusted: Vec<[u8; 32]>,
}

fn chain(start_seq: u32, start_hash: [u8; 32], tail_seq: u32, kind: SetKind) -> Chain {
    // 1) intermediate headers (value irrelevant: only the tail is certified);
    //    their chained hash determines the hash the tail set must pin.
    let mut prev = start_hash;
    let mut headers = Vec::new();
    for seq in start_seq + 1..tail_seq {
        let raw = header_bytes(seq, prev, &StellarValue::default(), MAX_PROTOCOL);
        prev = TestCrypto.sha256(&raw);
        headers.push(raw);
    }
    // 2) the tail transaction set pins `prev` (hash of the header before the tail).
    let (tx0b, tx1b) = txs();
    let tx0 = decode_xdr(&tx0b);
    let tx1 = decode_xdr(&tx1b);
    let tail_set = tx_set_bytes(prev, kind, &tx0, &tx1);
    // 3) the tail header externalizes the value committing to that set.
    let tail_value = StellarValue {
        tx_set_hash: Hash(TestCrypto.sha256(&tail_set)),
        close_time: stellar_xdr::TimePoint(1),
        upgrades: VecM::default(),
        ext: stellar_xdr::StellarValueExt::Basic,
    };
    headers.push(header_bytes(tail_seq, prev, &tail_value, MAX_PROTOCOL));
    let envelopes = TRUSTED.iter().map(|i| envelope(&key(*i), tail_seq, &tail_value)).collect();

    Chain {
        start_seq,
        start_hash,
        headers,
        tail_seq,
        tail_value,
        tail_set,
        tx0: tx0b,
        tx1: tx1b,
        envelopes,
        trusted: TRUSTED.iter().map(|i| node_id(&key(*i))).collect(),
    }
}

fn run<'a>(
    c: &Chain,
    headers: &[&'a [u8]],
    envelopes: &[&'a [u8]],
    tail_set: Option<&'a [u8]>,
    claims: &[(&'a [u8], u32)],
    threshold: u32,
) -> Result<SpanOutcome, Error> {
    let trust =
        Trust { network_id: NETWORK_ID, trusted_nodes: c.trusted.clone(), threshold, max_protocol_version: MAX_PROTOCOL };
    let proof = SpanProof { headers, tail_envelopes: envelopes, tail_set, claims };
    verify_span(&TestCrypto, &trust, c.start_seq, c.start_hash, &proof)
}

fn refs<'a>(items: &'a [Vec<u8>]) -> Vec<&'a [u8]> {
    items.iter().map(|i| i.as_slice()).collect()
}

// ------------------------------------------------------------------ tests

#[test]
fn wellformed_span_verifies_and_chains_acceptance() {
    // Two-ledger span: header 12 is certified, header 11 pinned transitively.
    let c = chain(10, [5u8; 32], 12, SetKind::Generalized);
    let outcome = run(&c, &refs(&c.headers), &refs(&c.envelopes), Some(&c.tail_set), &[], 3).unwrap();
    assert_eq!(outcome.tail_seq, 12);
    assert_eq!(outcome.pinned_seq, Some(11));
    assert_eq!(outcome.quorum_signers, 3);
    assert!(outcome.claim_ids.is_empty());
    assert_eq!(outcome.tail_hash, TestCrypto.sha256(c.headers.last().unwrap()));
}

#[test]
fn wrong_start_hash_breaks_the_chain() {
    let c = chain(10, [5u8; 32], 12, SetKind::Generalized);
    let mut bad = c.start_hash;
    bad[0] ^= 0x01;
    let trust = Trust {
        network_id: NETWORK_ID,
        trusted_nodes: c.trusted.clone(),
        threshold: 3,
        max_protocol_version: MAX_PROTOCOL,
    };
    let proof = SpanProof {
        headers: &refs(&c.headers),
        tail_envelopes: &refs(&c.envelopes),
        tail_set: Some(&c.tail_set),
        claims: &[],
    };
    let err = verify_span(&TestCrypto, &trust, c.start_seq, bad, &proof).unwrap_err();
    assert_eq!(err, Error::PreviousLedgerHashMismatch { index: 0 });
}

#[test]
fn tampered_intermediate_header_is_rejected() {
    // Flipping one byte of header 11 changes its hash, so header 12's
    // `previousLedgerHash` no longer matches (and the tail set can pin the
    // forged value — the mismatch fails at the chain walk, not at the set).
    let c = chain(10, [5u8; 32], 12, SetKind::Generalized);
    let mut headers = c.headers.clone();
    headers[0][100] ^= 0x01;
    let trust = Trust {
        network_id: NETWORK_ID,
        trusted_nodes: c.trusted.clone(),
        threshold: 3,
        max_protocol_version: MAX_PROTOCOL,
    };
    let proof = SpanProof {
        headers: &refs(&headers),
        tail_envelopes: &refs(&c.envelopes),
        tail_set: Some(&c.tail_set),
        claims: &[],
    };
    let err = verify_span(&TestCrypto, &trust, c.start_seq, c.start_hash, &proof).unwrap_err();
    assert_eq!(err, Error::PreviousLedgerHashMismatch { index: 1 });
}

#[test]
fn unexpected_ledger_sequence_is_rejected() {
    let c = chain(10, [5u8; 32], 12, SetKind::Generalized);
    let mut headers = c.headers.clone();
    headers.remove(0); // header 12 now claims slot 12 from head 10: a gap
    let err = run(&c, &refs(&headers), &refs(&c.envelopes), Some(&c.tail_set), &[], 3).unwrap_err();
    assert_eq!(err, Error::UnexpectedLedgerSeq { index: 0, prev_seq: 10, actual: 12 });
}

#[test]
fn quorum_threshold_met_and_not_met() {
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    // Met: exactly 3 of 3 externalizers.
    let outcome = run(&c, &refs(&c.headers), &refs(&c.envelopes), Some(&c.tail_set), &[], 3).unwrap();
    assert_eq!(outcome.quorum_signers, 3);
    // Not met: threshold 4 cannot be reached with 3 envelopes.
    let err = run(&c, &refs(&c.headers), &refs(&c.envelopes), Some(&c.tail_set), &[], 4).unwrap_err();
    assert_eq!(err, Error::QuorumNotReached { signers: 3, threshold: 4 });
}

#[test]
fn untrusted_signer_skipped_and_votes_deduplicated() {
    // Threshold 2, 1 untrusted + 2 trusted + a duplicate of the first trusted
    // node: untrusted must neither count nor fail, duplicate counts once.
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    let mut envelopes = vec![envelope(&key(UNTRUSTED), c.tail_seq, &c.tail_value)];
    envelopes.extend(c.envelopes.iter().take(2).cloned());
    envelopes.push(envelopes[1].clone());
    let outcome =
        run(&c, &refs(&c.headers), &refs(&envelopes), Some(&c.tail_set), &[], 2).unwrap();
    assert_eq!(outcome.quorum_signers, 2);
}

#[test]
fn tampered_signature_hard_fails() {
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    // flip one signature bit in the raw envelope (the signature is the trailing
    // 68 bytes of the SCPEnvelope XDR: 4-byte length + 64-byte signature)
    let mut raw = c.envelopes[0].clone();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    let env: ScpEnvelope = decode_xdr(&raw);
    let mut envelopes = c.envelopes.clone();
    envelopes[0] = encode_xdr(&env);
    let err =
        run(&c, &refs(&c.headers), &refs(&envelopes), Some(&c.tail_set), &[], 3).unwrap_err();
    assert_eq!(err, Error::InvalidValidatorSignature { index: 0 });
}

#[test]
fn wrong_network_id_hard_fails() {
    // The signed message embeds networkID; re-verifying the honest signatures
    // against a different trust network_id must fail — proves the message
    // construction itself is exercised.
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    let trust = Trust {
        network_id: [8u8; 32],
        trusted_nodes: c.trusted.clone(),
        threshold: 3,
        max_protocol_version: MAX_PROTOCOL,
    };
    let proof = SpanProof {
        headers: &refs(&c.headers),
        tail_envelopes: &refs(&c.envelopes),
        tail_set: Some(&c.tail_set),
        claims: &[],
    };
    let err = verify_span(&TestCrypto, &trust, c.start_seq, c.start_hash, &proof).unwrap_err();
    assert_eq!(err, Error::InvalidValidatorSignature { index: 0 });
}

#[test]
fn externalized_value_mismatch_is_rejected() {
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    // Envelope externalizes a value committing to a *different* set.
    let other = StellarValue {
        tx_set_hash: Hash([9u8; 32]),
        close_time: c.tail_value.close_time.clone(),
        upgrades: VecM::default(),
        ext: stellar_xdr::StellarValueExt::Basic,
    };
    let err = run(
        &c,
        &refs(&c.headers),
        &[envelope(&key(0), c.tail_seq, &other).as_slice()],
        Some(&c.tail_set),
        &[],
        1,
    )
    .unwrap_err();
    assert_eq!(err, Error::ExternalizedValueMismatch { index: 0 });
}

#[test]
fn claims_proven_index_checks() {
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    // In range and matching: proven, id = sha256(claim bytes).
    let outcome = run(
        &c,
        &refs(&c.headers),
        &refs(&c.envelopes),
        Some(&c.tail_set),
        &[(&c.tx1, 1)],
        3,
    )
    .unwrap();
    assert_eq!(outcome.claim_ids, vec![TestCrypto.sha256(&c.tx1)]);
    // Right bytes, wrong slot: rejected.
    let err = run(
        &c,
        &refs(&c.headers),
        &refs(&c.envelopes),
        Some(&c.tail_set),
        &[(&c.tx1, 0)],
        3,
    )
    .unwrap_err();
    assert_eq!(err, Error::ClaimEnvelopeMismatch { claim: 0, index: 0 });
    // Out of range.
    let err = run(
        &c,
        &refs(&c.headers),
        &refs(&c.envelopes),
        Some(&c.tail_set),
        &[(&c.tx0, 2)],
        3,
    )
    .unwrap_err();
    assert_eq!(err, Error::ClaimIndexOutOfRange { claim: 0, index: 2, len: 2 });
}

#[test]
fn claim_without_tx_set_is_rejected() {
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    let err =
        run(&c, &refs(&c.headers), &refs(&c.envelopes), None, &[(&c.tx0, 0)], 3).unwrap_err();
    assert_eq!(err, Error::ClaimsRequireTxSet);
}

#[test]
fn provisional_span_without_set_is_unpinned() {
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    let outcome = run(&c, &refs(&c.headers), &refs(&c.envelopes), None, &[], 3).unwrap();
    assert_eq!(outcome.pinned_seq, None);
}

#[test]
fn prefix_fast_path_matches_full_parse() {
    for kind in [SetKind::Generalized, SetKind::Legacy] {
        let c = chain(11, [5u8; 32], 12, kind);
        let hdrs = refs(&c.headers);
        let envs = refs(&c.envelopes);
        // Fast path (no claims): previousLedgerHash read from the 36-byte prefix.
        let fast = run(&c, &hdrs, &envs, Some(&c.tail_set), &[], 3).unwrap();
        assert_eq!(fast.pinned_seq, Some(11));
        // Full parse (claims present): must agree on the pin and prove txs.
        let claims = &[(&c.tx0[..], 0u32), (&c.tx1[..], 1u32)];
        let full = run(&c, &hdrs, &envs, Some(&c.tail_set), claims, 3).unwrap();
        assert_eq!(full.pinned_seq, fast.pinned_seq);
        assert_eq!(full.tail_hash, fast.tail_hash);
        assert_eq!(full.quorum_signers, fast.quorum_signers);
        assert_eq!(
            full.claim_ids,
            vec![TestCrypto.sha256(&c.tx0), TestCrypto.sha256(&c.tx1)]
        );
    }
}

#[test]
fn protocol_version_beyond_max_is_rejected() {
    let c = chain(11, [5u8; 32], 12, SetKind::Generalized);
    let mut headers = c.headers.clone();
    // `chain(start_seq, start_hash, tail_seq, …)` builds a single-header span (the
    // tail), whose predecessor is the chain's start hash — so the version bump
    // replaces element 0, not element 1.
    headers[0] = header_bytes(c.tail_seq, [5u8; 32], &c.tail_value, MAX_PROTOCOL + 1);
    let err =
        run(&c, &refs(&headers), &refs(&c.envelopes), Some(&c.tail_set), &[], 3).unwrap_err();
    assert_eq!(err, Error::ProtocolVersionExceeded { version: MAX_PROTOCOL + 1, max: MAX_PROTOCOL });
}

#[test]
fn journal_roundtrip_and_garbage() {
    let j = EpochJournal {
        start_seq: 5,
        start_hash: [1u8; 32],
        end_seq: 9,
        end_hash: [2u8; 32],
        claim_ids: vec![[3u8; 32], [4u8; 32]],
    };
    let bytes = encode_journal(&j);
    assert_eq!(bytes.len(), 76 + 64);
    assert_eq!(decode_journal(&bytes).unwrap(), j);

    let empty = EpochJournal {
        start_seq: 0,
        start_hash: [0u8; 32],
        end_seq: 0,
        end_hash: [0u8; 32],
        claim_ids: vec![],
    };
    assert_eq!(bytes.len() - 64, encode_journal(&empty).len());
    assert_eq!(decode_journal(&encode_journal(&empty)).unwrap(), empty);

    // Trailing garbage rejected.
    let mut bad = encode_journal(&empty);
    bad.push(0);
    assert_eq!(
        decode_journal(&bad),
        Err(Error::MalformedJournal("trailing bytes after claim ids"))
    );

    // Truncated input rejected.
    let bad = encode_journal(&j)[..100].to_vec();
    assert!(decode_journal(&bad).is_err());

    // Claim count / length mismatch rejected.
    let mut bad = encode_journal(&j);
    bad.truncate(108);
    assert!(decode_journal(&bad).is_err());

    // Shorter than the 76-byte header rejected.
    assert!(decode_journal(&[0u8; 40]).is_err());
}
