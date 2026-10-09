//! Host-agnostic Stellar light client verification core.
//!
//! Verifies a *span* of consecutive ledger headers authenticated by ONE quorum
//! certificate at the tail (the same semantics `contract/src/lib.rs` implements
//! on-chain), expressed against a pluggable [`Crypto`] backend so the exact
//! same code can run in the NEAR contract (host functions) and in a native
//! RISC Zero guest (`risc0-guest-runner`). No panics: every failure is an
//! [`Error`].
//!
//! # Sparse verification
//!
//! A *span* of ledger headers is authenticated by ONE quorum certificate at the
//! tail instead of one per ledger. The certificate is a set of validator
//! signatures over `xdr(networkID, ENVELOPE_TYPE_SCP, statement)`, where the
//! statement externalizes the tail's `StellarValue`. That value commits to
//! `txSetHash`, and the tail's transaction set commits to
//! `previousLedgerHash` — which pins the header before the tail, and that
//! header pins the one before it, transitively back to the stored head. One
//! certificate therefore authenticates an entire span (~428 B per intermediate
//! ledger).
//!
//! The tail transaction set is *optional*:
//! - present → the span is pinned immediately (`pinned_seq` reports through
//!   which ledger);
//! - absent → the span is provisional. The head still advances and later spans
//!   still chain to it, and the chain gets pinned by any later span that does
//!   bring a set. Claims can never be provisional: proving inclusion needs the
//!   set, so claims carry it.

use std::io::Cursor;

use stellar_xdr::{
    EnvelopeType, GeneralizedTransactionSet, Hash, LedgerHeader, Limited, Limits, PublicKey,
    ReadXdr, ScpEnvelope, ScpStatementPledges, Signature, StellarValue, TransactionEnvelope,
    TransactionPhase, TransactionSet, TxSetComponent, Value, WriteXdr,
};

mod journal;

pub use journal::{decode_journal, encode_journal, EpochJournal};

/// Cryptographic primitives the verifier needs, supplied by the host: NEAR host
/// functions in the contract, and the guest's own SHA-256 / ed25519
/// implementations (which RISC Zero constrains inside the VM).
pub trait Crypto {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32];
    fn ed25519_verify(&self, signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool;
}

/// Trust configuration — deliberately configuration, not consensus: Stellar
/// has no on-chain validator set. Operators pin node ids and a threshold.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Trust {
    /// sha256(Stellar network passphrase) — first 32 bytes of every signed message.
    pub network_id: [u8; 32],
    pub trusted_nodes: Vec<[u8; 32]>,
    pub threshold: u32,
    pub max_protocol_version: u32,
}

/// A span of consecutive ledgers plus the evidence authenticating its tail.
/// Borrowed so the caller's decoded payload buffers are never copied.
pub struct SpanProof<'a> {
    /// XDR `LedgerHeader` for each ledger `start_seq + 1 ..= tail_seq`, ascending.
    pub headers: &'a [&'a [u8]],
    /// XDR `ScpEnvelope`s forming the quorum certificate for the tail ledger.
    pub tail_envelopes: &'a [&'a [u8]],
    /// XDR transaction set of the tail ledger. Optional: it is what pins the chain.
    pub tail_set: Option<&'a [u8]>,
    /// Inclusion claims `(tx envelope XDR, index)` to prove against the tail's
    /// transaction set.
    pub claims: &'a [(&'a [u8], u32)],
}

/// What was proven about one span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanOutcome {
    pub tail_seq: u32,
    pub tail_hash: [u8; 32],
    /// Ledger through which the chain is pinned by signed bytes, if the tail set
    /// was verified. The tail header itself is pinned by the next span that
    /// brings a set.
    pub pinned_seq: Option<u32>,
    /// Distinct trusted signers whose signatures were verified.
    pub quorum_signers: u32,
    /// sha256(tx envelope) per proven claim.
    pub claim_ids: Vec<[u8; 32]>,
}

/// One variant per failure of the reference semantics. `Display` carries the
/// contract's original panic string plus positional context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    EmptySpan,
    InvalidHeaderXdr { index: usize },
    UnexpectedLedgerSeq { index: usize, prev_seq: u32, actual: u32 },
    PreviousLedgerHashMismatch { index: usize },
    ProtocolVersionExceeded { version: u32, max: u32 },
    InvalidEnvelopeXdr { index: usize },
    InvalidStellarValueXdr { index: usize },
    ExternalizedValueMismatch { index: usize },
    InvalidSignatureLength { index: usize },
    InvalidValidatorSignature { index: usize },
    QuorumNotReached { signers: u32, threshold: u32 },
    NoExternalizeStatement,
    TxSetHashMismatch,
    TxSetTooShort,
    InvalidTxSetXdr,
    NonCanonicalTxSet,
    TxSetPreviousLedgerHashMismatch,
    ClaimsRequireTxSet,
    ClaimIndexOutOfRange { claim: usize, index: u32, len: usize },
    ClaimEnvelopeMismatch { claim: usize, index: u32 },
    MalformedJournal(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EmptySpan => f.write_str("span needs at least the tail header"),
            Error::InvalidHeaderXdr { index } => {
                write!(f, "invalid ledger header xdr — header {index}")
            }
            Error::UnexpectedLedgerSeq { index, prev_seq, actual } => write!(
                f,
                "unexpected ledger sequence — header {index} is {actual}, expected {} + 1",
                prev_seq
            ),
            Error::PreviousLedgerHashMismatch { index } => {
                write!(f, "header previous ledger hash mismatch — header {index}")
            }
            Error::ProtocolVersionExceeded { version, max } => write!(
                f,
                "ledger protocol version is beyond the supported maximum — {version} > {max}"
            ),
            Error::InvalidEnvelopeXdr { index } => {
                write!(f, "invalid scp envelope xdr — envelope {index}")
            }
            Error::InvalidStellarValueXdr { index } => {
                write!(f, "invalid stellar value xdr — envelope {index}")
            }
            Error::ExternalizedValueMismatch { index } => {
                write!(f, "externalized value differs from the header scp value — envelope {index}")
            }
            Error::InvalidSignatureLength { index } => {
                write!(f, "signature is not 64 bytes — envelope {index}")
            }
            Error::InvalidValidatorSignature { index } => {
                write!(f, "invalid validator signature — envelope {index}")
            }
            Error::QuorumNotReached { signers, threshold } => {
                write!(f, "quorum threshold not met — {signers} of {threshold}")
            }
            Error::NoExternalizeStatement => f.write_str("no externalize statement for ledger"),
            Error::TxSetHashMismatch => {
                f.write_str("transaction set does not hash to the signed value")
            }
            Error::TxSetTooShort => f.write_str("transaction set is too short"),
            Error::InvalidTxSetXdr => f.write_str("invalid transaction set xdr"),
            Error::NonCanonicalTxSet => f.write_str("transaction set is not canonical xdr"),
            Error::TxSetPreviousLedgerHashMismatch => {
                f.write_str("tx set previous ledger hash mismatch")
            }
            Error::ClaimsRequireTxSet => f.write_str("claims require the tail transaction set"),
            Error::ClaimIndexOutOfRange { claim, index, len } => write!(
                f,
                "claimed tx index is out of range — claim {claim} claims index {index}, set has {len}"
            ),
            Error::ClaimEnvelopeMismatch { claim, index } => write!(
                f,
                "claimed tx envelope is not the element at that index — claim {claim}, index {index}"
            ),
            Error::MalformedJournal(reason) => {
                write!(f, "invalid epoch journal encoding — {reason}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Chain-walk the span, verify the tail certificate and (if supplied) the tail
/// transaction set, then prove any claims against that set.
pub fn verify_span<C: Crypto>(
    crypto: &C,
    trust: &Trust,
    start_seq: u32,
    start_hash: [u8; 32],
    proof: &SpanProof,
) -> Result<SpanOutcome, Error> {
    if proof.headers.is_empty() {
        return Err(Error::EmptySpan);
    }

    // 1) the headers form a chain from the starting head to the tail.
    let mut prev_seq = start_seq;
    let mut prev_hash = start_hash;
    let mut pinned_by_set = start_hash;
    let mut tail: Option<(LedgerHeader, [u8; 32])> = None;
    for (index, raw) in proof.headers.iter().enumerate() {
        let header: LedgerHeader = decode(raw).map_err(|_| Error::InvalidHeaderXdr { index })?;
        // `checked_add` keeps the u32::MAX edge an error instead of a panic;
        // no real ledger can chain past u32::MAX anyway.
        let expected_seq = prev_seq
            .checked_add(1)
            .ok_or(Error::UnexpectedLedgerSeq { index, prev_seq, actual: header.ledger_seq })?;
        if header.ledger_seq != expected_seq {
            return Err(Error::UnexpectedLedgerSeq { index, prev_seq, actual: header.ledger_seq });
        }
        if header.previous_ledger_hash.0 != prev_hash {
            return Err(Error::PreviousLedgerHashMismatch { index });
        }
        let hash = crypto.sha256(raw);
        let seq = header.ledger_seq;
        if index + 1 == proof.headers.len() {
            // `prev_hash` is the point the tail set must pin.
            pinned_by_set = prev_hash;
            tail = Some((header, hash));
        }
        prev_seq = seq;
        prev_hash = hash;
    }
    let (tail_header, tail_hash) = tail.ok_or(Error::EmptySpan)?;
    if tail_header.ledger_version > trust.max_protocol_version {
        return Err(Error::ProtocolVersionExceeded {
            version: tail_header.ledger_version,
            max: trust.max_protocol_version,
        });
    }

    // 2) a quorum of trusted nodes externalized exactly the tail header's SCP value.
    let (signed_value, quorum_signers) = check_quorum(crypto, trust, &tail_header, proof.tail_envelopes)?;

    // 3) the signed value commits to the tail's transaction set ...
    let mut pinned_seq = None;
    let mut txs: Vec<TransactionEnvelope> = Vec::new();
    if let Some(set) = proof.tail_set {
        if crypto.sha256(set) != signed_value.tx_set_hash.0 {
            return Err(Error::TxSetHashMismatch);
        }
        // ... and the set pins the previous header, which pins the chain backwards.
        let set_prev = if proof.claims.is_empty() {
            tx_set_prev_hash(set)?
        } else {
            let (prev, list) = parse_tx_set(set)?;
            txs = list;
            prev.0
        };
        if set_prev != pinned_by_set {
            return Err(Error::TxSetPreviousLedgerHashMismatch);
        }
        // The tail header is pinned by the *next* span that brings a set; this
        // span is pinned through the ledger before the tail.
        pinned_seq = Some(prev_seq.saturating_sub(1));
    }

    // 4) claims need the set: inclusion cannot be proven without it.
    if !proof.claims.is_empty() && proof.tail_set.is_none() {
        return Err(Error::ClaimsRequireTxSet);
    }
    let mut claim_ids = Vec::with_capacity(proof.claims.len());
    for (claim, (envelope_bytes, index)) in proof.claims.iter().enumerate() {
        let idx = *index as usize;
        if idx >= txs.len() {
            return Err(Error::ClaimIndexOutOfRange { claim, index: *index, len: txs.len() });
        }
        let encoded = encode(&txs[idx])?;
        if encoded != *envelope_bytes {
            return Err(Error::ClaimEnvelopeMismatch { claim, index: *index });
        }
        claim_ids.push(crypto.sha256(&encoded));
    }

    Ok(SpanOutcome {
        tail_seq: tail_header.ledger_seq,
        tail_hash,
        pinned_seq,
        quorum_signers,
        claim_ids,
    })
}

/// Verify signatures of trusted nodes externalizing exactly the header's SCP
/// value. One pass; stops as soon as the threshold is met.
fn check_quorum<C: Crypto>(
    crypto: &C,
    trust: &Trust,
    header: &LedgerHeader,
    envelopes: &[&[u8]],
) -> Result<(StellarValue, u32), Error> {
    let mut counted: Vec<[u8; 32]> = Vec::new();
    let mut value: Option<StellarValue> = None;
    for (index, raw) in envelopes.iter().enumerate() {
        let envelope: ScpEnvelope = decode(raw).map_err(|_| Error::InvalidEnvelopeXdr { index })?;
        let statement = &envelope.statement;
        if statement.slot_index != u64::from(header.ledger_seq) {
            continue; // witness for a different slot
        }
        let ScpStatementPledges::Externalize(ext) = &statement.pledges else {
            continue; // only EXTERNALIZE finalizes a value
        };

        // The externalized value must be exactly the header's SCP value.
        let externalized: StellarValue = decode(value_bytes(&ext.commit.value))
            .map_err(|_| Error::InvalidStellarValueXdr { index })?;
        if externalized != header.scp_value {
            return Err(Error::ExternalizedValueMismatch { index });
        }
        value = Some(externalized);

        let PublicKey::PublicKeyTypeEd25519(key) = &statement.node_id.0;
        let node_id = key.0;
        if counted.contains(&node_id) {
            continue; // one vote per node
        }
        if !trust.trusted_nodes.contains(&node_id) {
            continue; // not part of the pinned trust set
        }

        // stellar-core: signature = sign(xdr(networkID, ENVELOPE_TYPE_SCP, statement))
        let statement_xdr = encode(statement)?;
        let mut message = Vec::with_capacity(32 + 4 + statement_xdr.len());
        message.extend_from_slice(&trust.network_id);
        message.extend_from_slice(&(EnvelopeType::Scp as i32).to_be_bytes());
        message.extend_from_slice(&statement_xdr);

        let signature = signature_bytes(&envelope.signature).ok_or(Error::InvalidSignatureLength { index })?;
        if !crypto.ed25519_verify(&signature, &message, &node_id) {
            return Err(Error::InvalidValidatorSignature { index });
        }

        counted.push(node_id);
        if counted.len() as u32 >= trust.threshold {
            break;
        }
    }
    let signers = counted.len() as u32;
    if signers < trust.threshold {
        return Err(Error::QuorumNotReached { signers, threshold: trust.threshold });
    }
    let value = value.ok_or(Error::NoExternalizeStatement)?;
    Ok((value, signers))
}

// ---------------------------------------------------------------- decoding helpers

fn decode<T: ReadXdr>(bytes: &[u8]) -> Result<T, stellar_xdr::Error> {
    let mut reader = Limited::new(Cursor::new(bytes), Limits::none());
    T::read_xdr_to_end(&mut reader)
}

fn try_decode<T: ReadXdr>(bytes: &[u8]) -> Option<T> {
    let mut reader = Limited::new(Cursor::new(bytes), Limits::none());
    T::read_xdr_to_end(&mut reader).ok()
}

fn encode<T: WriteXdr>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut writer = Limited::new(&mut buf, Limits::none());
    value.write_xdr(&mut writer).map_err(|_| Error::NonCanonicalTxSet)?;
    Ok(buf)
}

/// Read `previousLedgerHash` from a transaction set without decoding the set.
///
/// ponytail: the set kind is inferred from the XDR union discriminant (4 bytes) instead
/// of parsing every transaction envelope — a 341 KiB set of ~385 envelopes reduced to a
/// 36-byte read. The sha256 check pins these bytes to the signed value and the chain
/// check pins the hash, so misreading the kind fails closed (it can only reject), with
/// the theoretical exception of a 2^-32 prefix collision. Upgrade path: [`parse_tx_set`],
/// which is exact and already used whenever claims are present.
fn tx_set_prev_hash(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.len() < 36 {
        return Err(Error::TxSetTooShort);
    }
    let discriminant = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let offset = if discriminant == 1 {
        4 // GeneralizedTransactionSet: union discriminant precedes TransactionSetV1
    } else {
        0 // TransactionSet starts with the hash
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[offset..offset + 32]);
    Ok(out)
}

/// Split a transaction set into its `previousLedgerHash` and its transactions.
///
/// Both encodings start with that hash: `TransactionSet` directly, and
/// `GeneralizedTransactionSet` after the union discriminant. Whichever type
/// re-encodes byte-identically is the one the network hashed.
fn parse_tx_set(bytes: &[u8]) -> Result<(Hash, Vec<TransactionEnvelope>), Error> {
    if let Some(set) = try_decode::<GeneralizedTransactionSet>(bytes) {
        if encode(&set)? == bytes {
            let GeneralizedTransactionSet::V1(v1) = &set;
            let mut txs = Vec::new();
            for phase in v1.phases.iter() {
                match phase {
                    TransactionPhase::V0(components) => {
                        for component in components.iter() {
                            let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(component) =
                                component;
                            txs.extend(component.txs.iter().cloned());
                        }
                    }
                    TransactionPhase::V1(component) => {
                        // Parallel phase: stages of dependent-tx clusters, flattened in
                        // serialization order so indices match the set as hashed.
                        for stage in component.execution_stages.iter() {
                            for cluster in stage.0.iter() {
                                txs.extend(cluster.0.iter().cloned());
                            }
                        }
                    }
                }
            }
            return Ok((v1.previous_ledger_hash.clone(), txs));
        }
    }
    let set: TransactionSet = decode(bytes).map_err(|_| Error::InvalidTxSetXdr)?;
    if encode(&set)? != bytes {
        return Err(Error::NonCanonicalTxSet);
    }
    Ok((set.previous_ledger_hash.clone(), set.txs.iter().cloned().collect()))
}

fn value_bytes(value: &Value) -> &[u8] {
    value.0.as_slice()
}

fn signature_bytes(signature: &Signature) -> Option<[u8; 64]> {
    <[u8; 64]>::try_from(signature.0.as_slice()).ok()
}
