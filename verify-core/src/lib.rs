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
//! - present → the span is pinned immediately (`authenticated_head` reports
//!   the latest authenticated checkpoint — the ledger *before* the tail);
//! - absent → the span is provisional. The head still advances and later spans
//!   still chain to it, and the chain gets pinned by any later span that does
//!   bring a set. Claims can never be provisional: proving inclusion needs the
//!   set, and the predecessor context (its header or an authenticated anchor),
//!   so claims carry both.

use std::io::Cursor;

use stellar_xdr::{
    EnvelopeType, GeneralizedTransactionSet, Hash, LedgerHeader, LedgerUpgrade, Limited, Limits,
    PublicKey, ReadXdr, ScpEnvelope, ScpStatementPledges, Signature, StellarValue,
    TransactionEnvelope, TransactionPhase, TransactionSet, TxSetComponent, Value, WriteXdr,
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

/// Validate quorum configuration before processing any witness.
pub fn validate_trust(trust: &Trust) -> Result<(), Error> {
    if trust.threshold == 0 || trust.threshold as usize > trust.trusted_nodes.len() {
        return Err(Error::InvalidTrust("threshold outside trusted node count"));
    }
    for (index, node) in trust.trusted_nodes.iter().enumerate() {
        if trust.trusted_nodes[..index].contains(node) {
            return Err(Error::InvalidTrust("duplicate trusted node"));
        }
    }
    Ok(())
}

/// Domain-separated commitment to the complete policy, independent of node order.
pub fn trust_digest<C: Crypto>(crypto: &C, trust: &Trust) -> Result<[u8; 32], Error> {
    validate_trust(trust)?;
    let mut nodes = trust.trusted_nodes.clone();
    nodes.sort_unstable();
    let mut bytes = Vec::with_capacity(80 + nodes.len() * 32);
    bytes.extend_from_slice(b"stellar-lightclient/trust/v1\0");
    bytes.extend_from_slice(&trust.network_id);
    bytes.extend_from_slice(&(nodes.len() as u32).to_be_bytes());
    for node in nodes {
        bytes.extend_from_slice(&node);
    }
    bytes.extend_from_slice(&trust.threshold.to_be_bytes());
    bytes.extend_from_slice(&trust.max_protocol_version.to_be_bytes());
    Ok(crypto.sha256(&bytes))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub seq: u32,
    pub hash: [u8; 32],
}

/// A span of consecutive ledgers plus the evidence authenticating its tail.
/// Borrowed so the caller's decoded payload buffers are never copied.
pub struct SpanProof<'a> {
    /// Optional authenticated starting header, needed for single-header claims.
    pub start_header: Option<&'a [u8]>,
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
    pub authenticated_head: Option<Checkpoint>,
    /// Distinct trusted signers whose signatures were verified.
    pub quorum_signers: u32,
    /// sha256(tx envelope) per proven claim.
    pub claim_ids: Vec<[u8; 32]>,
}

/// One variant per failure of the reference semantics. `Display` carries the
/// contract's original panic string plus positional context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidTrust(&'static str),
    InvalidStartHeader,
    ClaimsRequirePredecessor,
    InvalidUpgradeXdr,
    UpgradeNotMonotonic { version: u32, predecessor: u32 },
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
            Error::InvalidTrust(reason) => write!(f, "invalid trust: {reason}"),
            Error::InvalidStartHeader => f.write_str("starting header does not match checkpoint"),
            Error::ClaimsRequirePredecessor => f.write_str("claims require an authenticated predecessor header"),
            Error::InvalidUpgradeXdr => f.write_str("invalid signed ledger upgrade"),
            Error::UpgradeNotMonotonic { version, predecessor } => write!(
                f,
                "protocol upgrade must increase monotonically — {version} <= {predecessor}"
            ),
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
    validate_trust(trust)?;
    if proof.headers.is_empty() {
        return Err(Error::EmptySpan);
    }

    // 1) the headers form a chain from the starting head to the tail.
    let mut prev_seq = start_seq;
    let mut prev_hash = start_hash;
    let mut pinned_by_set = start_hash;
    let mut tail: Option<(LedgerHeader, [u8; 32])> = None;
    let mut predecessor_version = None;
    if let Some(raw) = proof.start_header {
        let header: LedgerHeader = decode(raw).map_err(|_| Error::InvalidStartHeader)?;
        if header.ledger_seq != start_seq || crypto.sha256(raw) != start_hash {
            return Err(Error::InvalidStartHeader);
        }
        check_protocol(header.ledger_version, trust)?;
        predecessor_version = Some(header.ledger_version);
    }
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
        } else {
            check_protocol(header.ledger_version, trust)?;
            predecessor_version = Some(header.ledger_version);
        }
        prev_seq = seq;
        prev_hash = hash;
    }
    let (tail_header, tail_hash) = tail.ok_or(Error::EmptySpan)?;

    // 2) a quorum of trusted nodes externalized exactly the tail header's SCP value.
    let (signed_value, quorum_signers) = check_quorum(crypto, trust, &tail_header, proof.tail_envelopes)?;
    // The tail's unsigned ledger_version is not authenticated, so it is never
    // consulted: the signed `LedgerUpgrade::Version` ceilings and the
    // authenticated predecessor govern what transactions may execute.
    for upgrade in signed_value.upgrades.iter() {
        // `UpgradeType` is opaque bytes; the inner upgrade is attacker-shaped
        // until decoded, so malformed bytes fail closed.
        let upgrade: LedgerUpgrade =
            decode(upgrade.0.as_slice()).map_err(|_| Error::InvalidUpgradeXdr)?;
        if let LedgerUpgrade::Version(version) = upgrade {
            check_protocol(version, trust)?;
            // Upgrades::isValidForApply: strictly monotonic — the only version
            // a ledger upgrade can select is above the predecessor's.
            if let Some(prev) = predecessor_version {
                if version <= prev {
                    return Err(Error::UpgradeNotMonotonic { version, predecessor: prev });
                }
            }
        }
    }

    // 3) the signed value commits to the tail's transaction set ...
    let mut authenticated_head = None;
    let mut txs: Vec<TransactionEnvelope> = Vec::new();
    if let Some(set) = proof.tail_set {
        // ... and the set pins the previous header, which pins the chain
        // backwards, and its signed `txSetHash` commits to exactly its
        // contents. stellar-core hashes the two encodings differently
        // (TxSetFrame.cpp): generalized over the whole XDR, legacy as
        // SHA256(prev || envelopes) without the vector count.
        let kind = if proof.claims.is_empty() {
            tx_set_kind_prev(set, pinned_by_set)?
        } else {
            predecessor_version.ok_or(Error::ClaimsRequirePredecessor)?;
            let (kind, prev, list) = parse_tx_set(set)?;
            if prev.0 != pinned_by_set {
                return Err(Error::TxSetPreviousLedgerHashMismatch);
            }
            txs = list;
            kind
        };
        let set_hash = match kind {
            SetKind::Generalized => crypto.sha256(set),
            SetKind::Legacy => legacy_tx_set_contents_hash(crypto, set)
                .ok_or(Error::TxSetTooShort)?,
        };
        if set_hash != signed_value.tx_set_hash.0 {
            return Err(Error::TxSetHashMismatch);
        }
        // The tail header is pinned by the *next* span that brings a set; this
        // span is pinned through the ledger before the tail.
        authenticated_head = Some(Checkpoint { seq: prev_seq - 1, hash: pinned_by_set });
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
        authenticated_head,
        quorum_signers,
        claim_ids,
    })
}

fn check_protocol(version: u32, trust: &Trust) -> Result<(), Error> {
    if version > trust.max_protocol_version {
        return Err(Error::ProtocolVersionExceeded { version, max: trust.max_protocol_version });
    }
    Ok(())
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
    let mut reader = Limited::new(Cursor::new(bytes), Limits { depth: 64, len: bytes.len() });
    T::read_xdr_to_end(&mut reader)
}

fn try_decode<T: ReadXdr>(bytes: &[u8]) -> Option<T> {
    decode(bytes).ok()
}

fn encode<T: WriteXdr>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut writer = Limited::new(&mut buf, Limits::none());
    value.write_xdr(&mut writer).map_err(|_| Error::NonCanonicalTxSet)?;
    Ok(buf)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetKind {
    Generalized,
    Legacy,
}

/// `sha256(previousLedgerHash || raw envelope XDRs)` for a legacy
/// `TransactionSet`, per stellar-core's
/// `computeNonGeneralizedTxSetContentsHash` — the 4-byte vector count at
/// bytes 32..36 is deliberately **not** hashed. `set` must be the canonical
/// XDR encoding; `None` on any input too short to carry the prefix.
pub fn legacy_tx_set_contents_hash<C: Crypto>(crypto: &C, set: &[u8]) -> Option<[u8; 32]> {
    if set.len() < 36 {
        return None;
    }
    let mut buf = Vec::with_capacity(set.len() - 4);
    buf.extend_from_slice(&set[..32]);
    buf.extend_from_slice(&set[36..]);
    Some(crypto.sha256(&buf))
}

/// The signed hash pins the bytes; match both possible layouts against the
/// expected predecessor rather than guessing from a colliding legacy prefix.
fn tx_set_kind_prev(bytes: &[u8], expected: [u8; 32]) -> Result<SetKind, Error> {
    if bytes.len() < 36 {
        return Err(Error::TxSetTooShort);
    }
    if bytes[..4] == 1i32.to_be_bytes() && bytes[4..36] == expected {
        Ok(SetKind::Generalized)
    } else if bytes[..32] == expected {
        Ok(SetKind::Legacy)
    } else {
        Err(Error::TxSetPreviousLedgerHashMismatch)
    }
}

/// Split a transaction set into its kind, its `previousLedgerHash`, and its
/// transactions (moved out of the parsed set — no deep copy).
///
/// Whichever encoding re-encodes byte-identically is the one the network
/// hashed; both encodings start with the previous hash
/// (`GeneralizedTransactionSet` after the union discriminant).
fn parse_tx_set(bytes: &[u8]) -> Result<(SetKind, Hash, Vec<TransactionEnvelope>), Error> {
    if let Some(set) = try_decode::<GeneralizedTransactionSet>(bytes) {
        if encode(&set)? == bytes {
            let GeneralizedTransactionSet::V1(v1) = set;
            let mut txs = Vec::new();
            for phase in Vec::from(v1.phases) {
                match phase {
                    TransactionPhase::V0(components) => {
                        for component in Vec::from(components) {
                            let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(component) =
                                component;
                            txs.extend(Vec::from(component.txs));
                        }
                    }
                    TransactionPhase::V1(component) => {
                        // Parallel phase: stages of dependent-tx clusters, flattened in
                        // serialization order so indices match the set as hashed.
                        for stage in Vec::from(component.execution_stages) {
                            for cluster in Vec::from(stage.0) {
                                txs.extend(Vec::from(cluster.0));
                            }
                        }
                    }
                }
            }
            return Ok((SetKind::Generalized, v1.previous_ledger_hash, txs));
        }
    }
    let set: TransactionSet = decode(bytes).map_err(|_| Error::InvalidTxSetXdr)?;
    if encode(&set)? != bytes {
        return Err(Error::NonCanonicalTxSet);
    }
    Ok((SetKind::Legacy, set.previous_ledger_hash, Vec::from(set.txs)))
}

fn value_bytes(value: &Value) -> &[u8] {
    value.0.as_slice()
}

fn signature_bytes(signature: &Signature) -> Option<[u8; 64]> {
    <[u8; 64]>::try_from(signature.0.as_slice()).ok()
}
