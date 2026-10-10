//! Transaction **outcome** proofs: what the network did with a transaction, not
//! merely that it was submitted.
//!
//! # What commits outcomes
//!
//! `LedgerHeader.tx_set_result_hash` is *"the TransactionResultSet that led to
//! this ledger"* (stellar-xdr `Stellar-ledger.x`), set by stellar-core as
//! `xdrSha256(txResultSet)` — a plain hash over the canonical
//! [`TransactionResultSet`] XDR. No generalized/legacy split, unlike the
//! transaction-set hashing in [`crate::verify_span`].
//!
//! # Which header is allowed to commit them
//!
//! **Never the tail header.** The quorum certificate signs a
//! [`stellar_xdr::StellarValue`] (`txSetHash`, `closeTime`, `upgrades`) — it does
//! *not* cover `tx_set_result_hash`, so that field of the tail header is as
//! unauthenticated as the tail's `ledger_version`, which [`crate::verify_span`]
//! deliberately ignores. Binding outcomes to the tail header would let anyone
//! take real headers, a real certificate and a real transaction set, rewrite only
//! the tail header's `tx_set_result_hash`, and present a failed payment as a
//! success.
//!
//! Outcomes are therefore bound to the **authenticated head** — the ledger the
//! span pins through signed bytes. That header's hash is pinned by the tail
//! transaction set, so every field in its XDR, `tx_set_result_hash` included, is
//! authentic.
//!
//! The consequence is inherent to sparse verification and is not a workaround:
//! the outcome for ledger L is provable in the span whose authenticated head is
//! L — one span after L was a span's tail.
//!
//! # The join key
//!
//! [`TransactionResultPair::transaction_hash`] is **not** the envelope hash that
//! `claim_id` uses. stellar-core sets it to `getContentsHash()` — the
//! network-bound signature-payload hash — whereas `claim_id` is
//! `sha256(xdr(TransactionEnvelope))` (`getFullHash()`). The two never compare
//! equal. [`tx_contents_hash`] reproduces stellar-core's preimage exactly.
//!
//! Because stellar-core emits a [`TransactionResultPair`] only for a transaction
//! it actually applied, a result row proves inclusion on its own. An outcome
//! claim therefore needs no separate transaction-set proof.

use stellar_xdr::{
    EnvelopeType, Hash, InnerTransactionResultResult, InvokeHostFunctionResult,
    InvokeHostFunctionSuccessPreImage, OperationResult, OperationResultTr, TransactionEnvelope,
    TransactionResult, TransactionResultPair, TransactionResultResult, TransactionResultSet, VecM,
    WriteXdr,
};

use super::{decode, encode, Crypto, Error};

/// Append the canonical XDR of `value` to `out`.
fn push_xdr<T: WriteXdr>(out: &mut Vec<u8>, value: &T) -> Result<(), Error> {
    out.extend_from_slice(&encode(value)?);
    Ok(())
}

/// stellar-core `TransactionFrame::getContentsHash()` /
/// `FeeBumpTransactionFrame::getContentsHash()`: `sha256` over the network id,
/// the envelope-type tag, and the transaction body.
///
/// This is what [`TransactionResultPair::transaction_hash`] carries. It is
/// **not** `sha256(xdr(TransactionEnvelope))` — the envelope hash includes the
/// signatures and is what `claim_id` uses.
///
/// The v0 preimage carries an extra `0` tag where v1 carries its
/// `MuxedAccount` discriminant, which is why
/// `xdr_to_opaque(mNetworkID, ENVELOPE_TYPE_TX, 0, mEnvelope.v0().tx)` hashes
/// the same bytes as the v0-to-v1 converted `Transaction`.
///
/// **Coverage gap:** `testdata/fixture.json` contains only v1 envelopes, so the
/// v1 branch is the only one exercised against real data. The v0 and fee-bump
/// preimages are transcribed from stellar-core (`TransactionFrame.cpp`,
/// `FeeBumpTransactionFrame.cpp`) but have no hand-vector yet — do not read
/// green fixture tests as covering them.
pub fn tx_contents_hash<C: Crypto>(
    crypto: &C,
    network_id: [u8; 32],
    envelope_bytes: &[u8],
) -> Result<[u8; 32], Error> {
    let envelope: TransactionEnvelope =
        decode(envelope_bytes).map_err(|_| Error::InvalidTxEnvelopeXdr)?;
    let mut pre = Vec::with_capacity(envelope_bytes.len() + 40);
    pre.extend_from_slice(&network_id);
    match &envelope {
        TransactionEnvelope::TxV0(e) => {
            push_xdr(&mut pre, &EnvelopeType::Tx)?;
            push_xdr(&mut pre, &0i32)?;
            push_xdr(&mut pre, &e.tx)?;
        }
        TransactionEnvelope::Tx(e) => {
            push_xdr(&mut pre, &EnvelopeType::Tx)?;
            push_xdr(&mut pre, &e.tx)?;
        }
        TransactionEnvelope::TxFeeBump(e) => {
            push_xdr(&mut pre, &EnvelopeType::TxFeeBump)?;
            push_xdr(&mut pre, &e.tx)?;
        }
    }
    Ok(crypto.sha256(&pre))
}

/// Decode the supplied [`TransactionResultSet`], requiring canonical XDR so
/// [`outcome_digest`] is well defined.
pub fn decode_result_set(bytes: &[u8]) -> Result<TransactionResultSet, Error> {
    let set: TransactionResultSet = decode(bytes).map_err(|_| Error::InvalidResultSetXdr)?;
    if encode(&set).map_or(true, |b| b != bytes) {
        return Err(Error::NonCanonicalResultSet);
    }
    Ok(set)
}

/// `sha256` over the canonical [`TransactionResultPair`] XDR — what the epoch
/// journal commits for a proven outcome.
pub fn outcome_digest<C: Crypto>(
    crypto: &C,
    pair: &TransactionResultPair,
) -> Result<[u8; 32], Error> {
    Ok(crypto.sha256(&encode(pair)?))
}

/// Prove `(tx envelope, TransactionResultPair)` outcome claims against an
/// authenticated [`TransactionResultSet`].
///
/// Each claim must satisfy both bindings:
///
/// 1. `pair.transaction_hash == tx_contents_hash(envelope)` — the row belongs to
///    this envelope, not to some other transaction in the same ledger;
/// 2. `pair` is an element of `results` — the row is the one the ledger
///    committed, so a `TxFailed` cannot be re-presented as `TxSuccess`.
///
/// Returns the outcome digest per claim, in claim order.
pub fn verify_outcome_claims<C: Crypto>(
    crypto: &C,
    network_id: [u8; 32],
    results: &TransactionResultSet,
    claims: &[(&[u8], &[u8])],
) -> Result<Vec<[u8; 32]>, Error> {
    let mut digests = Vec::with_capacity(claims.len());
    for (outcome, (envelope_bytes, pair_bytes)) in claims.iter().enumerate() {
        let pair: TransactionResultPair =
            decode(pair_bytes).map_err(|_| Error::InvalidResultPairXdr { outcome })?;
        let want = tx_contents_hash(crypto, network_id, envelope_bytes)
            .map_err(|_| Error::InvalidOutcomeEnvelopeXdr { outcome })?;
        if pair.transaction_hash.0 != want {
            return Err(Error::OutcomeTransactionHashMismatch { outcome });
        }
        let canonical = encode(&pair)?;
        let committed = results
            .results
            .iter()
            .any(|row| encode(row).map_or(false, |b| b == canonical));
        if !committed {
            return Err(Error::OutcomeNotInResults { outcome });
        }
        digests.push(crypto.sha256(&canonical));
    }
    Ok(digests)
}

/// Operation results of a transaction result, at the level the Soroban hook
/// hangs off.
fn soroban_success_hash(result: &TransactionResult) -> Option<Hash> {
    fn ops(results: &VecM<OperationResult>) -> Option<Hash> {
        results.iter().find_map(|op| match op {
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(
                InvokeHostFunctionResult::Success(h),
            )) => Some(h.clone()),
            _ => None,
        })
    }
    match &result.result {
        TransactionResultResult::TxSuccess(rs) => ops(rs),
        TransactionResultResult::TxFeeBumpInnerSuccess(p) => match &p.result.result {
            InnerTransactionResultResult::TxSuccess(rs) => ops(rs),
            _ => None,
        },
        _ => None,
    }
}

/// Verify that `preimage_bytes` is the [`InvokeHostFunctionSuccessPreImage`]
/// committed by a *proven* [`TransactionResultPair`], and return it.
///
/// This is the receipt-event proof: the emitted [`stellar_xdr::ContractEvent`]s
/// sit inside the hashed preimage, so once the result pair is proven against an
/// authenticated result set the events are exactly the ones the ledger agreed
/// on. The work is one `sha256` over supplied bytes.
pub fn soroban_success_preimage<C: Crypto>(
    crypto: &C,
    result_pair_bytes: &[u8],
    preimage_bytes: &[u8],
) -> Result<InvokeHostFunctionSuccessPreImage, Error> {
    let pair: TransactionResultPair = decode(result_pair_bytes)
        .map_err(|_| Error::SorobanSuccess("not a TransactionResultPair"))?;
    let committed = soroban_success_hash(&pair.result)
        .ok_or(Error::SorobanSuccess("no successful invoke_host_function"))?;
    if crypto.sha256(preimage_bytes) != committed.0 {
        return Err(Error::SorobanSuccess("success preimage hash mismatch"));
    }
    let preimage: InvokeHostFunctionSuccessPreImage = decode(preimage_bytes)
        .map_err(|_| Error::SorobanSuccess("invalid success preimage xdr"))?;
    if encode(&preimage).map_or(true, |b| b != preimage_bytes) {
        return Err(Error::SorobanSuccess("non-canonical success preimage"));
    }
    Ok(preimage)
}

/// The committed `sha256(InvokeHostFunctionSuccessPreImage)` of a result pair,
/// for callers that want to check a preimage themselves.
pub fn committed_soroban_hash(
    result_pair_bytes: &[u8],
) -> Result<Option<Hash>, Error> {
    let pair: TransactionResultPair = decode(result_pair_bytes)
        .map_err(|_| Error::SorobanSuccess("not a TransactionResultPair"))?;
    Ok(soroban_success_hash(&pair.result))
}
