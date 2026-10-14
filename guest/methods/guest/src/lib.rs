//! RISC Zero guest for the Stellar light-client epoch path.
//!
//! Verifies a whole epoch of ledger closes + deposit claims with the shared
//! [`verify_core::verify_span`] (one quorum certificate per span, chain-pinned
//! through each span's tail transaction set) and commits a compact
//! [`verify_core::EpochJournal`]. Off-chain, the relayer builds an [`EpochInput`],
//! `run_epoch_bytes` deserializes it — in-guest the zkVM runs this same code,
//! so the journal the NEAR contract checks was produced by the same
//! verification path.

use bincode::Options;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, verify_batch};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use verify_core::{
    encode_journal, trust_digest, verify_span, Checkpoint, Crypto, EpochJournal,
    Error, SpanProof, Trust,
};

// Byte-transport serde helpers.
//
// The XDR payloads below ride bincode's *byte buffer* encoding instead of the
// default `Vec<u8>` sequence. The wire form is byte-identical — `u64` length
// then raw bytes, for bincode's serializer and the `u8` sequence serde would
// otherwise emit — but deserialisation takes the reader's bulk path instead
// of one seq-visitor dispatch *per byte*. On real fixtures the per-byte walk
// of the tail transaction set dominated the input decode.

/// Serialises as bytes; deserialises through `deserialize_byte_buf`.
struct ByteBuf<'a>(&'a [u8]);

impl Serialize for ByteBuf<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

/// The `Vec<u8>` half of the pair: accept owned or borrowed bytes (the bulk
/// path), and a `u8` sequence too, so payloads encoded by a non-bincode
/// serde backend still decode.
pub(crate) struct OwnedByteBuf(pub(crate) Vec<u8>);

impl<'de> Deserialize<'de> for OwnedByteBuf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_byte_buf(ByteBufVisitor).map(OwnedByteBuf)
    }
}

struct ByteBufVisitor;

impl<'de> serde::de::Visitor<'de> for ByteBufVisitor {
    type Value = Vec<u8>;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a byte buffer")
    }
    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
        Ok(v)
    }
    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, seq: A) -> Result<Vec<u8>, A::Error> {
        Vec::<u8>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
    }
}

/// `Option<Vec<u8>>` field helper.
mod opt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{ByteBuf, OwnedByteBuf};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            None => s.serialize_none(),
            Some(bytes) => s.serialize_some(&ByteBuf(bytes)),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        struct OptionByteBuf;
        impl<'de> serde::de::Visitor<'de> for OptionByteBuf {
            type Value = Option<Vec<u8>>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an optional byte buffer")
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Option<Vec<u8>>, E> {
                Ok(None)
            }
            fn visit_some<D: Deserializer<'de>>(
                self,
                d: D,
            ) -> Result<Option<Vec<u8>>, D::Error> {
                OwnedByteBuf::deserialize(d).map(|b| Some(b.0))
            }
        }
        d.deserialize_option(OptionByteBuf)
    }
}

/// `Vec<Vec<u8>>` field helper.
mod bytes_list {
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};

    use super::{ByteBuf, OwnedByteBuf};

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for bytes in v {
            seq.serialize_element(&ByteBuf(bytes))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        struct ByteBufList;
        impl<'de> serde::de::Visitor<'de> for ByteBufList {
            type Value = Vec<Vec<u8>>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a list of byte buffers")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Vec<Vec<u8>>, A::Error> {
                let mut v = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(OwnedByteBuf(bytes)) = seq.next_element()? {
                    v.push(bytes);
                }
                Ok(v)
            }
        }
        d.deserialize_seq(ByteBufList)
    }
}

/// `Vec<(Vec<u8>, u32)>` field helper: claimed envelope + set index.
mod claims_list {
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{ByteBuf, OwnedByteBuf};

    pub fn serialize<S: Serializer>(v: &[(Vec<u8>, u32)], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for (bytes, index) in v {
            seq.serialize_element(&(ByteBuf(bytes), *index))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<(Vec<u8>, u32)>, D::Error> {
        Vec::<(OwnedByteBuf, u32)>::deserialize(d)
            .map(|v| v.into_iter().map(|(b, i)| (b.0, i)).collect())
    }
}

/// `Vec<(Vec<u8>, Vec<u8>)>` field helper: outcome claim pair.
mod outcome_list {
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{ByteBuf, OwnedByteBuf};

    pub fn serialize<S: Serializer>(
        v: &[(Vec<u8>, Vec<u8>)],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for (bytes, pair) in v {
            seq.serialize_element(&(ByteBuf(bytes), ByteBuf(pair)))?;
        }
        seq.end()
    }

    /// `(tx envelope XDR, TransactionResultPair XDR)`.
    type OutcomePair = (Vec<u8>, Vec<u8>);

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<OutcomePair>, D::Error> {
        Vec::<(OwnedByteBuf, OwnedByteBuf)>::deserialize(d)
            .map(|v| v.into_iter().map(|(b, p)| (b.0, p.0)).collect())
    }
}

/// The guest's [`Crypto`] backend: real SHA-256 and ed25519, no shortcuts.
/// Malformed keys or signatures fail closed (`false`) — verification never
/// panics on attacker-controlled input.
pub struct Sha256Dalek;

impl Crypto for Sha256Dalek {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn ed25519_verify(&self, signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let sig = Signature::from_bytes(signature);
        // `verify`, not `verify_strict`. In this crate the two differ by exactly
        // one check: `verify_strict` additionally rejects small-order `R` or `A`
        // (ed25519-dalek `verifying.rs`), and `verify` is the one matching
        // nearcore's host `ed25519_verify`. Non-canonical `S` is *not* the
        // difference — both paths reject it — so that is not what "non-strict"
        // refers to here.
        //
        // The property is "accepts exactly what the chain accepts", pinned case
        // by case in `verifier/tests/host_ed25519_parity.rs`. Known gap: that
        // corpus has no small-order `R`/`A` case, which is the one axis where the
        // two rules actually part; building a signature valid under a weak key
        // needs a degenerate nonce.
        key.verify(message, &sig).is_ok()
    }

    /// One multi-scalar multiplication for the whole quorum instead of
    /// `2 * n` double-base muls. `verify_batch` derives its per-signature
    /// weights from a Merlin transcript (`ZeroRng`), so it is deterministic and
    /// safe to run inside the zkVM — no OS entropy anywhere in the path.
    ///
    /// The verifier semantics are unchanged: the caller falls back to
    /// per-signature checks whenever this returns `false`, so a bad batch
    /// still names the offending index.
    fn ed25519_verify_batch(
        &self,
        signatures: &[[u8; 64]],
        messages: &[&[u8]],
        public_keys: &[[u8; 32]],
    ) -> bool {
        if signatures.len() != messages.len() || signatures.len() != public_keys.len() {
            return false;
        }
        let sigs: Vec<Signature> = signatures.iter().map(Signature::from_bytes).collect();
        let keys: Result<Vec<VerifyingKey>, _> =
            public_keys.iter().map(|k| VerifyingKey::from_bytes(k)).collect();
        match keys {
            Ok(keys) => verify_batch(messages, &sigs, &keys).is_ok(),
            Err(_) => false,
        }
    }
}

/// [`Sha256Dalek`] with the epoch's trust-set keys decompressed once up
/// front, instead of once per signature per span (`from_bytes` is Edwards
/// point decompression — hundreds of thousands of cycles each).
///
/// `check_quorum` filters every candidate through `trust.trusted_nodes`
/// before the signature reaches a crypto call, so every key that reaches
/// this backend was in the cache the moment it was built. A lookup miss
/// therefore means the trust set itself carried a malformed key —
/// decompressed on the spot, which `from_bytes` still rejects exactly as
/// the uncached path would. Fail-closed behaviour is unchanged.
struct CachedTrustKeys<'a>(&'a [([u8; 32], VerifyingKey)]);

impl CachedTrustKeys<'_> {
    /// Decompresses `trust` once. Malformed keys are dropped, not stored;
    /// their absence reproduces the uncached `false`.
    ///
    /// Linear scan over `trusted_nodes` per lookup: trust sets are tens of
    /// keys, the scan is a few tens of array compares per signature — noise
    /// against the decompression it avoids.
    fn for_trust(trust: &Trust) -> Vec<([u8; 32], VerifyingKey)> {
        trust
            .trusted_nodes
            .iter()
            .filter_map(|k| VerifyingKey::from_bytes(k).ok().map(|vk| (*k, vk)))
            .collect()
    }

    fn lookup(&self, bytes: &[u8; 32]) -> Option<VerifyingKey> {
        self.0.iter().find(|(k, _)| k == bytes).map(|(_, vk)| *vk)
    }
}

impl Crypto for CachedTrustKeys<'_> {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        Sha256Dalek.sha256(bytes)
    }

    fn ed25519_verify(&self, signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
        let Some(key) =
            self.lookup(public_key).or_else(|| VerifyingKey::from_bytes(public_key).ok())
        else {
            return false;
        };
        // `verify` (not `verify_strict`) — see `Sha256Dalek::ed25519_verify`
        // for why this is the nearcore-parity rule.
        key.verify(message, &Signature::from_bytes(signature)).is_ok()
    }

    fn ed25519_verify_batch(
        &self,
        signatures: &[[u8; 64]],
        messages: &[&[u8]],
        public_keys: &[[u8; 32]],
    ) -> bool {
        if signatures.len() != messages.len() || signatures.len() != public_keys.len() {
            return false;
        }
        let sigs: Vec<Signature> = signatures.iter().map(Signature::from_bytes).collect();
        let keys: Option<Vec<VerifyingKey>> = public_keys
            .iter()
            .map(|k| self.lookup(k).or_else(|| VerifyingKey::from_bytes(k).ok()))
            .collect();
        match keys {
            Some(keys) => verify_batch(messages, &sigs, &keys).is_ok(),
            None => false,
        }
    }
}

/// One span: headers, the tail's quorum certificates, the tail's transaction
/// set (if pinned), and claims against that set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpanInput {
    /// Authenticated header at `start_seq`, when claims need predecessor context.
    #[serde(with = "opt_bytes")]
    pub start_header: Option<Vec<u8>>,
    #[serde(with = "bytes_list")]
    pub headers: Vec<Vec<u8>>,
    #[serde(with = "bytes_list")]
    pub tail_envelopes: Vec<Vec<u8>>,
    #[serde(with = "opt_bytes")]
    pub tail_set: Option<Vec<u8>>,
    #[serde(with = "claims_list")]
    pub claims: Vec<(Vec<u8>, u32)>,
    /// Outcome claims `(tx envelope XDR, TransactionResultPair XDR)`, proven
    /// against [`SpanInput::tail_results`].
    #[serde(with = "outcome_list")]
    pub outcome_claims: Vec<(Vec<u8>, Vec<u8>)>,
    /// `TransactionResultSet` XDR for the **authenticated head** ledger.
    #[serde(with = "opt_bytes")]
    pub tail_results: Option<Vec<u8>>,
}

/// Everything the guest needs to attest an epoch. Field order is the relayer
/// contract: `trust`, `start_seq`, `start_hash`, `spans`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochInput {
    pub trust: Trust,
    pub start_seq: u32,
    pub start_hash: [u8; 32],
    pub spans: Vec<SpanInput>,
}

/// Verifies every span in order, chaining each span's start from the previous
/// outcome, and returns the journal for the whole epoch. Claim ids accumulate
/// across all spans; a zero-span epoch is valid and yields a start==end journal.
///
/// The journal's `end_seq`/`end_hash` commit the latest authenticated
/// checkpoint (the starting head if no span pinned anything), never the
/// unauthenticated tail, and `policy_digest` binds the trust policy the
/// proofs were signed under. Trust is validated even for a zero-span epoch.
pub fn run_epoch(input: &EpochInput) -> Result<EpochJournal, Error> {
    let keys = CachedTrustKeys::for_trust(&input.trust);
    run_epoch_with(&CachedTrustKeys(&keys), input)
}

/// Same as [`run_epoch`] with an injectable crypto backend (for testing).
pub fn run_epoch_with<C: Crypto>(crypto: &C, input: &EpochInput) -> Result<EpochJournal, Error> {
    let policy_digest = trust_digest(crypto, &input.trust)?;
    let mut authenticated_head = Checkpoint { seq: input.start_seq, hash: input.start_hash };
    let mut start_seq = input.start_seq;
    let mut start_hash = input.start_hash;
    let mut claim_ids = Vec::new();
    let mut outcome_digests = Vec::new();

    for span in &input.spans {
        let headers: Vec<&[u8]> = span.headers.iter().map(|h| h.as_slice()).collect();
        let tail_envelopes: Vec<&[u8]> = span
            .tail_envelopes
            .iter()
            .map(|e| e.as_slice())
            .collect();
        let claims: Vec<(&[u8], u32)> = span
            .claims
            .iter()
            .map(|(c, i)| (c.as_slice(), *i))
            .collect();
        let outcome_claims: Vec<(&[u8], &[u8])> = span
            .outcome_claims
            .iter()
            .map(|(e, p)| (e.as_slice(), p.as_slice()))
            .collect();

        let proof = SpanProof {
            start_header: span.start_header.as_deref(),
            headers: &headers,
            tail_envelopes: &tail_envelopes,
            tail_set: span.tail_set.as_deref(),
            claims: &claims,
            outcome_claims: &outcome_claims,
            tail_results: span.tail_results.as_deref(),
        };
        let outcome = verify_span(crypto, &input.trust, start_seq, start_hash, &proof)?;

        claim_ids.extend_from_slice(&outcome.claim_ids);
        outcome_digests.extend_from_slice(&outcome.outcome_digests);
        // Chaining follows the working tail; the journal commits only the
        // latest authenticated checkpoint, never an unauthenticated end.
        if let Some(head) = outcome.authenticated_head {
            authenticated_head = head;
        }
        start_seq = outcome.tail_seq;
        start_hash = outcome.tail_hash;
    }

    Ok(EpochJournal {
        start_seq: input.start_seq,
        start_hash: input.start_hash,
        end_seq: authenticated_head.seq,
        end_hash: authenticated_head.hash,
        policy_digest,
        claim_ids,
        outcome_digests,
    })
}

/// zkVM entry helper: deserialize the [`EpochInput`], run the epoch, return
/// the journal bytes for commitment.
pub fn run_epoch_bytes(input_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let input: EpochInput = bincode::options()
        .with_fixint_encoding()
        .with_limit(input_bytes.len() as u64)
        .reject_trailing_bytes()
        .deserialize(input_bytes)
        .map_err(|e| format!("invalid epoch input: {e}"))?;
    let journal = run_epoch(&input).map_err(|e| format!("epoch verification failed: {e}"))?;
    Ok(encode_journal(&journal))
}
