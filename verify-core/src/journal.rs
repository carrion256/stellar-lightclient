//! Canonical encoding for the [`EpochJournal`] the guest commits to its journal.
//!
//! # Canonical encoding (v2)
//!
//! All integers little-endian, matching the RISC Zero journal byte order:
//!
//! ```text
//! version          u32 = 2 (4 B)
//! start_seq        u32  (4 B)
//! start_hash       raw  (32 B)
//! end_seq          u32  (4 B)
//! end_hash         raw  (32 B)
//! policy_digest    raw  (32 B)
//! claim_count      u32  (4 B)
//! claim_ids        claim_count × raw 32 B
//! outcome_count    u32  (4 B)
//! outcome_digests  outcome_count × raw 32 B
//! ```
//!
//! `end_seq`/`end_hash` are the latest *authenticated* checkpoint, never an
//! unauthenticated tail, and `policy_digest` is [`crate::trust_digest`] for the
//! trust set that signed the epoch, so the guest is bound to the policy that
//! produced it. Total size = 116 + 32 × (claim_count + outcome_count).
//!
//! `claim_ids` are `sha256(tx envelope)` per proven inclusion claim.
//! `outcome_digests` are `sha256` over the canonical `TransactionResultPair`
//! XDR per proven outcome claim, in claim order. A consumer proves an outcome by
//! supplying the pair and checking its digest is committed here; the pair's
//! `transaction_hash` binds it back to the envelope.
//!
//! `decode_journal` accepts exactly this layout. Version 1 journals (112-byte
//! header, no outcome block) and version-less v0 journals are **rejected**:
//! adding outcomes is a breaking journal change and there is no migration shim.
//! Wrong lengths — short input, count mismatch, trailing garbage — are rejected
//! with [`Error::MalformedJournal`].

use crate::Error;

/// What the guest commits to in its journal. Canonical encoding so guest and
/// contract agree byte-for-byte.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochJournal {
    pub start_seq: u32,
    pub start_hash: [u8; 32],
    pub end_seq: u32,
    pub end_hash: [u8; 32],
    /// `trust_digest` of the trust policy that authenticated this epoch.
    pub policy_digest: [u8; 32],
    pub claim_ids: Vec<[u8; 32]>,
    /// `sha256(canonical TransactionResultPair)` per proven outcome claim.
    pub outcome_digests: Vec<[u8; 32]>,
}

const VERSION: u32 = 2;
/// Named layout offsets. `decode_journal` derives every position from these, so
/// the layout has one expression rather than a set of literals that must be
/// kept in step with the constants by hand — the hazard that bit this format
/// once already, when `claim_ids` moved and the cursor started at the wrong
/// place. `encode_journal` appends in this order and the round-trip tests pin
/// the two together.
const OFF_VERSION: usize = 0;
const OFF_START_SEQ: usize = OFF_VERSION + 4;
const OFF_START_HASH: usize = OFF_START_SEQ + 4;
const OFF_END_SEQ: usize = OFF_START_HASH + 32;
const OFF_END_HASH: usize = OFF_END_SEQ + 4;
const OFF_POLICY: usize = OFF_END_HASH + 32;
const OFF_CLAIM_COUNT: usize = OFF_POLICY + 32;
/// Fixed prefix through `claim_count`.
const CLAIMS_OFFSET: usize = OFF_CLAIM_COUNT + 4;
/// Smallest legal journal: the fixed prefix plus the `outcome_count` word.
const V2_HEADER_LEN: usize = CLAIMS_OFFSET + 4;

pub fn encode_journal(j: &EpochJournal) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        V2_HEADER_LEN + 32 * (j.claim_ids.len() + j.outcome_digests.len()),
    );
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&j.start_seq.to_le_bytes());
    out.extend_from_slice(&j.start_hash);
    out.extend_from_slice(&j.end_seq.to_le_bytes());
    out.extend_from_slice(&j.end_hash);
    out.extend_from_slice(&j.policy_digest);
    // The counts are u32: more than u32::MAX entries cannot encode, and
    // decoding clamps to u32::MAX so such a journal round-trips as a
    // length-mismatch error rather than a silent truncation.
    let claims = u32::try_from(j.claim_ids.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&claims.to_le_bytes());
    for id in &j.claim_ids {
        out.extend_from_slice(id);
    }
    let outcomes = u32::try_from(j.outcome_digests.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&outcomes.to_le_bytes());
    for id in &j.outcome_digests {
        out.extend_from_slice(id);
    }
    out
}

/// Read a `count × 32 B` block starting at `cursor`, advancing it.
fn read_ids(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    what: &'static str,
) -> Result<Vec<[u8; 32]>, Error> {
    let end = cursor
        .checked_add(count.checked_mul(32).ok_or(Error::MalformedJournal(what))?)
        .ok_or(Error::MalformedJournal(what))?;
    if end > bytes.len() {
        return Err(Error::MalformedJournal(what));
    }
    let mut ids = Vec::with_capacity(count);
    for chunk in bytes[*cursor..end].chunks(32) {
        let mut id = [0u8; 32];
        id.copy_from_slice(chunk);
        ids.push(id);
    }
    *cursor = end;
    Ok(ids)
}

/// Read `N` bytes at `at` — `None` rather than a panic on any short read.
///
/// The journal is untrusted input (`verify_claim` decodes a caller-supplied
/// one), and a panic here is a contract trap rather than a diagnostic, so
/// panic-freedom must not rest on the length check staying where it is.
fn chunk<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

pub fn decode_journal(bytes: &[u8]) -> Result<EpochJournal, Error> {
    let short = || Error::MalformedJournal("input shorter than header");
    if bytes.len() < V2_HEADER_LEN {
        return Err(short());
    }
    let u32_at = |at: usize| -> Result<u32, Error> {
        Ok(u32::from_le_bytes(chunk::<4>(bytes, at).ok_or_else(short)?))
    };
    let word_at = |at: usize| -> Result<[u8; 32], Error> {
        chunk::<32>(bytes, at).ok_or_else(short)
    };

    let version = u32_at(OFF_VERSION)?;
    if version != VERSION {
        // v0 (version-less, 76-byte header) and v1 (112-byte header, no outcome
        // block) are both unsupported: the journal format changed incompatibly.
        return Err(Error::MalformedJournal("unsupported journal version"));
    }
    let start_seq = u32_at(OFF_START_SEQ)?;
    let end_seq = u32_at(OFF_END_SEQ)?;
    let claim_count = u32_at(OFF_CLAIM_COUNT)? as usize;

    let mut cursor = CLAIMS_OFFSET;
    let claim_ids = read_ids(bytes, &mut cursor, claim_count, "claim count exceeds remaining bytes")?;
    let outcome_count = u32_at(cursor)? as usize;
    cursor += 4;
    let outcome_digests =
        read_ids(bytes, &mut cursor, outcome_count, "outcome count exceeds remaining bytes")?;
    if cursor != bytes.len() {
        return Err(Error::MalformedJournal("trailing bytes after outcome digests"));
    }

    Ok(EpochJournal {
        start_seq,
        start_hash: word_at(OFF_START_HASH)?,
        end_seq,
        end_hash: word_at(OFF_END_HASH)?,
        policy_digest: word_at(OFF_POLICY)?,
        claim_ids,
        outcome_digests,
    })
}
