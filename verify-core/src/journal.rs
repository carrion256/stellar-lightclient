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
/// Fixed prefix through `claim_count`.
const CLAIMS_OFFSET: usize = 112;
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

pub fn decode_journal(bytes: &[u8]) -> Result<EpochJournal, Error> {
    if bytes.len() < V2_HEADER_LEN {
        return Err(Error::MalformedJournal("input shorter than header"));
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if version != VERSION {
        // v0 (version-less, 76-byte header) and v1 (112-byte header, no outcome
        // block) are both unsupported: the journal format changed incompatibly.
        return Err(Error::MalformedJournal("unsupported journal version"));
    }
    let start_seq = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let end_seq = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
    let claim_count =
        u32::from_le_bytes([bytes[108], bytes[109], bytes[110], bytes[111]]) as usize;
    let mut cursor = CLAIMS_OFFSET;
    let claim_ids = read_ids(bytes, &mut cursor, claim_count, "claim count exceeds remaining bytes")?;
    if cursor + 4 > bytes.len() {
        return Err(Error::MalformedJournal("missing outcome count"));
    }
    let outcome_count =
        u32::from_le_bytes([bytes[cursor], bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3]])
            as usize;
    cursor += 4;
    let outcome_digests =
        read_ids(bytes, &mut cursor, outcome_count, "outcome count exceeds remaining bytes")?;
    if cursor != bytes.len() {
        return Err(Error::MalformedJournal("trailing bytes after outcome digests"));
    }

    let mut start_hash = [0u8; 32];
    start_hash.copy_from_slice(&bytes[8..40]);
    let mut end_hash = [0u8; 32];
    end_hash.copy_from_slice(&bytes[44..76]);
    let mut policy_digest = [0u8; 32];
    policy_digest.copy_from_slice(&bytes[76..108]);
    Ok(EpochJournal {
        start_seq,
        start_hash,
        end_seq,
        end_hash,
        policy_digest,
        claim_ids,
        outcome_digests,
    })
}
