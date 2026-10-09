//! Canonical encoding for the [`EpochJournal`] the guest commits to its journal.
//!
//! # Canonical encoding (v1)
//!
//! All integers little-endian, matching the RISC Zero journal byte order:
//!
//! ```text
//! version          u32 = 1 (4 B)
//! start_seq        u32  (4 B)
//! start_hash       raw  (32 B)
//! end_seq          u32  (4 B)
//! end_hash         raw  (32 B)
//! policy_digest    raw  (32 B)
//! claim_count      u32  (4 B)
//! claim_ids        claim_count × raw 32 B
//! ```
//!
//! `end_seq`/`end_hash` are the latest *authenticated* checkpoint, never an
//! unauthenticated tail, and `policy_digest` is [`crate::trust_digest`] for the
//! trust set that signed the epoch, so the guest is bound to the policy that
//! produced it. Total size = 112 + 32 × claim_count. `decode_journal` accepts
//! exactly this layout: v0 journals (version-less, 76-byte header) and wrong
//! lengths (short input, claim-count mismatch, trailing garbage) are rejected
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
}

const V1_HEADER_LEN: usize = 112;

pub fn encode_journal(j: &EpochJournal) -> Vec<u8> {
    let mut out = Vec::with_capacity(V1_HEADER_LEN + 32 * j.claim_ids.len());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&j.start_seq.to_le_bytes());
    out.extend_from_slice(&j.start_hash);
    out.extend_from_slice(&j.end_seq.to_le_bytes());
    out.extend_from_slice(&j.end_hash);
    out.extend_from_slice(&j.policy_digest);
    // The count is u32: more than u32::MAX claim ids cannot encode, and
    // decoding clamps to u32::MAX so such a journal round-trips as a
    // length-mismatch error rather than a silent truncation.
    let count = u32::try_from(j.claim_ids.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    for id in &j.claim_ids {
        out.extend_from_slice(id);
    }
    out
}

pub fn decode_journal(bytes: &[u8]) -> Result<EpochJournal, Error> {
    if bytes.len() < V1_HEADER_LEN {
        return Err(Error::MalformedJournal("input shorter than header"));
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if version != 1 {
        return Err(Error::MalformedJournal("unsupported journal version"));
    }
    let start_seq = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let end_seq = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
    let claim_count =
        u32::from_le_bytes([bytes[108], bytes[109], bytes[110], bytes[111]]) as usize;
    let claims_len = claim_count
        .checked_mul(32)
        .ok_or(Error::MalformedJournal("claim count exceeds remaining bytes"))?;
    let total = V1_HEADER_LEN
        .checked_add(claims_len)
        .ok_or(Error::MalformedJournal("claim count exceeds remaining bytes"))?;
    if bytes.len() < total {
        return Err(Error::MalformedJournal("claim count exceeds remaining bytes"));
    }
    if bytes.len() > total {
        return Err(Error::MalformedJournal("trailing bytes after claim ids"));
    }
    let mut start_hash = [0u8; 32];
    start_hash.copy_from_slice(&bytes[8..40]);
    let mut end_hash = [0u8; 32];
    end_hash.copy_from_slice(&bytes[44..76]);
    let mut policy_digest = [0u8; 32];
    policy_digest.copy_from_slice(&bytes[76..108]);
    let mut claim_ids = Vec::with_capacity(claim_count);
    for chunk in bytes[V1_HEADER_LEN..].chunks(32) {
        let mut id = [0u8; 32];
        id.copy_from_slice(chunk);
        claim_ids.push(id);
    }
    Ok(EpochJournal {
        start_seq,
        start_hash,
        end_seq,
        end_hash,
        policy_digest,
        claim_ids,
    })
}
