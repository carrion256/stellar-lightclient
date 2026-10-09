//! Canonical encoding for the [`EpochJournal`] the guest commits to its journal.
//!
//! # Canonical encoding (v0)
//!
//! All integers little-endian, matching the RISC Zero journal byte order:
//!
//! ```text
//! start_seq        u32  (4 B)
//! start_hash       raw  (32 B)
//! end_seq          u32  (4 B)
//! end_hash         raw  (32 B)
//! claim_count      u32  (4 B)
//! claim_ids        claim_count × raw 32 B
//! ```
//!
//! Total size = 76 + 32 × claim_count. `decode_journal` accepts exactly this
//! layout: wrong lengths (short input, claim-count mismatch, trailing garbage)
//! are rejected with [`Error::MalformedJournal`].

use crate::Error;

/// What the guest commits to in its journal. Canonical encoding so guest and
/// contract agree byte-for-byte.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochJournal {
    pub start_seq: u32,
    pub start_hash: [u8; 32],
    pub end_seq: u32,
    pub end_hash: [u8; 32],
    pub claim_ids: Vec<[u8; 32]>,
}

pub fn encode_journal(j: &EpochJournal) -> Vec<u8> {
    let mut out = Vec::with_capacity(76 + 32 * j.claim_ids.len());
    out.extend_from_slice(&j.start_seq.to_le_bytes());
    out.extend_from_slice(&j.start_hash);
    out.extend_from_slice(&j.end_seq.to_le_bytes());
    out.extend_from_slice(&j.end_hash);
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
    if bytes.len() < 76 {
        return Err(Error::MalformedJournal("input shorter than header"));
    }
    let start_seq = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let end_seq = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
    let claim_count = u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]) as usize;
    let claims_len = claim_count
        .checked_mul(32)
        .ok_or(Error::MalformedJournal("claim count exceeds remaining bytes"))?;
    let total = 76usize
        .checked_add(claims_len)
        .ok_or(Error::MalformedJournal("claim count exceeds remaining bytes"))?;
    if bytes.len() < total {
        return Err(Error::MalformedJournal("claim count exceeds remaining bytes"));
    }
    if bytes.len() > total {
        return Err(Error::MalformedJournal("trailing bytes after claim ids"));
    }
    let mut start_hash = [0u8; 32];
    start_hash.copy_from_slice(&bytes[4..36]);
    let mut end_hash = [0u8; 32];
    end_hash.copy_from_slice(&bytes[40..72]);
    let mut claim_ids = Vec::with_capacity(claim_count);
    for chunk in bytes[76..].chunks(32) {
        let mut id = [0u8; 32];
        id.copy_from_slice(chunk);
        claim_ids.push(id);
    }
    Ok(EpochJournal {
        start_seq,
        start_hash,
        end_seq,
        end_hash,
        claim_ids,
    })
}
