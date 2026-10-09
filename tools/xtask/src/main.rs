//! xtask: fetch a real Stellar mainnet fixture for the light-client contract tests.
//!
//! Usage:
//!   xtask fetch-fixture [--archive <url>] [--checkpoint <ledger>] [--out <path>]
//!   xtask --help

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::MultiGzDecoder;
use guest::Sha256Dalek;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use verify_core::{legacy_tx_set_contents_hash, verify_span, SpanProof, Trust};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;

use stellar_xdr::{
    self as xdr, GeneralizedTransactionSet, LedgerHeaderHistoryEntry, Limits, Limited, NodeId,
    PublicKey, ReadXdr, ScpEnvelope, ScpHistoryEntry, TransactionEnvelope,
    TransactionHistoryEntry, TransactionHistoryEntryExt, TransactionHistoryResultEntry,
    TransactionPhase, TxSetComponent, WriteXdr,
};

const DEFAULT_ARCHIVE: &str = "https://history.stellar.org/prd/core-live/core_live_001";
const NETWORK_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// Records per ledger-header/txs/results checkpoint file (default stellar-core
/// checkpoint frequency; mainnet archives use production frequency).
const CHECKPOINT_LEN: usize = 64;

/// Latest completed checkpoint (k*64-1) at or below `current`, inclusive.
/// i64 arithmetic so `current < 63` cannot underflow; `None` when none exists.
fn default_checkpoint(current: u32) -> Option<u32> {
    let boundary = (i64::from(current) + 1) / 64 * 64 - 1;
    u32::try_from(boundary).ok()
}

const USAGE: &str = "\
xtask — Stellar light-client fixture fetcher

USAGE:
    xtask fetch-fixture [OPTIONS]

OPTIONS:
    --archive <url>       History archive base URL
                          (default: https://history.stellar.org/prd/core-live/core_live_001)
    --checkpoint <ledger> Checkpoint ledger to fetch (must be k*64-1;
                          explicit values are never substituted).
                          Default: latest completed checkpoint (k*64-1) at or
                          below currentLedger, inclusive of the boundary.
    --out <path>          Output fixture path (default: testdata/fixture.json)
    -h, --help            Print this help
";

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let sub = match args.next() {
        Some(s) => s,
        None => {
            eprint!("{USAGE}");
            return Err("missing subcommand (expected `fetch-fixture`)".into());
        }
    };
    if sub == "--help" || sub == "-h" || sub == "help" {
        println!("{USAGE}");
        return Ok(());
    }
    if sub != "fetch-fixture" {
        eprint!("{USAGE}");
        return Err(format!("unknown subcommand `{sub}` (expected `fetch-fixture`)"));
    }

    let mut archive = DEFAULT_ARCHIVE.to_string();
    let mut out = "testdata/fixture.json".to_string();
    let mut checkpoint: Option<u32> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--archive" => archive = next_value(&mut args, "--archive")?,
            "--out" => out = next_value(&mut args, "--out")?,
            "--checkpoint" => {
                checkpoint = Some(
                    next_value(&mut args, "--checkpoint")?
                        .parse::<u32>()
                        .map_err(|e| format!("bad --checkpoint: {e}"))?,
                )
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    archive = archive.trim_end_matches('/').to_string();

    // The requested checkpoint never depends on the HAS file. Validate an
    // explicit value first; only a default fetch consults the HAS file.
    if let Some(ck) = checkpoint {
        if ck % 64 != 63 {
            return Err(format!("--checkpoint {ck} is not a checkpoint ledger (k*64-1)"));
        }
    }
    let checkpoint = match checkpoint {
        Some(ck) => ck,
        None => {
            // a. HAS file -> currentLedger -> default checkpoint.
            let has_url = format!("{archive}/.well-known/stellar-history.json");
            println!("fetching {has_url}");
            let has: Value = serde_json::from_str(&http_get_string(&has_url)?)
                .map_err(|e| format!("{has_url}: {e}"))?;
            let current_ledger_raw = has["currentLedger"]
                .as_u64()
                .ok_or("HAS file has no numeric currentLedger")?;
            let current_ledger = u32::try_from(current_ledger_raw)
                .map_err(|_| format!("currentLedger {current_ledger_raw} exceeds u32 range"))?;
            default_checkpoint(current_ledger)
                .ok_or("HAS has no completed checkpoint yet")?
        }
    };

    // b/c. Download + decode the four checkpoint files. No substitution and
    // no retry: corrupt, missing, or unreachable evidence for the requested
    // checkpoint fails the run explicitly.
    let (ledgers, scp, txs, results) = fetch_checkpoint(&archive, checkpoint)?;

    // d. Pick the consecutive pair with the most total transactions.
    let (seq_a, seq_b) =
        select_pair(&ledgers, &scp, &txs).ok_or("no consecutive tx-bearing pair found")?;

    // Build one close object per ledger, running all integrity assertions.
    let close_a = build_close(&ledgers, &scp, &txs, &results, seq_a, None)?;
    let close_b = build_close(&ledgers, &scp, &txs, &results, seq_b, Some(&close_a))?;

    // A claim-bearing span needs an authenticated predecessor header (shared
    // core rejects single-header claimant spans otherwise). The predecessor
    // of the FIRST close comes from the archive file itself (select_pair
    // skips pairs whose predecessor is not in the file).
    let pred_seq = seq_a - 1;
    let pred = ledgers
        .iter()
        .find(|e| e.header.ledger_seq == pred_seq)
        .ok_or(format!("ledger {pred_seq} (predecessor of {seq_a}) not in file"))?;
    let start_header_xdr = xdr_encode(&pred.header)?;

    // Authenticate both closes with the shared guest/core crypto before
    // publishing: quorum signatures, value/header binding, header chain link.
    authenticate_close(&close_a, &start_header_xdr)?;
    authenticate_close(&close_b, &decode_b64(&close_a, "header_xdr_b64")?)?;

    // 5. Top-level fixture JSON, pretty-printed, stable key order.
    let fixture = json!({
        "archive": archive,
        "network_passphrase": NETWORK_PASSPHRASE,
        "checkpoint_ledger": checkpoint,
        "start_header_xdr_b64": STANDARD.encode(&start_header_xdr),
        "closes": [close_a, close_b],
    });
    let path = Path::new(&out);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }

    // Atomic publish: a uniquely-named tmp file (`create_new`, never
    // clobbering anything) is renamed into place only after every check has
    // passed, so an error anywhere above preserves the old output.
    let (tmp, mut file) = create_temporary_output(&out)?;
    let publication = (|| -> std::io::Result<()> {
        serde_json::to_writer_pretty(&mut file, &fixture)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if publication.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    publication.map_err(|e| e.to_string())?;

    // Summary.
    println!("wrote {}", path.display());
    println!("checkpoint_ledger: {checkpoint}");
    for (c, label) in [(&close_a, "close 1"), (&close_b, "close 2")] {
        println!(
            "{label}: ledger_seq={} tx_count={} envelopes={} distinct_signers={} tx_set_kind={} tx_set_bytes={} results_bytes={}",
            c["ledger_seq"].as_u64().unwrap(),
            c["tx_count"].as_u64().unwrap(),
            c["scp_envelopes_b64"].as_array().unwrap().len(),
            c["signer_count"].as_u64().unwrap(),
            c["tx_set_kind"].as_str().unwrap(),
            STANDARD.decode(c["tx_set_xdr_b64"].as_str().unwrap()).unwrap().len(),
            STANDARD.decode(c["results_xdr_b64"].as_str().unwrap()).unwrap().len(),
        );
    }
    Ok(())
}
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

/// GET a URL; gunzip if the payload is gzip, else pass through.
fn http_get_bytes(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url).call().map_err(|e| format!("{url}: {e}"))?;
    let mut raw = Vec::new();
    resp.into_reader()
        .read_to_end(&mut raw)
        .map_err(|e| format!("{url}: {e}"))?;
    if raw.starts_with(&[0x1f, 0x8b]) {
        let mut buf = Vec::new();
        MultiGzDecoder::new(&raw[..])
            .read_to_end(&mut buf)
            .map_err(|e| format!("{url}: gunzip: {e}"))?;
        Ok(buf)
    } else {
        Ok(raw)
    }
}

fn http_get_string(url: &str) -> Result<String, String> {
    String::from_utf8(http_get_bytes(url)?).map_err(|e| format!("{url}: utf-8: {e}"))
}

/// `<kind>/<ww>/<xx>/<yy>/<kind>-<hex>.xdr.gz` for a checkpoint ledger.
fn checkpoint_path(kind: &str, seq: u32) -> String {
    let hex = format!("{seq:08x}");
    let (ww, xx, yy) = (&hex[0..2], &hex[2..4], &hex[4..6]);
    format!("{kind}/{ww}/{xx}/{yy}/{kind}-{hex}.xdr.gz")
}
/// RFC 5531 framing: 4-byte big-endian header, bit 31 marks the last
/// fragment (always set in Stellar usage), and the record length is the
/// 31-bit value (`header & 0x7fff_ffff`). Each record body must decode fully
/// (`read_xdr_to_end`): truncated headers, truncated bodies, trailing junk,
/// or an undecodable record are hard errors. Checkpoint files carry exactly
/// their per-ledger records — no HAS footer.
fn record_body<'a>(bytes: &'a [u8], pos: usize) -> Result<(&'a [u8], usize), String> {
    if pos + 4 > bytes.len() {
        return Err("truncated record header".into());
    }
    let header = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
    if header & 0x8000_0000 == 0 {
        return Err(format!("missing msg bit in record header {header:#010x}"));
    }
    let len = (header & 0x7fff_ffff) as usize;
    let end = pos + 4 + len;
    if end > bytes.len() {
        return Err("truncated record body".into());
    }
    Ok((&bytes[pos + 4..end], end))
}

/// Decode every framed record, consuming each one exactly. Decoding is
/// depth-bounded (64) and byte-bounded to the record body, so untrusted
/// length prefixes cannot force over-allocation or stack overflow.
fn decode_seq<T: ReadXdr>(bytes: &[u8], kind: &str) -> Result<Vec<T>, String> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < bytes.len() {
        let (body, next) = record_body(bytes, pos)?;
        let mut r = Limited::new(
            body,
            Limits {
                depth: 64,
                len: body.len(),
            },
        );
        out.push(T::read_xdr_to_end(&mut r).map_err(|e| format!("{kind}: {e}"))?);
        pos = next;
    }
    Ok(out)
}

type CheckpointFiles = (
    Vec<LedgerHeaderHistoryEntry>,
    Vec<ScpHistoryEntry>,
    Vec<TransactionHistoryEntry>,
    Vec<TransactionHistoryResultEntry>,
);

fn fetch_checkpoint(archive: &str, checkpoint: u32) -> Result<CheckpointFiles, String> {
    println!("fetching checkpoint {checkpoint} files");
    let ledgers = decode_seq::<LedgerHeaderHistoryEntry>(
        &http_get_bytes(&format!("{archive}/{}", checkpoint_path("ledger", checkpoint)))?,
        "ledger",
    )?;
    let scp = decode_seq::<ScpHistoryEntry>(
        &http_get_bytes(&format!("{archive}/{}", checkpoint_path("scp", checkpoint)))?,
        "scp",
    )?;
    let txs = decode_seq::<TransactionHistoryEntry>(
        &http_get_bytes(&format!("{archive}/{}", checkpoint_path("transactions", checkpoint)))?,
        "transactions",
    )?;
    let results = decode_seq::<TransactionHistoryResultEntry>(
        &http_get_bytes(&format!("{archive}/{}", checkpoint_path("results", checkpoint)))?,
        "results",
    )?;
    // The ledger-header file carries exactly one record per ledger for the
    // checkpoint (stellar-core CheckSingleLedgerHeaderWork); any other count
    // is evidence this file does not attest the checkpoint — never publish
    // from it. Transaction/result files may legitimately hold fewer records,
    // so only the ledger file is count-checked.
    if ledgers.len() != CHECKPOINT_LEN {
        return Err(format!(
            "ledger file for checkpoint {checkpoint} has {} records, expected {CHECKPOINT_LEN}",
            ledgers.len()
        ));
    }
    Ok((ledgers, scp, txs, results))
}

/// The transaction envelopes of a history tx-set, whatever its kind.
/// For a `GeneralizedTransactionSet`, envelopes are collected from phases in
/// file order (the same order stellar-core applies them).
fn set_txs(e: &TransactionHistoryEntry) -> Result<Vec<TransactionEnvelope>, String> {
    match &e.ext {
        TransactionHistoryEntryExt::V0 => Ok(e.tx_set.txs.to_vec()),
        TransactionHistoryEntryExt::V1(v1) => {
            let GeneralizedTransactionSet::V1(set) = v1;
            let mut txs = Vec::new();
            for phase in set.phases.iter() {
                match phase {
                    TransactionPhase::V0(components) => {
                        for c in components.iter() {
                                let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                                txs.extend(c.txs.iter().cloned());
                        }
                    }
                    TransactionPhase::V1(p) => {
                        for stage in p.execution_stages.iter() {
                            for cluster in stage.0.iter() {
                                txs.extend(cluster.0.iter().cloned());
                            }
                        }
                    }
                }
            }
            Ok(txs)
        }
    }
}

/// The raw ed25519 public key bytes of a SCP node id.
fn node_id_bytes(node: &NodeId) -> Result<[u8; 32], String> {
    match &node.0 {
        PublicKey::PublicKeyTypeEd25519(key) => Ok(key.0),
    }
}

/// Group SCP envelopes by slot index, preserving file order, unfiltered.
fn envelopes_by_slot(scp: &[ScpHistoryEntry]) -> BTreeMap<u64, Vec<ScpEnvelope>> {
    let mut map: BTreeMap<u64, Vec<ScpEnvelope>> = BTreeMap::new();
    for entry in scp {
        let envs = match entry {
            ScpHistoryEntry::V0(v0) => v0.ledger_messages.messages.to_vec(),
        };
        for env in envs {
            map.entry(env.statement.slot_index).or_default().push(env);
        }
    }
    map
}

fn select_pair(
    ledgers: &[LedgerHeaderHistoryEntry],
    scp: &[ScpHistoryEntry],
    txs: &[TransactionHistoryEntry],
) -> Option<(u32, u32)> {
    // A claim-bearing first close needs its predecessor (seq-1) present in
    // the checkpoint file; the file's first ledger has none. The 64 ledgers
    // are contiguous from `ledgers[0]`, so the predecessor exists exactly
    // when this ledger is not the file's first entry.
    let min_seq = ledgers.first().map(|e| e.header.ledger_seq).unwrap_or(1);
    let tx_by_seq: BTreeMap<u32, &TransactionHistoryEntry> =
        txs.iter().map(|e| (e.ledger_seq, e)).collect();
    let by_slot = envelopes_by_slot(scp);
    let mut best: Option<(usize, u32)> = None; // (total txs, seq)
    for pair in ledgers.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        if b.header.ledger_seq != a.header.ledger_seq + 1 {
            continue;
        }
        let seq = a.header.ledger_seq;
        if seq <= min_seq {
            continue;
        }
        let (Some(ta), Some(tb)) = (tx_by_seq.get(&seq), tx_by_seq.get(&(seq + 1))) else {
            continue;
        };
        let ca = tx_count(ta);
        let cb = tx_count(tb);
        if ca == 0 || cb == 0 {
            continue;
        }
        let (Some(ea), Some(eb)) = (by_slot.get(&(seq as u64)), by_slot.get(&(seq as u64 + 1)))
        else {
            continue;
        };
        // Eligibility is per ledger: `build_close` requires an EXTERNALIZE and
        // >= 6 distinct signers in EACH slot's own envelope set, so the
        // predicate must be checked per slot here — a pair that only
        // qualifies on the union must not win selection.
        if !(slot_qualified(ea) && slot_qualified(eb)) {
            continue;
        }
        if best.map_or(true, |(score, _)| ca + cb > score) {
            best = Some((ca + cb, seq));
        }
    }
    best.map(|(_, seq)| (seq, seq + 1))
}

/// A slot certificate is usable only if its own envelopes externalize and
/// carry at least 6 distinct node ids (matching `build_close`'s assertions).
fn slot_qualified(envs: &[ScpEnvelope]) -> bool {
    let externalized = envs
        .iter()
        .any(|e| matches!(e.statement.pledges, xdr::ScpStatementPledges::Externalize(_)));
    let signers: BTreeSet<[u8; 32]> = envs
        .iter()
        .filter_map(|e| node_id_bytes(&e.statement.node_id).ok())
        .collect();
    externalized && signers.len() >= 6
}

/// Envelope count of a history tx-set, computed from lengths — no clones.
/// The selected sets are cloned once by `build_close`, not by scoring.
fn tx_count(e: &TransactionHistoryEntry) -> usize {
    match &e.ext {
        TransactionHistoryEntryExt::V0 => e.tx_set.txs.len(),
        TransactionHistoryEntryExt::V1(v1) => {
            let GeneralizedTransactionSet::V1(set) = v1;
            set.phases
                .iter()
                .map(|phase| match phase {
                    TransactionPhase::V0(components) => components
                        .iter()
                        .map(|c| {
                            let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                            c.txs.len()
                        })
                        .sum::<usize>(),
                    TransactionPhase::V1(p) => p
                        .execution_stages
                        .iter()
                        .map(|stage| stage.0.iter().map(|cluster| cluster.0.len()).sum::<usize>())
                        .sum::<usize>(),
                })
                .sum()
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn xdr_encode<T: WriteXdr>(v: &T) -> Result<Vec<u8>, String> {
    v.to_xdr(Limits::none()).map_err(|e| e.to_string())
}

fn build_close(
    ledgers: &[LedgerHeaderHistoryEntry],
    scp: &[ScpHistoryEntry],
    txs: &[TransactionHistoryEntry],
    results: &[TransactionHistoryResultEntry],
    seq: u32,
    prev: Option<&Map<String, Value>>,
) -> Result<Map<String, Value>, String> {
    let lhe = ledgers
        .iter()
        .find(|e| e.header.ledger_seq == seq)
        .ok_or(format!("ledger {seq} not in file"))?;
    let header = &lhe.header;

    // Assert: sha256(header_xdr) == header hash (byte-exact re-encoding).
    let header_xdr = xdr_encode(header)?;
    if sha256(&header_xdr) != lhe.hash.0 {
        return Err(format!(
            "ledger {seq}: sha256(header_xdr) != LedgerHeaderHistoryEntry.hash — re-encoding is not byte-exact"
        ));
    }

    // SCP envelopes for this slot (ledger_seq == slot_index), file order, unfiltered.
    let by_slot = envelopes_by_slot(scp);
    let envs = by_slot
        .get(&(seq as u64))
        .ok_or(format!("ledger {seq}: no SCP history entry"))?;
    let externalize = envs
        .iter()
        .any(|e| matches!(e.statement.pledges, xdr::ScpStatementPledges::Externalize(_)));
    if !externalize {
        return Err(format!("ledger {seq}: slot has no EXTERNALIZE statement"));
    }
    let distinct: BTreeSet<[u8; 32]> = envs
        .iter()
        .map(|e| node_id_bytes(&e.statement.node_id))
        .collect::<Result<_, _>>()?;
    if distinct.len() < 6 {
        return Err(format!("ledger {seq}: only {} distinct nodes (<6)", distinct.len()));
    }

    // Empirical tx-set kind: hash the candidate encodings, match scp_value.tx_set_hash.
    let tx_entry = txs
        .iter()
        .find(|e| e.ledger_seq == seq)
        .ok_or(format!("ledger {seq}: no tx history entry"))?;
    let tx_list = set_txs(tx_entry)?;
    if tx_list.is_empty() {
        return Err(format!("ledger {seq}: empty tx set"));
    }
    let (kind, tx_set_xdr, prev_ledger_hash): (&str, Vec<u8>, [u8; 32]) =
        match &tx_entry.ext {
            TransactionHistoryEntryExt::V0 => (
                "legacy",
                xdr_encode(&tx_entry.tx_set)?,
                tx_entry.tx_set.previous_ledger_hash.0,
            ),
            TransactionHistoryEntryExt::V1(v1) => (
                "generalized",
                xdr_encode(v1)?,
                match v1 {
                    GeneralizedTransactionSet::V1(set) => set.previous_ledger_hash.0,
                },
            ),
        };
    // Verify the tx-set commitment with the shared verify-core rule, never a
    // local convention: legacy TransactionSet hashes the *contents*
    // (sha256(previous_hash || envelope XDRs), tx-count excluded), generalized
    // V1 sets hash the whole canonical XDR. Both are signed bytes, so a hash
    // mismatch means the fetched evidence does not attest this header.
    let tx_set_hash = match &tx_entry.ext {
        TransactionHistoryEntryExt::V0 => legacy_tx_set_contents_hash(&Sha256Dalek, &tx_set_xdr)
            .ok_or(format!("ledger {seq}: legacy tx set too short"))?,
        TransactionHistoryEntryExt::V1(_) => sha256(&tx_set_xdr),
    };
    if tx_set_hash != header.scp_value.tx_set_hash.0 {
        return Err(format!("ledger {seq}: {kind} tx set hash != header.scp_value.tx_set_hash"));
    }

    // Assert: sha256(results_xdr) == header.tx_set_result_hash.
    let res_entry = results
        .iter()
        .find(|e| e.ledger_seq == seq)
        .ok_or(format!("ledger {seq}: no results history entry"))?;
    let results_xdr = xdr_encode(&res_entry.tx_result_set)?;
    if sha256(&results_xdr) != header.tx_set_result_hash.0 {
        return Err(format!(
            "ledger {seq}: sha256(results_xdr) != header.tx_set_result_hash"
        ));
    }

    // Chosen tx: index 0 (deterministic); element identity re-verified below.
    let tx_index: u32 = 0;
    if (tx_index as usize) >= tx_list.len() {
        return Err(format!("ledger {seq}: tx_index {tx_index} >= tx_count {}", tx_list.len()));
    }
    let env_xdr = xdr_encode(&tx_list[tx_index as usize])?;
    let decoded_back = TransactionEnvelope::from_xdr(&env_xdr[..], Limits::none())
        .map_err(|e| e.to_string())?;
    if decoded_back != tx_list[tx_index as usize] {
        return Err(format!("ledger {seq}: envelope at index {tx_index} does not round-trip"));
    }

    // Consecutive-chain check for the second close.
    if let Some(prev) = prev {
        let expected = STANDARD
            .decode(prev["header_hash_b64"].as_str().unwrap())
            .unwrap();
        if prev_ledger_hash.to_vec() != expected {
            return Err(format!(
                "ledger {seq}: tx_set.previous_ledger_hash != header hash of previous close (chain link)"
            ));
        }
    }

    // Emit object with EXACTLY these keys, in this order.
    let mut close = Map::new();
    close.insert("ledger_seq".into(), json!(seq));
    close.insert("header_xdr_b64".into(), json!(STANDARD.encode(&header_xdr)));
    close.insert("header_hash_b64".into(), json!(STANDARD.encode(lhe.hash.0)));
    close.insert(
        "scp_value_xdr_b64".into(),
        json!(STANDARD.encode(xdr_encode(&header.scp_value)?)),
    );
    close.insert(
        "scp_envelopes_b64".into(),
        Value::Array(
            envs.iter()
                .map(|e| Ok::<_, String>(json!(STANDARD.encode(xdr_encode(e)?))))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    close.insert("tx_set_kind".into(), json!(kind));
    close.insert("tx_set_xdr_b64".into(), json!(STANDARD.encode(&tx_set_xdr)));
    close.insert(
        "tx_set_previous_ledger_hash_b64".into(),
        json!(STANDARD.encode(prev_ledger_hash)),
    );
    close.insert("results_xdr_b64".into(), json!(STANDARD.encode(&results_xdr)));
    close.insert("tx_index".into(), json!(tx_index));
    close.insert("tx_envelope_xdr_b64".into(), json!(STANDARD.encode(&env_xdr)));
    close.insert("tx_count".into(), json!(tx_list.len() as u32));
    close.insert(
        "distinct_signers_b64".into(),
        Value::Array(distinct.iter().map(|k| json!(STANDARD.encode(k))).collect()),
    );
    close.insert("signer_count".into(), json!(distinct.len() as u32));
    // The attested quorum is EXTERNALIZE signers only. Trust derived from all
    // signers (`distinct_signers_b64`) counts prepare/confirm-only nodes and
    // inflates the threshold beyond what can ever verify; downstream trust
    // (relay/contract) must use `externalizers_b64` + `externalizer_count`.
    let externalizers: BTreeSet<[u8; 32]> = envs
        .iter()
        .filter(|e| matches!(e.statement.pledges, xdr::ScpStatementPledges::Externalize(_)))
        .map(|e| node_id_bytes(&e.statement.node_id))
        .collect::<Result<_, _>>()?;
    if externalizers.is_empty() {
        return Err(format!(
            "ledger {seq}: EXTERNALIZE present but no valid externalizer node id"
        ));
    }
    close.insert(
        "externalizers_b64".into(),
        Value::Array(externalizers.iter().map(|k| json!(STANDARD.encode(k))).collect()),
    );
    close.insert("externalizer_count".into(), json!(externalizers.len() as u32));
    Ok(close)
}

/// Keep ownership of the exclusive temporary file through publication.
fn create_temporary_output(target: &str) -> Result<(String, std::fs::File), String> {
    let path = format!("{target}.tmp-{}", std::process::id());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("{path}: {e}"))?;
    Ok((path, file))
}

/// Decode a base64 string field of a built close object.
fn decode_b64(close: &Map<String, Value>, key: &str) -> Result<Vec<u8>, String> {
    let raw = close[key].as_str().ok_or(format!("close field {key} missing"))?;
    STANDARD.decode(raw).map_err(|e| format!("close field {key}: {e}"))
}

/// Re-verify one close with the shared guest/core crypto: decode the base64
/// fixture fields back and run `verify_core::verify_span` with real SHA-256 +
/// ed25519 over them (quorum signatures, value/header binding, header chain).
///
/// What this proves is SELF-CONSISTENCY of the shipped bytes: the ed25519
/// signatures verify against the node keys listed in the same fixture, and
/// the values/headers/tx-set pin each other. It proves nothing about who the
/// validators are — anyone with arbitrary keys can sign under
/// `xdr(sha256(NETWORK_PASSPHRASE), ENVELOPE_TYPE_SCP, statement)`, so
/// independently trusted validator identity and the checkpoint itself remain
/// external pinned inputs (the trust digest), never established here. This
/// check attests that the fixture is internally coherent and tamper-free
/// relative to its own claimed quorum.
fn authenticate_close(close: &Map<String, Value>, predecessor: &[u8]) -> Result<(), String> {
    let seq = close["ledger_seq"].as_u64().ok_or("close has no ledger_seq")? as u32;
    let header_xdr = decode_b64(close, "header_xdr_b64")?;
    let header: xdr::LedgerHeader = xdr::LedgerHeader::from_xdr(&header_xdr[..], Limits::none())
        .map_err(|e| format!("ledger {seq}: header decode: {e}"))?;
    let tx_set_xdr = decode_b64(close, "tx_set_xdr_b64")?;
    let tx_envelope = decode_b64(close, "tx_envelope_xdr_b64")?;
    let tx_index = close["tx_index"].as_u64().ok_or("close has no tx_index")? as u32;
    let envelopes = close["scp_envelopes_b64"]
        .as_array()
        .ok_or(format!("ledger {seq}: no scp_envelopes_b64"))?
        .iter()
        .map(|v| {
            let raw = v.as_str().ok_or(format!("ledger {seq}: envelope not base64"))?;
            STANDARD.decode(raw).map_err(|e| format!("ledger {seq}: envelope: {e}"))
        })
        .collect::<Result<Vec<Vec<u8>>, String>>()?;

    // The quorum is the DISTINCT EXTERNALIZE signers only. Every selected
    // externalizer's signature must verify (threshold == its size); nodes
    // seen on prepare/confirm statements are irrelevant to it.
    let externalizers: BTreeSet<[u8; 32]> = envelopes
        .iter()
        .filter_map(|raw| {
            let env = ScpEnvelope::from_xdr(
                &raw[..],
                Limits { depth: 64, len: raw.len() },
            )
            .ok()?;
            matches!(env.statement.pledges, xdr::ScpStatementPledges::Externalize(_))
                .then(|| node_id_bytes(&env.statement.node_id).ok())
                .flatten()
        })
        .collect();
    let trusted_nodes: Vec<[u8; 32]> = externalizers.into_iter().collect();
    let trust = Trust {
        network_id: sha256(NETWORK_PASSPHRASE.as_bytes()),
        threshold: trusted_nodes.len() as u32,
        trusted_nodes,
        max_protocol_version: header.ledger_version,
    };

    // Claims always need an authenticated predecessor header (shared core
    // rejects single-header claimant spans with ClaimsRequirePredecessor).
    // `predecessor` is the ledger seq-1 header: the archive's own entry for
    // close A, close A's own bytes for close B.
    let pred: xdr::LedgerHeader = xdr::LedgerHeader::from_xdr(predecessor, Limits::none())
        .map_err(|e| format!("ledger {seq}: predecessor header decode: {e}"))?;
    let pred_seq = pred.ledger_seq;
    let headers: Vec<&[u8]> = vec![&header_xdr[..]];
    let envs: Vec<&[u8]> = envelopes.iter().map(|e| e.as_slice()).collect();
    let claims: Vec<(&[u8], u32)> = vec![(&tx_envelope[..], tx_index)];
    let proof = SpanProof {
        start_header: Some(predecessor),
        headers: &headers,
        tail_envelopes: &envs,
        tail_set: Some(&tx_set_xdr[..]),
        claims: &claims,
    };
    verify_span(&Sha256Dalek, &trust, pred_seq, sha256(predecessor), &proof)
        .map_err(|e| format!("ledger {seq}: core verification failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_real_close_rejects_tampered_signature() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../testdata/fixture.json"
        )).unwrap();
        let predecessor = STANDARD.decode(
            fixture["closes"][0]["header_xdr_b64"].as_str().unwrap()
        ).unwrap();
        let mut close = fixture["closes"][1].as_object().unwrap().clone();
        authenticate_close(&close, &predecessor).unwrap();

        for value in close["scp_envelopes_b64"].as_array_mut().unwrap() {
            let raw = STANDARD.decode(value.as_str().unwrap()).unwrap();
            let mut env = ScpEnvelope::from_xdr(&raw, Limits::none()).unwrap();
            if matches!(env.statement.pledges, xdr::ScpStatementPledges::Externalize(_)) {
                let mut signature = env.signature.to_vec();
                signature[0] ^= 1;
                env.signature = signature.try_into().unwrap();
                *value = json!(STANDARD.encode(env.to_xdr(Limits::none()).unwrap()));
                break;
            }
        }
        assert!(authenticate_close(&close, &predecessor).is_err());
    }

    // ---- checkpoint defaults and validation -----------------------------

    #[test]
    fn default_checkpoint_includes_completed_boundary() {
        // currentLedger ON the boundary is the newest completed checkpoint.
        assert_eq!(default_checkpoint(127), Some(127));
        assert_eq!(default_checkpoint(130), Some(127));
        assert_eq!(default_checkpoint(64), Some(63));
        assert_eq!(default_checkpoint(63), Some(63));
        assert_eq!(default_checkpoint(u32::MAX), Some(u32::MAX));
    }

    #[test]
    fn default_checkpoint_none_below_first_boundary_no_underflow() {
        assert_eq!(default_checkpoint(0), None);
        assert_eq!(default_checkpoint(62), None);
    }

    // ---- framed record decoding ------------------------------------------

    fn frame(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for body in records {
            // RFC 5531: bit 31 last-fragment marker + 31-bit length.
            let header = 0x8000_0000 | body.len() as u32;
            out.extend_from_slice(&header.to_be_bytes());
            out.extend_from_slice(body);
        }
        out
    }

    fn header_record() -> Vec<u8> {
        LedgerHeaderHistoryEntry::default().to_xdr(Limits::none()).unwrap()
    }

    #[test]
    fn decode_seq_accepts_exact_records() {
        let bytes = frame(&[header_record(), header_record()]);
        let out = decode_seq::<LedgerHeaderHistoryEntry>(&bytes, "ledger").unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn decode_seq_rejects_trailing_junk_in_record() {
        let mut body = header_record();
        body.push(0xFF);
        let bytes = frame(&[body]);
        assert!(decode_seq::<LedgerHeaderHistoryEntry>(&bytes, "ledger").is_err());
    }

    #[test]
    fn decode_seq_rejects_appended_garbage_record() {
        let bytes = frame(&[header_record(), vec![0xDE, 0xAD, 0xBE, 0xEF]]);
        // The old code suppressed this once 64 records had been read; strict
        // typing means any undecodable record is an error regardless of count.
        assert!(decode_seq::<LedgerHeaderHistoryEntry>(&bytes, "ledger").is_err());
    }

    #[test]
    fn decode_seq_rejects_truncated_framing() {
        let bytes = frame(&[header_record()]);
        // chop the body short
        assert!(decode_seq::<LedgerHeaderHistoryEntry>(&bytes[..bytes.len() - 1], "ledger").is_err());
        // header truncated
        assert!(decode_seq::<LedgerHeaderHistoryEntry>(&bytes[..3], "ledger").is_err());
    }

    #[test]
    fn decode_seq_rejects_missing_msg_bit() {
        let body = header_record();
        let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);
        assert!(decode_seq::<LedgerHeaderHistoryEntry>(&bytes, "ledger").is_err());
    }

    // ---- per-slot eligibility ---------------------------------------------

    fn envelope(node: u8, externalize: bool) -> ScpEnvelope {
        let mut key = [0u8; 32];
        key[0] = node;
        ScpEnvelope {
            statement: xdr::ScpStatement {
                slot_index: 100,
                node_id: NodeId(PublicKey::PublicKeyTypeEd25519(xdr::Uint256(key))),
                pledges: if externalize {
                    xdr::ScpStatementPledges::Externalize(xdr::ScpStatementExternalize::default())
                } else {
                    xdr::ScpStatementPledges::Prepare(xdr::ScpStatementPrepare::default())
                },
            },
            signature: xdr::Signature::default(),
        }
    }

    fn qualified_slot(externalize: bool, nodes: u8) -> Vec<ScpEnvelope> {
        (0..nodes).map(|n| envelope(n, externalize && n == 0)).collect()
    }

    #[test]
    fn slot_qualified_requires_own_externalize_and_six_nodes() {
        assert!(slot_qualified(&qualified_slot(true, 6)));
        // No EXTERNALIZE of its own, however many nodes.
        assert!(!slot_qualified(&qualified_slot(false, 6)));
        assert!(!slot_qualified(&qualified_slot(false, 20)));
        // EXTERNALIZE but only 5 distinct nodes.
        assert!(!slot_qualified(&qualified_slot(true, 5)));
        // The reported bug: union qualification (externalize in slot A, 6
        // distinct nodes split across slots) must NOT qualify either slot
        // alone — the old union check let such pairs win selection and then
        // fail `build_close`'s per-slot assertions.
        let ea: Vec<ScpEnvelope> = (0..3).map(|n| envelope(n, n == 0)).collect();
        let eb: Vec<ScpEnvelope> = (3..6).map(|n| envelope(n, false)).collect();
        assert!(!slot_qualified(&ea)); // 6-node union: only 3 signers of its own
        assert!(!slot_qualified(&eb)); // no EXTERNALIZE of its own
    }

    // ---- tx counting ------------------------------------------------------

    fn tx_env() -> TransactionEnvelope {
        TransactionEnvelope::TxV0(xdr::TransactionV0Envelope::default())
    }

    #[test]
    fn tx_count_legacy_counts_without_cloning() {
        let mut e = TransactionHistoryEntry::default();
        e.tx_set.txs = (0..3).map(|_| tx_env()).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(tx_count(&e), 3);
    }

    #[test]
    fn tx_count_generalized_sums_phases_and_clusters() {
        let mut e = TransactionHistoryEntry::default();
        let phases = vec![
            TransactionPhase::V0(
                vec![TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                    xdr::TxSetComponentTxsMaybeDiscountedFee {
                        base_fee: None,
                        txs: (0..3).map(|_| tx_env()).collect::<Vec<_>>().try_into().unwrap(),
                    },
                )]
                .try_into()
                .unwrap(),
            ),
            TransactionPhase::V1(xdr::ParallelTxsComponent {
                base_fee: None,
                execution_stages: vec![xdr::ParallelTxExecutionStage(
                    vec![xdr::DependentTxCluster(
                        (0..2).map(|_| tx_env()).collect::<Vec<_>>().try_into().unwrap(),
                    )]
                    .try_into()
                    .unwrap(),
                )]
                .try_into()
                .unwrap(),
            }),
        ];
        e.ext = TransactionHistoryEntryExt::V1(GeneralizedTransactionSet::V1(
            xdr::TransactionSetV1 {
                previous_ledger_hash: xdr::Hash([0; 32]),
                phases: phases.try_into().unwrap(),
            },
        ));
        assert_eq!(tx_count(&e), 5);
    }
}
