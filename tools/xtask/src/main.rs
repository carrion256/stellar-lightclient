//! xtask: fetch a real Stellar mainnet fixture for the light-client contract tests.
//!
//! Usage:
//!   xtask fetch-fixture [--archive <url>] [--checkpoint <ledger>] [--out <path>]
//!   xtask --help

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::MultiGzDecoder;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use stellar_xdr::{
    self as xdr, GeneralizedTransactionSet, LedgerHeaderHistoryEntry, Limits, Limited, NodeId,
    PublicKey, ReadXdr, ScpEnvelope, ScpHistoryEntry, TransactionEnvelope,
    TransactionHistoryEntry, TransactionHistoryEntryExt, TransactionHistoryResultEntry,
    TransactionPhase, TxSetComponent, WriteXdr,
};

const DEFAULT_ARCHIVE: &str = "https://history.stellar.org/prd/core-live/core_live_001";
const NETWORK_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

const USAGE: &str = "\
xtask — Stellar light-client fixture fetcher

USAGE:
    xtask fetch-fixture [OPTIONS]

OPTIONS:
    --archive <url>       History archive base URL
                          (default: https://history.stellar.org/prd/core-live/core_live_001)
    --checkpoint <ledger> Checkpoint ledger (k*64-1) to fetch
                          (default: latest complete checkpoint from the HAS file)
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

    // a. HAS file -> currentLedger -> default checkpoint.
    let has_url = format!("{archive}/.well-known/stellar-history.json");
    println!("fetching {has_url}");
    let has: Value =
        serde_json::from_str(&http_get_string(&has_url)?).map_err(|e| format!("{has_url}: {e}"))?;
    let current_ledger = has["currentLedger"]
        .as_u64()
        .ok_or("HAS file has no numeric currentLedger")? as u32;
    let default_checkpoint = current_ledger - (current_ledger % 64) - 1;
    let mut checkpoint = checkpoint.unwrap_or(default_checkpoint);

    // b/c. Download + decode the four checkpoint files.
    let (ledgers, scp, txs, results) = loop {
        match fetch_checkpoint(&archive, checkpoint) {
            Ok(files) => break files,
            Err(e) if checkpoint >= 64 => {
                eprintln!("checkpoint {checkpoint} unavailable ({e}); falling back 64 ledgers");
                checkpoint -= 64;
            }
            Err(e) => return Err(e),
        }
    };

    // d. Pick the consecutive pair with the most total transactions.
    let (seq_a, seq_b) =
        select_pair(&ledgers, &scp, &txs).ok_or("no consecutive tx-bearing pair found")?;

    // Build one close object per ledger, running all integrity assertions.
    let close_a = build_close(&ledgers, &scp, &txs, &results, seq_a, None)?;
    let close_b = build_close(&ledgers, &scp, &txs, &results, seq_b, Some(&close_a))?;

    // 5. Top-level fixture JSON, pretty-printed, stable key order.
    let fixture = json!({
        "archive": archive,
        "network_passphrase": NETWORK_PASSPHRASE,
        "checkpoint_ledger": checkpoint,
        "closes": [close_a, close_b],
    });
    let path = Path::new(&out);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n")
        .map_err(|e| e.to_string())?;

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
/// Decode the record-framed XDR body of a history file.
///
/// History archive `.xdr.gz` files are framed: each record is preceded by a
/// u32 header `(0x80000000 | record_length)` (the last record also sets bit
/// 0x00800000). The record bodies are the raw canonical XDR of the entry type.
/// The ledger file carries one trailing HAS snapshot record after the 64
/// ledger headers; skip it.
fn decode_seq<T: ReadXdr>(bytes: &[u8]) -> Result<Vec<T>, String> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < bytes.len() {
        if pos + 4 > bytes.len() {
            return Err("truncated record header".into());
        }
        let header = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        if header & 0x8000_0000 == 0 {
            return Err(format!("missing msg bit in record header {header:#010x}"));
        }
        // ponytail: bit 23 of the header doubles as last-record flag; records
        // are <8MB (stellar-core chunk limit), so mask the 23-bit length.
        let len = (header & 0x007f_ffff) as usize;
        if pos + len > bytes.len() {
            return Err("truncated record body".into());
        }
        let mut r = Limited::new(&bytes[pos..pos + len], Limits::none());
        match T::read_xdr(&mut r) {
            Ok(entry) => out.push(entry),
            Err(_) if pos + len >= bytes.len() && out.len() >= 64 => {
                // trailing HAS snapshot record in the ledger file
            }
            Err(e) => return Err(format!("xdr decode: {e}")),
        }
        pos += len;
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
    let ledgers = decode_seq::<LedgerHeaderHistoryEntry>(&http_get_bytes(&format!(
        "{archive}/{}",
        checkpoint_path("ledger", checkpoint)
    ))?)?;
    let scp = decode_seq::<ScpHistoryEntry>(&http_get_bytes(&format!(
        "{archive}/{}",
        checkpoint_path("scp", checkpoint)
    ))?)?;
    let txs = decode_seq::<TransactionHistoryEntry>(&http_get_bytes(&format!(
        "{archive}/{}",
        checkpoint_path("transactions", checkpoint)
    ))?)?;
    let results = decode_seq::<TransactionHistoryResultEntry>(&http_get_bytes(&format!(
        "{archive}/{}",
        checkpoint_path("results", checkpoint)
    ))?)?;
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
        let (Some(ta), Some(tb)) = (tx_by_seq.get(&seq), tx_by_seq.get(&(seq + 1))) else {
            continue;
        };
        let (ca, cb) = match (tx_count(ta), tx_count(tb)) {
            (Ok(ca), Ok(cb)) if ca > 0 && cb > 0 => (ca, cb),
            _ => continue,
        };
        let (Some(ea), Some(eb)) = (by_slot.get(&(seq as u64)), by_slot.get(&(seq as u64 + 1)))
        else {
            continue;
        };
        if ea.is_empty() || eb.is_empty() {
            continue;
        }
        let externalize = ea.iter().chain(eb.iter()).any(|e| {
            matches!(e.statement.pledges, xdr::ScpStatementPledges::Externalize(_))
        });
        if !externalize {
            continue;
        }
        let distinct: BTreeSet<[u8; 32]> = ea
            .iter()
            .chain(eb.iter())
            .filter_map(|e| node_id_bytes(&e.statement.node_id).ok())
            .collect();
        if distinct.len() < 6 {
            continue;
        }
        if best.map_or(true, |(score, _)| ca + cb > score) {
            best = Some((ca + cb, seq));
        }
    }
    best.map(|(_, seq)| (seq, seq + 1))
}

fn tx_count(e: &TransactionHistoryEntry) -> Result<usize, String> {
    Ok(set_txs(e)?.len())
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
    assert_eq!(
        sha256(&header_xdr),
        lhe.hash.0,
        "ledger {seq}: sha256(header_xdr) != LedgerHeaderHistoryEntry.hash — re-encoding is not byte-exact"
    );

    // SCP envelopes for this slot (ledger_seq == slot_index), file order, unfiltered.
    let by_slot = envelopes_by_slot(scp);
    let envs = by_slot
        .get(&(seq as u64))
        .ok_or(format!("ledger {seq}: no SCP history entry"))?;
    let externalize = envs
        .iter()
        .any(|e| matches!(e.statement.pledges, xdr::ScpStatementPledges::Externalize(_)));
    assert!(externalize, "ledger {seq}: slot has no EXTERNALIZE statement");
    let distinct: BTreeSet<[u8; 32]> = envs
        .iter()
        .map(|e| node_id_bytes(&e.statement.node_id))
        .collect::<Result<_, _>>()?;
    assert!(
        distinct.len() >= 6,
        "ledger {seq}: only {} distinct nodes (<6)",
        distinct.len()
    );

    // Empirical tx-set kind: hash the candidate encodings, match scp_value.tx_set_hash.
    let tx_entry = txs
        .iter()
        .find(|e| e.ledger_seq == seq)
        .ok_or(format!("ledger {seq}: no tx history entry"))?;
    let tx_list = set_txs(tx_entry)?;
    assert!(!tx_list.is_empty(), "ledger {seq}: empty tx set");
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
    assert_eq!(
        sha256(&tx_set_xdr),
        header.scp_value.tx_set_hash.0,
        "ledger {seq}: sha256({kind} tx_set_xdr) != header.scp_value.tx_set_hash"
    );

    // Assert: sha256(results_xdr) == header.tx_set_result_hash.
    let res_entry = results
        .iter()
        .find(|e| e.ledger_seq == seq)
        .ok_or(format!("ledger {seq}: no results history entry"))?;
    let results_xdr = xdr_encode(&res_entry.tx_result_set)?;
    assert_eq!(
        sha256(&results_xdr),
        header.tx_set_result_hash.0,
        "ledger {seq}: sha256(results_xdr) != header.tx_set_result_hash"
    );

    // Chosen tx: index 0 (deterministic); element identity re-verified below.
    let tx_index: u32 = 0;
    assert!(
        (tx_index as usize) < tx_list.len(),
        "ledger {seq}: tx_index {tx_index} >= tx_count {}",
        tx_list.len()
    );
    let env_xdr = xdr_encode(&tx_list[tx_index as usize])?;
    let decoded_back = TransactionEnvelope::from_xdr(&env_xdr[..], Limits::none())
        .map_err(|e| e.to_string())?;
    assert_eq!(
        decoded_back, tx_list[tx_index as usize],
        "ledger {seq}: envelope at index {tx_index} does not round-trip"
    );

    // Consecutive-chain check for the second close.
    if let Some(prev) = prev {
        let expected = STANDARD
            .decode(prev["header_hash_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            prev_ledger_hash.to_vec(),
            expected,
            "ledger {seq}: tx_set.previous_ledger_hash != header hash of previous close (chain link)"
        );
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
    Ok(close)
}
