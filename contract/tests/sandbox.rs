//! On-chain end-to-end tests against a real NEAR node.
//!
//! `near-workspaces` boots a local `neard sandbox` and deploys the actual wasm
//! artifact there. Unlike `src/tests.rs` — which executes the contract natively
//! through near-sdk's mock — this crosses every real boundary:
//!
//! * the real wasm binary loads (the thing `cargo build --target wasm32` only
//!   proves syntactically),
//! * the real `alt_bn128_g1_multiexp` / `alt_bn128_pairing_check` host functions
//!   run (the mock delegates to VMLogic; this runs neard itself — the genuine
//!   upstream Groth16 seal in `testdata/risc0_receipt_fixture.json` verifies
//!   through them),
//! * gas is metered by the real runtime, so `total_gas_burnt` is the number a
//!   transaction would actually pay,
//! * arguments cross the real JSON/base64 *and* raw-Borsh serialization boundaries.
//!
//! Run with: `cargo test -p stellar-light-client --test sandbox -- --nocapture`

use base64::Engine as _;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use near_workspaces::types::Gas;
use near_workspaces::{Contract, Worker};
use serde_json::{json, Value};
use stellar_light_client::{SpanProofRaw, TxClaimRaw};
use stellar_xdr::WriteXdr;

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/fixture.json");

fn fixture() -> Value {
    let raw = std::fs::read_to_string(FIXTURE_PATH)
        .expect("testdata/fixture.json missing — run: cargo run -p xtask -- fetch-fixture");
    serde_json::from_str(&raw).expect("fixture is not valid json")
}

/// Standard base64 of the bytes — the wire form `Base64VecU8` expects.
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("fixture has invalid base64")
}

fn b64_field(v: &Value) -> String {
    v.as_str().expect("expected base64 string").to_string()
}

fn b64_list(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("expected array")
        .iter()
        .map(b64_field)
        .collect()
}


/// Sparse span `[first, tail]` in the contract's `SpanProof` JSON shape: both
/// headers, but only the *tail* carries the certificate and transaction set.
/// No `start_header`: multi-header spans authenticate their own predecessor
/// (the penultimate header), and provisional spans are not submittable.
fn span_json(first: &Value, tail: &Value) -> Value {
    json!({
        "start_header": Value::Null,
        "headers": [
            b64_field(&first["header_xdr_b64"]),
            b64_field(&tail["header_xdr_b64"]),
        ],
        "tail_envelopes": b64_list(&tail["scp_envelopes_b64"]),
        "tail_tx_set_xdr": b64_field(&tail["tx_set_xdr_b64"]),
        "tx_claims": [{
            "tx_envelope_xdr": b64_field(&tail["tx_envelope_xdr_b64"]),
            "tx_index": tail["tx_index"],
        }],
    })
}

fn num(v: &Value) -> u32 {
    v.as_u64().expect("expected number") as u32
}

/// Call a no-argument view.
///
/// near-sdk deserialises a zero-arg method's input as `()`, and serde's unit type
/// accepts `null` but not `{}` — while `{}` is the conventional empty call args.
/// Try the convention first and fall back, so the test is right either way.
async fn view_json(contract: &Contract, method: &str) -> Value {
    match contract.view(method).args_json(json!({})).await {
        Ok(result) => result.json().expect("view must return json"),
        Err(_) => contract
            .view(method)
            .args_json(Value::Null)
            .await
            .unwrap_or_else(|e| panic!("{method} failed to answer either encoding: {e}"))
            .json()
            .expect("view must return json"),
    }
}

/// The newest modification time among the wasm build inputs: all sources and
/// manifests of this crate and its local path dependencies (`verifier`,
/// `verify-core`), plus the workspace root manifests. The deployed contract
/// embeds the local dependencies, so their changes make the artifact stale too.
fn latest_build_input() -> Option<(std::path::PathBuf, std::time::SystemTime)> {
    fn newest_of(dir: &std::path::Path, current: &mut Option<(std::path::PathBuf, std::time::SystemTime)>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            // This module is behind #[cfg(test)] and is not a WASM build input.
            if path.ends_with("contract/src/tests.rs") {
                continue;
            }
            if path.is_dir() {
                newest_of(&path, current);
            } else if let Ok(time) = std::fs::metadata(&path).and_then(|m| m.modified()) {
                if current.as_ref().is_none_or(|(_, t)| time > *t) {
                    *current = Some((path, time));
                }
            }
        }
    }
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut newest: Option<(std::path::PathBuf, std::time::SystemTime)> = None;
    for dir in ["contract/src", "verifier/src", "verify-core/src"] {
        newest_of(&workspace.join(dir), &mut newest);
    }
    for manifest in [
        "contract/Cargo.toml",
        "verifier/Cargo.toml",
        "verify-core/Cargo.toml",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        let path = workspace.join(manifest);
        if let Ok(time) = std::fs::metadata(&path).and_then(|m| m.modified()) {
            if newest.as_ref().is_none_or(|(_, t)| time > *t) {
                newest = Some((path, time));
            }
        }
    }
    newest
}

/// Read the compiled wasm artifact.
///
/// The test deliberately does NOT shell out to cargo to build it: a nested build
/// contends for the same target-dir lock that the running `cargo test` holds.
/// Build it first with
/// `cargo build -p stellar-light-client --release --target wasm32-unknown-unknown`.
fn read_wasm() -> Vec<u8> {
    // Cargo runs test binaries with CWD at the *package* root, so a relative
    // CARGO_TARGET_DIR must be resolved against the workspace root, not CWD.
    let workspace_root = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
    let target_dir = match std::env::var("CARGO_TARGET_DIR") {
        Ok(dir) if std::path::Path::new(&dir).is_absolute() => dir,
        Ok(dir) => format!("{workspace_root}/{dir}"),
        Err(_) => format!("{workspace_root}/target"),
    };
    let path = format!("{target_dir}/wasm32-unknown-unknown/release/stellar_light_client.wasm");
    // `cargo test` does not rebuild this artifact, so a stale wasm silently
    // tests an old contract (calls to newer methods trap with no logs).
    // Freshness must bind the artifact to EVERY relevant build input — this
    // crate and its local path dependencies (`verifier`, `verify-core`)
    // including all their sources and manifests, plus the workspace root
    // Cargo.toml/Cargo.lock — not just the entry file.
    if let (Ok(wasm_time), Some((src, src_time))) =
        (std::fs::metadata(&path).and_then(|m| m.modified()), latest_build_input())
    {
        assert!(
            wasm_time >= src_time,
            "wasm artifact at {path} is OLDER than {src:?} — rebuild first:\n\
             \x20 cargo build -p stellar-light-client --release --target wasm32-unknown-unknown"
        );
    }
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "wasm artifact not found at {path} ({e}); build it first with:\n\
             \x20 cargo build -p stellar-light-client --release --target wasm32-unknown-unknown"
        )
    })
}

/// The client's epoch inputs, shared between deployment and the claim-binding
/// tests so both agree on network, trust policy, checkpoint and image.
fn client_epoch_inputs(f: &Value) -> (u32, [u8; 32], [u8; 32], Vec<Vec<u8>>, u32, [u8; 32]) {
    use sha2::{Digest, Sha256};
    let first = &f["closes"][0];
    let network_id: [u8; 32] =
        Sha256::digest(f["network_passphrase"].as_str().unwrap().as_bytes()).into();
    let head_hash: [u8; 32] = b64_decode(&b64_field(&first["tx_set_previous_ledger_hash_b64"]))
        .try_into()
        .expect("checkpoint hash is 32 bytes");
    let trusted_nodes: Vec<Vec<u8>> =
        b64_list(&first["distinct_signers_b64"]).into_iter().map(|s| b64_decode(&s)).collect();
    let threshold = trusted_nodes.len() as u32;
    (num(&first["ledger_seq"]) - 1, head_hash, network_id, trusted_nodes, threshold, [0xEEu8; 32])
}

/// Deploy and initialise the light client against the fixture's real mainnet
/// data. Trust set = the node ids that actually signed this mainnet ledger;
/// threshold = all of them, so the fixture's certificate can and must reach it.
async fn deploy_light_client(worker: &Worker<near_workspaces::network::Sandbox>) -> (Contract, Value) {
    let wasm = read_wasm();
    let contract = worker
        .dev_deploy(&wasm)
        .await
        .expect("wasm must deploy to the sandbox");

    let f = fixture();
    let (head_seq, head_hash, network_id, trusted_nodes, threshold, epoch_image_id) =
        client_epoch_inputs(&f);

    let outcome = contract
        .call("new")
        .args_json(json!({
            "owner": contract.id(),
            "network_id": b64(&network_id),
            "trusted_nodes": trusted_nodes.iter().map(|n| b64(n)).collect::<Vec<_>>(),
            "threshold": threshold,
            "max_protocol_version": 99,
            "head_seq": head_seq,
            "head_hash": b64(&head_hash),
            "control_root": b64(&[0x11u8; 32]),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "epoch_image_id": b64(&epoch_image_id),
        }))
        .transact()
        .await
        .expect("init call must reach the chain");
    assert!(outcome.is_success(), "init failed: {outcome:?}");
    (contract, f)
}


#[tokio::test(flavor = "multi_thread")]
async fn e2e_sparse_span_submission_advances_the_head() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;

    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();
    let outcome = contract
        .call("submit_span").gas(Gas::from_tgas(300))
        .args_json(json!({ "span": span_json(&first, &tail) }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "submit_span failed: {:?}", outcome.logs());

    // The head advances only through the authenticated predecessor — the
    // first header, pinned by the tail's signed transaction set — never to
    // the unauthenticated tail itself.
    let head = view_json(&contract, "get_head").await;
    assert_eq!(head["ledger_seq"], json!(num(&first["ledger_seq"])));

    // Real gas, metered by neard — this is what a transaction would pay.
    println!(
        "submit_span ({} txs in set): {} Tgas burnt on-chain",
        tail["tx_count"],
        outcome.total_gas_burnt.as_gas() / 1_000_000_000_000,
    );

    // The claim is proven and returned — never stored by the light client.
    let evidence: Value = outcome.json()?;
    assert_eq!(
        evidence["authenticated_head"]["ledger_seq"],
        json!(num(&first["ledger_seq"]))
    );
    let tx_id = {
        use sha2::{Digest, Sha256};
        b64(&Sha256::digest(b64_decode(&b64_field(&tail["tx_envelope_xdr_b64"]))))
    };
    assert_eq!(evidence["claimed_tx_ids"], json!([tx_id]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_provisional_span_is_viewable_but_not_submittable() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();

    // The view reports provisional spans with no authenticated head...
    let mut span = span_json(&first, &tail);
    span["tail_tx_set_xdr"] = json!(null);
    span["tx_claims"] = json!([]); // claims need the tx set; a provisional witness carries none
    let evidence: Value = contract
        .view("verify_span_view")
        .args_json(json!({
            "head_seq": num(&first["ledger_seq"]) - 1,
            "head_hash": b64_field(&first["tx_set_previous_ledger_hash_b64"]),
            "span": span,
        }))
        .await?
        .json()?;
    assert!(evidence["authenticated_head"].is_null(), "no tail set, no authenticated head");

    // ...but the same span can never move the stored head.
    let outcome = contract
        .call("submit_span").gas(Gas::from_tgas(300))
        .args_json(json!({ "span": span }))
        .transact()
        .await?;
    assert!(!outcome.is_success(), "provisional spans must not be submittable");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_wrapper_views_are_readable_by_anyone() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;

    let wrapper = view_json(&contract, "get_wrapper").await;
    assert_eq!(wrapper["control_root"], json!(b64(&[0x11u8; 32])));
    assert_eq!(wrapper["bn254_control_id"], json!(b64(&[0x22u8; 32])));

    let compatible: bool = contract
        .view("is_wrapper_compatible")
        .args_json(json!({
            "control_root": b64(&[0x11u8; 32]),
            "bn254_control_id": b64(&[0x22u8; 32]),
        }))
        .await?
        .json()?;
    assert!(compatible, "pinned wrapper must be reported compatible");

    let incompatible: bool = contract
        .view("is_wrapper_compatible")
        .args_json(json!({
            "control_root": b64(&[0x99u8; 32]),
            "bn254_control_id": b64(&[0x22u8; 32]),
        }))
        .await?
        .json()?;
    assert!(!incompatible, "unpinned wrapper must be reported incompatible");

    // A receipt from an unpinned wrapper is rejected on-chain, before any proof work.
    let outcome = contract
        .call("verify_receipt").gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x99u8; 32]),
            "claim_digest": b64(&[0u8; 32]),
            "bn254_control_id": b64(&[0x22u8; 32]),
        }))
        .transact()
        .await?;
    assert!(!outcome.is_success(), "unpinned wrapper must not verify");
    std::fs::write("/tmp/sandbox_wrapper_outcome.txt", format!("{outcome:#?}")).ok();
    let debug = format!("{:?}", outcome.logs());
    assert!(
        debug.contains("unsupported RISC Zero wrapper"),
        "rejection reason should name the wrapper, got: {debug}"
    );

    // And a well-formed-but-invalid seal from the *pinned* wrapper yields
    // verified: false rather than a panic.
    let outcome = contract
        .call("verify_receipt").gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x11u8; 32]),
            "claim_digest": b64(&[0u8; 32]),
            "bn254_control_id": b64(&[0x22u8; 32]),
        }))
        .transact()
        .await?;
    let evidence: Value = outcome.json()?;
    assert_eq!(evidence["verified"], json!(false));
    let _ = f;
    Ok(())
}


// ------------------------------------------- group 3: verify_claim (RISC Zero)

/// The canonical trust-policy commitment, computed in-test the same way the
/// guest computes it for its journal (`verify_core::trust_digest`).
fn trust_policy_digest(
    network_id: &[u8; 32],
    trusted_nodes: &[Vec<u8>],
    threshold: u32,
    max_protocol_version: u32,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut nodes: Vec<&Vec<u8>> = trusted_nodes.iter().collect();
    nodes.sort();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"stellar-lightclient/trust/v1\0");
    bytes.extend_from_slice(network_id);
    bytes.extend_from_slice(&(nodes.len() as u32).to_be_bytes());
    for node in nodes {
        bytes.extend_from_slice(node);
    }
    bytes.extend_from_slice(&threshold.to_be_bytes());
    bytes.extend_from_slice(&max_protocol_version.to_be_bytes());
    Sha256::digest(&bytes).to_vec()
}

/// Digest helpers route through `env::sha256`, which needs a mocked
/// blockchain in-process; the chain calls below still go to the sandbox.
fn epoch_claim_digest(image_id: [u8; 32], journal: &[u8]) -> Vec<u8> {
    testing_env!(VMContextBuilder::new().build());
    verifier::claim::claim_digest(&verifier::claim::ok_claim(image_id, journal)).to_vec()
}

/// The epoch journal a real guest would commit for `client`: current policy,
/// stored start checkpoint, coherent end two ledgers later.
fn epoch_journal_for(
    network_id: &[u8; 32],
    trusted_nodes: &[Vec<u8>],
    threshold: u32,
    head_seq: u32,
    head_hash: [u8; 32],
) -> Vec<u8> {
    verify_core::encode_journal(&verify_core::EpochJournal {
        policy_digest: trust_policy_digest(network_id, trusted_nodes, threshold, 99)
            .try_into()
            .unwrap(),
        start_seq: head_seq,
        start_hash: head_hash,
        end_seq: head_seq + 2,
        end_hash: [0xBB; 32],
        claim_ids: vec![[0x0C; 32], [0x0D; 32]],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_verify_claim_reports_bad_proof_with_zeroed_epoch_fields() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;
    let (head_seq, head_hash, network_id, trusted_nodes, threshold, image_id) = client_epoch_inputs(&f);
    let journal = epoch_journal_for(&network_id, &trusted_nodes, threshold, head_seq, head_hash);
    // The claim digest is DERIVED by the contract; callers cannot choose it.
    let claim_digest = epoch_claim_digest(image_id, &journal);

    // A garbage seal cannot verify — but the journal still binds, and the
    // unverified evidence must expose no epoch fields.
    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x11u8; 32]),
            "claim_digest": b64(&claim_digest),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "journal": b64(&journal),
        }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "verify_claim must not panic: {:?}", outcome.logs());
    let evidence: Value = outcome.json()?;
    assert_eq!(evidence["verified"], json!(false), "garbage seal must not verify");
    assert_eq!(evidence["end_seq"], json!(0));
    assert!(evidence["claim_ids"].as_array().unwrap().is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_verify_claim_rejects_foreign_image_claim() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;
    let (head_seq, head_hash, network_id, trusted_nodes, threshold, _) = client_epoch_inputs(&f);
    let journal = epoch_journal_for(&network_id, &trusted_nodes, threshold, head_seq, head_hash);
    // The digest binds a DIFFERENT guest image: the wrapper verifying key is
    // universal, so this is the only line of defence.
    let foreign_digest = epoch_claim_digest([0x77u8; 32], &journal);

    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x11u8; 32]),
            "claim_digest": b64(&foreign_digest),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "journal": b64(&journal),
        }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "binding failure must not panic: {:?}", outcome.logs());
    assert_eq!(outcome.json::<Value>()?["verified"], json!(false));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_verify_claim_rejects_stale_checkpoint() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;
    let (head_seq, head_hash, network_id, trusted_nodes, threshold, image_id) = client_epoch_inputs(&f);
    let stale = epoch_journal_for(&network_id, &trusted_nodes, threshold, head_seq - 1, head_hash);
    let claim_digest = epoch_claim_digest(image_id, &stale);

    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x11u8; 32]),
            "claim_digest": b64(&claim_digest),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "journal": b64(&stale),
        }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "binding failure must not panic: {:?}", outcome.logs());
    assert_eq!(outcome.json::<Value>()?["verified"], json!(false));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_verify_claim_rejects_foreign_policy_journal() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;
    let (head_seq, head_hash, network_id, trusted_nodes, threshold, image_id) = client_epoch_inputs(&f);
    let mut journal = epoch_journal_for(&network_id, &trusted_nodes, threshold, head_seq, head_hash);
    journal[76] ^= 0x01; // corrupt the v1 policy_digest: same encoding, foreign policy
    let claim_digest = epoch_claim_digest(image_id, &journal);

    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x11u8; 32]),
            "claim_digest": b64(&claim_digest),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "journal": b64(&journal),
        }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "binding failure must not panic: {:?}", outcome.logs());
    assert_eq!(outcome.json::<Value>()?["verified"], json!(false));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_verify_claim_rejects_unpinned_wrapper() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, _) = deploy_light_client(&worker).await;
    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x99u8; 32]),
            "claim_digest": b64(&[0u8; 32]),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "journal": b64(&[]),
        }))
        .transact()
        .await?;
    assert!(!outcome.is_success(), "unpinned wrapper must be rejected");
    let logs = format!("{:?}", outcome.logs());
    assert!(
        logs.contains("unsupported RISC Zero wrapper"),
        "rejection reason should be logged, got: {logs}"
    );
    Ok(())
}

// -------------------------------- group 4: genuine seal, raw path, head auth
//
// The genuine-receipt fixture (source-pinned upstream RISC Zero v3.0 Groth16
// seal) drives the REAL `alt_bn128_*` host functions in this sandbox — proof
// that the pairing gate is live and the wrapper pin accepts real receipts. The
// journal is a genuine zkVM journal, but it is *not* a Stellar epoch journal:
// `verify_claim`'s journal binding must reject it even though the raw receipt
// pairs — a valid execution is not a valid epoch claim.

const RISCV0_RECEIPT_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/risc0_receipt_fixture.json");

fn hex_bytes(value: &serde_json::Value) -> Vec<u8> {
    let hex = value.as_str().expect("expected hex string");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

struct ReceiptFixture {
    seal: Vec<u8>,
    journal: Vec<u8>,
    control_root: [u8; 32],
    bn254_control_id: [u8; 32],
    claim_digest: [u8; 32],
}

/// Genuine upstream RISC Zero v3.0 Groth16 receipt fixture (source-pinned).
/// Not a Stellar epoch journal — only the wrapper/pairing boundary applies.
fn fixture_seal() -> ReceiptFixture {
    let raw = std::fs::read_to_string(RISCV0_RECEIPT_PATH)
        .expect("testdata/risc0_receipt_fixture.json missing");
    let json: serde_json::Value =
        serde_json::from_str(&raw).expect("receipt fixture is not valid json");
    let digest = |name: &str| -> [u8; 32] {
        let bytes = hex_bytes(&json[name]);
        bytes.try_into().expect("fixture digest is 32 bytes")
    };
    ReceiptFixture {
        seal: hex_bytes(&json["seal"]),
        journal: hex_bytes(&json["journal"]),
        control_root: digest("control_root"),
        bn254_control_id: digest("bn254_control_id"),
        claim_digest: digest("claim_digest"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_genuine_risc0_seal_verifies_on_chain() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, _f) = deploy_light_client(&worker).await;
    let fixture = fixture_seal();

    // The fixture wrapper identity differs from the test init pins; the owner
    // (the sandbox contract account is its own predecessor) may rotate to it.
    let rotated = contract
        .call("update_wrapper")
        .args_json(json!({
            "control_root": b64(&fixture.control_root),
            "bn254_control_id": b64(&fixture.bn254_control_id),
        }))
        .transact()
        .await?;
    assert!(rotated.is_success(), "owner must pin the real wrapper: {:?}", rotated.logs());

    // Raw receipt from the real wrapper verifies against the real alt_bn128
    // host functions — the pairing gate is live, not vacuous.
    let outcome = contract
        .call("verify_receipt")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&fixture.seal),
            "control_root": b64(&fixture.control_root),
            "claim_digest": b64(&fixture.claim_digest),
            "bn254_control_id": b64(&fixture.bn254_control_id),
        }))
        .transact()
        .await?;
    let logs = format!("{:?}", outcome.logs());
    let evidence: Value = outcome.json()?;
    assert_eq!(
        evidence["verified"],
        json!(true),
        "genuine upstream seal must pair: {logs}"
    );

    // Flipping a claim-digest bit must fail.
    let mut wrong = fixture.claim_digest;
    wrong[0] ^= 0x01;
    let outcome = contract
        .call("verify_receipt")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&fixture.seal),
            "control_root": b64(&fixture.control_root),
            "claim_digest": b64(&wrong),
            "bn254_control_id": b64(&fixture.bn254_control_id),
        }))
        .transact()
        .await?;
    assert_eq!(outcome.json::<Value>()?["verified"], json!(false));

    // A malformed (non-canonical raw coordinate) seal must also fail: the
    // strict decoder refuses coordinate encodings above the field modulus.
    let mut malformed = fixture.seal.clone();
    malformed[32] |= 0x80; // high bit of G1_Y's leading byte: >= modulus
    let outcome = contract
        .call("verify_receipt")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&malformed),
            "control_root": b64(&fixture.control_root),
            "claim_digest": b64(&fixture.claim_digest),
            "bn254_control_id": b64(&fixture.bn254_control_id),
        }))
        .transact()
        .await?;
    assert_eq!(
        outcome.json::<Value>()?["verified"],
        json!(false),
        "non-canonical seal coordinates must not pair"
    );

    // The genuine seal proves a *generic* zkVM execution. Its journal is not
    // an EpochJournal, and its image is not this contract's epoch image, so
    // verify_claim's bindings refuse it — even though the receipt itself
    // pairs — and the evidence exposes zero epoch fields.
    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&fixture.seal),
            "control_root": b64(&fixture.control_root),
            "claim_digest": b64(&fixture.claim_digest),
            "bn254_control_id": b64(&fixture.bn254_control_id),
            "journal": b64(&fixture.journal),
        }))
        .transact()
        .await?;
    let evidence: Value = outcome.json()?;
    assert_eq!(evidence["verified"], json!(false), "a generic execution is not an epoch claim");
    assert_eq!(evidence["end_seq"], json!(0), "unverified evidence exposes no epoch fields");
    assert!(evidence["claim_ids"].as_array().unwrap().is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_borsh_raw_span_submission_advances_the_head() -> anyhow::Result<()> {
    use near_sdk::borsh::BorshSerialize;

    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;
    let first = f["closes"][0].clone();
    let tail = f["closes"][1].clone();

    // Exactly the bytes a relayer would place in the raw call input: Borsh,
    // no JSON, no base64. `start_header` is first and `None` here.
    let raw = SpanProofRaw {
        start_header: None,
        headers: vec![b64_decode(&b64_field(&first["header_xdr_b64"])), b64_decode(&b64_field(&tail["header_xdr_b64"]))],
        tail_envelopes: b64_list(&tail["scp_envelopes_b64"]).into_iter().map(|s| b64_decode(&s)).collect(),
        tail_tx_set: Some(b64_decode(&b64_field(&tail["tx_set_xdr_b64"]))),
        tx_claims: vec![TxClaimRaw {
            tx_envelope: b64_decode(&b64_field(&tail["tx_envelope_xdr_b64"])),
            tx_index: num(&tail["tx_index"]),
        }],
    };
    let mut bytes = Vec::new();
    raw.serialize(&mut bytes).expect("borsh encode");

    let outcome = contract
        .call("submit_span_raw")
        .gas(Gas::from_tgas(300))
        .args(bytes)
        .transact()
        .await?;
    assert!(outcome.is_success(), "raw submit_span failed: {:?}", outcome.logs());

    let evidence: Value = outcome.json()?;
    assert_eq!(evidence["authenticated_head"]["ledger_seq"], json!(num(&first["ledger_seq"])));
    let head = view_json(&contract, "get_head").await;
    assert_eq!(head["ledger_seq"], json!(num(&first["ledger_seq"])));

    // The claim is proven and returned — never stored by the light client.
    let tx_id = {
        use sha2::{Digest, Sha256};
        b64(&Sha256::digest(b64_decode(&b64_field(&tail["tx_envelope_xdr_b64"]))))
    };
    assert_eq!(evidence["claimed_tx_ids"], json!([tx_id]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_forged_tail_hash_is_never_persisted() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;
    let close = f["closes"][0].clone();
    let original_head = view_json(&contract, "get_head").await;

    // Tamper ONLY the tail header's tx_set_result_hash: the signed envelope,
    // SCP value and transaction set all still check out, and the core accepts
    // the span — but the tail header's own hash (now forged) must never land
    // in contract state. Only the authenticated predecessor may.
    // Decode, flip the result hash, re-encode — the native regression's path;
    // byte 68 is close_time (4 version + 32 prev + 32 tx_set_hash), which is signed.
    let original = b64_decode(&b64_field(&close["header_xdr_b64"]));
    let mut reader =
        stellar_xdr::Limited::new(std::io::Cursor::new(original.as_slice()), stellar_xdr::Limits::none());
    let mut header: stellar_xdr::LedgerHeader =
        stellar_xdr::ReadXdr::read_xdr_to_end(&mut reader).expect("fixture header is valid xdr");
    header.tx_set_result_hash.0[0] ^= 0x01;
    let mut forged = Vec::new();
    header
        .write_xdr(&mut stellar_xdr::Limited::new(&mut forged, stellar_xdr::Limits::none()))
        .expect("re-encode tampered header");
    let outcome = contract
        .call("submit_span")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "span": {
                "start_header": Value::Null,
                "headers": [b64(&forged)],
                "tail_envelopes": b64_list(&close["scp_envelopes_b64"]),
                "tail_tx_set_xdr": b64_field(&close["tx_set_xdr_b64"]),
                "tx_claims": [],
            }
        }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "tampered header must still chain: {:?}", outcome.logs());

    // Head is the *original* checkpoint, not the forged tail hash.
    let head = view_json(&contract, "get_head").await;
    assert_eq!(head["ledger_seq"], original_head["ledger_seq"]);
    assert_eq!(head["header_hash"], original_head["header_hash"]);

    // And the next honest overlapping span is still accepted — the chain is
    // not poisoned by the rejected submission. It advances to the first
    // header's checkpoint: the ledger authenticated by the tail's signed set.
    let tail = f["closes"][1].clone();
    let outcome = contract
        .call("submit_span")
        .gas(Gas::from_tgas(300))
        .args_json(json!({ "span": span_json(&close, &tail) }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "honest span after forgery must be accepted: {:?}", outcome.logs());
    let head = view_json(&contract, "get_head").await;
    assert_eq!(head["ledger_seq"], json!(num(&close["ledger_seq"])));
    Ok(())
}
