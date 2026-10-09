//! On-chain end-to-end tests against a real NEAR node.
//!
//! `near-workspaces` boots a local `neard sandbox` and deploys the actual wasm
//! artifact there. Unlike `src/tests.rs` — which executes the contract natively
//! through near-sdk's mock — this crosses every real boundary:
//!
//! * the real wasm binary loads (the thing `cargo build --target wasm32` only
//!   proves syntactically),
//! * the real `alt_bn128_g1_multiexp` / `alt_bn128_pairing_check` host functions
//!   run (the mock delegates to VMLogic; this runs neard itself),
//! * gas is metered by the real runtime, so `total_gas_burnt` is the number a
//!   transaction would actually pay,
//! * arguments cross the real JSON/base64 serialization boundary.
//!
//! Run with: `cargo test -p stellar-light-client --test sandbox -- --nocapture`

use base64::Engine as _;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use near_workspaces::types::Gas;
use near_workspaces::{Contract, Worker};
use serde_json::{json, Value};

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

/// One-header span at `close`, matching the contract's `SpanProof` JSON shape.
fn span_json(close: &Value) -> Value {
    json!({
        "headers": [b64_field(&close["header_xdr_b64"])],
        "tail_envelopes": b64_list(&close["scp_envelopes_b64"]),
        "tail_tx_set_xdr": b64_field(&close["tx_set_xdr_b64"]),
        "tx_claims": [{
            "tx_envelope_xdr": b64_field(&close["tx_envelope_xdr_b64"]),
            "tx_index": close["tx_index"],
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
    // `cargo test` does not rebuild this artifact, so a stale wasm silently tests an
    // old contract (calls to newer methods trap with no logs). Fail loudly instead.
    let source = format!("{}/src/lib.rs", env!("CARGO_MANIFEST_DIR"));
    if let (Ok(wasm), Ok(src)) = (std::fs::metadata(&path), std::fs::metadata(&source)) {
        if let (Ok(wasm_time), Ok(src_time)) = (wasm.modified(), src.modified()) {
            assert!(
                wasm_time >= src_time,
                "wasm artifact at {path} is OLDER than contract/src/lib.rs — rebuild first:\n\
                 \x20 cargo build -p stellar-light-client --release --target wasm32-unknown-unknown"
            );
        }
    }
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "wasm artifact not found at {path} ({e}); build it first with:\n\
             \x20 cargo build -p stellar-light-client --release --target wasm32-unknown-unknown"
        )
    })
}

/// Deploy and initialise the light client against the fixture's real mainnet data.
async fn deploy_light_client(worker: &Worker<near_workspaces::network::Sandbox>) -> (Contract, Value) {
    let wasm = read_wasm();
    let contract = worker
        .dev_deploy(&wasm)
        .await
        .expect("wasm must deploy to the sandbox");

    let f = fixture();
    let first = f["closes"][0].clone();
    let network_id = {
        // sha256(network passphrase) — the first 32 bytes of every Stellar signature.
        use sha2::{Digest, Sha256};
        let passphrase = f["network_passphrase"].as_str().unwrap();
        Sha256::digest(passphrase.as_bytes())
    };
    // Trust set = the node ids that actually signed this mainnet ledger; threshold =
    // all of them, so the fixture's certificate can and must reach it.
    let trusted_nodes = b64_list(&first["distinct_signers_b64"]);

    let outcome = contract
        .call("new")
        .args_json(json!({
            "owner": contract.id(),
            "network_id": b64(&network_id),
            "trusted_nodes": trusted_nodes,
            "threshold": trusted_nodes.len(),
            "max_protocol_version": 99,
            "head_seq": num(&first["ledger_seq"]) - 1,
            "head_hash": b64_field(&first["tx_set_previous_ledger_hash_b64"]),
            "control_root": b64(&[0x11u8; 32]),
            "bn254_control_id": b64(&[0x22u8; 32]),
        }))
        .transact()
        .await
        .expect("init call must reach the chain");
    assert!(outcome.is_success(), "init failed: {outcome:?}");
    (contract, f)
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_span_submission_advances_the_head() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, f) = deploy_light_client(&worker).await;

    let close = f["closes"][0].clone();
    let expected_seq = num(&close["ledger_seq"]);

    let outcome = contract
        .call("submit_span").gas(Gas::from_tgas(300))
        .args_json(json!({ "span": span_json(&close) }))
        .transact()
        .await?;
    std::fs::write("/tmp/sandbox_span_outcome.txt", format!("{outcome:#?}")).ok();
    assert!(outcome.is_success(), "submit_span failed: {:?}", outcome.logs());

    // Real on-chain state advanced, and the claim was proven.
    let head = view_json(&contract, "get_head").await;
    assert_eq!(head["ledger_seq"], json!(expected_seq));

    // Real gas, metered by neard — this is what a transaction would pay.
    println!(
        "submit_span ({} txs in set): {} Tgas burnt on-chain",
        close["tx_count"],
        outcome.total_gas_burnt.as_gas() / 1_000_000_000_000,
    );

    // The claim is proven and returned — never stored by the light client.
    let evidence: Value = outcome.json()?;
    let tx_id = {
        use sha2::{Digest, Sha256};
        b64(&Sha256::digest(b64_decode(&b64_field(&close["tx_envelope_xdr_b64"]))))
    };
    assert_eq!(evidence["claimed_tx_ids"], json!([tx_id]));
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

/// Build a structurally-consistent (claim, journal) pair.
///
/// `verifier::claim`'s digest helpers route through `env::sha256`, which needs a
/// mocked blockchain in-process; the chain calls below still go to the sandbox.
fn epoch_claim_fixture(journal: &[u8]) -> (Vec<u8>, Vec<u8>) {
    testing_env!(VMContextBuilder::new().build());
    let claim = verifier::claim::ok_claim([0x11u8; 32], journal);
    let digest = verifier::claim::claim_digest(&claim);
    (claim.encode(), digest.to_vec())
}

fn epoch_journal_bytes() -> Vec<u8> {
    verify_core::encode_journal(&verify_core::EpochJournal {
        start_seq: 64822012,
        start_hash: [0xAA; 32],
        end_seq: 64822014,
        end_hash: [0xBB; 32],
        claim_ids: vec![[0x0C; 32], [0x0D; 32]],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_verify_claim_decodes_journal_but_reports_bad_proof() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, _f) = deploy_light_client(&worker).await;
    let journal = epoch_journal_bytes();
    let (claim, claim_digest) = epoch_claim_fixture(&journal);

    // A garbage seal cannot verify — but the claim/journal binding is checked
    // independently and the journal must still be readable from the evidence.
    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x11u8; 32]),
            "claim_digest": b64(&claim_digest),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "claim": b64(&claim),
            "journal": b64(&journal),
        }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "verify_claim must not panic: {:?}", outcome.logs());
    let evidence: Value = outcome.json()?;
    assert_eq!(evidence["verified"], json!(false), "garbage seal must not verify");
    assert_eq!(evidence["end_seq"], json!(64822014));
    assert_eq!(evidence["claim_ids"], json!([b64(&[0x0C; 32]), b64(&[0x0D; 32])]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_verify_claim_rejects_claim_digest_mismatch() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, _f) = deploy_light_client(&worker).await;
    let journal = epoch_journal_bytes();
    let (claim, _) = epoch_claim_fixture(&journal);

    // A receipt whose claim_digest public input does not match the claim bytes is
    // reported as unverified, never accepted.
    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x11u8; 32]),
            "claim_digest": b64(&[0xFF; 32]),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "claim": b64(&claim),
            "journal": b64(&journal),
        }))
        .transact()
        .await?;
    assert!(outcome.is_success(), "binding failure must not panic: {:?}", outcome.logs());
    let evidence: Value = outcome.json()?;
    assert_eq!(evidence["verified"], json!(false));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_verify_claim_rejects_unpinned_wrapper() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, _f) = deploy_light_client(&worker).await;
    let journal = epoch_journal_bytes();
    let (claim, claim_digest) = epoch_claim_fixture(&journal);

    let outcome = contract
        .call("verify_claim")
        .gas(Gas::from_tgas(300))
        .args_json(json!({
            "seal": b64(&[0u8; 256]),
            "control_root": b64(&[0x99u8; 32]),
            "claim_digest": b64(&claim_digest),
            "bn254_control_id": b64(&[0x22u8; 32]),
            "claim": b64(&claim),
            "journal": b64(&journal),
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
