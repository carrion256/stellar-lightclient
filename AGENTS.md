# Development environment

## Entry

```bash
nix develop --no-pure-eval .#default
```

Or `direnv allow` once and `cd` into the repo — `.envrc` calls
`use flake . --no-pure-eval` for you.

**Flakes only see git-tracked files.** `git add` any new file before entering the
shell, or nix will report it as missing. Lockfile changes require re-adding.

## Shell guarantees

- Rust (stable) with the `wasm32-unknown-unknown` and `wasm32v1-none` targets
  preinstalled (the latter for Soroban contracts).
- `cargo-risczero` **3.0.6** (with `r0vm`), from nix. The pinned Groth16
  verifying key in `groth16-core/src/risc0.rs` and the `ReceiptClaim` digest in
  `groth16-core/src/claim.rs` come from the **3.0.5** verification crates
  (`risc0-groth16`, `risc0-binfmt`, `risc0-zkp`) — those did not move between
  3.0.5 and 3.0.6, so the wrapper identity is expected to be unchanged.
  If any *verification* crate bumps, re-transcribe the VK and re-pin the claim
  digest before trusting a receipt. Re-pin in `groth16-core`, **not** in
  `verifier/src/risc0.rs` or `verifier/src/claim.rs` — those are thin NEAR
  adapters over the shared crate and hold no constants of their own.
  The definitive check is to build a seal and confirm its `bn254_control_id`
  matches the deployed value. Note the two chains differ here: the NEAR contract
  *stores* `control_root`/`bn254_control_id` (set by `update_wrapper`, readable
  via `get_wrapper`, comparable via `is_wrapper_compatible`), so it has a pinned
  value to check against. The Soroban contract does not — it is a stateless
  verifier and takes both as caller-supplied arguments, so there is nothing to
  compare against in the deployment and the caller must pin them at integration
  time.
- OpenSSL headers + `pkg-config`, so `openssl-sys` (pulled in by near-workspaces)
  builds against nix's openssl instead of compiling from source.
- `commit.gpgsign=false` for the session only, via `GIT_CONFIG_*` — this
  workstation has no usable gpg secret key, and the setting must never leak into
  global or per-repo git config.

## Commands

| task | command |
|---|---|
| contract wasm | `cargo build -p stellar-light-client --release --target wasm32-unknown-unknown` |
| workspace tests, including NEAR sandbox | `cargo test --workspace` |
| standalone guest tests | `cargo test --manifest-path guest/methods/guest/Cargo.toml` |
| relayer tests | `python3 -m unittest discover -s tools -p test_relay.py` |
| NEAR contract wasm | `cargo build -p stellar-light-client --release --target wasm32-unknown-unknown` |
| Soroban contract wasm | `stellar contract build --manifest-path stellar-verifier/Cargo.toml` |
| zkVM guest toolchain | `risc0-setup` |
| build guest program (does not prove a receipt) | `cargo risczero build --manifest-path guest/Cargo.toml --features zkvm-entrypoint` |
| fetch and authenticate a fixture | `cargo run -p xtask -- fetch-fixture --checkpoint 64822015 --out /tmp/stellar-fixture.json` |
| prepare raw-Borsh calldata | `python3 tools/relay.py --proof testdata/fixture.json --contract lc.testnet --format borsh --dry-run --output /tmp/span.borsh` |

Build the wasm **before** `cargo test`: sandbox e2e deploys that artifact.
Its freshness guard checks contract, verifier, and verify-core sources and
manifests, plus the root manifest and lockfile. The guest has a separate
workspace and lockfile, so its tests must also be run explicitly.

## Building the Soroban contract

`stellar-verifier` is a Soroban contract and does **not** build with plain
`cargo build`. Three things bite, in the order you will hit them:

1. `soroban-sdk` v28 requires `stellar-cli` **v25.2.0+** and rejects `cargo
   build` outright ("use `stellar contract build`"). The CLI lives at
   `~/.cargo/bin/stellar` and is **not on `PATH`** in the nix shell — export
   `$HOME/.cargo/bin` first. Version here is 26.1.0.
2. The target is **`wasm32v1-none`**, not `wasm32-unknown-unknown`. Rust 1.82+
   enables `reference-types`/`multi-value` on `wasm32-unknown-unknown`, which
   the Soroban Environment rejects. `wasm32v1-none` is a `no_std` target, so
   anything linked into a contract must be `no_std`-clean. It is provisioned by
   `devenv.nix`; outside the shell you need
   `rustup target add wasm32v1-none` first or the build dies with
   `can't find crate for core` before reaching any of your code.
3. `stellar contract build` refuses a release profile without
   `overflow-checks = true`. The workspace profile sets it; do not remove it.

`groth16-core` is the shared, chain-agnostic Groth16 core behind both verifiers.
It must stay `no_std`-clean and must never depend on `near-sdk` or
`soroban-sdk` — the chain seam is the three-method `ProofOps` trait
(`sha256`, `g1_multiexp`, `pairing_check`). Each chain supplies a provider and
owns its own point encoding: NEAR uses 32-byte little-endian coordinates,
Soroban uses Ethereum-compatible big-endian.

The Docker guest builder needs network access to crates.io. For a locally
installed `risc0` toolchain, the Nix shell's `rustc` must not shadow that
toolchain during a native guest build:

```bash
RUSTC="$(rustup which --toolchain risc0 rustc)" \
RUSTDOC="$(rustup which --toolchain risc0 rustdoc)" \
CARGO_TARGET_RISCV32IM_RISC0_ZKVM_ELF_RUSTFLAGS='--cfg getrandom_backend="custom" -C link-arg=-Ttext=0x00200800' \
rustup run risc0 cargo build --manifest-path guest/Cargo.toml \
  --release --locked --target riscv32im-risc0-zkvm-elf --features zkvm-entrypoint
```

RISC Zero 3 requires the user ELF to be packaged with the default
`risc0_zkos_v1compat::V1COMPAT_ELF` kernel using
`risc0_binfmt::ProgramBinary::new(user_elf, kernel).encode()` before execution
or image-ID calculation. `risc0-build` performs this packaging automatically.
The guest reads `ExecutorEnv::builder().write(&input_bytes.len())` followed by
`write_slice(&input_bytes)`, where the payload is fixed-int bincode `EpochInput`.
Use `default_executor().execute(env, program)` for execution-only verification;
the `r0vm --elf` CLI proves even when no receipt output path is supplied.

## Verification and API boundaries

- Span submission persists only `authenticated_head`: the predecessor pinned
  by the signed tail transaction set. The tail header is provisional. A
  subsequent span starts at the stored predecessor and re-includes the prior
  tail; submissions without a transaction-set pin are rejected.
- Single-header transaction claims require `start_header`, matching the
  starting checkpoint. Multi-header claims obtain that predecessor from the
  span. Protocol checks use authenticated predecessors and signed upgrades,
  not the unsigned tail version.
- **Outcome claims** prove what a transaction *did*, not just that it was
  submitted. An outcome claim is `(tx envelope, TransactionResultPair)`, and it
  needs no transaction-set proof: stellar-core emits a result row only for a
  transaction it applied, so the row implies inclusion. Two bindings make it
  sound — the row's `transaction_hash` must equal `tx_contents_hash(network_id,
  envelope)`, and the row must be an element of the committed result set, so a
  `TxFailed` cannot be re-presented as `TxSuccess`.
- Outcomes bind to the **authenticated head** header, never the tail. The quorum
  certificate signs `StellarValue` (`txSetHash`, `closeTime`, `upgrades`), so
  `tx_set_result_hash` of the tail header is as unauthenticated as the tail's
  `ledger_version`, which is ignored. Binding outcomes to the tail would let
  anyone take real headers, a real certificate and a real transaction set,
  rewrite only the tail header's `tx_set_result_hash`, and present a failed
  payment as a success. The one-span lag is inherent to sparse verification: the
  outcome for ledger L is provable in the span whose authenticated head is L.
- `tx_set_result_hash` is `sha256` of the whole canonical
  `TransactionResultSet`, vector count included — a plain `xdrSha256`, with no
  generalized/legacy split like the transaction-set hashing.
  `TransactionResultPair.transaction_hash` is stellar-core's
  `getContentsHash()`: the network-bound signature-payload hash, **not** the
  envelope hash that `claim_id` uses. The two never compare equal; join on the
  contents hash. `tx_contents_hash` reproduces the preimage exactly, including
  the extra `0` tag in the v0 form and `ENVELOPE_TYPE_TX_FEE_BUMP` for fee
  bumps.
- Soroban receipt events are committed: `InvokeHostFunctionResult::Success(Hash)`
  is `sha256(InvokeHostFunctionSuccessPreImage)`, and that preimage carries both
  `return_value` and the emitted `ContractEvent`s. `soroban_success_preimage`
  checks a supplied preimage against a proven result pair — one `sha256`.
  `TransactionMeta` (balance and trustline deltas, diagnostic events) is *not*
  header-committed, so effects remain unprovable.
- Epoch journals are version 2 and commit the trust-policy digest plus, per
  proven outcome claim, `sha256` over the canonical `TransactionResultPair` XDR.
  `new` now requires `epoch_image_id`; `verify_claim` derives a canonical
  successful receipt claim itself and no longer accepts serialized claim bytes.
  It checks the configured image, current policy and starting checkpoint before
  pairing. Unverified evidence exposes no decoded epoch checkpoint or claim IDs.
- `verify_receipt` verifies a RISC Zero success receipt for a caller-named
  image and journal: the claim digest is derived on-chain and the exit code is
  fixed to `Halted(0)`. It is not epoch-bound and proves nothing about Stellar;
  consumers must check `image_id` themselves. Neither it nor an inclusion ID
  proves that a Stellar transaction succeeded or that a deposit occurred.
  `verify_claim` is a view; it does not advance stored state.
- These are intentional state, calldata, and journal-format changes, not a
  migration shim. Existing deployments require an explicit migration or new
  deployment; old journals and old Borsh calldata are not compatible.
- Owner-only `update_epoch_image_id` and `update_max_protocol_version` allow
  explicit upgrades. Rebuild and audit the guest before rotating its image ID.
- The relayer uses near-cli-rs `file-args` for both JSON and Borsh, avoiding
  operating-system argument-size limits. `--output` writes exact call bytes;
  `--send` requires a signer and keeps temporary calldata alive until the CLI
  exits. Dry runs and offline transaction construction do not submit anything.
- `xtask` authenticates fixture signatures and internal consistency before
  atomic publication. Fixture-supplied signer IDs are not an independent
  mainnet trust anchor. Pin validator identity separately. Explicit checkpoints
  are never silently replaced by older ones.

`testdata/risc0_receipt_fixture.json` contains a genuine upstream RISC Zero 3.0
receipt with immutable source references, including its control constants and
wire transformations. Native and sandbox checks verify it against the pinned
key and reject altered public inputs and noncanonical coordinates; it is not
a Stellar epoch receipt. `testdata/groth16_fixture.json` is a separate,
deterministic toy-circuit fixture for generic Groth16 math only.
