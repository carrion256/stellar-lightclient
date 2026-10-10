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

- Rust (stable) with the `wasm32-unknown-unknown` target preinstalled.
- `cargo-risczero` **3.0.6** (with `r0vm`), from nix. The pinned Groth16
  verifying key in `verifier/src/risc0.rs` and the `ReceiptClaim` digest in
  `verifier/src/claim.rs` come from the **3.0.5** verification crates
  (`risc0-groth16`, `risc0-binfmt`, `risc0-zkp`) — those did not move between
  3.0.5 and 3.0.6, so the wrapper identity is expected to be unchanged.
  If any *verification* crate bumps, re-transcribe the VK and re-pin the claim
  digest before trusting a receipt. The definitive check is to build a seal and
  confirm its `bn254_control_id` matches the contract's pinned value.
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
| standalone guest tests | `cargo test --manifest-path guest/Cargo.toml` |
| relayer tests | `python3 -m unittest discover -s tools -p test_relay.py` |
| zkVM guest toolchain | `risc0-setup` |
| build guest program (does not prove a receipt) | `cargo risczero build --manifest-path guest/Cargo.toml --features zkvm-entrypoint` |
| fetch and authenticate a fixture | `cargo run -p xtask -- fetch-fixture --checkpoint 64822015 --out /tmp/stellar-fixture.json` |
| prepare raw-Borsh calldata | `python3 tools/relay.py --proof testdata/fixture.json --contract lc.testnet --format borsh --dry-run --output /tmp/span.borsh` |

Build the wasm **before** `cargo test`: sandbox e2e deploys that artifact.
Its freshness guard checks contract, verifier, and verify-core sources and
manifests, plus the root manifest and lockfile. The guest has a separate
workspace and lockfile, so its tests must also be run explicitly.

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
- Epoch journals are version 1 and commit the trust-policy digest. `new` now
  requires `epoch_image_id`; `verify_claim` derives a canonical successful
  receipt claim itself and no longer accepts serialized claim bytes. It checks
  the configured image, current policy and starting checkpoint before pairing.
  Unverified evidence exposes no decoded epoch checkpoint or claim IDs.
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
