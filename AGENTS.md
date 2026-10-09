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
| tests | `cargo test --workspace` |
| zkVM guest toolchain | `risc0-setup` |
| build + prove a real seal | `cargo risczero build -p guest --features guest/zkvm-entrypoint` |

Build the wasm **before** `cargo test`: the sandbox e2e deploys that artifact, and
`contract/tests/sandbox.rs` now fails loudly if the artifact is older than
`contract/src/lib.rs`.
