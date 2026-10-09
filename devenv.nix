{ pkgs, ... }:
{
  # Rust toolchain + the wasm target the NEAR contract is compiled against.
  languages.rust = {
    enable = true;
    channel = "stable";
    targets = [ "wasm32-unknown-unknown" ];
  };

  packages = with pkgs; [
    # --- RISC Zero zkVM tooling -------------------------------------------
    # Provides `cargo-risczero` and `r0vm` (the zkVM runtime) for building and
    # proving guests. Verified in-shell at 3.0.6.
    #
    # Version relationship to the pinned verifying key:
    #   tooling       risc0-zkvm 3.0.6        (executor/prover; builds the guest)
    #   verification  risc0-groth16 3.0.5, risc0-binfmt 3.0.5, risc0-zkp 3.0.5
    #                 (the VK transcribed into verifier/src/risc0.rs and the
    #                  ReceiptClaim digest reproduced in verifier/src/claim.rs
    #                  come from these)
    # The verification-side crates did not move between 3.0.5 and 3.0.6, so the
    # wrapper identity is expected to be unchanged. The definitive check — after
    # `risc0-setup` installs the guest toolchain — is to build a seal and confirm
    # its bn254_control_id equals the value pinned in the contract. If the
    # verification crates ever bump, re-transcribe the VK and re-pin the claim
    # digest before trusting any receipt.
    cargo-risczero

    # --- native build prerequisites ---------------------------------------
    # near-workspaces -> near-jsonrpc-client -> native-tls needs OpenSSL headers
    # and pkg-config to find them. With these present, openssl-sys builds
    # against nix's openssl instead of compiling it from source.
    openssl
    pkg-config
    perl
    gnumake
    cmake

    # --- repo tooling -----------------------------------------------------
    python3 # tools/relay.py
    git
    curl # xtask pulls fixtures from Stellar history archives
  ];

  enterShell = ''
    # Session-scoped git identity for this repo's workflow: this workstation has
    # no usable gpg secret key, so commit.gpgsign is disabled WITHOUT mutating
    # global or per-repo git config.
    export GIT_CONFIG_COUNT=1
    export GIT_CONFIG_KEY_0=commit.gpgsign
    export GIT_CONFIG_VALUE_0=false

    echo "── stellar-lightclient dev shell ─────────────────────────────"
    printf '  rustc           %s\n' "$(rustc --version 2>/dev/null || echo 'missing')"
    printf '  cargo-risczero  %s\n' "$(cargo risczero --version 2>/dev/null | head -1 || echo 'missing')"
    printf '  openssl         %s\n' "$(pkg-config --modversion openssl 2>/dev/null || echo 'missing')"
    printf '  commit.gpgsign  %s\n' "$(git config --get commit.gpgsign 2>/dev/null || echo 'unset')"
    echo
    echo "  contract wasm : cargo build -p stellar-light-client --release --target wasm32-unknown-unknown"
    echo "  tests         : cargo test --workspace"
    echo "  guest toolchain: risc0-setup   (only needed to build/prove a zkVM guest)"
    echo "──────────────────────────────────────────────────────────────"
  '';

  scripts.risc0-setup.exec = ''
    #!/usr/bin/env bash
    # Install the zkVM rustc toolchain that `cargo risczero build` needs.
    # cargo-risczero 3.0.6 no longer installs it directly (its `install`
    # subcommand just tells you to use rzup), so bootstrap rzup if absent.
    # Idempotent: safe to run repeatedly. Network-heavy on first run.
    set -euo pipefail
    export PATH="$HOME/.cargo/bin:$PATH"
    if ! command -v rzup >/dev/null 2>&1; then
      echo "rzup not found — installing it with cargo (first run only)"
      cargo install rzup --locked
    fi
    echo "installing the zkVM toolchain via rzup"
    rzup install
    echo
    echo "done. Build the guest program (receipt proving is a separate step):"
    echo "  cargo risczero build --manifest-path guest/Cargo.toml --features zkvm-entrypoint"
  '';
}
