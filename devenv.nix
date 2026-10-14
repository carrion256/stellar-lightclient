{ pkgs, ... }:
let
  # One place for the RISC Zero versions this repo is built and measured with.
  # `enterShell` warns when the running tools differ, and `risc0-setup` installs
  # exactly these — so changing a number here is the whole upgrade, and the
  # image-ID / bn254_control_id re-check in the comment below is its checklist.
  risc0Version = "3.0.6"; # cargo-risczero and r0vm, from nixpkgs (flake.lock)
  risc0RustToolchain = "1.97.0"; # zkVM rustc, installed by rzup; builds the guest ELF
  rzupVersion = "0.5.2"; # the rzup that installs it
in
{
  # Rust toolchain + the wasm target the NEAR contract is compiled against.
  languages.rust = {
    enable = true;
    channel = "stable";
    targets = [ "wasm32-unknown-unknown" "wasm32v1-none" ];
  };

  packages = with pkgs; [
    # --- RISC Zero zkVM tooling -------------------------------------------
    # Provides `cargo-risczero` and `r0vm` (the zkVM runtime) for building and
    # proving guests. Not constrained by version here: nixpkgs resolves
    # whatever `flake.lock` pins, which is currently 3.0.6, and `nix flake
    # update` would move it silently. `enterShell` warns when the running
    # version differs from `risc0Version` above, which is what makes a moved
    # lock visible. (`nix shell nixpkgs#cargo-risczero` is a *different*
    # nixpkgs — your registry's, 3.0.5 at the time of writing — not this shell.)
    #
    # Version relationship to the pinned verifying key:
    #   tooling       risc0-zkvm 3.0.6        (executor/prover; builds the guest)
    #   verification  risc0-groth16 3.0.5, risc0-binfmt 3.0.5, risc0-zkp 3.0.5
    #                 (the VK transcribed into groth16-core/src/risc0.rs and the
    #                  ReceiptClaim digest reproduced in groth16-core/src/claim.rs
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

    # Warn when the running RISC Zero tools differ from the versions this repo is
    # built and measured with (the `let` block at the top of devenv.nix). A
    # warning, not an abort: a shell that refuses to open is one you cannot use to
    # fix it. The nixpkgs pin in flake.lock is what normally keeps these equal.
    risc0_warn() { printf '  WARNING  %s\n' "$1" >&2; }
    have_cr="$(cargo risczero --version 2>/dev/null | head -1)"
    [ "$have_cr" = "cargo-risczero ${risc0Version}" ] || \
      risc0_warn "cargo-risczero is '$have_cr', expected 'cargo-risczero ${risc0Version}'. A moved flake.lock needs the image ID and bn254_control_id re-checked (see devenv.nix)."
    have_vm="$(r0vm --version 2>/dev/null | head -1)"
    [ "$have_vm" = "risc0-r0vm ${risc0Version}" ] || \
      risc0_warn "r0vm is '$have_vm', expected 'risc0-r0vm ${risc0Version}'."
    toolchain="$(readlink "$HOME/.rustup/toolchains/risc0" 2>/dev/null || true)"
    case "$toolchain" in
      "") ;; # not installed: only needed to build a guest, and risc0-setup installs it
      *"/v${risc0RustToolchain}-rust-"*) ;;
      *) risc0_warn "risc0 rust toolchain is $toolchain, expected v${risc0RustToolchain}. Run risc0-setup: a different compiler changes the guest ELF and its image ID." ;;
    esac
    unset -f risc0_warn
    unset have_cr have_vm toolchain
  '';

  scripts.risc0-setup.exec = ''
    #!/usr/bin/env bash
    # Install the zkVM rustc toolchain that `cargo risczero build` needs, at the
    # version pinned in the `let` block above rather than whatever is latest: the
    # guest ELF, and therefore its image ID, depends on that compiler.
    #
    # Only the `rust` component is installed. cargo-risczero and r0vm come from
    # nixpkgs (flake.lock); a bare `rzup install` would also download the latest
    # of both into ~/.risc0, a second set of tools that disagrees with the shell's.
    # Idempotent: safe to run repeatedly. Network-heavy on first run.
    set -euo pipefail
    export PATH="$HOME/.cargo/bin:$PATH"
    if ! command -v rzup >/dev/null 2>&1; then
      echo "rzup not found — installing rzup ${rzupVersion} with cargo (first run only)"
      cargo install rzup --locked --version ${rzupVersion}
    fi
    echo "installing the zkVM rust toolchain ${risc0RustToolchain} via rzup"
    rzup install rust ${risc0RustToolchain}
    rzup use rust ${risc0RustToolchain}
    echo
    echo "done. Build the guest program (receipt proving is a separate step):"
    echo "  cargo risczero build --manifest-path guest/methods/guest/Cargo.toml --features zkvm-entrypoint"
  '';
}
