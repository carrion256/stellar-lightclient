# Stellar → NEAR light client: common workflows.
#
#   just            list recipes
#   just test       the gate you want before committing
#   just guest      build + embed the zkVM guest
#
# Most recipes assume the devenv shell (`just dev`) or an equivalent environment.

# ── knobs ────────────────────────────────────────────────────────────────────

# risc0 guest-builder image. The default (r0.1.88.0) ships rustc 1.88, below the
# MSRV of risc0's own dependencies (ruint needs 1.90). r0.1.97.0 matches the
# rzup toolchain and is what the guest has been built and verified against.
risc0_tag := env("RISC0_DOCKER_CONTAINER_TAG", "r0.1.97.0")

# Docker build containers cannot resolve DNS on this workstation (they inherit a
# VPN-side resolver they cannot reach) though IP networking works. `just
# docker-shim` writes a wrapper adding --network=host to `docker build`: no
# daemon restart, no host resolver changes, no disturbance to running containers.
docker_shim := "/tmp/dockershim"

# Environment for anything that builds a RISC Zero guest: cargo-risczero on PATH
# (nix or ~/.cargo/bin) plus the shim and the image tag above.
risc0_env := "PATH=" + docker_shim + ":$HOME/.cargo/bin:$PATH RISC0_DOCKER_CONTAINER_TAG=" + risc0_tag

# ── environment ──────────────────────────────────────────────────────────────

# Enter the devenv shell (Rust + wasm32 target, cargo-risczero/r0vm, openssl).
dev:
    nix develop --no-pure-eval .#default

# Write the docker build shim used by the RISC Zero guest builds.
docker-shim:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{docker_shim}}
    cat > {{docker_shim}}/docker <<'EOF'
    #!/usr/bin/env bash
    # Shim: make `docker build` use host networking so build containers inherit
    # the host's working DNS. Resolves the real docker from PATH, skipping itself.
    self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    real=""
    IFS=':' read -ra _parts <<<"$PATH"
    for p in "${_parts[@]}"; do
      [ -n "$p" ] || continue
      [ "$(cd "$p" 2>/dev/null && pwd)" = "$self_dir" ] && continue
      if [ -x "$p/docker" ]; then real="$p/docker"; break; fi
    done
    [ -n "$real" ] || { echo "docker shim: no real docker found on PATH" >&2; exit 127; }
    if [ "${1:-}" = "build" ]; then shift; exec "$real" build --network=host "$@"; fi
    exec "$real" "$@"
    EOF
    chmod +x {{docker_shim}}/docker
    echo "wrote {{docker_shim}}/docker"

# Install the zkVM rustc toolchain (needed for `guest-native` and for proving).
risc0-setup:
    nix develop --no-pure-eval .#default -c bash -lc 'risc0-setup'

# ── build ────────────────────────────────────────────────────────────────────

# Build the NEAR contract wasm (the sandbox e2e deploys this artifact).
wasm:
    cargo build -p stellar-light-client --release --target wasm32-unknown-unknown

# Build the zkVM guest and embed GUEST_ELF / GUEST_ID / GUEST_PATH via methods.
guest: docker-shim
    {{risc0_env}} cargo build --release --manifest-path guest/Cargo.toml -p methods

# Build the loose guest ELF without embedding, using the risc0 CLI.
guest-elf: docker-shim
    {{risc0_env}} cargo risczero build --manifest-path guest/Cargo.toml --features zkvm-entrypoint

# Build the guest natively with the local risc0 toolchain, without Docker.
guest-native:
    RUSTC="$(rustup which --toolchain risc0 rustc)" \
    RUSTDOC="$(rustup which --toolchain risc0 rustdoc)" \
    CARGO_TARGET_RISCV32IM_RISC0_ZKVM_ELF_RUSTFLAGS='--cfg getrandom_backend="custom" -C link-arg=-Ttext=0x00200800' \
    rustup run risc0 cargo build --manifest-path guest/Cargo.toml \
        --release --locked --target riscv32im-risc0-zkvm-elf --features zkvm-entrypoint

# ── test ─────────────────────────────────────────────────────────────────────

# Full gate: wasm first, then workspace, guest, and relayer suites.
test: wasm test-workspace test-guest test-relay

# Workspace tests including the NEAR sandbox e2e (build `just wasm` first).
test-workspace:
    cargo test --workspace

# Standalone guest tests (own workspace and lockfile).
test-guest:
    cargo test --manifest-path guest/Cargo.toml

# Relayer unit tests.
test-relay:
    python3 -m unittest discover -s tools -p test_relay.py

# Contract unit tests only, no sandbox e2e.
test-contract:
    cargo test -p stellar-light-client --lib

# ── fixtures and calldata ────────────────────────────────────────────────────

# Fetch and authenticate a Stellar mainnet fixture (signatures + consistency).
fixture checkpoint='64822015' out='/tmp/stellar-fixture.json':
    cargo run -p xtask -- fetch-fixture --checkpoint {{checkpoint}} --out {{out}}

# Regenerate the deterministic toy-circuit Groth16 fixture (generic math only).
fixture-g16:
    cargo run --release -p groth16-fixture -- --out testdata/groth16_fixture.json

# Render raw-Borsh span calldata (no submission happens).
calldata contract='lc.testnet' out='/tmp/span.borsh':
    python3 tools/relay.py --proof testdata/fixture.json --contract {{contract}} --format borsh --dry-run --output {{out}}

# Render the JSON form of the same span submission.
calldata-json contract='lc.testnet':
    python3 tools/relay.py --proof testdata/fixture.json --contract {{contract}} --format json --dry-run

# ── maintenance ──────────────────────────────────────────────────────────────

# Remove build output and generated calldata (keeps testdata fixtures).
clean:
    rm -rf target target-contract target-xtask target-fixture guest/target
    rm -f /tmp/span.borsh /tmp/stellar-fixture.json

# Show uncommitted work before handing the tree to someone else.
status:
    git status --short --branch
