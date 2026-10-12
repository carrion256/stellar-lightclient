//! Measurement-only guest: identical to `guest` except `ed25519_verify`
//! returns `true` without checking.
//!
//! Its purpose is to split the zkVM cycle count. `run_epoch` with the real
//! crypto costs `generic work + ed25519`; with the stub it costs `generic work`
//! (XDR parse of the envelopes and headers, bincode input decode, journal
//! encode — and `sha256`, which the precompile makes small). The difference is
//! the ed25519 share, which is the number the byte-span optimisation needs:
//! if generic work dominates the accelerated build, the walker is the lever; if
//! ed25519 does, it is not.
//!
//! This is a separate binary rather than a feature of `guest` so that a stubbed
//! verification path can never be what the production guest is built from. The
//! fixture's signatures are all valid, so the journal this produces is
//! identical to the real guest's — it is the cycle count that differs.
//!
//! `required-features` in Cargo.toml keeps this target out of builds without
//! `--features zkvm-entrypoint`; the `compile_error` below is the same guard
//! `guest.rs` carries, so a stray `cargo build --bin guest-stub` cannot silently
//! produce a stubbed guest. Note the meta-item form — `compile_error("…")`,
//! no `!`. Inside `cfg_attr` the attribute is passed through as an AST node
//! rather than invoked, and the bang makes rustc reject it at parse time
//! regardless of the predicate.
#![cfg_attr(
    not(feature = "zkvm-entrypoint"),
    compile_error("guest-stub bin requires --features zkvm-entrypoint")
)]
struct StubCrypto;

impl verify_core::Crypto for StubCrypto {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    fn ed25519_verify(&self, _: &[u8; 64], _: &[u8], _: &[u8; 32]) -> bool {
        true
    }
}

fn main() {
    let len: usize = risc0_zkvm::guest::env::read();
    let mut input_bytes = vec![0u8; len];
    risc0_zkvm::guest::env::read_slice(&mut input_bytes);
    let input: guest::EpochInput = bincode::deserialize(&input_bytes).expect("input");
    let journal = guest::run_epoch_with(&StubCrypto, &input).expect("epoch");
    risc0_zkvm::guest::env::commit_slice(&verify_core::encode_journal(&journal));
}
