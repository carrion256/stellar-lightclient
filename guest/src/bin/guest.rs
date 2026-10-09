//! RISC Zero guest entrypoint. Only compiled with `--features zkvm-entrypoint`
//! (`required-features` in Cargo.toml); the compile_error below fires if the
//! target is built without it, so a stray `cargo build --bin guest` cannot
//! silently produce a binary that is not the zkVM guest.
#![cfg_attr(
    not(feature = "zkvm-entrypoint"),
    compile_error!("`guest` bin requires --features zkvm-entrypoint (native builds skip this target via required-features)")
)]

fn main() {
    // Raw bytes in, raw bytes out: `read_vec` returns the host's
    // `EnvBuilder::write_slice` buffer verbatim (no serde wrapping), and
    // `commit_slice` commits the journal bytes verbatim so the receipt
    // journal digests to sha256(encode_journal bytes) exactly, matching
    // `verifier::claim::ok_output_digest`.
    let input_bytes = risc0_zkvm::guest::env::read_vec();
    match guest::run_epoch_bytes(&input_bytes) {
        Ok(journal_bytes) => risc0_zkvm::guest::env::commit_slice(&journal_bytes),
        Err(e) => panic!("{e}"),
    }
}
