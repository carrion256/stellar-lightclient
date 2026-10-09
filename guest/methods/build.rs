//! Build the `guest` zkVM program and embed its ELF + image id.
//!
//! This is the canonical risc0 "methods" layout: instead of leaving the guest ELF
//! as a loose artifact to be extracted from a docker build, `risc0-build` compiles
//! it and embeds both the bytes and the derived image id as Rust constants (see
//! `src/lib.rs`). The image id is the guest's identity — exactly what the NEAR
//! side needs to compare against the pinned `bn254_control_id`.
use std::collections::HashMap;

fn main() {
    let mut options = HashMap::new();
    options.insert(
        "guest",
        // The entrypoint lives behind a feature so plain `cargo test` builds
        // natively without the RISC Zero toolchain.
        risc0_build::GuestOptionsBuilder::default()
            .features(vec!["zkvm-entrypoint".to_string()])
            .build()
            .expect("guest options"),
    );
    risc0_build::embed_methods_with_options(options);
}
