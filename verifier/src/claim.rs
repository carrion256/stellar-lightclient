//! RISC Zero receipt-claim handling: `ReceiptClaim`, `claim_digest`, `journal_digest`.
//!
//! These routines reproduce — byte for byte, no `risc0-*` runtime dependency — the
//! digests RISC Zero itself computes when it builds and verifies a receipt. The
//! Groth16 wrapper public input `claim_digest` *is* the digest computed here; if any
//! field, field order, or padding rule deviates, `verify_claim` would accept claims
//! no honest prover ever produced (or reject real ones), so every rule is cited to
//! the vendored source that defines it:
//!
//! - `tagged_struct` (the digest primitive): `risc0-binfmt-3.0.5/src/hash.rs:69-88`.
//!   `hash_bytes` is plain SHA-256 over raw bytes
//!   (`risc0-zkp-3.0.5/src/core/hash/sha/cpu.rs:39-49`, checked against the NIST
//!   vector `sha256("abc")` in `risc0-zkp-3.0.5/src/core/hash/sha/mod.rs:381-383`),
//!   and `Digest::ZERO` is the digest for pruned/absent values
//!   (`risc0-zkp-3.0.5/src/core/digest.rs`; `Option::None` → zero digest per
//!   `risc0-binfmt-3.0.5/src/hash.rs:57-64`).
//! - `ReceiptClaim::digest()`: `risc0-zkvm-3.0.5/src/claim/receipt.rs:326-341`.
//!   Field order is `input, pre, post, output` as digest children, `sys_exit,
//!   user_exit` as raw LE u32 data words — note this differs from the struct's
//!   declared field order (`pre, post, exit_code, input, output`, receipt.rs:57-72).
//! - The canonical `ok()` claim shape (used by this project's guest):
//!   `risc0-zkvm-3.0.5/src/claim/receipt.rs:77-95` — `Halted(0)`, `input = None`,
//!   `post = SystemState { pc: 0, merkle_root: ZERO }`, `output.journal` = the
//!   committed journal, `output.assumptions = Pruned(ZERO)` (empty assumptions list
//!   digests to `Digest::ZERO` via the empty fold, receipt.rs:530-538).
//! - `SystemState` digest: `tagged_struct("risc0.SystemState", [merkle_root], [pc])`,
//!   `risc0-binfmt-3.0.5/src/sys_state.rs:69-74`.
//!
//! RISC Zero only — this project never uses SP1.

use near_sdk::env;

/// A `ReceiptClaim` at the digest granularity the Groth16 wrapper uses.
///
/// The Groth16 public input is the claim *digest*; the wrapper itself only ever
/// handles these fields at digest level (`risc0-zkvm-3.0.5/src/claim/receipt.rs:119-152`
/// `decode`/`encode` treat `input`/`output` as plain digests too), so this struct
/// carries `pre`/`post`/`output` as 32-byte digests rather than the expanded
/// `SystemState`/`Output` values of the upstream struct.
///
/// Exit code is split into the `sys_exit`/`user_exit` pair exactly as
/// `ExitCode::into_pair()` defines it (`risc0-binfmt-3.0.5/src/exit_code.rs:65-72`):
/// `Halted(u) = (0, u)`, `Paused(u) = (1, u)`, `SystemSplit = (2, 0)`.
pub struct ReceiptClaim {
    /// The `SystemState` digest just before execution (for `ok()` claims: the
    /// image ID). Upstream field `pre` (receipt.rs:59).
    pub pre: [u8; 32],
    /// The `SystemState` digest just after execution. Upstream field `post`
    /// (receipt.rs:62).
    pub post: [u8; 32],
    /// System half of the exit code (0 = Halted, 1 = Paused, 2 = Split).
    pub sys_exit: u32,
    /// User half of the exit code (guest-chosen).
    pub user_exit: u32,
    /// The `Output` digest (`risc0.Output` tagged struct over journal +
    /// assumptions), or `None` for a claim with no output. Upstream field
    /// `output` (receipt.rs:71); `None` follows the pruned rule and digests to
    /// zero.
    pub output: Option<[u8; 32]>,
}

impl ReceiptClaim {
    /// Wire encoding: `pre ‖ post ‖ output(32; zero when None) ‖ sys_exit_le ‖
    /// user_exit_le` — 104 bytes, no versioning (the field set is frozen upstream).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(104);
        out.extend_from_slice(&self.pre);
        out.extend_from_slice(&self.post);
        out.extend_from_slice(&self.output.unwrap_or([0u8; 32]));
        out.extend_from_slice(&self.sys_exit.to_le_bytes());
        out.extend_from_slice(&self.user_exit.to_le_bytes());
        out
    }

    /// Inverse of [`ReceiptClaim::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 104 {
            return Err("receipt claim must be 104 bytes".into());
        }
        let pre: [u8; 32] = bytes[0..32].try_into().unwrap();
        let post: [u8; 32] = bytes[32..64].try_into().unwrap();
        let output: [u8; 32] = bytes[64..96].try_into().unwrap();
        let sys_exit = u32::from_le_bytes(bytes[96..100].try_into().unwrap());
        let user_exit = u32::from_le_bytes(bytes[100..104].try_into().unwrap());
        Ok(Self {
            pre,
            post,
            // output digests to zero when all-zero: the pruned rule (hash.rs:57-64).
            // Note this is the encoding of `output: None`, not of a real digest
            // equal to zero — such a digest is cryptographically unreachable.
            output: (output != [0u8; 32]).then_some(output),
            sys_exit,
            user_exit,
        })
    }
}

/// SHA-256 of raw bytes — identical to `risc0_zkp::core::hash::sha::cpu::Impl::hash_bytes`
/// (`risc0-zkp-3.0.5/src/core/hash/sha/cpu.rs:39-49`) and to the guest's on-circuit
/// journal hashing (`risc0-zkvm-3.0.5/src/sha.rs`, host/guest equivalence asserted
/// in its doc example, sha.rs:41-46).
pub fn journal_digest(journal: &[u8]) -> [u8; 32] {
    let digest = env::sha256(journal);
    digest.try_into().unwrap()
}

/// Tagged-struct digest primitive — literal transcription of `tagged_struct`
/// (`risc0-binfmt-3.0.5/src/hash.rs:69-88`): `sha256( tag_digest ‖ down… ‖ data_le…
/// ‖ down_count_u16_le )` where `tag_digest = sha256(tag)`.
fn tagged_struct(tag: &str, down: &[[u8; 32]], data: &[u32]) -> [u8; 32] {
    let tag_digest = journal_digest(tag.as_bytes());
    let mut all = Vec::with_capacity(32 * (down.len() + 1) + 4 * data.len() + 2);
    all.extend_from_slice(&tag_digest);
    for d in down {
        all.extend_from_slice(d);
    }
    for w in data {
        all.extend_from_slice(&w.to_le_bytes());
    }
    let down_count = down.len() as u16;
    all.extend_from_slice(&down_count.to_le_bytes());
    journal_digest(&all)
}

/// The `Digest::ZERO` of pruned/absent values (`risc0-zkp-3.0.5/src/core/digest.rs`;
/// `Option::None` digests to it per `risc0-binfmt-3.0.5/src/hash.rs:57-64`).
const ZERO: [u8; 32] = [0u8; 32];

/// The `Output` digest for a committed journal with an empty assumptions list —
/// i.e. the `output` child of the guest's `ReceiptClaim::ok()` claim
/// (`risc0-zkvm-3.0.5/src/claim/receipt.rs:441-450`; empty assumptions digest from
/// the empty `tagged_list` fold, receipt.rs:530-538 + hash.rs:94-101).
pub fn ok_output_digest(journal: &[u8]) -> [u8; 32] {
    tagged_struct("risc0.Output", &[journal_digest(journal), ZERO], &[])
}

/// The `ReceiptClaim` digest that equals the Groth16 `claim_digest` public input.
/// Reproduces `ReceiptClaim::digest()`
/// (`risc0-zkvm-3.0.5/src/claim/receipt.rs:326-341`) — digest children
/// `input(=ZERO here), pre, post, output`, data words `sys_exit, user_exit` LE,
/// tag `"risc0.ReceiptClaim"`. `input` is the zero digest for any claim our guest
/// can construct (`Input` is uninhabited upstream, receipt.rs:394-412; the `decode`
/// path keeps it opaque, so we treat it as always pruned/None → zero).
pub fn claim_digest(claim: &ReceiptClaim) -> [u8; 32] {
    tagged_struct(
        "risc0.ReceiptClaim",
        &[ZERO, claim.pre, claim.post, claim.output.unwrap_or(ZERO)],
        &[claim.sys_exit, claim.user_exit],
    )
}

/// `ReceiptClaim::ok()` claim (`risc0-zkvm-3.0.5/src/claim/receipt.rs:77-95`) for an
/// image ID and journal — exit `Halted(0)`, post state `SystemState { pc: 0,
/// merkle_root: ZERO }` digested per `risc0-binfmt-3.0.5/src/sys_state.rs:69-74`.
pub fn ok_claim(image_id: [u8; 32], journal: &[u8]) -> ReceiptClaim {
    ReceiptClaim {
        pre: image_id,
        post: tagged_struct("risc0.SystemState", &[ZERO], &[0]),
        sys_exit: 0,
        user_exit: 0,
        output: Some(ok_output_digest(journal)),
    }
}
