# 08 - Groth16 verifier on Stellar

**Status: new verifier port.** The verifier exists in this repository
(`verifier/`); it is written against NEAR host functions and must be ported.

## Problem

The whole proving story currently terminates on NEAR. If the audience is the Stellar
ecosystem — grants, vault compliance, permissioned finance — then the proof has to be
checkable **on Stellar**, not asserted about Stellar from somewhere else.

The 2026-10-09 discussion reached the same conclusion directly: the Groth16
verifier was built for NEAR, but should also be built for Stellar, because the grant
case is compliance, privacy, and trust authority *on Stellar*.

## What exists here

| module | role |
|---|---|
| `verifier/src/lib.rs` | layout and entry points |
| `verifier/src/groth16.rs` | Groth16 verification over BN254 |
| `verifier/src/risc0.rs` | RISC Zero seal handling, `public_inputs`, pinned VK |
| `verifier/src/claim.rs` | claim digest derivation, pinned `ReceiptClaim` digest |
| `verifier/src/bn128.rs` | BN254 primitives and wire encoding |

The verified surface is small and well-defined: `verify_receipt` derives the claim
digest on-chain and checks a 256-byte seal against a pinned wrapper identity
(`contract/src/lib.rs:508-566`). A port only has to reproduce that.

## The technical crux: pairing availability

The implementation is explicit about where it draws the line.
`verifier/src/bn128.rs:1` opens: *"BN254 primitives over NEAR's `alt_bn128` host
functions."* And `verifier/src/lib.rs:3-6` states the choice outright:

> This crate verifies them on NEAR by driving the curve arithmetic through the
> chain's `alt_bn128` host functions (`env::alt_bn128_g1_multiexp`,
> `env::alt_bn128_pairing_check`) instead of running a pure-Rust pairing
> implementation inside the contract.

**Stellar has no equivalent host function surface.** That is the entire difficulty of
this port, and it should be said plainly in any grant document. The options:

| approach | tradeoff |
|---|---|
| Pure-Rust BN254 pairing in the contract | no new trust assumption; likely the dominant cost of the whole verification |
| Curve-native Groth16 on a curve Stellar supports | would need a different proving backend — not a port, a different system |
| Verify off-chain, attest on-chain | reintroduces the trust the verifier exists to remove |

The realistic path is the first. The existing code already separates the *encoding*
crux from the *arithmetic*: `bn128.rs` documents NEAR's 32-byte little-endian
wire format (G1 uncompressed 64 B, G2 128 B, pairing element 192 B). A Stellar port
replaces both the arithmetic backend and that encoding, and keeps `groth16.rs` and
`claim.rs` logic intact.

There is a measured cost datum to start from: the test in
`verifier/tests/risc0_verify.rs:116-120` times one Groth16 verification as a
four-pair pairing check plus one multiexp against the real nearcore VMLogic gas
meter. That number is the NEAR baseline to compare a Stellar implementation against.

## Porting checklist

1. BN254 field and curve arithmetic (base field, scalar field, G1, G2).
2. Multiexp and multi-pairing check, replacing `alt_bn128_g1_multiexp` and
   `alt_bn128_pairing_check`.
3. Wire encoding for the Stellar contract environment, replacing NEAR's 32-byte LE
   conventions.
4. Re-transcribe and re-pin the Groth16 verifying key and the `ReceiptClaim` digest.
   Per `AGENTS.md`, these come from the 3.0.5 verification crates and the wrapper
   identity is expected unchanged between 3.0.5 and 3.0.6 — but the definitive check
   is building a seal and confirming its `bn254_control_id` matches the pinned value.
5. Port the fixture tests. `testdata/risc0_receipt_fixture.json` is a genuine
   upstream RISC Zero 3.0 receipt with its control constants and wire
   transformations, and the existing tests verify it against the pinned key **and
   reject altered public inputs and noncanonical coordinates**. Those negative tests
   are the part that matters; carry them over.
   `testdata/groth16_fixture.json` is a deterministic toy-circuit fixture for
   generic Groth16 math only — use it for the arithmetic, not for RISC Zero claims.
6. Port the wrapper-compatibility check. `is_wrapper_compatible`
   (`contract/src/lib.rs:477-498`) is a pure, write-nothing check against the pinned
   identity and is the right primitive to expose on Stellar too.

## What the verifier makes possible on Stellar

Once a receipt is checkable on Stellar, the use cases from this set that terminate
there become real:

- **Private access control** (use case 03): prove compliance locally, verify the
  receipt in a Stellar vault. This is the "prove once, move around" shape, and it is
  the compliance-plus-privacy case for an ecosystem grant.
- **Proof of reserves / custody / NAV** (use case 04): verify a position attestation
  where the vault actually lives.
- **Cross-chain reply** (use case 02): the Stellar side learns a NEAR-side fact
  without trusting a relayer.
- **Generic state reads** (use case 07): any assertion, verifiable on Stellar, with
  the same shared wrapper key.

## Trust model

- The pinned wrapper identity (`control_root`, `bn254_control_id`) is the anchor.
  Note the operational warning already in the contract: pinning a wrapper identity
  can strand the contract on a permanently impossible wrapper if that build stops
  being reproducible (`contract/src/lib.rs:498`). The Stellar port should keep the
  same rotation surface and the same warning.
- The claim digest is derived by the verifier, never supplied. Preserve that
  property exactly — it is what stops a caller redirecting a proof to a digest of
  their choosing.

## Limits

- **A verifier proves a receipt, not a fact.** Same rule as everywhere else in this
  set: `verified: true` means the named image halted successfully committing that
  journal. The consumer still checks `image_id` and the journal schema.
- **Compute budget is an open question.** Pairing is expensive. Whether one
  verification fits comfortably in a Stellar transaction is a measurement, not an
  assumption, and it should be measured before anything downstream is promised.
- **Do not claim confidential transactions from this.** This is a verifier. Amount
  privacy is a separate construction, and the standard for permissioned finance
  referred to as "3613" in the discussion needs its exact CAP number confirmed
  before being cited externally.

## Acceptance criteria

- [ ] A genuine upstream RISC Zero 3.0 receipt verifies on Stellar against the
      pinned key.
- [ ] Altered public inputs and noncanonical coordinates are rejected — the negative
      tests, ported, not just the positive one.
- [ ] The claim digest is derived by the contract, not accepted from the caller.
- [ ] The pinned VK and `ReceiptClaim` digest match a freshly built seal's
      `bn254_control_id`.
- [ ] Measured cost per verification, published, with the comparison to the NEAR
      baseline.
- [ ] Wrapper identity is rotatable, with the stranding risk documented.
