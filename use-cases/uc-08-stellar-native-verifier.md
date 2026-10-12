# 08 - Groth16 verifier on Stellar

**Status: shipped.** `stellar-verifier/` is a Soroban contract sharing
`groth16-core` with the NEAR verifier, with 22 tests covering the real RISC
Zero 3.0 receipt and the negative cases.

Measured on the Soroban host, per verification:

| fixture | what it proves | cpu insns | mem bytes |
|---|---|---|---|
| `testdata/risc0_receipt_fixture.json` | the real upstream RISC Zero 3.0 receipt | **27,677,866** | 292,462 |
| `testdata/groth16_fixture.json` | toy circuit, generic Groth16 math only | 26,280,240 | 281,607 |

The receipt figure is the one to quote; the toy circuit is a different program
and only exercises the arithmetic.

Its trust model differs from the NEAR contract's and that is deliberate:
`control_root` and `bn254_control_id` are **caller arguments, not stored pins**,
because both feed the Groth16 public inputs — they are part of the statement
being proven, so a wrong value fails to verify rather than widening what is
accepted. The consequence is that the contract supplies **no reference values**:
a consumer wanting "this receipt came from RISC Zero release X" must pin both
against X at integration time. There is therefore no stored wrapper identity to
rotate and no stranding risk; the NEAR deployment keeps `get_wrapper` /
`is_wrapper_compatible` because it *does* store one.

One acceptance criterion below remains open: the seal-build check confirming a
freshly built seal's `bn254_control_id` matches the pinned value.

## Problem

The whole proving story currently terminates on NEAR. If the audience is the Stellar
ecosystem — grants, vault compliance, permissioned finance — then the proof has to be
checkable **on Stellar**, not asserted about Stellar from somewhere else.

The 2026-10-09 discussion reached the same conclusion directly: the Groth16
verifier was built for NEAR, but should also be built for Stellar, because the grant
case is compliance, privacy, and trust authority *on Stellar*.

## What exists here

The verifier is now split so the proof system is shared and only the host
adapter differs:

| crate / module | role |
|---|---|
| `groth16-core` | the shared core: verification equation, RISC Zero seal parsing, claim digests |
| `groth16-core/src/ops.rs` | `ProofOps` — the entire chain seam (`sha256`, `g1_multiexp`, `pairing_check`) |
| `groth16-core/src/groth16.rs` | the verification equation, generic over `ProofOps` |
| `groth16-core/src/bn254.rs` | arkworks point types and buffer layout |
| `groth16-core/src/risc0.rs`, `claim.rs` | pinned VK, seal parsing, `ReceiptClaim` digests |
| `verifier/src/ops.rs` | NEAR provider: `alt_bn128_*` host functions, 32-byte LE encoding |
| `stellar-verifier/src/ops.rs` | Soroban provider: `Bn254::g1_msm` / `pairing_check`, big-endian encoding |
| `stellar-verifier/src/lib.rs` | the Stellar contract |

The verified surface is small and well-defined: `verify_receipt` derives the claim
digest on-chain and checks a 256-byte seal against a pinned wrapper identity
(`contract/src/lib.rs:508-566`). A port only has to reproduce that.

## The technical crux: pairing availability — resolved

The NEAR implementation drives curve arithmetic through chain host functions
rather than a pure-Rust pairing. `verifier/src/bn128.rs:1` opens *"BN254
primitives over NEAR's `alt_bn128` host functions"*, and `verifier/src/lib.rs:3-6`
states the choice outright:

> This crate verifies them on NEAR by driving the curve arithmetic through the
> chain's `alt_bn128` host functions (`env::alt_bn128_g1_multiexp`,
> `env::alt_bn128_pairing_check`) instead of running a pure-Rust pairing
> implementation inside the contract.

**Stellar exposes the same primitives natively, across two CAPs.** This matters
because the provider leans on the later one:

| host function | CAP | min protocol | mainnet since |
|---|---|---|---|
| `bn254_g1_add`, `bn254_g1_mul`, `bn254_multi_pairing_check` | CAP-0074 | 25 | 2026-01-22 (X-Ray) |
| `bn254_g1_msm`, `bn254_g1_is_on_curve`, `bn254_fr_*` | CAP-0080 | **26** | 2026-05-06 (Yardstick) |

Both are live, so the contract is deployable today. But note precisely what it
needs: **the Soroban provider uses `g1_msm`, which is Protocol 26.** A
Protocol-25-only deployment would have to express the multiexp as
`g1_mul` + `g1_add` per element — more host calls, same result. Do not
characterise the whole surface as "CAP-0074" without that caveat.

Two details from CAP-0074 worth carrying: G1 serialises as
`concat(be_bytes(X), be_bytes(Y))` — confirming the big-endian encoding — and
*"This function does NOT perform subgroup check on the inputs."* That last line
is why the shared core's on-curve and prime-order-subgroup checks are
load-bearing rather than defensive: the host will happily accept a point
outside the subgroup.

(Stellar's docs page still labels some examples "P25 Preview"; that is docs
status, not host-function status.)

| operation | NEAR | Soroban |
|---|---|---|
| multi-scalar multiplication | `env::alt_bn128_g1_multiexp` | `Bn254::g1_msm` |
| multi-pairing product check | `env::alt_bn128_pairing_check` | `Bn254::pairing_check` |
| SHA-256 | `env::sha256` | `crypto::sha256` |

plus `g1_add`, `g1_mul`, `g1_is_on_curve`, and `fr_add`/`fr_sub`/`fr_mul`/
`fr_pow`/`fr_inv`.

So this is a port of the same shape, not a redesign. The one real difference is
**wire encoding**, and it is the thing that will silently break a naive port:

| | G1 | G2 |
|---|---|---|
| NEAR | `(x, y)`, 32-byte **little-endian** each, 64 B | `(x.c0, x.c1, y.c0, y.c1)`, 32-byte LE, 128 B |
| Soroban | `be(X) ‖ be(Y)`, 32-byte **big-endian** each, 64 B | Ethereum-compatible — confirm coefficient order from the `Bn254G2Affine` docs |

Soroban's `Bn254G1Affine` is a thin wrapper over `BytesN<64>` in
Ethereum-compatible format: infinity is 64 zero bytes, the two flag bits
(0x80/0x40 of the first byte) must be unset, and `from_bytes` does **not**
validate — the host traps when an invalid point reaches a host function. A wrong
G2 coefficient order is worse than a trap: it produces proofs that simply fail to
verify, which reads as a bad proof rather than a bad port.

The seam already exists. Groth16 verification is exactly one multiexp and one
multi-pairing check (`groth16-core/src/groth16.rs:155-163`) — and that code is
already chain-agnostic, sitting in the shared core behind `impl ProofOps`. So
the chain-specific part is two functions and a byte encoding, and nothing of
the proof system needs porting.

There is a measured cost datum to start from: the test in
`verifier/tests/risc0_verify.rs:116-120` times one Groth16 verification as a
four-pair pairing check plus one multiexp against the real nearcore VMLogic gas
meter. That number is the NEAR baseline to compare a Stellar deployment against.

## Porting checklist

1. A `ProofOps` provider over Soroban's `Bn254`: `g1_msm` for
   `g1_multiexp`, `pairing_check`, and `crypto::sha256`. Everything else is
   shared from `groth16-core`.
2. Wire encoding: arkworks affine points into Soroban's big-endian form and
   back. G2 coefficient order must come from the SDK docs, not from the NEAR
   layout.
3. No BN254 arithmetic to implement — the host does the pairing. Do not port a
   pure-Rust pairing; that was the fallback before CAP-0074, and it is now
   strictly worse.
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
- **Compute budget is still a measurement, not an assumption.** The host does the
  pairing now, so the cost is metered like any other host function rather than
  being dominated by in-contract arithmetic. Whether one verification fits
  comfortably in a Stellar transaction should be measured before anything
  downstream is promised; `verifier/tests/risc0_verify.rs:116-120` is the NEAR
  baseline to compare against.
- **Do not claim confidential transactions from this.** This is a verifier. Amount
  privacy is a separate construction, and the standard for permissioned finance
  referred to as "3613" in the discussion needs its exact CAP number confirmed
  before being cited externally.

## Acceptance criteria

- [x] A genuine upstream RISC Zero 3.0 receipt verifies on Stellar against the
      pinned key.
- [x] Altered public inputs and noncanonical coordinates are rejected — the negative
      tests, ported, not just the positive one.
- [x] The claim digest is derived by the contract, not accepted from the caller.
- [ ] The pinned VK and `ReceiptClaim` digest match a freshly built seal's
      `bn254_control_id`.
- [ ] **Partial:** measured cost per verification is published — **27,677,866 cpu insns /
      292,462 mem bytes** for the real receipt (26,280,240 / 281,607 for the
      toy circuit). The comparison to the NEAR baseline
      (`verifier/tests/risc0_verify.rs:116-120`) is still outstanding, and the
      two are not directly comparable: Soroban meters cpu insns and memory,
      NEAR meters gas. A conversion needs a stated basis, not a side-by-side
      number.
- [x] Wrapper identity is rotatable, with the stranding risk documented —
      **not applicable here, by design.** There is no stored wrapper identity:
      `control_root`/`bn254_control_id` are caller arguments folded into the
      Groth16 public inputs, so a wrong value fails rather than widens. Nothing
      to rotate, nothing to strand. The consequence is the inverse — the
      contract supplies no reference values, so the consumer must pin against a
      named RISC Zero release at integration time.
