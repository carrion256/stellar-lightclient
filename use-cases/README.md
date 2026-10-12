# Light client use cases

What you can build on `stellar-lightclient`, and what each thing actually requires.

Every use case here is grounded in what this repository verifies today. Where a use
case needs work that does not exist yet, the document says so explicitly and names
the missing piece. Nothing below is inferred from a roadmap.

## What the light client proves today

Three primitives, all implemented and tested:

1. **Ledger span authentication.** One SCP quorum certificate at the tail
   authenticates a whole run of consecutive ledger headers. Intermediate ledgers
   cost only their header (~428 B each) because the tail's signed transaction set
   pins `previousLedgerHash`, which pins the header before it, transitively back to
   the stored head. See `verify-core/src/lib.rs:10-20`.
2. **Transaction inclusion claims.** A claim is `(tx envelope XDR, index)`. It is
   proven against the tail's *authenticated* transaction set, and yields
   `claim_id = sha256(tx envelope)`. See `verify-core/src/lib.rs:345-360`.
3. **ZK-compressed epochs.** The RISC Zero guest runs the *same* `verify_core`
   verification path over an `EpochInput` and commits a compact `EpochJournal`
   (v1: 112 + 32 x `claim_count` bytes, including the trust-policy digest).
   See `guest/methods/guest/src/lib.rs:1-12` and `verify-core/src/journal.rs:3-24`.

Two on-chain entry points consume those receipts on NEAR
(`contract/src/lib.rs:508-628`):

| entry point | binds to | what `verified: true` means |
|---|---|---|
| `verify_receipt` | caller-named `image_id` + journal | that image halted successfully committing exactly that journal. **Proves nothing about Stellar.** Consumers must check `image_id` themselves. |
| `verify_claim` | this contract's `epoch_image_id`, current trust policy digest, and the stored starting checkpoint | a real epoch under *this* contract's policy, with `end_seq`, `end_hash`, and the proven `claim_ids` returned |

## Three tiers of guarantee — do not conflate them

| tier | example | committed by the header? | status here |
|---|---|---|---|
| **Inclusion** | envelope sat at index N of the authenticated set | yes, via `txSetHash` | **shipped** |
| **Outcome** | succeeded, this fee, these Soroban events | yes, via `txSetResultHash` | **shipped** |
| **Effects** | these balance deltas actually moved | **no** | not provable from committed data |

A proven `claim_id` alone says only the first: the envelope sat at index N of an
authenticated transaction set. It does not say the transaction succeeded, that a
payment settled, or that a deposit occurred (`AGENTS.md`, "Verification and API
boundaries").

Outcomes are implemented as a second claim kind. `LedgerHeader.tx_set_result_hash`
commits the `TransactionResultSet`, and Soroban contract events sit inside the
hashed success preimage — so success, fee, per-operation result codes and emitted
events are all proven. They bind to the **authenticated head** header, not the
provisional tail, because the quorum certificate does not sign `tx_set_result_hash`;
the consequence is that the outcome for ledger L is provable one span after L was a
span's tail. See
[uc-01](uc-01-transaction-inclusion.md#proving-outcomes--shipped).

*Effects* remain out of reach: `TransactionMeta` balance and trustline deltas are not
header-committed (`LedgerCloseMeta` is observer-facing, and
`LedgerHeaderExtensionV1` carries no meta hash). Stellar does not Merkle-ize state
either, so there is no Merkle path to an account balance. Use cases needing effect
proofs must derive them by replaying state; each document says so.

## Capability map

| # | Use case | Proves | Status | Missing piece |
|---|---|---|---|---|
| [01](uc-01-transaction-inclusion.md) | Transaction inclusion and outcome attestation | envelope was in an authenticated ledger; succeeded, fee, Soroban events | **Shipped** | — |
| [02](uc-02-cross-chain-request-reply.md) | Cross-chain request/reply via NEAR MPC | a Stellar instruction is authentic | **Composes** | consumer contract + MPC signing policy |
| [03](uc-03-private-access-control.md) | Private KYC/AML/whitelist access proofs | caller holds a valid credential, without revealing identity | **New proving work** | credential circuit, in-browser prover, issuer witness |
| [04](uc-04-proof-of-reserves-and-nav.md) | Proof of reserves / custody / off-chain NAV | an attested balance or position is what it claims | **New proving work** | witness leg (exchange/brokerage attestation), balance guest |
| [05](uc-05-bridge-of-trust.md) | Configurable third-party bridge of trust | Stellar events to a threshold signer set | **Composes** | operator-deployable config; deliberately not operated by us |
| [06](uc-06-hedge-coverage-attestation.md) | Hedge / option coverage attestation | a covering option or policy exists | **New proving work** | attestation of the venue position (shares #04's witness leg) |
| [07](uc-07-verifiable-state-reads.md) | Verifiable state reads and off-chain attestation | an arbitrary Rust program ran and committed a journal | **Composes** | the specific guest program per assertion |
| [08](uc-08-stellar-native-verifier.md) | Groth16 verifier on Stellar | a RISC Zero receipt, verified on Stellar | **Shipped** | seal-build check of `bn254_control_id` |

Status vocabulary:

- **Shipped** — implemented and covered by tests in this repo.
- **Composes** — buildable from shipped primitives; the work is consumer code, not new cryptography.
- **New proving work** — needs a new guest program and, in most cases, an off-chain witness leg the light client does not provide.
- **New verifier port** — the verifier exists here (`verifier/`) but must be ported to the target chain.

## Why the verifying key is the multiplier

The Groth16 verifying key is RISC Zero's STARK-to-SNARK *wrapper* key: one key for
every program built with the same tooling version. The wrapper identity is pinned
on-chain as `control_root` + `bn254_control_id` and is exposed as a compatibility
check (`contract/src/lib.rs:468-506`).

Practical consequence: **a new use case does not need a new on-chain verifier.**
It needs a new guest program and a new `image_id` that the *consumer* checks. The
expensive pairing work and its trust anchor are shared. This is why use cases 03,
04, 06 and 07 are "new proving work" rather than "new infrastructure".

See `AGENTS.md` for the version caveat: if any *verification* crate bumps, the VK
and claim digest must be re-transcribed and re-pinned before a receipt is trusted.

## Repository map

| path | role |
|---|---|
| `verify-core/` | host-agnostic verification: spans, claims, trust policy, journal encoding |
| `guest/` | RISC Zero guest running `verify_core` over an `EpochInput` |
| `verifier/` | Groth16/RISC Zero receipt verification, claim digest derivation |
| `contract/` | NEAR contract `stellar-light-client` |
| `tools/relay.py` | relayer: builds calldata (Borsh ~27% smaller than JSON), dry-run or send |
| `tools/xtask/` | `fetch-fixture`: authenticates and atomically publishes fixtures |
| `testdata/` | RISC Zero 3.0 receipt fixture, toy Groth16 fixture, Stellar fixture |
