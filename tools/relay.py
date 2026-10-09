#!/usr/bin/env python3
"""Relayer: submit Stellar span proofs to the NEAR light-client contract.

Consumes the proof JSON produced by the fixture fetcher
(`cargo run -p xtask -- fetch-fixture`) and builds a *span* proof: one header per
ledger, with a single quorum certificate and transaction set at the tail. The tail's
certificate authenticates every ledger BEFORE the tail; the tail header itself is
only pinned by the next submission from the stored checkpoint, or by its own tx set
plus a supplied `start_header_xdr_b64` (claims always need that predecessor).

Two encodings:
  --format json   JSON + base64 args for `submit_span` (explorer/wallet friendly)
  --format borsh  raw Borsh call bytes for `submit_span_raw` (no base64: ~27% smaller)

Proofs are calldata only: the contract verifies them in memory and stores just the
chain head and trust configuration. Nothing here records settlements — that belongs
to the bridge built on top of the light client.

Usage:
    tools/relay.py --proof testdata/fixture.json --contract lc.testnet --dry-run
    tools/relay.py --proof testdata/fixture.json --contract lc.testnet --format borsh --dry-run
    tools/relay.py --proof testdata/fixture.json --contract lc.testnet --signer relayer.testnet --send

`--send` invokes `near-cli-rs` using a temporary file for either encoding.
Without it, a replayable shell command recreates the payload via stdin (or points
at the file given to `--output`). Never pass large calldata in argv.

Single-header spans with claims are rejected unless the proof carries
`start_header_xdr_b64`: the shared core refuses claims without an authenticated
predecessor, so don't print or send known-failing proofs.
"""

import argparse
import base64
import binascii
import json
import shlex
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

def b64(value: str, field: str = "base64") -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field}: expected a base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{field}: invalid base64") from exc
    if base64.b64encode(decoded).decode() != value:
        raise ValueError(f"{field}: expected canonical base64")
    return decoded


def build_span(proof: dict, tail_index: int, with_claims: bool) -> dict:
    """One span over all closes, certified at `tail_index`."""
    closes = proof["closes"]
    if not isinstance(closes, list) or not closes:
        raise ValueError("closes: expected a nonempty list")
    if not -len(closes) <= tail_index < len(closes):
        raise ValueError(f"--tail-index must be between {-len(closes)} and {len(closes) - 1}")
    if tail_index < 0:
        tail_index += len(closes)
    tail = closes[tail_index]
    span = {
        "start_header": proof.get("start_header_xdr_b64"),
        "headers": [c["header_xdr_b64"] for c in closes[: tail_index + 1]],
        "tail_envelopes": tail["scp_envelopes_b64"],
        "tail_tx_set_xdr": tail["tx_set_xdr_b64"],
        "tx_claims": [],
    }
    if with_claims and tail.get("tx_envelope_xdr_b64") is not None:
        span["tx_claims"].append(
            {
                "tx_envelope_xdr": tail["tx_envelope_xdr_b64"],
                "tx_index": tail["tx_index"],
            }
        )
    for index, value in enumerate(span["headers"]):
        b64(value, f"headers[{index}]")
    if not isinstance(span["tail_envelopes"], list):
        raise ValueError("tail_envelopes: expected a list")
    for index, value in enumerate(span["tail_envelopes"]):
        b64(value, f"tail_envelopes[{index}]")
    for field in ("start_header", "tail_tx_set_xdr"):
        if span[field] is not None:
            b64(span[field], field)
    if span["tx_claims"] and len(span["headers"]) == 1 and span["start_header"] is None:
        raise ValueError(
            "claims require an authenticated predecessor header: this proof has a "
            "single header and carries no start_header_xdr_b64 — supply it, or "
            "use --no-claims (the shared core rejects this proof otherwise)"
        )
    for claim in span["tx_claims"]:
        b64(claim["tx_envelope_xdr"], "tx_envelope_xdr")
        if type(claim["tx_index"]) is not int or not 0 <= claim["tx_index"] <= 0xFFFFFFFF:
            raise ValueError("tx_index: expected a u32 integer")
    return span


def borsh_bytes(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def borsh_vec_bytes(items: list) -> bytes:
    return struct.pack("<I", len(items)) + b"".join(borsh_bytes(i) for i in items)


def encode_borsh(span: dict) -> bytes:
    """SpanProofRaw: start-header Option, headers, envelopes, set Option, claims."""
    def option(value):
        return b"\x00" if value is None else b"\x01" + borsh_bytes(b64(value))

    out = option(span["start_header"])
    out += borsh_vec_bytes([b64(h) for h in span["headers"]])
    out += borsh_vec_bytes([b64(e) for e in span["tail_envelopes"]])
    out += option(span["tail_tx_set_xdr"])
    out += struct.pack("<I", len(span["tx_claims"]))
    for claim in span["tx_claims"]:
        out += borsh_bytes(b64(claim["tx_envelope_xdr"]))
        out += struct.pack("<I", claim["tx_index"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--proof", required=True, help="proof JSON from xtask fetch-fixture")
    ap.add_argument("--contract", required=True, help="NEAR account id of the light-client contract")
    ap.add_argument("--signer", help="NEAR account id that signs and pays (required with --send)")
    ap.add_argument(
        "--tail-index",
        type=int,
        default=-1,
        help="index of the close certified at the span tail (default: last)",
    )
    ap.add_argument(
        "--format",
        default="json",
        choices=("json", "borsh"),
        help="call encoding: json for submit_span, borsh for submit_span_raw",
    )
    ap.add_argument("--no-claims", action="store_true", help="omit the tail's tx claim")
    ap.add_argument("--gas", default="300.0 Tgas", help="prepaid gas (default: 300.0 Tgas)")
    ap.add_argument("--network", default="testnet", choices=("testnet", "mainnet"), help="NEAR network")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--send", action="store_true", help="execute via near-cli-rs using file-args")
    mode.add_argument("--dry-run", action="store_true", help="print the call payload and exit")
    ap.add_argument("--output", help="also save raw JSON/Borsh call bytes at this path")
    args = ap.parse_args()
    if args.send and not args.signer:
        ap.error("--send requires --signer")
    try:
        with open(args.proof) as fh:
            proof = json.load(fh)
        span = build_span(proof, args.tail_index, not args.no_claims)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        ap.error(f"invalid proof: {exc}")

    if args.format == "borsh":
        payload = encode_borsh(span)
        method = "submit_span_raw"
    else:
        payload = json.dumps({"span": span}, separators=(",", ":")).encode()
        method = "submit_span"

    if args.output:
        try:
            Path(args.output).write_bytes(payload)
        except OSError as exc:
            ap.error(f"cannot write --output: {exc}")

    if args.dry_run:
        if args.format == "borsh":
            print(f"hex:    {payload.hex()}")
            print(f"base64: {base64.b64encode(payload).decode()}")
            print(f"({len(payload)} bytes of borsh call args for submit_span_raw)")
        else:
            sys.stdout.write(payload.decode())
        return 0

    def command(path):
        cmd = [
            "near", "contract", "call-function", "as-transaction",
            args.contract, method, "file-args", path,
            "prepaid-gas", args.gas, "attached-deposit", "0 NEAR",
        ]
        if args.signer:
            cmd += ["sign-as", args.signer, "network-config", args.network, "sign-with-keychain", "send"]
        return cmd

    if not args.send:
        if args.output:
            # The file already holds the exact call bytes; replay needs no temp.
            print(shlex.join(command(args.output)))
            return 0
        # Here-document bytes go through stdin, never a large executable argument.
        cmd = command("__PAYLOAD_PATH__")
        shell = shlex.join(cmd).replace("__PAYLOAD_PATH__", '"$payload"')
        print("(payload=$(mktemp) || exit 1; trap 'rm -f \"$payload\"' EXIT;")
        print("base64 --decode > \"$payload\" <<'STELLAR_CALL_BYTES'")
        print(base64.b64encode(payload).decode())
        print("STELLAR_CALL_BYTES")
        print(shell + ")")
        return 0

    try:
        with tempfile.TemporaryDirectory(prefix="stellar-relay-") as directory:
            path = Path(directory) / "args"
            path.write_bytes(payload)
            return subprocess.call(command(str(path)))
    except FileNotFoundError:
        print("near-cli-rs executable `near` not found; install it and add it to PATH", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"cannot submit call: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
