#!/usr/bin/env python3
"""Relayer: submit Stellar span proofs to the NEAR light-client contract.

Consumes the proof JSON produced by the fixture fetcher
(`cargo run -p xtask -- fetch-fixture`) and builds a *span* proof: one header per
ledger, with a single quorum certificate and transaction set at the tail. The tail's
certificate authenticates the whole span, so intermediate ledgers cost only 428 B.

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

`--send` shells out to `near-cli-rs`; without it the exact command (or raw bytes) is
printed.
"""

import argparse
import json
import shlex
import struct
import subprocess
import sys

# fixture key → contract key for the tail close
CLOSE_KEYS = {
    "header_xdr_b64": "header",
    "scp_envelopes_b64": "tail_envelopes",
    "tx_set_xdr_b64": "tail_tx_set_xdr",
}


def b64(value: str) -> bytes:
    import base64

    return base64.b64decode(value)


def build_span(proof: dict, tail_index: int, with_claims: bool) -> dict:
    """One span over all closes, certified at `tail_index`."""
    closes = proof["closes"]
    if tail_index < 0:
        tail_index += len(closes)
    tail = closes[tail_index]
    span = {
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
    return span


def borsh_bytes(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def borsh_vec_bytes(items: list) -> bytes:
    return struct.pack("<I", len(items)) + b"".join(borsh_bytes(i) for i in items)


def encode_borsh(span: dict) -> bytes:
    """Borsh for SpanProofRaw: Vec<Vec<u8>>, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<claim>."""
    out = borsh_vec_bytes([b64(h) for h in span["headers"]])
    out += borsh_vec_bytes([b64(e) for e in span["tail_envelopes"]])
    tail = b64(span["tail_tx_set_xdr"]) if span["tail_tx_set_xdr"] else None
    out += b"\x00" if tail is None else b"\x01" + borsh_bytes(tail)
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
    ap.add_argument("--send", action="store_true", help="execute via near-cli-rs instead of printing")
    ap.add_argument("--dry-run", action="store_true", help="print the call payload and exit")
    args = ap.parse_args()

    with open(args.proof) as fh:
        proof = json.load(fh)
    span = build_span(proof, args.tail_index, not args.no_claims)

    if args.format == "borsh":
        payload = encode_borsh(span)
        method = "submit_span_raw"
    else:
        payload = json.dumps({"span": span}, separators=(",", ":")).encode()
        method = "submit_span"

    if args.dry_run:
        if args.format == "borsh":
            import base64

            print(f"hex:    {payload.hex()}")
            print(f"base64: {base64.b64encode(payload).decode()}")
            print(f"({len(payload)} bytes of borsh call args for submit_span_raw)")
        else:
            sys.stdout.write(payload.decode())
        return 0

    if args.format == "borsh":
        # near-cli-rs only carries JSON args; raw Borsh bytes go to the RPC as args_base64.
        print("borsh args are raw bytes: use --dry-run and submit the base64 via RPC args_base64",
              file=sys.stderr)
        return 2

    cmd = [
        "near", "contract", "call-function", "as-transaction",
        args.contract, method, "json-args", payload.decode(),
        "prepaid-gas", args.gas, "attached-deposit", "0 NEAR",
    ]
    if args.signer:
        cmd += ["sign-as", args.signer, "network-config", args.network, "sign-with-keychain", "send"]

    if not args.send:
        if args.format == "borsh":
            print("borsh args need to be passed as raw bytes; use --dry-run to capture them")
        print(shlex.join(cmd))
        return 0

    if not args.signer:
        print("--send requires --signer", file=sys.stderr)
        return 2
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
