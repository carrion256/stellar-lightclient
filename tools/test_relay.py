#!/usr/bin/env python3
"""Regression tests for tools/relay.py — run with:

    python3 -m unittest discover -s tools -p 'test_relay.py'

No mocks stand in for the payload path: the fake `near` binary is a real
subprocess that opens the file-args file and reports its size, so the tests
observe the actual argv, actual file lifecycle, and actual exit codes.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import relay  # noqa: E402

FAKE_NEAR = """#!/bin/sh
path=""
take=0
maxlen=0
for a in "$@"; do
  l=${#a}
  if [ "$l" -gt "$maxlen" ]; then maxlen=$l; fi
  if [ "$take" = 1 ]; then path="$a"; take=0; fi
  if [ "$a" = "file-args" ]; then take=1; fi
done
if [ -z "$path" ]; then echo "no file-args in argv" >&2; exit 91; fi
if [ ! -f "$path" ]; then echo "args file already deleted: $path" >&2; exit 92; fi
bytes=$(wc -c < "$path" | tr -d ' ')
printf '%s %s\\n' "$bytes" "$maxlen" > "$FAKE_NEAR_RESULT"
exit 0
"""


def close(tx_set_b64=None):
    return {
        "ledger_seq": 100,
        "header_xdr_b64": base64.b64encode(b"H" * 48).decode(),
        "header_hash_b64": base64.b64encode(b"h" * 32).decode(),
        "scp_envelopes_b64": [base64.b64encode(b"E" * 10).decode()],
        "tx_set_kind": "legacy",
        "tx_set_xdr_b64": tx_set_b64 or base64.b64encode(b"T" * 40).decode(),
        "tx_set_previous_ledger_hash_b64": base64.b64encode(b"\x00" * 32).decode(),
        "results_xdr_b64": base64.b64encode(b"R").decode(),
        "tx_index": 0,
        "tx_envelope_xdr_b64": base64.b64encode(b"V" * 8).decode(),
        "tx_count": 1,
    }


def proof(n=2, tx_set_b64=None, start_header=None):
    doc = {
        "archive": "https://example.invalid",
        "network_passphrase": "Public Global Stellar Network ; September 2015",
        "checkpoint_ledger": 127,
        "closes": [close(tx_set_b64) for _ in range(n)],
    }
    if start_header is not None:
        doc["start_header_xdr_b64"] = start_header
    return doc


def base_span(**overrides):
    span = {
        "start_header": None,
        "headers": [],
        "tail_envelopes": [],
        "tail_tx_set_xdr": None,
        "tx_claims": [],
    }
    span.update(overrides)
    return span


class EncodingTests(unittest.TestCase):
    def test_b64_accepts_canonical(self):
        self.assertEqual(relay.b64(base64.b64encode(b"foo").decode()), b"foo")

    def test_b64_rejects_alphabet_junk(self):
        with self.assertRaisesRegex(ValueError, "invalid base64"):
            relay.b64(base64.b64encode(b"foo").decode() + "!!!", "header")

    def test_b64_rejects_noncanonical_padding(self):
        # "AB==" decodes to b"\\x00" but carries set bits in the padding —
        # canonical check must reject it even though the alphabet is valid.
        with self.assertRaisesRegex(ValueError, "canonical"):
            relay.b64("AB==", "header")

    def test_b64_rejects_non_string(self):
        with self.assertRaisesRegex(ValueError, "base64 string"):
            relay.b64(123, "tx_set")

    def test_empty_bytes_some_vs_none(self):
        none = relay.encode_borsh(base_span())
        empty = relay.encode_borsh(base_span(tail_tx_set_xdr=""))
        # tail-set option sits after the two empty vecs: 00 | 00000000 | 00000000 | OPT | claims
        self.assertEqual(none, b"\x00" + b"\x00" * 8 + b"\x00" + b"\x00" * 4)
        self.assertEqual(empty, b"\x00" + b"\x00" * 8 + b"\x01" + b"\x00" * 8)

    def test_start_header_is_first_borsh_field(self):
        raw = b"AB"
        enc = relay.encode_borsh(base_span(start_header=base64.b64encode(raw).decode()))
        self.assertEqual(enc, b"\x01\x02\x00\x00\x00" + raw + b"\x00" * 8 + b"\x00\x00\x00\x00\x00")

    def test_claim_on_single_header_without_anchor_rejected(self):
        with self.assertRaisesRegex(ValueError, "authenticated predecessor"):
            relay.build_span(proof(n=1), 0, True)

    def test_claim_on_single_header_with_anchor_ok(self):
        anchor = base64.b64encode(b"A" * 48).decode()
        span = relay.build_span(proof(n=1, start_header=anchor), 0, True)
        self.assertEqual(span["start_header"], anchor)
        self.assertEqual(len(span["tx_claims"]), 1)

    def test_no_claims_single_header_ok(self):
        span = relay.build_span(proof(n=1), 0, False)
        self.assertEqual(span["tx_claims"], [])

    def test_tail_index_bounds(self):
        with self.assertRaisesRegex(ValueError, "tail-index"):
            relay.build_span(proof(n=2), -3, True)
        with self.assertRaisesRegex(ValueError, "tail-index"):
            relay.build_span(proof(n=2), 2, True)


class CliTests(unittest.TestCase):
    def run_relay(self, *extra, env=None):
        return subprocess.run(
            [sys.executable, str(HERE / "relay.py"), *extra],
            capture_output=True, text=True, env=env,
        )

    def test_missing_proof_file_clear_error(self):
        proc = self.run_relay("--proof", "no-such.json", "--contract", "lc.testnet")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid proof", proc.stderr)

    def test_send_and_dry_run_mutually_exclusive(self):
        proc = self.run_relay("--proof", "x.json", "--contract", "c", "--send", "--dry-run")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not allowed with argument", proc.stderr)

    def test_send_requires_signer(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "proof.json"
            f.write_text(json.dumps(proof()))
            proc = self.run_relay("--proof", str(f), "--contract", "c", "--send")
            self.assertEqual(proc.returncode, 2)
            self.assertIn("--send requires --signer", proc.stderr)

    def test_malformed_base64_rejected_not_encoded(self):
        with tempfile.TemporaryDirectory() as d:
            p = proof()
            p["closes"][0]["header_xdr_b64"] += "!!!"
            f = Path(d) / "proof.json"
            f.write_text(json.dumps(p))
            for fmt in ("json", "borsh"):
                proc = self.run_relay("--proof", str(f), "--contract", "c", "--format", fmt)
                self.assertEqual(proc.returncode, 2, fmt)
                self.assertIn("invalid base64", proc.stderr)

    def test_missing_near_executable_actionable(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "proof.json"
            f.write_text(json.dumps(proof()))
            empty = Path(d) / "empty"
            empty.mkdir()
            env = dict(os.environ, PATH=str(empty))
            proc = self.run_relay(
                "--proof", str(f), "--contract", "c", "--signer", "s.testnet", "--send",
                env=env,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("near-cli-rs", proc.stderr)


class FileArgsLifecycleTests(unittest.TestCase):
    """The big-payload path is exercised against a real fake `near` binary."""

    BIG = base64.b64encode(b"T" * 380_000).decode()  # >128 KiB once serialized

    def fake_env(self, d):
        bindir = Path(d) / "bin"
        bindir.mkdir()
        fake = bindir / "near"
        fake.write_text(FAKE_NEAR)
        fake.chmod(0o755)
        result = Path(d) / "result"
        env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
                   FAKE_NEAR_RESULT=str(result))
        return env, result

    def test_big_json_payload_goes_through_file_args(self):
        with tempfile.TemporaryDirectory() as d:
            env, result = self.fake_env(d)
            f = Path(d) / "proof.json"
            f.write_text(json.dumps(proof(tx_set_b64=self.BIG)))
            proc = subprocess.run(
                [sys.executable, str(HERE / "relay.py"),
                 "--proof", str(f), "--contract", "lc.testnet",
                 "--signer", "relayer.testnet", "--send"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            # Recompute the expected payload and compare bytes + argv hygiene.
            span = relay.build_span(proof(tx_set_b64=self.BIG), -1, True)
            expected = len(json.dumps({"span": span}, separators=(",", ":")).encode())
            seen_bytes, max_arg = result.read_text().split()
            self.assertEqual(int(seen_bytes), expected)
            # Linux caps a single argument at 128 KiB; our argv stays tiny.
            self.assertLess(int(max_arg), 1024)
            # The fake opened the file while relay's temp dir was alive;
            # TemporaryDirectory guarantees cleanup after the call returned.

    def test_printed_command_is_replayable(self):
        with tempfile.TemporaryDirectory() as d:
            env, result = self.fake_env(d)
            f = Path(d) / "proof.json"
            f.write_text(json.dumps(proof(tx_set_b64=self.BIG)))
            proc = subprocess.run(
                [sys.executable, str(HERE / "relay.py"),
                 "--proof", str(f), "--contract", "lc.testnet",
                 "--signer", "relayer.testnet"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            expected_span = relay.build_span(proof(tx_set_b64=self.BIG), -1, True)
            expected_size = len(json.dumps({"span": expected_span}, separators=(",", ":")).encode())
            self.assertEqual(self.run_replay(proc.stdout, env), str(expected_size))

    def test_output_path_used_by_printed_command(self):
        with tempfile.TemporaryDirectory() as d:
            env, result = self.fake_env(d)
            f = Path(d) / "proof.json"
            out = Path(d) / "span.args"
            f.write_text(json.dumps(proof()))
            proc = subprocess.run(
                [sys.executable, str(HERE / "relay.py"),
                 "--proof", str(f), "--contract", "lc.testnet",
                 "--signer", "relayer.testnet", "--output", str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(out.exists())
            printed = proc.stdout
            self.assertIn(str(out), printed)
            self.assertNotIn("mktemp", printed)
            span = relay.build_span(proof(), -1, True)
            expected = len(json.dumps({"span": span}, separators=(",", ":")).encode())
            self.assertEqual(self.run_replay(printed, env), str(expected))

    def run_replay(self, printed, env):
        replay = subprocess.run(["sh"], input=printed, capture_output=True, text=True, env=env)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        return result_size(env)

    def test_borsh_payload_via_output_and_file_args(self):
        with tempfile.TemporaryDirectory() as d:
            env, result = self.fake_env(d)
            f = Path(d) / "proof.json"
            out = Path(d) / "span.borsh"
            f.write_text(json.dumps(proof(tx_set_b64=self.BIG)))
            proc = subprocess.run(
                [sys.executable, str(HERE / "relay.py"),
                 "--proof", str(f), "--contract", "lc.testnet",
                 "--format", "borsh", "--signer", "relayer.testnet", "--output", str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = relay.encode_borsh(relay.build_span(proof(tx_set_b64=self.BIG), -1, True))
            self.assertEqual(out.read_bytes(), payload)
            self.assertEqual(self.run_replay(proc.stdout, env), str(len(payload)))


def result_size(env):
    return Path(env["FAKE_NEAR_RESULT"]).read_text().split()[0]


if __name__ == "__main__":
    unittest.main()
