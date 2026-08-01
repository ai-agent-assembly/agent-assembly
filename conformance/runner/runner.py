#!/usr/bin/env python3
"""
Agent Assembly Python Conformance Runner.

Validates that a Python SDK implementation produces the same credential-detection
results as the language-neutral JSON vectors in conformance/vectors/credential_detection/.

Usage
-----
    pip install -r conformance/runner/requirements.txt
    python conformance/runner/runner.py [--vectors PATH] [--verbose]

Exit codes
----------
    0  All vectors passed.
    1  One or more vectors failed.
    2  The SDK under test could not be imported.

Implementing the SDK shim
-------------------------
Set the environment variable AA_SDK_MODULE to the Python module that provides
a scan() function with this signature:

    def scan(text: str) -> list[dict]:
        ...
        # Returns a list of findings, each a dict with keys:
        #   "kind"   (str)  — matches CredentialKind.as_str() in aa-core
        #   "offset" (int)  — byte offset of the finding in `text`

If AA_SDK_MODULE is unset the runner uses a no-op stub that always returns []
and prints a warning — all vectors with expected_findings will fail.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
    _GREEN = Fore.GREEN
    _RED = Fore.RED
    _YELLOW = Fore.YELLOW
    _RESET = Style.RESET_ALL
except ImportError:
    _GREEN = _RED = _YELLOW = _RESET = ""

# ---------------------------------------------------------------------------
# SDK shim loading
# ---------------------------------------------------------------------------

def _load_sdk_scan():
    """Return the scan() callable from the configured SDK module."""
    module_name = os.environ.get("AA_SDK_MODULE", "")
    if not module_name:
        print(
            f"{_YELLOW}WARNING: AA_SDK_MODULE is not set — "
            f"using no-op stub; all positive-finding vectors will fail.{_RESET}"
        )

        def _noop(text: str) -> list[dict]:
            return []

        return _noop

    try:
        mod = importlib.import_module(module_name)
        return mod.scan
    except ImportError as exc:
        print(f"{_RED}ERROR: cannot import AA_SDK_MODULE={module_name!r}: {exc}{_RESET}")
        sys.exit(2)


# ---------------------------------------------------------------------------
# Vector loading
# ---------------------------------------------------------------------------

def _load_vectors(vectors_dir: Path) -> list[dict[str, Any]]:
    """Load all *.json files from *vectors_dir* in sorted filename order."""
    files = sorted(vectors_dir.glob("*.json"))
    if not files:
        print(f"{_YELLOW}WARNING: no vector files found in {vectors_dir}{_RESET}")
    vectors = []
    for f in files:
        with f.open(encoding="utf-8") as fh:
            vectors.append(json.load(fh))
    return vectors


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------

def _findings_match(actual: list[dict], expected: list[dict]) -> tuple[bool, str]:
    """Return (ok, reason) comparing actual to expected findings."""
    if len(actual) != len(expected):
        return False, (
            f"finding count mismatch: got {len(actual)}, expected {len(expected)}"
        )
    for i, (a, e) in enumerate(zip(actual, expected)):
        if a.get("kind") != e.get("kind"):
            return False, (
                f"finding[{i}] kind mismatch: got {a.get('kind')!r}, "
                f"expected {e.get('kind')!r}"
            )
        if a.get("offset") != e.get("offset"):
            return False, (
                f"finding[{i}] offset mismatch: got {a.get('offset')!r}, "
                f"expected {e.get('offset')!r}"
            )
    return True, ""


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(vectors_dir: Path, verbose: bool) -> bool:
    """Run all vectors against the SDK. Returns True if all pass."""
    if not os.environ.get("AA_SDK_MODULE", ""):
        print(
            f"{_YELLOW}INFO: AA_SDK_MODULE is not set — "
            f"Python SDK conformance is a placeholder; skipping test run.{_RESET}"
        )
        print("Set AA_SDK_MODULE to the Python module name when the SDK is ready.")
        return True

    scan = _load_sdk_scan()
    vectors = _load_vectors(vectors_dir)

    passed = 0
    failed = 0
    failures: list[str] = []

    for v in vectors:
        desc = v.get("description", "<no description>")
        input_text = v["input_text"]
        expected_findings = v.get("expected_findings", [])
        expected_redacted = v.get("expected_redacted", input_text)

        actual_findings = scan(input_text)

        ok, reason = _findings_match(actual_findings, expected_findings)
        if not ok:
            failed += 1
            msg = f"FAIL [{desc}]: {reason}"
            failures.append(msg)
            if verbose:
                print(f"{_RED}{msg}{_RESET}")
            continue

        # Redact check: reconstruct the redacted string from findings.
        # Approximates Rust's ScanResult::redact() — see _redact for the two
        # ways it still diverges (no coalescing, fails open).
        redacted = _redact(input_text, actual_findings)
        if redacted != expected_redacted:
            failed += 1
            msg = (
                f"FAIL [{desc}]: redact mismatch\n"
                f"  got:      {redacted!r}\n"
                f"  expected: {expected_redacted!r}"
            )
            failures.append(msg)
            if verbose:
                print(f"{_RED}{msg}{_RESET}")
        else:
            passed += 1
            if verbose:
                print(f"{_GREEN}PASS [{desc}]{_RESET}")

    # Summary
    total = passed + failed
    print(f"\n{'─' * 60}")
    print(f"Results: {passed}/{total} passed", end="")
    if failed:
        print(f", {_RED}{failed} failed{_RESET}")
        for f_msg in failures:
            print(f"  {f_msg}")
    else:
        print(f"  {_GREEN}all passed{_RESET}")

    return failed == 0


def _is_utf8_boundary(buf: bytes, index: int) -> bool:
    """True if *index* is the start of a character in *buf* (Rust `is_char_boundary`)."""
    if index in (0, len(buf)):
        return True
    # UTF-8 continuation bytes are 0b10xxxxxx; any other byte starts a character.
    return buf[index] & 0xC0 != 0x80


def _redact(text: str, findings: list[dict]) -> str:
    """Apply findings to text in reverse offset order.

    `offset` and `end` are **byte** positions in the UTF-8 encoding of *text* —
    that is the unit the reference scanner emits and the unit the vector schema
    documents. Splicing therefore happens on the encoded `bytes`, which is
    decoded back once at the end; slicing the `str` would index code points and
    land the redaction in the wrong place for any non-ASCII input.

    A span that is out of range, inverted, or not aligned to a character
    boundary is skipped rather than spliced, so this never emits invalid UTF-8.

    That skip is where this **diverges from** Rust's `ScanResult::redact`, which
    fails closed on exactly those spans and returns `"[REDACTED]"` for the whole
    text (aa-security/src/scanner.rs:447-458). Rust also coalesces overlapping
    findings before splicing; this does not. Both gaps are AAASM-5373 — until
    they close, do not describe this function as mirroring the Rust one.
    """
    # Each finding must have "kind", "offset", and "end" (byte end of match).
    # If "end" is absent, the runner cannot redact — skip silently.
    sorted_findings = sorted(findings, key=lambda f: f.get("offset", 0), reverse=True)
    result = text.encode("utf-8")
    for finding in sorted_findings:
        offset = finding.get("offset")
        end = finding.get("end")
        kind = finding.get("kind", "UNKNOWN")
        if offset is None or end is None:
            continue
        if offset < 0 or end > len(result) or offset > end:
            continue
        if not _is_utf8_boundary(result, offset) or not _is_utf8_boundary(result, end):
            continue
        placeholder = f"[REDACTED:{kind}]".encode("utf-8")
        result = result[:offset] + placeholder + result[end:]
    return result.decode("utf-8")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    default_vectors = here.parent / "vectors" / "credential_detection"

    p = argparse.ArgumentParser(
        description="Agent Assembly Python conformance runner"
    )
    p.add_argument(
        "--vectors",
        type=Path,
        default=default_vectors,
        help="Path to the credential_detection vector directory "
        f"(default: {default_vectors})",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true", help="Print each vector result"
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    ok = run(args.vectors, args.verbose)
    sys.exit(0 if ok else 1)
