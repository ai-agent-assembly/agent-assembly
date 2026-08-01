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
        #   "offset" (int)  — start of the finding, as a byte offset into the
        #                     UTF-8 encoding of `text` (not a str index)
        #   "end"    (int)  — end of the match, same unit. Required: a finding
        #                     without it names a region of unknown extent, so
        #                     the redaction fails closed (see _redact).

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
    """Return (ok, reason) comparing actual to expected findings.

    **`end` is deliberately not graded here** (AAASM-5373 AC 7). Grading it
    would need an `end` on every `expected_findings` entry, and the vectors
    carry none — adding one is a change to the vector schema, which ADR 0015
    puts off-limits as a way to make an implementation pass. That is a design
    decision to take on its own merits, not a side effect of this fix, so the
    schema is left alone and the omission is recorded rather than papered over.

    `end` is not ungraded in the suite as a whole, though, and it is no longer
    possible to slip a wrong one past the runner. It is graded indirectly, and
    now strictly, through the redaction comparison in `run()`: before this
    change `_redact` skipped any span it could not splice, so a nonsense `end`
    could vanish silently and leave the rest of the text matching. `_redact`
    now fails closed, so a wrong `end` either splices to the wrong string or
    collapses the whole text to "[REDACTED]" — and both mismatch
    `expected_redacted`. The escape hatch that made this omission dangerous is
    what closed; the omission itself is now merely narrow.
    """
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

        # Redact check: reconstruct the redacted string from findings, the same
        # way Rust's ScanResult::redact() does (coalesce, splice, fail closed).
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


def _kind_priority(kind: str) -> int:
    """Relative confidence of *kind*, mirroring `CredentialKind::priority()`.

    Only the two generic backstops score below the specific detectors
    (aa-security/src/scanner.rs:334-368). An unrecognised kind is treated as
    specific: an SDK that reports a kind this runner has never heard of has
    made a *more* precise claim than "high entropy", and downgrading it would
    let a generic label win a merge it loses in Rust.
    """
    if kind == "GenericHighEntropy":
        return 0
    if kind == "EmailAddress":
        return 1
    return 2


def _coalesce_findings(findings: list[dict]) -> list[tuple[int, int, str]] | None:
    """Merge findings into non-overlapping `(offset, end, kind)` spans.

    Mirrors `coalesce_findings` (aa-security/src/scanner.rs:670-695): sort by
    `(offset, end)`, then fold each finding into the running span when it starts
    **strictly before** that span's `end`. The merged span takes the union of
    the two ends and the label of the highest-`_kind_priority` finding in the
    run, with ties going to the one seen first — so a specific detector
    (`PostgresUrl`) claims the span from a generic backstop (`EmailAddress`)
    that happens to start at a lower offset.

    The `<` is deliberate and load-bearing: Rust merges **overlapping** spans
    only. A span starting exactly at the previous span's `end` — adjacent but
    not overlapping — stays separate and produces two labels. A merge written
    with `<=` would silently emit one label where Rust emits two.

    Returns `None` when a finding carries no usable span at all (`offset` or
    `end` missing), which the caller turns into a fail-closed result: a finding
    names a region the scanner flagged, and one whose extent is unknown cannot
    be proven redacted.
    """
    spans: list[tuple[int, int, str]] = []
    for finding in sorted(
        findings, key=lambda f: (f.get("offset") or 0, f.get("end") or 0)
    ):
        offset = finding.get("offset")
        end = finding.get("end")
        if offset is None or end is None:
            return None
        kind = finding.get("kind", "UNKNOWN")
        if spans and offset < spans[-1][1]:
            last_offset, last_end, last_kind = spans[-1]
            if _kind_priority(kind) > _kind_priority(last_kind):
                last_kind = kind
            spans[-1] = (last_offset, max(last_end, end), last_kind)
        else:
            spans.append((offset, end, kind))
    return spans


def _redact(text: str, findings: list[dict]) -> str:
    """Reconstruct the redacted text, mirroring Rust's `ScanResult::redact`.

    `offset` and `end` are **byte** positions in the UTF-8 encoding of *text* —
    that is the unit the reference scanner emits and the unit the vector schema
    documents. Splicing therefore happens on the encoded `bytes`, which is
    decoded back once at the end; slicing the `str` would index code points and
    land the redaction in the wrong place for any non-ASCII input.

    Findings are coalesced into non-overlapping spans first (see
    `_coalesce_findings`), then spliced in reverse offset order so the earlier
    spans' byte positions stay valid across each replacement.

    **Fails closed.** A span that is out of range, inverted, or not aligned to a
    character boundary cannot be spliced, but it still marks a region the
    scanner flagged as a secret. Returning the rest of the text would hand back
    that region in the clear, so the whole value collapses to `"[REDACTED]"`
    instead — byte for byte what `ScanResult::redact` does
    (aa-security/src/scanner.rs:443-461, "never return the raw text with a
    secret intact"), and what ADR 0015 requires of a DLP trust boundary.

    Rust evaluates its bounds and char-boundary checks against the buffer as it
    is being spliced; this validates every span against the original buffer
    up front. The two agree because coalescing leaves the spans disjoint, so no
    splice can move a byte that a later check looks at, and because the only
    two outcomes are "every span spliced" and "`[REDACTED]`" — which of several
    invalid spans is noticed first cannot change the answer.
    """
    buf = text.encode("utf-8")
    spans = _coalesce_findings(findings)
    if spans is None:
        return "[REDACTED]"
    for offset, end, _kind in spans:
        if offset < 0 or end > len(buf) or offset > end:
            return "[REDACTED]"
        if not _is_utf8_boundary(buf, offset) or not _is_utf8_boundary(buf, end):
            return "[REDACTED]"
    result = buf
    for offset, end, kind in reversed(spans):
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
