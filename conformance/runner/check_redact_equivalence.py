#!/usr/bin/env python3
"""
Differential check: the byte-slicing `_redact` vs. the code-point-slicing one it replaced.

Why this exists
---------------
AAASM-5371 changed how `runner._redact` interprets a finding's span. The claim
that came with it — "ASCII behaviour is unchanged" — is the kind of claim that is
easy to assert and easy to get wrong, because every committed ASCII vector passes
either way. This script is the evidence for it, kept runnable so the number in the
PR is reproducible rather than something you have to take on trust.

It drives both implementations over every span position in every ASCII vector and
compares their output byte for byte.

Cases are bucketed by span geometry rather than counted as one number, because
the two behaviours AAASM-5373 is about — coalescing overlapping findings, and
failing closed on a span that cannot be spliced — only ever show up in two of
these shapes. Bucketing first means the sweep can say *where* behaviour changed
and not merely that it did, and it keeps the "ASCII behaviour is unchanged"
claim attached to the cases that claim is actually about:

    unchanged   spliceable, non-overlapping, distinct offsets → identical, else exit 1
    coalesced   spliceable, but sorting/merging would matter  → reported only
    fail-closed at least one unspliceable span                → reported only
    malformed   offset < 0                                    → reported only

Only the first is asserted on. Today every bucket reports zero differences,
because nothing has changed yet; the counts become meaningful as soon as
something does.

The malformed bucket is the one pre-existing exception: the old code let a
negative offset fall through to Python's negative indexing and spliced garbage
into the middle of the text; the new code rejects it. That is a fix, not a
regression, so it is counted and printed rather than asserted away.

Self-check
----------
A differential harness that compares two things which are quietly the same object
reports zero mismatches forever and looks like proof. `--self-check` sabotages the
new implementation by one character and asserts this sweep *notices*, so a clean
run means the sweep can discriminate rather than that it is inert.

Run
---
    python conformance/runner/check_redact_equivalence.py
    python conformance/runner/check_redact_equivalence.py --self-check

Needs no SDK, sets no environment, and reads the vectors without writing to them.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner import _redact  # noqa: E402

Redactor = Callable[[str, list[dict]], str]


def _legacy_redact(text: str, findings: list[dict]) -> str:
    """`_redact` exactly as it stood before AAASM-5371 — slices the `str`.

    Kept verbatim, and deliberately not refactored: its value is being the thing
    that actually shipped, so any tidying would weaken the comparison.
    """
    sorted_findings = sorted(findings, key=lambda f: f.get("offset", 0), reverse=True)
    result = text
    for finding in sorted_findings:
        offset = finding.get("offset")
        end = finding.get("end")
        kind = finding.get("kind", "UNKNOWN")
        if offset is None or end is None:
            continue
        if end > len(result) or offset > end:
            continue
        placeholder = f"[REDACTED:{kind}]"
        result = result[:offset] + placeholder + result[end:]
    return result


def _mutated_redact(text: str, findings: list[dict]) -> str:
    """The current `_redact` with a one-character sabotage: `offset` → `offset + 1`.

    Used only by --self-check, to prove the sweep below can tell two nearly
    identical implementations apart.
    """
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
        placeholder = f"[REDACTED:{kind}]".encode("utf-8")
        result = result[: offset + 1] + placeholder + result[end:]  # ← the sabotage
    return result.decode("utf-8", errors="replace")


def _positions(n: int) -> list[int]:
    """Every index 0..n for short inputs; ~160 evenly spaced ones for long inputs.

    Private keys run to a few thousand bytes and an exhaustive O(n^2) pair sweep
    over those adds hours without adding span *shapes*. The endpoint is always
    included because off-by-one at the tail is the interesting case.
    """
    step = 1 if n <= 160 else max(1, n // 160)
    positions = list(range(0, n + 1, step))
    if positions[-1] != n:
        positions.append(n)
    return positions


def _wellformed_cases(n: int, positions: list[int]) -> list[list[dict]]:
    """Span sets with non-negative offsets: single, paired, and degenerate."""
    cases: list[list[dict]] = []
    # Single span at every (offset, end) pair with offset <= end.
    for o, e in itertools.combinations_with_replacement(positions, 2):
        cases.append([{"kind": "K", "offset": o, "end": e}])
    # Two spans, sampled every 7th triple, so overlapping and adjacent pairs are
    # covered without squaring the single-span cost. The second span is short and
    # anchored at o2 to exercise the reverse-order splice after a length change.
    for o1, e1, o2 in itertools.islice(
        itertools.product(positions, positions, positions), 0, None, 7
    ):
        if not (o1 <= e1 <= n and o2 <= n):
            continue
        cases.append(
            [
                {"kind": "A", "offset": o1, "end": e1},
                {"kind": "B", "offset": o2, "end": min(o2 + 5, n)},
            ]
        )
    # Degenerate shapes: no findings, missing "end", past the end, inverted.
    cases.append([])
    cases.append([{"kind": "K", "offset": 0}])
    cases.append([{"kind": "K", "offset": 3, "end": n + 50}])
    cases.append([{"kind": "K", "offset": n, "end": 0}])
    return cases


def _malformed_cases(n: int, positions: list[int]) -> list[list[dict]]:
    """Negative offsets — impossible from a `usize`-based scanner, possible from a bug."""
    negatives = sorted({-1, -2, -(n // 2 or 1), -n or -1})
    return [
        [{"kind": "K", "offset": o, "end": e}]
        for o in negatives
        for e in positions
    ]


def _load_ascii_vectors(vectors_dir: Path) -> tuple[list[str], int]:
    """Return the ASCII vector inputs, plus how many files were skipped as non-ASCII."""
    inputs, skipped = [], 0
    for f in sorted(vectors_dir.glob("*.json")):
        with f.open(encoding="utf-8") as fh:
            v: dict[str, Any] = json.load(fh)
        text = v["input_text"]
        if all(ord(c) < 128 for c in text):
            inputs.append(text)
        else:
            skipped += 1
    return inputs, skipped


def _spans_are_valid(text: str, findings: list[dict]) -> bool:
    """True if every finding carries a span `_redact` can actually splice."""
    n = len(text.encode("utf-8"))
    for f in findings:
        offset, end = f.get("offset"), f.get("end")
        if offset is None or end is None:
            return False
        if offset < 0 or end > n or offset > end:
            return False
    return True


def _sort_or_merge_matters(findings: list[dict]) -> bool:
    """True if coalescing and the `(offset, end)` sort could change the outcome.

    Two ways they can:

    * **Overlap** — some span starts strictly before the previous one ends, so
      coalescing them into their union is not a no-op. The `<` is the same
      strict test the Rust reference uses (aa-security/src/scanner.rs:679):
      spans that merely touch (`a.end == b.offset`) do not count, because that
      implementation does not merge those either.
    * **A shared offset** — sorting on `offset` alone leaves the splice order of
      two spans at the same offset up to the input order, and splicing them in
      the wrong order corrupts the first label while leaving the text behind it
      intact. Sorting on `(offset, end)` pins it.
    """
    spans = sorted((f["offset"], f["end"]) for f in findings)
    for (prev_offset, prev_end), (offset, _) in zip(spans, spans[1:]):
        if offset < prev_end or offset == prev_offset:
            return True
    return False


def _classify(text: str, findings: list[dict]) -> str:
    """Which of the three behaviours AAASM-5373 is about this span set exercises.

    * ``"failclosed"`` — at least one unspliceable span, so the choice between
      skipping it and replacing the whole text is live.
    * ``"coalesced"``  — all spans spliceable, but sorting and merging could
      change the result (see `_sort_or_merge_matters`).
    * ``"unchanged"``  — all spans spliceable, none overlap, no two share an
      offset. Coalescing is a no-op, the splice order is unambiguous, and there
      is nothing to fail closed on, so no redaction change should ever be
      visible here. This is the bucket that carries AAASM-5371's "ASCII
      behaviour is unchanged" claim.
    """
    if not _spans_are_valid(text, findings):
        return "failclosed"
    return "coalesced" if _sort_or_merge_matters(findings) else "unchanged"


class SweepResult:
    """Per-bucket counts from one pass over every span shape."""

    def __init__(self) -> None:
        self.seen: dict[str, int] = {"unchanged": 0, "coalesced": 0, "failclosed": 0}
        self.differs: dict[str, int] = {"unchanged": 0, "coalesced": 0, "failclosed": 0}
        self.malformed_differs = 0
        self.samples: list[str] = []


def sweep(inputs: list[str], new: Redactor) -> SweepResult:
    """Compare *new* against the legacy implementation, bucketed by span geometry."""
    r = SweepResult()
    for text in inputs:
        positions = _positions(len(text))
        for findings in _wellformed_cases(len(text), positions):
            bucket = _classify(text, findings)
            r.seen[bucket] += 1
            if _legacy_redact(text, findings) != new(text, findings):
                r.differs[bucket] += 1
                if bucket == "unchanged" and len(r.samples) < 5:
                    r.samples.append(f"unchanged-bucket span differs: {findings}")
        for findings in _malformed_cases(len(text), positions):
            if _legacy_redact(text, findings) != new(text, findings):
                r.malformed_differs += 1
    return r


def main() -> int:
    here = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument(
        "--vectors",
        type=Path,
        default=here.parent / "vectors" / "credential_detection",
        help="credential_detection vector directory (read-only)",
    )
    p.add_argument(
        "--self-check",
        action="store_true",
        help="prove the sweep detects a one-character sabotage of _redact",
    )
    args = p.parse_args()

    inputs, skipped = _load_ascii_vectors(args.vectors)
    if not inputs:
        print(f"ERROR: no ASCII vectors found in {args.vectors}")
        return 2

    if args.self_check:
        r = sweep(inputs, _mutated_redact)
        mismatched = r.differs["unchanged"]
        print(f"self-check: sabotaged implementation produced {mismatched} mismatches")
        print("            (counted in the unchanged bucket, where the two must agree)")
        if mismatched == 0:
            print("ERROR: the sweep did not notice a broken implementation.")
            return 1
        print("OK: the sweep discriminates.")
        return 0

    r = sweep(inputs, _redact)
    print(f"ASCII vectors swept        : {len(inputs)}")
    print(f"non-ASCII vectors skipped  : {skipped}")
    print(f"well-formed span cases     : {sum(r.seen.values())}")
    print(f"  unchanged bucket         : {r.seen['unchanged']} cases, "
          f"{r.differs['unchanged']} differ from legacy (must be 0)")
    print(f"  sort/merge bucket        : {r.seen['coalesced']} cases, "
          f"{r.differs['coalesced']} differ from legacy")
    print(f"  fail-closed bucket       : {r.seen['failclosed']} cases, "
          f"{r.differs['failclosed']} differ from legacy")
    print(f"malformed (offset < 0) now rejected instead of mangled: {r.malformed_differs}")
    for s in r.samples:
        print(f"  {s}")
    if r.differs["unchanged"]:
        print("FAIL: behaviour changed for a span set that neither coalescing nor")
        print("      fail-closed should touch.")
        return 1
    print("OK: identical for every span set neither behaviour touches.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
