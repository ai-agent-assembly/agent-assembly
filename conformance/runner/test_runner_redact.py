#!/usr/bin/env python3
"""
Regression tests for the conformance runner's redaction reconstruction.

Why this file exists
--------------------
`runner._redact` reassembles the redacted string from the spans an SDK reports,
and the vector schema defines those spans in **bytes** (that is what the Rust
reference scanner emits). Python `str` indices are code points, so on any input
containing a multi-byte character the two units diverge and the splice lands in
the wrong place — silently, because `_redact` has no way to tell a wrong-but-
in-range index from a right one.

Every vector in the suite was ASCII when the runner was written, where the two
units coincide, so nothing caught it. These fixtures are deliberately multi-byte
so the units cannot coincide: they fail against a code-point-slicing `_redact`
and pass against a byte-slicing one.

The fixtures are synthetic and defined here rather than loaded from
`conformance/vectors/` on purpose — the runner must be provable independently of
which vectors happen to be committed, and no fixture here contains real
credential material or real personal data.

Run
---
    python conformance/runner/test_runner_redact.py     # stdlib unittest
    pytest conformance/runner/test_runner_redact.py     # or under pytest
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner import _redact  # noqa: E402


def _span(kind: str, text: str, secret: str) -> dict:
    """Build the finding an SDK reporting byte offsets would return for *secret*."""
    offset = text.encode("utf-8").index(secret.encode("utf-8"))
    return {"kind": kind, "offset": offset, "end": offset + len(secret.encode("utf-8"))}


class RedactByteOffsetTests(unittest.TestCase):
    """`_redact` must interpret `offset`/`end` as byte positions, not code points."""

    def test_multibyte_prefix_shifts_the_span(self) -> None:
        # The label before the value is CJK, so the value's byte offset (13) and
        # its code-point offset (9) differ. A code-point splice cuts four bytes
        # early and leaves a fragment of the flagged value in the output.
        secret = "sk-DUMMY-NOT-A-REAL-KEY"
        text = f"メモ token={secret}"
        findings = [_span("SyntheticKey", text, secret)]

        self.assertEqual(_redact(text, findings), "メモ token=[REDACTED:SyntheticKey]")

    def test_multibyte_value_body(self) -> None:
        # The flagged value is itself multi-byte (full-width digits, 3 bytes
        # each), so `end` overshoots the code-point length by a factor of three.
        secret = "１２３４５６７８"
        text = f"番号={secret}"
        findings = [_span("SyntheticNumber", text, secret)]

        self.assertEqual(_redact(text, findings), "番号=[REDACTED:SyntheticNumber]")

    def test_multiple_spans_with_multibyte_separator(self) -> None:
        # Two spans separated by multi-byte text. `_redact` splices in reverse
        # offset order, so this also proves the earlier span's byte offsets stay
        # valid after the later splice changed the buffer's length.
        first = "DUMMY-VALUE-ONE"
        second = "DUMMY-VALUE-TWO"
        text = f"一={first}、二={second}"
        findings = [
            _span("SyntheticKey", text, first),
            _span("SyntheticToken", text, second),
        ]

        self.assertEqual(
            _redact(text, findings),
            "一=[REDACTED:SyntheticKey]、二=[REDACTED:SyntheticToken]",
        )

    def test_span_inside_a_character_is_skipped_pending_fail_closed(self) -> None:
        # A span that starts mid-character cannot be spliced without producing
        # invalid UTF-8, so the runner drops it — never mojibake, never a raise.
        #
        # This pins CURRENT HARNESS BEHAVIOUR, NOT DESIRED BEHAVIOUR. The Rust
        # reference rejects the same span and then fails *closed*: it returns
        # "[REDACTED]" for the entire text rather than hand back text it cannot
        # prove is clean (aa-security/src/scanner.rs:454-458 — "never return the
        # raw text with a secret intact"). The runner fails open here.
        #
        # Closing that gap is AAASM-5373. Whoever does it must change this
        # assertion — it is a marker for the divergence, not an endorsement of it.
        text = "番号=1234"
        findings = [{"kind": "SyntheticNumber", "offset": 1, "end": 6}]

        self.assertEqual(_redact(text, findings), text)

    def test_out_of_range_span_is_skipped_pending_fail_closed(self) -> None:
        # Same divergence as above for an out-of-range span: the runner skips it,
        # Rust returns "[REDACTED]" for the whole text
        # (aa-security/src/scanner.rs:447-458). Pins current behaviour; see
        # AAASM-5373.
        text = "番号=1234"
        findings = [{"kind": "SyntheticNumber", "offset": 3, "end": 999}]

        self.assertEqual(_redact(text, findings), text)


class RedactAsciiUnchangedTests(unittest.TestCase):
    """ASCII behaviour is the contract the 26 committed vectors rely on.

    These pass both before and after the byte-offset fix by design — they are a
    guard against regressing ASCII, not evidence that the fix works.
    """

    def test_single_ascii_span(self) -> None:
        secret = "DUMMY-NOT-A-REAL-KEY"
        text = f"key={secret}"
        findings = [_span("SyntheticKey", text, secret)]

        self.assertEqual(_redact(text, findings), "key=[REDACTED:SyntheticKey]")

    def test_no_findings_returns_input_unchanged(self) -> None:
        text = "nothing sensitive here"

        self.assertEqual(_redact(text, []), text)

    def test_finding_without_end_is_skipped(self) -> None:
        # The schema's `expected_findings` entries carry no `end`; only the SDK's
        # reply does. A finding without one is not redactable and must be left be.
        text = "key=DUMMY-NOT-A-REAL-KEY"
        findings = [{"kind": "SyntheticKey", "offset": 4}]

        self.assertEqual(_redact(text, findings), text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
