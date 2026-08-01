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

AAASM-5373 added the other two halves of the same contract: `_redact` coalesces
overlapping findings before splicing, and fails closed on a span it cannot
splice, so it now mirrors `ScanResult::redact` rather than approximating it.

Most fixtures here are synthetic and defined inline rather than loaded from
`conformance/vectors/` on purpose — the runner must be provable independently of
which vectors happen to be committed, and no fixture here contains real
credential material or real personal data. `MultiFindingVectorTests` is the one
exception: it reads four committed vectors (read-only) because the property
under test *is* that those specific goldens are reproducible.

Run
---
    python conformance/runner/test_runner_redact.py     # stdlib unittest
    pytest conformance/runner/test_runner_redact.py     # or under pytest
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner import _coalesce_findings, _findings_match, _redact  # noqa: E402


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

    def test_span_inside_a_character_fails_closed(self) -> None:
        # A span that starts mid-character cannot be spliced without producing
        # invalid UTF-8. Skipping it would return the flagged region in the
        # clear, so the whole value collapses to "[REDACTED]" — what
        # ScanResult::redact does (aa-security/src/scanner.rs:454-458, "never
        # return the raw text with a secret intact") and what ADR 0015 requires.
        #
        # The assertion that matters is `!= text`: a fail-open implementation
        # returns the input unchanged, so this cannot pass while the runner
        # leaks the region it was told about.
        text = "番号=1234"
        findings = [{"kind": "SyntheticNumber", "offset": 1, "end": 6}]

        self.assertEqual(_redact(text, findings), "[REDACTED]")
        self.assertNotEqual(_redact(text, findings), text)

    def test_out_of_range_span_fails_closed(self) -> None:
        # Same contract for a span running past the end of the buffer.
        text = "番号=1234"
        findings = [{"kind": "SyntheticNumber", "offset": 3, "end": 999}]

        self.assertEqual(_redact(text, findings), "[REDACTED]")

    def test_inverted_span_fails_closed(self) -> None:
        # offset > end is not a span the scanner can produce, but it is one a
        # buggy SDK can report. Rust's `span.offset <= span.end` guard rejects
        # it and falls into the same fail-closed branch.
        text = "key=DUMMY-NOT-A-REAL-KEY"
        findings = [{"kind": "SyntheticKey", "offset": 20, "end": 4}]

        self.assertEqual(_redact(text, findings), "[REDACTED]")

    def test_negative_offset_fails_closed(self) -> None:
        # Unreachable from Rust (offsets are `usize`) and therefore not a branch
        # ScanResult::redact has, but reachable from Python, where a negative
        # index silently means "from the end" and would splice into the middle
        # of the text. Treated as unspliceable rather than wrapped.
        text = "key=DUMMY-NOT-A-REAL-KEY"
        findings = [{"kind": "SyntheticKey", "offset": -4, "end": 10}]

        self.assertEqual(_redact(text, findings), "[REDACTED]")

    def test_one_bad_span_condemns_the_whole_text(self) -> None:
        # Fail-closed is all-or-nothing: a second, perfectly spliceable span
        # does not earn a partial result. Rust returns "[REDACTED]" from inside
        # the splice loop regardless of how many spans already succeeded.
        #
        # Without this, an implementation that failed closed only when *every*
        # span was bad would still pass the tests above.
        secret = "DUMMY-NOT-A-REAL-KEY"
        text = f"key={secret} tail"
        findings = [
            _span("SyntheticKey", text, secret),
            {"kind": "SyntheticOther", "offset": 25, "end": 9999},
        ]

        self.assertEqual(_redact(text, findings), "[REDACTED]")


class CoalesceSemanticsTests(unittest.TestCase):
    """`_coalesce_findings` must merge exactly where `coalesce_findings` does.

    The merge rule is `f.offset < last.end` — **strict**. Overlapping spans
    merge; a span that begins exactly where the previous one ends does not.
    Rust's inline comment calls that case "touching" and reads as if it merges,
    but the code compares with `<` (aa-security/src/scanner.rs:679), so it does
    not. The tests below pin both sides of that boundary, because a merge
    written `<=` is the natural misreading and passes every other test here.
    """

    def test_overlapping_spans_merge_to_their_union(self) -> None:
        findings = [
            {"kind": "SyntheticA", "offset": 0, "end": 10},
            {"kind": "SyntheticA", "offset": 4, "end": 20},
        ]

        self.assertEqual(_coalesce_findings(findings), [(0, 20, "SyntheticA")])

    def test_adjacent_spans_do_not_merge(self) -> None:
        # offset == previous end. Rust keeps these separate and emits two
        # labels; `<=` would emit one. Nothing else in this file distinguishes
        # the two, so this is the only guard on it.
        findings = [
            {"kind": "SyntheticA", "offset": 0, "end": 4},
            {"kind": "SyntheticB", "offset": 4, "end": 8},
        ]

        self.assertEqual(
            _coalesce_findings(findings),
            [(0, 4, "SyntheticA"), (4, 8, "SyntheticB")],
        )

    def test_adjacent_spans_produce_two_labels(self) -> None:
        # The same boundary observed through `_redact`'s output rather than its
        # intermediate spans.
        text = "AAAABBBB"
        findings = [
            {"kind": "SyntheticA", "offset": 0, "end": 4},
            {"kind": "SyntheticB", "offset": 4, "end": 8},
        ]

        self.assertEqual(
            _redact(text, findings), "[REDACTED:SyntheticA][REDACTED:SyntheticB]"
        )

    def test_disjoint_spans_stay_separate(self) -> None:
        findings = [
            {"kind": "SyntheticA", "offset": 0, "end": 3},
            {"kind": "SyntheticB", "offset": 5, "end": 8},
        ]

        self.assertEqual(
            _coalesce_findings(findings),
            [(0, 3, "SyntheticA"), (5, 8, "SyntheticB")],
        )

    def test_specific_kind_claims_the_span_from_a_generic_backstop(self) -> None:
        # The generic backstop starts first, so a "first one wins" merge would
        # label the span GenericHighEntropy. Rust picks by priority, not by
        # offset (aa-security/src/scanner.rs:681-684).
        findings = [
            {"kind": "GenericHighEntropy", "offset": 0, "end": 20},
            {"kind": "PostgresUrl", "offset": 5, "end": 20},
        ]

        self.assertEqual(_coalesce_findings(findings), [(0, 20, "PostgresUrl")])

    def test_email_backstop_outranks_high_entropy_but_loses_to_specific(self) -> None:
        # priority(): GenericHighEntropy 0 < EmailAddress 1 < everything else 2.
        self.assertEqual(
            _coalesce_findings(
                [
                    {"kind": "GenericHighEntropy", "offset": 0, "end": 10},
                    {"kind": "EmailAddress", "offset": 0, "end": 10},
                ]
            ),
            [(0, 10, "EmailAddress")],
        )
        self.assertEqual(
            _coalesce_findings(
                [
                    {"kind": "EmailAddress", "offset": 0, "end": 10},
                    {"kind": "MysqlUrl", "offset": 0, "end": 10},
                ]
            ),
            [(0, 10, "MysqlUrl")],
        )

    def test_equal_priority_keeps_the_first_label(self) -> None:
        # Rust replaces the label only on `>`, never on `==`, so the earlier
        # finding in `(offset, end)` order keeps it.
        findings = [
            {"kind": "SyntheticA", "offset": 0, "end": 10},
            {"kind": "SyntheticB", "offset": 2, "end": 10},
        ]

        self.assertEqual(_coalesce_findings(findings), [(0, 10, "SyntheticA")])

    def test_unordered_input_is_sorted_before_merging(self) -> None:
        # The SDK is not required to return findings in offset order.
        findings = [
            {"kind": "SyntheticB", "offset": 5, "end": 20},
            {"kind": "SyntheticA", "offset": 0, "end": 10},
        ]

        self.assertEqual(_coalesce_findings(findings), [(0, 20, "SyntheticA")])


# Byte spans the reference scanner reports for the four vectors below.
#
# Provenance: obtained from `aa_security::CredentialScanner::scan` over each
# vector's `input_text`, reading each finding's extent back through
# `ScanResult::redact` (the `end` field is private). The pair for
# private_keys_ec_short_trailing_line — [4,133) and [35,99) — is the same pair
# quoted in AAASM-5373's review comment, independently.
#
# Only `end` is supplied here. `kind` and `offset` are asserted against the
# vector's own `expected_findings` by the test below, so this table cannot
# drift on any field the vectors already pin — see AC 7 in AAASM-5373 on why
# `end` has no golden value to check against.
_REFERENCE_ENDS: dict[str, list[int]] = {
    "db_urls_postgres": [59, 59, 59],
    "db_urls_mysql": [42, 42],
    "db_urls_mongodb": [56, 56, 56],
    "private_keys_ec_short_trailing_line": [133, 99],
}

# The merged span each vector's findings must coalesce into: (offset, end, kind).
_EXPECTED_MERGED: dict[str, list[tuple[int, int, str]]] = {
    "db_urls_postgres": [(0, 59, "PostgresUrl")],
    "db_urls_mysql": [(0, 42, "MysqlUrl")],
    "db_urls_mongodb": [(0, 56, "MongodbUrl")],
    "private_keys_ec_short_trailing_line": [(4, 133, "EcPrivateKey")],
}

_VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors" / "credential_detection"


class MultiFindingVectorTests(unittest.TestCase):
    """The four vectors that declare several findings but one redaction label.

    Each of these can only be reproduced by coalescing: the scanner reports
    two or three overlapping spans and the golden `expected_redacted` carries a
    single label. Before AAASM-5373 the runner spliced per finding and could
    not produce them.

    These are the only tests here that read `conformance/vectors/` — read-only,
    and asserting against the committed goldens rather than restating them, so
    the vectors stay the single source of truth (ADR 0015: never edit a golden
    vector to make an implementation pass).
    """

    def _vector(self, name: str) -> dict:
        with (_VECTORS_DIR / f"{name}.json").open(encoding="utf-8") as fh:
            return json.load(fh)

    def _reference_findings(self, name: str, vector: dict) -> list[dict]:
        """Pair the vector's own `expected_findings` with the reference ends."""
        expected = vector["expected_findings"]
        ends = _REFERENCE_ENDS[name]
        self.assertEqual(
            len(expected),
            len(ends),
            f"{name}: reference end table is out of step with the vector",
        )
        return [
            {"kind": e["kind"], "offset": e["offset"], "end": end}
            for e, end in zip(expected, ends)
        ]

    def test_reference_spans_coalesce_to_a_single_labelled_span(self) -> None:
        # Asserted on the spans, not only on the output. For three of the four
        # vectors a per-finding splice visibly produces the wrong string, but
        # for private_keys_ec_short_trailing_line it accidentally produces the
        # right one: splicing [35,99) first shortens the buffer to 98 bytes, so
        # the later `result[133:]` is an out-of-range slice that silently
        # evaluates to b"" and truncates the tail away. That is the mechanism
        # behind the spurious solutions recorded in AAASM-5373's comment.
        #
        # An output-only assertion on that vector is therefore vacuous with
        # respect to coalescing — it passes with coalescing removed. Asserting
        # the merged spans is what makes all four discriminate.
        for name, merged in _EXPECTED_MERGED.items():
            with self.subTest(vector=name):
                vector = self._vector(name)
                findings = self._reference_findings(name, vector)

                self.assertEqual(_coalesce_findings(findings), merged)

    def test_reference_spans_reproduce_the_golden_redaction(self) -> None:
        for name in _EXPECTED_MERGED:
            with self.subTest(vector=name):
                vector = self._vector(name)
                findings = self._reference_findings(name, vector)

                self.assertEqual(
                    _redact(vector["input_text"], findings),
                    vector["expected_redacted"],
                )

    def test_each_vector_really_declares_more_findings_than_labels(self) -> None:
        # Guards the premise. If a vector were ever reduced to a single finding,
        # the two tests above would still pass but would no longer be testing
        # coalescing at all.
        for name in _EXPECTED_MERGED:
            with self.subTest(vector=name):
                vector = self._vector(name)

                self.assertGreater(len(vector["expected_findings"]), 1)
                self.assertEqual(vector["expected_redacted"].count("[REDACTED:"), 1)


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

    def test_finding_without_end_fails_closed(self) -> None:
        # The schema's `expected_findings` entries carry no `end`; only the SDK's
        # reply does. A reply that omits it names a flagged region of unknown
        # extent — the runner cannot prove that region was removed, so it fails
        # closed rather than returning the text untouched.
        #
        # This is a runner-only branch: a Rust `CredentialFinding` always has an
        # `end`, so ScanResult::redact never faces the case. It is resolved the
        # same way for the same reason (ADR 0015).
        text = "key=DUMMY-NOT-A-REAL-KEY"
        findings = [{"kind": "SyntheticKey", "offset": 4}]

        self.assertEqual(_redact(text, findings), "[REDACTED]")


class FindingsMatchGradingTests(unittest.TestCase):
    """What `_findings_match` grades, pinned so the omission stays deliberate.

    AAASM-5373 AC 7 asked for an explicit decision on `end`. The decision is:
    leave it ungraded here, because grading it needs an `end` on every
    `expected_findings` entry and that is a vector schema change (ADR 0015).
    These tests make the decision executable rather than a comment, so a future
    change to it has to be a change to this file.
    """

    def test_end_is_not_graded(self) -> None:
        # A wildly wrong `end` is still a match at this stage. It is caught
        # afterwards, by the redaction comparison in run().
        ok, reason = _findings_match(
            [{"kind": "SyntheticKey", "offset": 4, "end": 999}],
            [{"kind": "SyntheticKey", "offset": 4}],
        )

        self.assertTrue(ok, reason)

    def test_kind_and_offset_are_graded(self) -> None:
        # Guards the test above from being vacuous: if _findings_match graded
        # nothing at all, "end is not graded" would pass for the wrong reason.
        expected = [{"kind": "SyntheticKey", "offset": 4}]

        self.assertFalse(_findings_match([{"kind": "Other", "offset": 4}], expected)[0])
        self.assertFalse(
            _findings_match([{"kind": "SyntheticKey", "offset": 9}], expected)[0]
        )

    def test_a_wrong_end_fails_the_vector_on_an_unsubsumed_finding(self) -> None:
        # Named for what it actually tests: a *single* finding, whose span
        # nothing else overlaps. There the redaction does catch a wrong `end`.
        # The general claim — that a wrong `end` is always caught — is false;
        # see the counterexample below.
        secret = "DUMMY-NOT-A-REAL-KEY"
        text = f"key={secret}"
        expected_redacted = "key=[REDACTED:SyntheticKey]"
        wrong = [{"kind": "SyntheticKey", "offset": 4, "end": 999}]

        self.assertTrue(_findings_match(wrong, [{"kind": "SyntheticKey", "offset": 4}])[0])
        self.assertNotEqual(_redact(text, wrong), expected_redacted)
        self.assertNotEqual(_redact(text, wrong), text)

    def test_a_subsumed_wrong_end_is_not_detected(self) -> None:
        # The residual, made executable. `_redact` validates the *coalesced*
        # spans, so a finding whose span is swallowed by an overlapping sibling
        # has its `end` absorbed into `max(last_end, end)` and never checked.
        #
        # Here the real vector is used: db_urls_postgres reports PostgresUrl at
        # offset 13 with end 59, and EmailAddress/GenericHighEntropy both span
        # [0,59). Report the credential as a one-byte span, or as the inverted
        # span [13,0), and the vector still passes completely.
        #
        # This is faithful to Rust, which also validates after coalescing — it
        # is a limit on what the corpus can grade, not a conformance defect.
        # If a future change makes these detectable, this test should fail and
        # the residual note in runner._findings_match should be revised.
        with (_VECTORS_DIR / "db_urls_postgres.json").open(encoding="utf-8") as fh:
            vector = json.load(fh)

        for bad_end, shape in [(14, "one-byte span"), (0, "inverted span")]:
            with self.subTest(shape=shape):
                findings = [
                    {"kind": "EmailAddress", "offset": 0, "end": 59},
                    {"kind": "GenericHighEntropy", "offset": 0, "end": 59},
                    {"kind": "PostgresUrl", "offset": 13, "end": bad_end},
                ]

                self.assertTrue(
                    _findings_match(findings, vector["expected_findings"])[0]
                )
                self.assertEqual(
                    _redact(vector["input_text"], findings),
                    vector["expected_redacted"],
                    f"{shape} was detected — the residual has changed",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
