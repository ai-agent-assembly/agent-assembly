#!/usr/bin/env python3
"""Fail if an ADR or governance page asserts that a banned absolute is waiver-eligible.

AAASM-5671. ADR 0034 Decision 10 places factual truthfulness and ADR 0033's
forbidden design 7 (unqualified absolutes) *outside* the waiver mechanism. Before
that amendment the same ADR said the opposite in six places, and two sibling pages
copied one reading each — the contradiction survived review because no check could
see it. This is that check.

WHY THIS SHAPE
--------------
The test is deliberately fail-closed and phrased over the *governing vocabulary*
rather than over a blocklist of bad sentences: a segment that names a banned
absolute **and** names the waiver mechanism must also say, in the same segment,
that it is unwaivable. A new sentence pairing the two without that word fails,
whatever wording it invents. Stating "banned absolutes are waivable" and forgetting
to state that they are not are the same failure here, which is the point.

The five non-claim classes ADR 0034 Decision 10 enumerates (attributed quotation,
legal literal, external term, negative example, historical withdrawn claim) plus
test fixtures may carry the literal text. They are marked in-line:

    <!-- truth-exempt: historical-withdrawn - why this text is retained -->
    ... the exempted text ...
    <!-- /truth-exempt -->

The marker is validated too — an unknown class, a missing reason, an unclosed block
or a heading inside a block is an error, because each of those would turn the
exemption into a general bypass.

Usage:
    python3 scripts/check_absolutes_unwaivable.py            # scan the default set
    python3 scripts/check_absolutes_unwaivable.py PATH...    # scan specific files
    python3 scripts/check_absolutes_unwaivable.py --selftest # prove the detector fails

Exit codes: 0 clean, 1 violation found, 2 usage/IO error.
"""

from __future__ import annotations

import glob
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Governance surfaces. A page that can carry the rule is a page that can contradict
# it, so the ADR set and the contributor-facing development pages are both scanned.
DEFAULT_GLOBS: tuple[str, ...] = (
    "docs/src/adr/*.md",
    "docs/src/development/*.md",
    "TRUTH-ADOPTION.md",
    "docs/TRUTH-ADOPTION.md",
)

# Naming a banned absolute. Lower-cased substring match after markup stripping.
# "banned absolute" also matches "banned absolutes"; "banned-absolute" also matches
# "banned-absolutes list".
ABSOLUTE_ANCHORS: tuple[str, ...] = (
    "banned absolute",
    "banned-absolute",
    "absolutes ban",
    "ban on absolutes",
    "unqualified absolute",
    "forbidden design 7",
    "forbidden-designs list, item 7",
    "absolute product claim",
    "absolute claim",
)

# Naming the waiver mechanism. One stem covers waiver / waive / waived / waivable /
# waiving / waiver-approver / waiver-eligible — and, deliberately, "unwaivable",
# which the negation list below then clears.
WAIVER_STEM = "waiv"

# Tier 2. Three of the six sentences this amendment struck put the absolute in one
# sentence (or one table cell) and the waiver in the next, so a same-segment test
# cannot see them: "…the banned-absolutes list … | … this ADR adds the waiver
# mechanism, not the check". Tier 2 reads *forward* from each mention of a banned
# absolute to the end of its block and asks which comes first — a phrase that grants
# a waiver, or a phrase that denies one. Direction is what keeps it honest: prose
# states the ban and then qualifies it, so a grant reached before any denial is the
# qualification, while "a waiver may waive process … ADR 0033's banned absolutes are
# unwaivable" grants before the anchor and is not a qualification of it at all.
GRANTING_PHRASES: tuple[str, ...] = (
    "may waive",
    "who may waive",
    "may be waived",
    "can be waived",
    "is waived",
    "are waived",
    "waivable",
    "waiver mechanism",
    "waiver over",
    "waiver route",
    "under a waiver",
    "under an expiring waiver",
    "permission to publish",
    "waiver-eligible",
)

# Saying it is unwaivable. A segment that pairs an anchor with the waiver stem must
# contain one of these, or it reads as an assertion of waiver-eligibility.
UNWAIVABLE_MARKERS: tuple[str, ...] = (
    "unwaivable",
    "not waivable",
    "never waivable",
    "not waiver-eligible",
    "may not be waived",
    "cannot be waived",
    "must not be waived",
    "never be waived",
    "never waived",
    "not be waived",
    "may not waive",
    "never waive",
    "no waiver",
    "outside the waiver",
    "not subject to waiver",
    "no route through the waiver",
)

# ADR 0034 Decision 10's non-claim classes, plus test fixtures.
EXEMPT_CLASSES: frozenset[str] = frozenset(
    {
        "attributed-quotation",
        "legal-literal",
        "external-term",
        "negative-example",
        "historical-withdrawn",
        "test-fixture",
    }
)

OPEN_MARKER = re.compile(r"<!--\s*truth-exempt:\s*(?P<class>[a-z-]+)\s*(?P<sep>[-—:]+)?\s*(?P<reason>.*?)\s*-->")
CLOSE_MARKER = re.compile(r"<!--\s*/truth-exempt\s*-->")
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^#{1,6}\s")

# Markdown emphasis and code spans are stripped before matching so that
# "no `waiver-approver`" reads as "no waiver-approver" to the negation list.
MARKUP = re.compile(r"[`*_]")

# Segment boundaries: sentence enders followed by space, and table-cell pipes. The
# trailing-whitespace requirement is load-bearing — without it "§2.1" and "0033:607"
# split mid-reference and separate a denial from the absolute it denies.
BOUNDARY = re.compile(r"(?<=[.;?!])\s+|\|")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    message: str
    excerpt: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}\n    {self.excerpt}"


def _strip_markup(text: str) -> str:
    return MARKUP.sub("", text)


def _excerpt(text: str, limit: int = 160) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def scan_text(path: str, text: str) -> list[Finding]:
    """Return every finding in one document. Pure, so --selftest can call it."""
    findings: list[Finding] = []
    in_fence = False
    exempt_open_line = 0
    exempt_class = ""

    # (line_number, line_text) pairs of the block being accumulated.
    block: list[tuple[int, str]] = []

    def flush() -> None:
        nonlocal block
        if block:
            findings.extend(_scan_block(path, block))
            block = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if FENCE.match(raw):
            flush()
            in_fence = not in_fence
            continue
        if in_fence:
            continue

        close = CLOSE_MARKER.search(raw)
        if close:
            flush()
            if not exempt_open_line:
                findings.append(
                    Finding(path, lineno, "truth-exempt close marker with no open marker", _excerpt(raw))
                )
            exempt_open_line = 0
            exempt_class = ""
            continue

        opener = OPEN_MARKER.search(raw)
        if opener:
            flush()
            if exempt_open_line:
                findings.append(
                    Finding(
                        path,
                        lineno,
                        f"truth-exempt block opened at line {exempt_open_line} is not closed before this one",
                        _excerpt(raw),
                    )
                )
            exempt_open_line = lineno
            exempt_class = opener.group("class")
            reason = opener.group("reason") or ""
            if exempt_class not in EXEMPT_CLASSES:
                findings.append(
                    Finding(
                        path,
                        lineno,
                        f"unknown truth-exempt class {exempt_class!r}; ADR 0034 Decision 10 defines "
                        + ", ".join(sorted(EXEMPT_CLASSES)),
                        _excerpt(raw),
                    )
                )
            if len(reason.strip()) < 8:
                findings.append(
                    Finding(path, lineno, "truth-exempt marker carries no reason", _excerpt(raw))
                )
            continue

        if exempt_open_line:
            # Inside an exemption: the literal text is permitted, but it may not be
            # promoted into a heading, where the label does not travel with it.
            if HEADING.match(raw):
                findings.append(
                    Finding(
                        path,
                        lineno,
                        f"heading inside the truth-exempt ({exempt_class}) block opened at line {exempt_open_line}; "
                        "Decision 10 forbids an exempted absolute in a heading",
                        _excerpt(raw),
                    )
                )
            continue

        if not raw.strip() or HEADING.match(raw):
            flush()
            continue

        block.append((lineno, raw))

    flush()

    if exempt_open_line:
        findings.append(
            Finding(path, exempt_open_line, "truth-exempt block is never closed", "<!-- /truth-exempt --> missing")
        )
    if in_fence:
        findings.append(Finding(path, 1, "unbalanced code fence; the scan skipped to end of file", ""))

    return findings


def _scan_block(path: str, block: list[tuple[int, str]]) -> list[Finding]:
    """Unwrap a hard-wrapped block, then test each segment of it.

    Line-wrapping is why this cannot be a grep: several of the sentences this check
    governs span two or three source lines.
    """
    joined = ""
    line_of: list[int] = []
    for lineno, raw in block:
        if joined:
            joined += " "
            line_of.append(lineno)
        joined += raw
        line_of.extend([lineno] * len(raw))

    normalised = _strip_markup(joined)
    # _strip_markup only deletes characters, so rebuild the offset map alongside it.
    kept_lines = [line_of[i] for i, ch in enumerate(joined) if not MARKUP.match(ch)]

    lowered_block = normalised.lower()

    def line_at(offset: int) -> int:
        return kept_lines[offset] if offset < len(kept_lines) else block[0][0]

    # Reported at most once per offset, since tier 1 and tier 2 overlap by design.
    findings: dict[int, Finding] = {}

    # Tier 1 — an absolute and the waiver mechanism inside one sentence or cell,
    # in either order, with nothing saying it is unwaivable.
    for start, segment in _segments(normalised):
        seg = segment.lower()
        if WAIVER_STEM not in seg:
            continue
        if not any(anchor in seg for anchor in ABSOLUTE_ANCHORS):
            continue
        if any(marker in seg for marker in UNWAIVABLE_MARKERS):
            continue
        findings[start] = Finding(
            path,
            line_at(start),
            "a banned absolute and the waiver mechanism appear in one sentence without stating that "
            "it is unwaivable (ADR 0034 Decision 10, AAASM-5671)",
            _excerpt(segment),
        )

    # Tier 2 — reading forward from an absolute, a grant is reached before a denial.
    grants = sorted(_occurrences(lowered_block, GRANTING_PHRASES))
    denials = sorted(_occurrences(lowered_block, UNWAIVABLE_MARKERS))
    for anchor_at, _ in sorted(_occurrences(lowered_block, ABSOLUTE_ANCHORS)):
        grant = next((g for g in grants if g[0] > anchor_at), None)
        if grant is None:
            continue
        denial = next((d for d in denials if d[0] > anchor_at), None)
        if denial is not None and denial[0] < grant[0]:
            continue
        offset, phrase = grant
        if offset in findings:
            continue
        findings[offset] = Finding(
            path,
            line_at(offset),
            f"reading forward from a banned absolute, {phrase!r} grants a waiver before anything "
            "denies one (ADR 0034 Decision 10, AAASM-5671)",
            _excerpt(normalised[max(0, offset - 90) : offset + 90]),
        )

    return [findings[k] for k in sorted(findings)]


def _segments(text: str) -> list[tuple[int, str]]:
    """Split a block into sentences and table cells, keeping each one's offset."""
    out: list[tuple[int, str]] = []
    pos = 0
    for match in BOUNDARY.finditer(text):
        if match.start() > pos:
            out.append((pos, text[pos : match.start()]))
        pos = match.end()
    if pos < len(text):
        out.append((pos, text[pos:]))
    return out


def _occurrences(lowered: str, needles: tuple[str, ...]) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for needle in needles:
        start = lowered.find(needle)
        while start != -1:
            found.append((start, needle))
            start = lowered.find(needle, start + 1)
    return found


# --- self-test -------------------------------------------------------------
# A gate never seen red is not known to work. These fixtures are the detector's
# own regression suite and run before the real scan in CI.
_MUST_FAIL = [
    (
        "waivable-form opening",
        "A waiver is a recorded, approved, expiring permission to publish against a\n"
        "rule in this ADR or against ADR 0033's banned-absolutes list.\n",
    ),
    (
        "enumerated rule value",
        "| `rule` | The rule waived - a D-dimension, a forbidden design, a banned absolute |\n",
    ),
    (
        "wrapped sentence",
        "The banned absolutes of forbidden design 7 may be waived for ninety days\n"
        "under an approved and expiring waiver.\n",
    ),
    (
        "tier 2 across table cells",
        "| W8 | ADR 0033's banned-absolutes list is checked in CI | this ADR adds the waiver mechanism, not the check |\n",
    ),
    (
        "tier 2 across sentences",
        "ADR 0033's forbidden-designs list, item 7, bans a set of unqualified absolutes.\n"
        "That list feeds the planned CI gate. **Who may waive it** is ADR 0034 Decision 10 —\n"
        "an expiring, string-scoped waiver approved by a `waiver-approver`.\n",
    ),
    ("unknown exemption class", "<!-- truth-exempt: marketing - because we want to -->\nanything\n<!-- /truth-exempt -->\n"),
    ("unclosed exemption", "<!-- truth-exempt: negative-example - a demonstration of banned wording -->\nanything\n"),
    (
        "heading promoted out of an exemption",
        "<!-- truth-exempt: negative-example - a demonstration of banned wording -->\n"
        "## A banned absolute under waiver\n"
        "<!-- /truth-exempt -->\n",
    ),
]

_MUST_PASS = [
    ("flat form", "An ADR 0033 banned absolute is unwaivable; a waiver never reaches it.\n"),
    ("negated form", "A banned absolute may not be waived by any waiver-approver.\n"),
    (
        "ownership table row",
        "| Owns | the banned-absolutes list (forbidden design 7) | adoption records, waivers, supersession |\n",
    ),
    ("waivers without absolutes", "A waiver is recorded, approved and expiring, and fails closed.\n"),
    ("absolutes without waivers", "ADR 0033 forbidden design 7 bans a set of unqualified absolutes.\n"),
    (
        "grant stated before the absolute is named and then denied",
        "A waiver may waive process, timing or review sequencing, and it may never waive\n"
        "whether a statement is true. ADR 0033's banned absolutes are therefore unwaivable.\n",
    ),
    (
        "section reference is not a sentence boundary",
        "| `rule` | The waivable rule — a D-dimension of §2.1's tuple; never forbidden design 7's\n"
        "banned absolutes, which are unwaivable and are not legal values here |\n",
    ),
    (
        "denial reached before the grant",
        "An ADR 0033 banned absolute may not be waived; there is no waiver mechanism over it.\n",
    ),
    (
        "properly exempted historical text",
        "<!-- truth-exempt: historical-withdrawn - removed from Decision 10 by AAASM-5671 -->\n"
        "> A waiver is a permission to publish against ADR 0033's banned-absolutes list.\n"
        "<!-- /truth-exempt -->\n",
    ),
    (
        "code fence is not prose",
        "```text\nA waiver may cover a banned absolute.\n```\n",
    ),
]


def selftest() -> int:
    failures = 0
    for name, body in _MUST_FAIL:
        if not scan_text(f"<selftest:{name}>", body):
            print(f"SELFTEST FAIL: {name!r} should have been flagged and was not", file=sys.stderr)
            failures += 1
    for name, body in _MUST_PASS:
        found = scan_text(f"<selftest:{name}>", body)
        if found:
            print(f"SELFTEST FAIL: {name!r} should be clean; got:", file=sys.stderr)
            for f in found:
                print("  " + f.render(), file=sys.stderr)
            failures += 1
    total = len(_MUST_FAIL) + len(_MUST_PASS)
    if failures:
        print(f"selftest: {failures}/{total} cases failed", file=sys.stderr)
        return 1
    print(f"selftest: {total}/{total} cases passed ({len(_MUST_FAIL)} must-fail, {len(_MUST_PASS)} must-pass)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    if argv:
        paths = [Path(a) for a in argv]
    else:
        root = Path(__file__).resolve().parent.parent
        paths = []
        for pattern in DEFAULT_GLOBS:
            paths.extend(sorted(Path(p) for p in glob.glob(str(root / pattern))))

    if not paths:
        print("check_absolutes_unwaivable: no files matched; refusing to pass vacuously", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"check_absolutes_unwaivable: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        findings.extend(scan_text(str(path), text))

    if findings:
        print("ADR 0034 Decision 10: banned absolutes are unwaivable. These say otherwise:\n", file=sys.stderr)
        for finding in findings:
            print(finding.render(), file=sys.stderr)
        print(
            f"\n{len(findings)} violation(s) in {len(paths)} scanned file(s).\n"
            "Either state that the absolute is unwaivable in the same sentence, or - if the text is a\n"
            "quotation, a legal literal, an external term, a negative example, a withdrawn historical\n"
            "claim or a test fixture - wrap it in a <!-- truth-exempt: <class> - <reason> --> block.",
            file=sys.stderr,
        )
        return 1

    print(f"check_absolutes_unwaivable: {len(paths)} file(s) scanned, no waiver-eligible absolutes asserted.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
