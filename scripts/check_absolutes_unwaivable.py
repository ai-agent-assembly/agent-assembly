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

# Naming the mechanism. "waiv" covers waiver / waive / waived / waivable / waiving /
# waiver-approver / waiver-eligible — and, deliberately, "unwaivable", which the
# denial list below then clears. Decision 10 is titled "Waivers **and exceptions**"
# and its body says "a bounded exception", so a rule stated in the synonym is the
# same rule: without these stems, "a banned absolute may be published under a
# recorded, approved, expiring exception" reads as clean.
MECHANISM_STEMS: tuple[str, ...] = ("waiv", "exception", "exempted from")

# Tier 2. Three of the six sentences this amendment struck put the absolute in one
# sentence (or one table cell) and the mechanism in the next, so a same-segment test
# cannot see them: "…the banned-absolutes list … | … this ADR adds the waiver
# mechanism, not the check". Tier 2 pairs each mention of an absolute with the
# nearest granting phrase in *either* direction and asks whether a denial stands
# between them. Both directions are needed and neither is redundant: a grant that
# follows the absolute is the six struck sentences, and a grant that precedes it is
# "An expiring waiver may be approved for any rule. That includes ADR 0033's
# banned-absolutes list." The denial-between rule is what keeps "a waiver may waive
# process … it may never waive whether a statement is true … absolutes are
# unwaivable" clean: the denial intervenes, so the earlier grant is not about them.
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
    "expiring waiver",
    "approved waiver",
    "waiver may be approved",
    "permission to publish",
    "waiver-eligible",
    # The "exceptions" half of Decision 10's own title.
    "exempted from",
    "under an exception",
    "under a recorded exception",
    "expiring exception",
    "approved exception",
)

# Classes that describe *someone else's* words or a fixed form of words. None of them
# can license a statement about what this project's rules permit, so a granting
# phrase inside one is a marker being used as a bypass rather than a label.
# `negative-example`, `historical-withdrawn` and `test-fixture` are excluded from
# this restriction because carrying a rule-statement is exactly their purpose.
NON_LICENSING_CLASSES: frozenset[str] = frozenset(
    {"attributed-quotation", "legal-literal", "external-term"}
)

# A marker is a label on a passage, not a switch for a document. The longest
# legitimate block in this repository is the AAASM-5671 struck-text record; the cap
# is set well above it and well below "a marker at the top of the file".
MAX_EXEMPT_BLOCK_LINES = 60

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

# Link targets and bare URLs are dropped before matching. A heading slug is this
# check's vocabulary with the spaces removed —
# `#74-banned-absolutes-are-never-waivable` contains the anchor "banned-absolutes"
# and the grant "waivable", but not the denial "never waivable", which needs a
# space. A correctly named section therefore accused itself, and the AAASM-5598
# lane hit twelve of these on one page. A URL is never the sentence making the
# claim, so removing targets is both the fix and a precision win.
LINK_TARGET = re.compile(r"\](\([^)]*\))")
BARE_URL = re.compile(r"<?https?://[^\s>)]+>?")

# Segment boundaries: sentence enders followed by space, and table-cell pipes. The
# trailing-whitespace requirement is load-bearing — without it "§2.1" and "0033:607"
# split mid-reference and separate a denial from the absolute it denies.
BOUNDARY = re.compile(r"(?<=[.;?!])\s+|\|")

# Stands in for a blank line inside a block. It is a segment boundary, so tier 1
# never runs two paragraphs together into one "sentence", while tier 2 still reads
# across the break.
PARAGRAPH_BREAK = "|"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    message: str
    excerpt: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}\n    {self.excerpt}"


def _strip_markup(text: str) -> str:
    return _normalise(text, [0] * len(text))[0]


def _normalise(joined: str, line_of: list[int]) -> tuple[str, list[int]]:
    """Drop markup, link targets and bare URLs, keeping a per-character line map.

    Every removal is a deletion of whole characters, so the map is rebuilt in the
    same pass rather than inferred afterwards — an offset that points at the wrong
    line turns a real finding into an unfollowable one.
    """
    drop = bytearray(len(joined))
    for match in LINK_TARGET.finditer(joined):
        for i in range(match.start(1), match.end(1)):
            drop[i] = 1
    for match in BARE_URL.finditer(joined):
        for i in range(match.start(), match.end()):
            drop[i] = 1

    out: list[str] = []
    lines: list[int] = []
    for i, ch in enumerate(joined):
        if drop[i] or MARKUP.match(ch):
            continue
        out.append(ch)
        lines.append(line_of[i])
    return "".join(out), lines


def _excerpt(text: str, limit: int = 160) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def scan_text(path: str, text: str) -> list[Finding]:
    """Return every finding in one document. Pure, so --selftest can call it."""
    findings: list[Finding] = []
    in_fence = False
    exempt_open_line = 0
    exempt_class = ""
    exempt_body: list[str] = []

    # (line_number, line_text) pairs of the block being accumulated. A block runs to
    # the next heading rather than to the next blank line: an absolute stated in one
    # paragraph and granted a waiver in the next is one claim, and a paragraph-scoped
    # unit cannot see it. Paragraph breaks are kept as segment boundaries so tier 1
    # still never merges two paragraphs into one "sentence".
    block: list[tuple[int, str]] = []

    def flush() -> None:
        nonlocal block
        while block and block[-1][1] == PARAGRAPH_BREAK:
            block.pop()
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
            else:
                findings.extend(
                    _audit_exempt_block(path, exempt_open_line, exempt_class, exempt_body, lineno)
                )
            exempt_open_line = 0
            exempt_class = ""
            exempt_body = []
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
            exempt_body = []
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
            exempt_body.append(raw)
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

        if HEADING.match(raw):
            # A heading ends the block *and* is scanned as one of its own. Skipping
            # it would leave the one position Decision 10 bound 3 calls out — "never
            # in a heading … a heading is quoted alone in a table of contents" —
            # as the only place in the document the rule is not enforced.
            flush()
            findings.extend(_scan_block(path, [(lineno, raw)]))
            continue

        if not raw.strip():
            if block and block[-1][1] != PARAGRAPH_BREAK:
                block.append((lineno, PARAGRAPH_BREAK))
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

    normalised, kept_lines = _normalise(joined, line_of)

    lowered_block = normalised.lower()
    segments = _segments(normalised)

    def line_at(offset: int) -> int:
        return kept_lines[offset] if offset < len(kept_lines) else block[0][0]

    def segment_at(offset: int) -> str:
        for start, seg in segments:
            if start <= offset < start + len(seg):
                return seg.lower()
        return ""

    # Reported at most once per offset, since tier 1 and tier 2 overlap by design.
    findings: dict[int, Finding] = {}

    # Tier 1 — an absolute and the mechanism inside one sentence or cell, in either
    # order, with nothing saying it is unwaivable.
    for start, segment in segments:
        seg = segment.lower()
        if not any(stem in seg for stem in MECHANISM_STEMS):
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

    # Tier 2 — the nearest grant on either side of an absolute, with no denial
    # standing between the two.
    denial_hits = sorted(_occurrences(lowered_block, UNWAIVABLE_MARKERS))
    denial_spans = [(at, at + len(text)) for at, text in denial_hits]
    denial_at = [at for at, _ in denial_hits]

    def inside_a_denial(offset: int) -> bool:
        # "waivable" is a substring of "unwaivable"; a grant found inside a denial is
        # the denial, and treating it as a grant inverts the test.
        return any(lo <= offset < hi for lo, hi in denial_spans)

    grants = sorted(
        (at, text) for at, text in _occurrences(lowered_block, GRANTING_PHRASES) if not inside_a_denial(at)
    )

    for anchor_at, _ in sorted(_occurrences(lowered_block, ABSOLUTE_ANCHORS)):
        # If the absolute's own sentence says it is unwaivable, the pairing is settled
        # there and no neighbouring grant can be about it.
        if any(marker in segment_at(anchor_at) for marker in UNWAIVABLE_MARKERS):
            continue

        after = next(((at, text) for at, text in grants if at > anchor_at), None)
        before = next(((at, text) for at, text in reversed(grants) if at < anchor_at), None)

        for hit, direction in ((after, "forward"), (before, "backward")):
            if hit is None:
                continue
            offset, phrase = hit
            # A granting phrase in a sentence that denies waivability is not a grant:
            # "Four things may not be waived, because a waiver over them would remove
            # the property the rule exists to establish" is the denial itself.
            if any(marker in segment_at(offset) for marker in UNWAIVABLE_MARKERS):
                continue
            lo, hi = (anchor_at, offset) if direction == "forward" else (offset, anchor_at)
            if any(lo < d < hi for d in denial_at):
                continue
            if offset in findings:
                continue
            findings[offset] = Finding(
                path,
                line_at(offset),
                f"reading {direction} from a banned absolute, {phrase!r} grants a waiver with no "
                "denial between the two (ADR 0034 Decision 10, AAASM-5671)",
                _excerpt(normalised[max(0, min(lo, offset) - 60) : max(hi, offset) + 60]),
            )

    return [findings[k] for k in sorted(findings)]


def _audit_exempt_block(
    path: str, open_line: int, cls: str, body: list[str], close_line: int
) -> list[Finding]:
    """Check that a closed truth-exempt block is a label, not a bypass.

    The marker suppresses everything between its fences, which makes it the one
    construct in this check that can be turned against it: a marker naming a class
    that cannot license a rule-statement, or a marker stretched over a whole file,
    silences text the decision governs.
    """
    findings: list[Finding] = []

    # Every exempted line must be visibly *carried* rather than said: a blockquote,
    # a table row, or a fenced region (fences never reach `body` — they are skipped
    # upstream). Bare prose inside a marker is the page speaking in its own voice
    # with the label attached, which is what bound 2 forbids, and it is the one
    # bypass the class restriction below cannot reach: `historical-withdrawn` may
    # legitimately carry a rule-statement, so only the *form* can distinguish a
    # quoted withdrawn claim from a live one.
    for offset, line in enumerate(body):
        stripped = line.strip()
        if not stripped or stripped.startswith((">", "|")):
            continue
        findings.append(
            Finding(
                path,
                open_line + 1 + offset,
                f"bare prose inside the truth-exempt ({cls}) block opened at line {open_line}; "
                "exempted text must be quoted, tabulated or fenced so the page is not stating it",
                _excerpt(line),
            )
        )
        break

    if len(body) > MAX_EXEMPT_BLOCK_LINES:
        findings.append(
            Finding(
                path,
                open_line,
                f"truth-exempt ({cls}) block spans {len(body)} lines to line {close_line}, over the "
                f"{MAX_EXEMPT_BLOCK_LINES}-line cap; a marker labels a passage, it does not switch off a document",
                "",
            )
        )

    if cls in NON_LICENSING_CLASSES:
        text = _strip_markup(" ".join(body)).lower()
        spans = [(at, at + len(m)) for at, m in _occurrences(text, UNWAIVABLE_MARKERS)]
        for at, phrase in sorted(_occurrences(text, GRANTING_PHRASES)):
            if any(lo <= at < hi for lo, hi in spans):
                continue
            findings.append(
                Finding(
                    path,
                    open_line,
                    f"truth-exempt class {cls!r} cannot license a statement about waivability, but the "
                    f"block contains {phrase!r}; use negative-example, historical-withdrawn or "
                    "test-fixture, or state the rule outside the marker",
                    _excerpt(text),
                )
            )
            break

    return findings


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
    # Review round 1, blocker: a heading was a block boundary and its text was never
    # scanned, so the one position bound 3 singles out was the one position exempt
    # from the check. The control for these two is "waivable-form opening" above,
    # which differs only by not being a heading.
    ("waiver-eligible claim in an h2", "## A `banned absolute` may be waived under an expiring waiver\n"),
    ("waiver-eligible claim in an h4", "#### Banned absolutes may be waived under an expiring waiver\n"),
    # Review round 1: the mechanism stated in Decision 10's own synonym.
    (
        "exception as the mechanism",
        "A banned absolute may be published under a recorded, approved, expiring exception.\n",
    ),
    (
        "exempted-from as the mechanism",
        "ADR 0033's banned absolutes are exempted from enforcement under a recorded exception.\n",
    ),
    # Review round 1: tier 2 read forward only, and only to the end of a paragraph.
    (
        "grant precedes the absolute across sentences",
        "An expiring waiver may be approved by a waiver-approver for any rule.\n"
        "That includes ADR 0033's banned-absolutes list.\n",
    ),
    (
        "grant follows the absolute across a blank line",
        "ADR 0033's banned absolutes are listed in forbidden design 7.\n"
        "\n"
        "Each of them may be published under an expiring waiver once an approver signs.\n",
    ),
    (
        "grant in an earlier table column than the absolute",
        "| Rule | Status | Applies to |\n"
        "| --- | --- | --- |\n"
        "| Publication | may be waived for ninety days | ADR 0033's banned-absolutes list |\n",
    ),
    (
        "grant across blockquote paragraphs",
        "> ADR 0033's banned absolutes bind architecture and product descriptions.\n"
        ">\n"
        "> Each may be published under an expiring waiver.\n",
    ),
    # Review round 1: the marker silenced arbitrary content.
    (
        "non-licensing class used to silence a rule statement",
        "<!-- truth-exempt: external-term - fixed terminology we cannot paraphrase -->\n"
        "A banned absolute may be waived by any waiver-approver for ninety days.\n"
        "<!-- /truth-exempt -->\n",
    ),
    (
        "bare prose inside a class that may carry a rule-statement",
        "<!-- truth-exempt: historical-withdrawn - an old rule we are recording -->\n"
        "A banned absolute may be waived by any waiver-approver for ninety days.\n"
        "<!-- /truth-exempt -->\n",
    ),
    (
        "marker stretched over a document",
        "<!-- truth-exempt: negative-example - a demonstration of banned wording -->\n"
        + "filler line\n" * (MAX_EXEMPT_BLOCK_LINES + 1)
        + "<!-- /truth-exempt -->\n",
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
    # The backward pass and the heading scan must not fire on correct statements.
    ("heading stating the rule", "## Truthfulness and banned absolutes are unwaivable\n"),
    ("heading naming the mechanism only", "### 10. Waivers and exceptions\n"),
    (
        "grant, then denial, then the absolute across paragraphs",
        "A waiver may waive process, timing or review sequencing.\n"
        "\n"
        "It may never waive whether a statement is true.\n"
        "\n"
        "ADR 0033's banned absolutes are therefore unwaivable.\n",
    ),
    (
        "non-licensing class labelling text that states no rule",
        "<!-- truth-exempt: external-term - a vendor product name we cannot paraphrase -->\n"
        "> The product is marketed as Immutable Audit Vault.\n"
        "<!-- /truth-exempt -->\n",
    ),
    # Heading slugs carry this check's vocabulary with the spaces removed; a
    # correctly named section must not accuse itself.
    ("slug in a bare link", "See [§7.4](#74-banned-absolutes-are-never-waivable) for the rule.\n"),
    (
        "slug in a table of contents entry",
        "- [7.4 Banned absolutes are never waivable](#74-banned-absolutes-are-never-waivable)\n",
    ),
    (
        "slug in a wrapped sentence",
        "The banned-absolutes rule lives at\n"
        "[7.4](#74-banned-absolutes-are-never-waivable) and is enforced on every page.\n",
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
