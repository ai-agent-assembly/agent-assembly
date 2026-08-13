#!/usr/bin/env python3
"""Enforce the `CLAIM-ABS-*` / `CLAIM-VERB-*` claim vocabulary against product copy.

`docs/src/development/claim-vocabulary.md` specifies this rule set in full — the
rules (§5.3), the guards (§5.6), the normalisation pipeline (§6.2), the exempt
regions (§6.3), the file scope (§6.5) and the reporting contract (§6.6). Until
now the specification had no implementation, which is the defect
[AAASM-5679](https://lightning-dust-mite.atlassian.net/browse/AAASM-5679)
records: a claim already classified as a blocking `CLAIM-ABS-09` violation
survived on the repository's front page while a docs pipeline went green.

# Why this is a second script and not an extension of `check_absolutes_unwaivable.py`

They enforce different properties and it matters that they are not confused.
`check_absolutes_unwaivable.py` is a *meta*-check: it verifies that a governance
document does not declare a banned absolute to be waivable. It never looks for a
banned absolute in product copy, and it globs only `docs/src/adr/*`,
`docs/src/development/*` and `docs/TRUTH-ADOPTION.md`. Pointed directly at
`README.md` it exits 0 — verified, not assumed. A green run of that script is
therefore not evidence that no banned absolute shipped, and folding this rule set
into it would make one exit code stand for two unrelated claims.

# Scope, and where it deliberately exceeds §6.5

§6.5's scope is implemented as written. Two additions come from AAASM-5679's
acceptance criteria and are marked in `EXTRA_INCLUDES` rather than smuggled in:

* `design/**` — ADR 0025 makes the design specs *authoritative*, so a claim left
  there is re-derived into the dashboard later. `design/v2/hi-fi/audit-log.jsx`
  carried "Immutable governance trail" in both a header comment and a rendered
  page subtitle.
* `.jsx` / `.tsx` extensions, needed to reach the above.

Markdown structure does not apply to JSX, so those files are scanned as plain
text with no masking. The rules are multi-word phrases, so the practical risk of
matching an identifier is low, and the alternative — not scanning the
authoritative visual spec at all — is what let the claim sit there.

# The one implementation choice worth reading before changing anything

The mask filler is NUL (see `_FILLER`), and the reasoning is recorded there
because the first version got it wrong in a way that produced **blocking false
positives on correct English**. `.` was used initially, on the theory that a
masked region should also stop a collocation span; because `.` is a clause
boundary it truncated the `NEG` window instead, so a negated sentence containing
any inline code span was reported as a violation.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------
# §5.6 macros. Each carries its own non-capturing group, per the specification's
# warning that textual substitution of a bare alternation silently changes what
# the collocation rules mean (measured there as 0/0/12 -> 1503/1550/1155).
# --------------------------------------------------------------------------
MACROS: dict[str, str] = {
    "SEP": r"(?:[-‑_\s]+)",
    "DOC-NOUN": r"(?:reference|guide|list|example|walkthrough|inventory|history|re-audit|rewrite|set\b)",
    "GOV-NOUN": (
        r"(?:coverage|protection|mediation|interception|enforcement|visibility"
        r"|observability|monitoring|detection|inspection|audit(?:ing|s)?"
        r"|governance|security|telemetry)"
    ),
    "SUBJ": (
        r"(?:Agent\s+Assembly|Assembly|the\s+(?:gateway|proxy|runtime|SDK|sandbox"
        r"|platform|product|CLI|dashboard|policy\s+engine)|aa-[a-z-]+)"
    ),
}

NEG_PATTERN = re.compile(
    r"(?:\bno\b|\bnot\b|\bnever\b|\bneither\b|\bnor\b|\bwithout\b|\bnothing\b"
    r"|\bcannot\b|\bcan't\b|\bisn't\b|\baren't\b|\bdoesn't\b|\bdon't\b"
    r"|\brather\s+than\b|\binstead\s+of\b|\bnon-|\bunder-|\bincomplete\b)",
    re.IGNORECASE,
)
NEG_WINDOW_CHARS = 70
CLAUSE_BOUNDARIES = set(".;!?\n")

CFG_NOUN_PATTERN = re.compile(
    r"\s*(?:entry|entries|rule|rules|pattern|handler|route|case|branch|glob"
    r"|selector|wildcard|for\b)",
    re.IGNORECASE,
)

# NUL, and the choice matters in two directions that pull against each other.
#
# It must not be a clause boundary. `.` was used here first, and because
# `CLAUSE_BOUNDARIES` contains `.`, any masked region between a negation and a
# match truncated the NEG window — so "It does not, per `RFC-1`, catch
# everything." was reported as a **blocking** violation while the identical
# sentence without backticks was correctly suppressed. Banned absolutes are
# unwaivable (§7.4), so an author hit by that had no escape but to reword correct
# English, which §5.1 names as the way a blocking rule gets switched off.
#
# It must also not be whitespace. `SEP` expands to `[-‑_\s]+`, so a space filler
# would let `catch` and `everything` on opposite sides of a code span match
# CLAIM-ABS-01 as though they were adjacent.
#
# NUL satisfies both: it is a non-word character (so `\b` still anchors), it is
# not in `CLAUSE_BOUNDARIES`, it is not matched by `SEP`, and `[^.;:!?]` accepts
# it — so a collocation rule may still span a code span, which is what E3's
# "exempt the span, not the sentence around it" means.
_FILLER = "\x00"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    pattern: str
    guards: tuple[str, ...]


RULES: tuple[Rule, ...] = (
    Rule("CLAIM-ABS-01", "blocking", r"catch(?:es|ing)?<SEP>everything", ("NEG",)),
    Rule("CLAIM-ABS-02", "finding", r"catch[-‑_\s]?all", ("NEG", "CFG-NOUN")),
    Rule(
        "CLAIM-ABS-03",
        "blocking",
        r"(?:can\s?not|cannot|can't|could<SEP>not)<SEP>(?:be<SEP>)?bypass(?:ed)?",
        (),
    ),
    Rule("CLAIM-ABS-04", "blocking", r"un-?bypassable", ()),
    Rule("CLAIM-ABS-05", "blocking", r"nowhere<SEP>to<SEP>hide", ()),
    Rule("CLAIM-ABS-06", "finding", r"every<SEP>action", ("NEG",)),
    Rule("CLAIM-ABS-07", "blocking", r"every<SEP>tool<SEP>calls?", ("NEG",)),
    Rule("CLAIM-ABS-08", "blocking", r"no<SEP>code<SEP>changes?", ()),
    Rule("CLAIM-ABS-09", "blocking", r"immutable<SEP>audit", ()),
    Rule("CLAIM-ABS-10", "blocking", r"(?:full|whole)<SEP>fleet", ()),
    Rule(
        "CLAIM-ABS-11",
        "finding",
        r"\b(?:complete|comprehensive|universal)\s+(?!<DOC-NOUN>)[^.;:!?]{0,40}?\b<GOV-NOUN>\b",
        ("NEG",),
    ),
    Rule(
        "CLAIM-ABS-12",
        "finding",
        r"\b<GOV-NOUN>\b[^.;:!?]{0,40}?\b(?:is|are|was|were|remains?)\b"
        r"[^.;:!?]{0,15}?\b(?:complete|comprehensive|universal)\b",
        ("NEG",),
    ),
    Rule(
        "CLAIM-VERB-01",
        "finding",
        r"\b<SUBJ>\b[^.;:!?]{0,30}?\b(?:protects|enforces|catches|prevents"
        r"|guarantees|blocks|stops)\s+(?:the|a|an|all|every|any|its|their|each)?"
        r"\s*[a-z][a-z-]{2,}",
        ("NEG",),
    ),
)

QUOTE_RULE_ID = "CLAIM-QUOTE-01"


def _expand(pattern: str) -> str:
    for name, expansion in MACROS.items():
        pattern = pattern.replace(f"<{name}>", expansion)
    return pattern


COMPILED: tuple[tuple[Rule, re.Pattern[str]], ...] = tuple(
    (rule, re.compile(_expand(rule.pattern), re.IGNORECASE)) for rule in RULES
)

# --------------------------------------------------------------------------
# §6.5 file scope, plus AAASM-5679's additions.
# --------------------------------------------------------------------------
EXTENSIONS = {".md", ".markdown", ".mdx", ".html", ".txt"}
EXTRA_EXTENSIONS = {".jsx", ".tsx"}

INCLUDE_GLOBS = (
    "docs/src/**",
    "README.md",
    "**/README.md",
    "CONTRIBUTING.md",
    ".claude/**",
)
EXTRA_INCLUDES = ("design/**",)

EXCLUDE_GLOBS = (
    "verification-reports/**",
    ".ai/**",
    "scratchpad/**",
    "target/**",
    "node_modules/**",
)


def _matches_any(path: str, globs: tuple[str, ...]) -> bool:
    for pattern in globs:
        if fnmatch.fnmatch(path, pattern):
            return True
        # `docs/src/**` must match `docs/src/a/b.md`; fnmatch's `*` already
        # crosses `/`, but a trailing `/**` should also match nothing-after.
        if pattern.endswith("/**") and (
            path == pattern[:-3] or path.startswith(pattern[:-2])
        ):
            return True
    return False


def in_scope(path: str) -> bool:
    if _matches_any(path, EXCLUDE_GLOBS):
        return False
    suffix = Path(path).suffix
    if _matches_any(path, EXTRA_INCLUDES):
        return suffix in EXTENSIONS or suffix in EXTRA_EXTENSIONS
    if suffix not in EXTENSIONS:
        return False
    return _matches_any(path, INCLUDE_GLOBS)


def _is_repo_relative(root: Path, rel: str) -> bool:
    """True when `rel` names a path inside the repository (so scope applies)."""
    candidate = Path(rel)
    if candidate.is_absolute():
        try:
            candidate.relative_to(root)
        except ValueError:
            return False
    return (root / rel).exists() or not candidate.is_absolute()


def _changed_lines(root: Path, base: str, targets: list[str]) -> dict[str, set[int]]:
    """Line numbers added or modified since `base`, per file.

    Uses `git diff -U0` and reads the post-image hunk headers. A failure here is
    raised, never swallowed: a gate that silently treats "I could not work out
    what changed" as "nothing changed" passes everything, which is the defect
    this whole ticket is about.
    """
    result = subprocess.run(
        ["git", "diff", "-U0", "--no-color", f"{base}...HEAD", "--", *targets],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git diff against {base!r} failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )

    changed: dict[str, set[int]] = {}
    current: str | None = None
    hunk = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")
    for line in result.stdout.split("\n"):
        if line.startswith("+++ b/"):
            current = line[6:]
            changed.setdefault(current, set())
        elif current and (m := hunk.match(line)):
            start = int(m.group(1))
            count = int(m.group(2) or 1)
            changed[current].update(range(start, start + count))
    return changed


def tracked_files(root: Path) -> list[str]:
    """§6.5: tracked files only, so a gitignored artifact cannot change the result."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [p for p in out.stdout.split("\0") if p]


# --------------------------------------------------------------------------
# §6.2 normalisation. Every step preserves length, so an offset in the
# normalised text is an offset in the original file.
# --------------------------------------------------------------------------
_BLOCK_START = re.compile(
    r"""^(?:
          \#{1,6}\           # ATX heading
        | [-*+]\             # bullet
        | \d+[.)]\           # ordered list
        | \|                 # table row
        | (?:`{3,}|~{3,})    # code fence
        | (?:\*\s*){3,}$|(?:-\s*){3,}$|(?:_\s*){3,}$   # thematic break
        | <[A-Za-z/!]        # HTML block
        | (?:\ {4}|\t)\S     # indented code
    )""",
    re.VERBOSE,
)
_BQ = re.compile(r"^((?:\s*>\s?)*)")


def _blockquote_depth(line: str) -> tuple[int, str]:
    marker = _BQ.match(line).group(1)
    return marker.count(">"), line[len(marker) :]


# A real `<meta …>` element, not the word "meta" in prose. The first version was
# `<meta\b` matched anywhere on the line, and it marked an entire ADR table row
# structural because that row *discusses* `<meta description>` — promoting a
# correctly-quoted negative example to a blocking violation. Requiring the
# closing `>` and marking only the tag's own span fixes both halves.
_META_TAG = re.compile(r"<meta\s[^>]*>", re.IGNORECASE)
_TITLE_DESC_LINE = re.compile(r"^\s*(?:title|description)\s*:", re.IGNORECASE)
_ATX_HEADING = re.compile(r"^\s{0,3}#{1,6}\s")


def _structural_ranges(text: str) -> list[tuple[int, int]]:
    """Offsets where §6.3.1 bound 3 says E3 and E6 do **not** apply.

    ADR 0034 Decision 10 exempts a banned absolute only when it is labelled and
    presented as a non-product assertion, and bound 3 withdraws that even then
    for "a heading, a summary, page metadata, SEO text, marketing copy, or a
    user-facing conclusion" — because a heading is quoted alone in a table of
    contents and a `<meta description>` is quoted alone in a search result, and
    the label does not travel there.

    So in these positions a *backticked* or *quoted* banned absolute keeps its
    own severity. Without this the gate had a one-character bypass: the spec's
    own worked example -- a heading whose banned phrase sits in backticks --
    scored 0 blocking / 0 finding / 0 info — silent at every severity on a
    landing-page headline that renders the words in full.
    """
    ranges: list[tuple[int, int]] = []
    offset = 0
    lines = text.split("\n")
    in_front_matter = False
    for index, line in enumerate(lines):
        start, end = offset, offset + len(line)
        offset = end + 1

        # YAML front matter: a leading `---` on the very first line opens it.
        if index == 0 and line.strip() == "---":
            in_front_matter = True
            continue
        if in_front_matter:
            if line.strip() in {"---", "..."}:
                in_front_matter = False
            else:
                ranges.append((start, end))
            continue

        # A heading is structural in its entirety — it is quoted alone in a
        # table of contents.
        if _ATX_HEADING.match(line):
            ranges.append((start, end))
            continue

        # `title:` / `description:` — only the VALUE is the metadata.
        if m := _TITLE_DESC_LINE.match(line):
            ranges.append((start + m.end(), end))
            continue

        # A `<meta …>` element marks only its own span, so prose that merely
        # mentions one is untouched.
        for m in _META_TAG.finditer(line):
            ranges.append((start + m.start(), start + m.end()))
    return ranges


def _in_ranges(ranges: list[tuple[int, int]], offset: int) -> bool:
    return any(lo <= offset < hi for lo, hi in ranges)


def _mask_code_regions(text: str, structural: list[tuple[int, int]] | None = None) -> str:
    """E1-E5. Returns a same-length string with exempt regions replaced by `.`."""
    chars = list(text)
    n = len(text)

    def blank(start: int, end: int) -> None:
        for i in range(start, min(end, n)):
            if chars[i] != "\n":
                chars[i] = _FILLER

    # E4 HTML comments (may span lines).
    for m in re.finditer(r"<!--.*?-->", text, re.DOTALL):
        blank(m.start(), m.end())

    # E1 fenced code blocks.
    lines_span: list[tuple[int, int, str]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        lines_span.append((offset, offset + len(line), line))
        offset += len(line)

    fence: str | None = None
    for start, end, line in lines_span:
        stripped = line.lstrip()
        m = re.match(r"(`{3,}|~{3,})", stripped)
        if fence is None:
            if m:
                fence = m.group(1)
                blank(start, end)
        else:
            blank(start, end)
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None

    # E2 indented code blocks (only outside a fence; approximated per line).
    for start, end, line in lines_span:
        if re.match(r"^(?:\ {4}|\t)\S", line):
            blank(start, end)

    masked = "".join(chars)

    # E3 inline code spans, on the partially masked text.
    #
    # `[^`\n]` and not `(?:.|\n)`: CommonMark forbids a blank line inside a code
    # span, and the permissive form let one stray backtick pair up with another
    # lines away and mask everything between them — silently deleting whatever
    # violations lived in the gap.
    structural = structural or []
    for m in re.finditer(r"(`+)[^`\n]*?\1", masked):
        # §6.3.1 bound 3: in a heading, front matter, `<meta>` or a
        # `title:`/`description:` value, E3 does not apply.
        if _in_ranges(structural, m.start()):
            continue
        blank(m.start(), m.end())
    masked = "".join(chars)

    # E5 link destinations and bare URLs.
    for m in re.finditer(r"\]\([^)]*\)", masked):
        blank(m.start(), m.end())
    for m in re.finditer(r"<https?://[^>]*>|https?://\S+", masked):
        blank(m.start(), m.end())

    return "".join(chars)


def _join_soft_wraps(masked: str, original: str) -> str:
    """§6.2 step 2. Block structure is read from `original`, never from `masked`."""
    orig_lines = original.split("\n")
    out = list(masked)
    offset = 0
    offsets: list[int] = []
    for line in orig_lines:
        offsets.append(offset)
        offset += len(line) + 1

    for i in range(len(orig_lines) - 1):
        first, second = orig_lines[i], orig_lines[i + 1]
        if not first.strip() or not second.strip():
            continue
        depth_a, body_a = _blockquote_depth(first)
        depth_b, body_b = _blockquote_depth(second)
        if depth_a != depth_b:
            continue
        if not body_a.strip() or not body_b.strip():
            continue
        # Only the SECOND line is tested for a block start.
        if _BLOCK_START.match(body_b):
            continue
        newline_at = offsets[i] + len(first)
        if newline_at < len(out) and out[newline_at] == "\n":
            out[newline_at] = " "
    return "".join(out)


def _logical_line_bounds(text: str, index: int) -> tuple[int, int]:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return start, (len(text) if end == -1 else end)


def _quoted_spans(segment: str) -> list[tuple[int, int]]:
    """E6, paired per logical line."""
    spans: list[tuple[int, int]] = []
    for quote_open, quote_close in (('"', '"'), ("“", "”")):
        pending: int | None = None
        for i, ch in enumerate(segment):
            if quote_open == quote_close:
                if ch == quote_open:
                    if pending is None:
                        pending = i
                    else:
                        spans.append((pending, i + 1))
                        pending = None
            else:
                if ch == quote_open:
                    pending = i
                elif ch == quote_close and pending is not None:
                    spans.append((pending, i + 1))
                    pending = None
    return spans


def _neg_fires(text: str, match_start: int) -> bool:
    """§5.6 NEG: at most 70 chars back, and never past a clause boundary."""
    window_start = max(0, match_start - NEG_WINDOW_CHARS)
    i = match_start - 1
    while i >= window_start:
        if text[i] in CLAUSE_BOUNDARIES:
            window_start = i + 1
            break
        i -= 1
    return bool(NEG_PATTERN.search(text[window_start:match_start]))


@dataclass(frozen=True)
class Diagnostic:
    path: str
    line: int
    col: int
    rule_id: str
    severity: str
    message: str
    matched: str


def scan_text(path: str, original: str, markdown: bool = True) -> list[Diagnostic]:
    structural = _structural_ranges(original) if markdown else []
    if markdown:
        masked = _mask_code_regions(original, structural)
        normalised = _join_soft_wraps(masked, original)
    else:
        normalised = original

    # A newline that SURVIVED the join is a hard boundary, and must be one for
    # matching too. `SEP` expands to `[-‑_\s]+`, which includes `\n`, so without
    # this substitution `immutable\naudit` matches even where §6.2 step 2
    # deliberately refused to join — making the join's block-start test dead
    # code. The specification's own worked example depends on the opposite:
    # CHANGELOG.md:25 begins with a list marker, the join is forbidden, and
    # `immutable audit` is therefore NOT reassembled. Replacing with `_FILLER`
    # keeps every offset intact and reuses the filler's clause-boundary role.
    match_text = normalised.replace("\n", _FILLER)

    line_starts = [0]
    for i, ch in enumerate(original):
        if ch == "\n":
            line_starts.append(i + 1)

    def position(offset: int) -> tuple[int, int]:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - line_starts[lo] + 1

    diagnostics: list[Diagnostic] = []
    for rule, compiled in COMPILED:
        for m in compiled.finditer(match_text):
            if "NEG" in rule.guards and _neg_fires(match_text, m.start()):
                continue
            if "CFG-NOUN" in rule.guards and CFG_NOUN_PATTERN.match(
                match_text, m.end()
            ):
                continue

            line, col = position(m.start())
            matched = re.sub(r"\s+", " ", original[m.start() : m.end()]).strip()

            start, end = _logical_line_bounds(normalised, m.start())
            rel = m.start() - start
            in_quote = any(
                lo <= rel < hi for lo, hi in _quoted_spans(match_text[start:end])
            ) and not _in_ranges(structural, m.start())
            if in_quote:
                # §6.6: emitted IN PLACE OF the rule's own diagnostic.
                diagnostics.append(
                    Diagnostic(
                        path,
                        line,
                        col,
                        QUOTE_RULE_ID,
                        "info",
                        f"{rule.rule_id} phrase inside a quoted span (negative example)",
                        matched,
                    )
                )
            else:
                diagnostics.append(
                    Diagnostic(
                        path,
                        line,
                        col,
                        rule.rule_id,
                        rule.severity,
                        f"banned claim wording ({rule.rule_id})",
                        matched,
                    )
                )
    return sorted(diagnostics, key=lambda d: (d.path, d.line, d.col, d.rule_id))


def scan_file(root: Path, rel: str) -> list[Diagnostic]:
    try:
        text = (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    markdown = Path(rel).suffix not in EXTRA_EXTENSIONS
    return scan_text(rel, text, markdown=markdown)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="explicit paths (default: §6.5 scope)")
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="never exit non-zero; used while the blocking baseline is non-empty",
    )
    parser.add_argument("--selftest", action="store_true", help="run built-in fixtures")
    parser.add_argument(
        "--diff-base",
        help=(
            "restrict BLOCKING diagnostics to lines added or modified since this "
            "ref, per claim-vocabulary.md 6.6's adoption sequence"
        ),
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    root = Path(args.root).resolve()
    if args.paths:
        # An explicit path is scanned wherever it lives — including outside the
        # repository, which is how the falsification proof feeds the checker a
        # known-bad line without committing one. Relative-to-root is attempted
        # first only to keep diagnostics short for in-tree paths.
        targets = []
        for p in args.paths:
            candidate = Path(p)
            if candidate.is_absolute():
                try:
                    targets.append(str(candidate.relative_to(root)))
                except ValueError:
                    targets.append(str(candidate))
            else:
                targets.append(p)
        # 6.5's exclusions are semantic, not a convenience: `verification-reports/**`
        # is excluded because its job is to QUOTE overstatements in order to
        # disprove them. An explicit path must not smuggle those back in.
        dropped = [t for t in targets if _is_repo_relative(root, t) and not in_scope(t)]
        if dropped:
            for t in dropped:
                print(f"skipped (outside 6.5 scope): {t}")
            targets = [t for t in targets if t not in set(dropped)]
    else:
        targets = [p for p in tracked_files(root) if in_scope(p)]

    changed_lines: dict[str, set[int]] | None = None
    if args.diff_base:
        changed_lines = _changed_lines(root, args.diff_base, targets)

    diagnostics: list[Diagnostic] = []
    for rel in targets:
        for d in scan_file(root, rel):
            # 6.6: while the tree's blocking baseline is non-empty, blocking
            # rules gate the pull request's own added and modified lines. A
            # whole-file gate would fail an author on someone else's
            # pre-existing violation, which is not the adoption sequence the
            # specification describes.
            if (
                changed_lines is not None
                and d.severity == "blocking"
                and d.line not in changed_lines.get(d.path, set())
            ):
                d = Diagnostic(
                    d.path, d.line, d.col, d.rule_id, "pre-existing",
                    d.message + " (pre-existing; not introduced by this change)",
                    d.matched,
                )
            diagnostics.append(d)

    counts = {"blocking": 0, "finding": 0, "info": 0, "pre-existing": 0}
    for d in diagnostics:
        counts[d.severity] = counts.get(d.severity, 0) + 1
        print(f"{d.path}:{d.line}:{d.col} {d.rule_id} {d.severity} {d.message} — {d.matched!r}")

    # Always print the denominator: a count without its population is not a
    # measurement, and a scan set that silently shrank must be visible here.
    print(
        f"\ncheck_claim_vocabulary: {len(targets)} file(s) scanned; "
        f"{counts['blocking']} blocking, {counts['finding']} finding, "
        f"{counts['info']} info, {counts['pre-existing']} pre-existing."
    )

    if args.report_only:
        return 0
    return 1 if counts["blocking"] else 0


# --------------------------------------------------------------------------
# Self-test. Each rule gets a positive case, and every guard gets a case where
# it must suppress — a checker with no proven negative is indistinguishable from
# one that cannot fire.
# --------------------------------------------------------------------------
SELFTEST_CASES: tuple[tuple[str, str, str | None], ...] = (
    ("eBPF catches everything else, including bypass attempts.", "md", "CLAIM-ABS-01"),
    ("It does not catch everything.", "md", None),
    ("The gateway cannot be bypassed by an agent.", "md", "CLAIM-ABS-03"),
    ("An unbypassable control.", "md", "CLAIM-ABS-04"),
    ("With all three layers there is nowhere to hide.", "md", "CLAIM-ABS-05"),
    ("Checked before every tool call.", "md", "CLAIM-ABS-07"),
    ("Deploy with no code changes.", "md", "CLAIM-ABS-08"),
    ("Recorded in an immutable audit trail.", "md", "CLAIM-ABS-09"),
    ("Rolled out across the whole fleet.", "md", "CLAIM-ABS-10"),
    ("Governs the full fleet today.", "md", "CLAIM-ABS-10"),
    ("complete coverage of agent traffic", "md", "CLAIM-ABS-11"),
    ("a complete reference for operators", "md", None),          # DOC-NOUN guard
    ("There is no claim of complete detection.", "md", None),    # NEG guard
    ("catch-all rules are configured here", "md", None),         # CFG-NOUN guard
    ("a catch-all promise", "md", "CLAIM-ABS-02"),
    ("`immutable audit` is a banned phrase", "md", None),        # E3 inline code
    ('The bug was "an immutable audit trail" on the front page.', "md", QUOTE_RULE_ID),
    ("Immutable governance trail across all agents.", "jsx", None),
    ("Recorded in an immutable audit trail.", "jsx", "CLAIM-ABS-09"),
    # Rules that previously had no positive case at all. CLAIM-VERB-01 is 11 of
    # the 12 baseline findings — the most-firing rule was the least tested.
    ("Checked before every action the agent takes.", "md", "CLAIM-ABS-06"),
    ("Our coverage is complete.", "md", "CLAIM-ABS-12"),
    ("Agent Assembly enforces a zero-trust posture.", "md", "CLAIM-VERB-01"),
    # Exempt regions E1, E2 and E4, none of which had a case.
    ("```\nimmutable audit\n```", "md", None),
    ("    immutable audit trail\n", "md", None),
    ("<!-- immutable audit -->", "md", None),
    ("See [the docs](https://example.com/immutable-audit-trail).", "md", None),
    # §6.3.1 bound 3: a heading, front matter, `<meta>` or a title/description
    # value keeps the rule's own severity even when the phrase is backticked or
    # quoted. Before this, backticks in a heading were a one-character bypass of
    # a blocking gate.
    ("## Agent Assembly `catches everything` on your fleet", "md", "CLAIM-ABS-01"),
    ('## The "immutable audit" trail', "md", "CLAIM-ABS-09"),
    ('<meta name="description" content="an immutable audit trail">', "md", "CLAIM-ABS-09"),
    ("---\ntitle: An immutable audit trail\n---\n", "md", "CLAIM-ABS-09"),
    # ...but the same phrase backticked in body prose is still exempt.
    ("The phrase `catches everything` is banned in body copy.", "md", None),
    # The mask filler must not truncate the NEG window. With `.` as filler these
    # two lines disagreed — the backticked one was reported *blocking* while the
    # identical sentence without backticks was correctly suppressed, and banned
    # absolutes are unwaivable, so the author's only escape was to reword correct
    # English.
    ("It does not, per `RFC-1`, catch everything.", "md", None),
    ("It does not, per RFC-1, catch everything.", "md", None),
    ("This is not a claim of `verified` complete coverage.", "md", None),
)


def selftest() -> int:
    failures: list[str] = []

    # Written out literally, NOT derived from `RULES`. Deriving it from the
    # thing under test is circular: a severity typo changes both sides and the
    # assertion agrees with itself. That is exactly what the first version did,
    # and a mutation flipping CLAIM-ABS-09 from `blocking` to `info` — which
    # disables the gate, since exit status depends only on `blocking` — passed.
    EXPECTED_SEVERITY = {
        "CLAIM-ABS-01": "blocking",
        "CLAIM-ABS-02": "finding",
        "CLAIM-ABS-03": "blocking",
        "CLAIM-ABS-04": "blocking",
        "CLAIM-ABS-05": "blocking",
        "CLAIM-ABS-06": "finding",
        "CLAIM-ABS-07": "blocking",
        "CLAIM-ABS-08": "blocking",
        "CLAIM-ABS-09": "blocking",
        "CLAIM-ABS-10": "blocking",
        "CLAIM-ABS-11": "finding",
        "CLAIM-ABS-12": "finding",
        "CLAIM-VERB-01": "finding",
        QUOTE_RULE_ID: "info",
    }
    expected_severity = EXPECTED_SEVERITY

    # The declared table must also agree with the rule set, so a NEW rule cannot
    # be added without deciding its severity here.
    for rule in RULES:
        if EXPECTED_SEVERITY.get(rule.rule_id) != rule.severity:
            failures.append(
                f"{rule.rule_id} declares severity {rule.severity!r} but the "
                f"selftest expects {EXPECTED_SEVERITY.get(rule.rule_id)!r}"
            )

    for text, kind, expected in SELFTEST_CASES:
        diags = scan_text("<selftest>", text + "\n", markdown=(kind != "jsx"))
        ids = {d.rule_id for d in diags}
        if expected is None:
            if ids:
                failures.append(f"expected no diagnostic for {text!r}, got {sorted(ids)}")
            continue
        if expected not in ids:
            failures.append(f"expected {expected} for {text!r}, got {sorted(ids) or 'none'}")
            continue
        # Assert the SEVERITY too. Exit status depends only on `blocking`, so a
        # rule silently downgraded to `info` disables the gate while this suite
        # still reports every case passing.
        for d in diags:
            if d.rule_id == expected and d.severity != expected_severity[expected]:
                failures.append(
                    f"{expected} emitted severity {d.severity!r}, expected "
                    f"{expected_severity[expected]!r} for {text!r}"
                )

    # Every rule must have at least one positive case. Without this, deleting a
    # rule outright leaves the suite green.
    covered = {expected for _, _, expected in SELFTEST_CASES if expected}
    for rule in RULES:
        if rule.rule_id not in covered:
            failures.append(f"{rule.rule_id} has no positive selftest case")

    # The soft-wrap join (§6.2 step 2): a phrase split across a hard wrap whose
    # second line is a continuation must still be found.
    wrapped = "The record is kept in an immutable\naudit trail forever.\n"
    if not any(d.rule_id == "CLAIM-ABS-09" for d in scan_text("<w>", wrapped)):
        failures.append("soft-wrap join failed to reassemble 'immutable audit'")

    # ...and must NOT join across a genuine block start on the second line.
    not_wrapped = "The record is immutable\n- audit trails are pruned.\n"
    if any(d.rule_id == "CLAIM-ABS-09" for d in scan_text("<w2>", not_wrapped)):
        failures.append("soft-wrap join crossed a block start")

    # NEG clamp (§5.6): a negation in a PREVIOUS list item must not suppress a
    # violation on the next line. This is the measured README.md:134-135 case.
    clamped = (
        "- **Sidecar proxy** — intercepts outbound HTTPS without code changes.\n"
        "- **eBPF** — catches everything else, including bypass attempts.\n"
    )
    if not any(d.rule_id == "CLAIM-ABS-01" for d in scan_text("<c>", clamped)):
        failures.append("NEG window was not clamped to the clause; a true positive was lost")

    for failure in failures:
        print(f"selftest FAIL: {failure}")
    if failures:
        print(f"\ncheck_claim_vocabulary --selftest: {len(failures)} failure(s).")
        return 1
    print(
        f"check_claim_vocabulary --selftest: {len(SELFTEST_CASES) + 3} table case(s) "
        f"+ 3 inline check(s) passed; {len(RULES)} rule(s) have positive coverage."
    )
    return 0


if __name__ == "__main__":
    # An internal error must not exit 1. In a gate, 1 means "a blocking claim was
    # found"; a crash that also exits 1 is a false positive that looks exactly
    # like a real finding, and a crash that exits 0 is worse. Reserve 2 for
    # "the checker itself failed" so CI can tell the three apart.
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — deliberate top-level boundary
        print(f"check_claim_vocabulary: internal error: {exc!r}", file=sys.stderr)
        sys.exit(2)
