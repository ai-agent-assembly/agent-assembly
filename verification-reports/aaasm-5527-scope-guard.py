#!/usr/bin/env python3
"""Consistency guard for the AAASM-5527 coverage matrix.

Run before pushing any change to either AAASM-5527 artifact:

    python3 verification-reports/aaasm-5527-scope-guard.py

Why this exists
---------------
Across three review rounds the artifact produced the same defect four times, in
four different places, and it always had one shape: **a correct local
observation, or a correct local correction, applied to one site and not to its
siblings.** The original `reachable_in_release` boolean, the rc.6 rescoping, the
macOS proxy scoping that reached the prose and not the manifest, and two
markdown notes that silently failed to insert — all the same shape.

So the rules below are not general hygiene. Each one is a specific defect that
actually shipped, turned into an assertion.

What it does NOT do
-------------------
It reconciles the two artifacts against each other and against their own stated
counts. It cannot read prose for meaning: a sentence can be grammatical,
well-cited and still wrong, and a stranded clause that silently drops a scope
statement will pass every check here. A PASS is "the two files agree and their
counts are real", never "the document is correct".

Known ways this guard can PASS while something is wrong
-------------------------------------------------------
Found by review after the guard shipped. Recorded so the next person does not
over-trust an exit code. Routed to AAASM-5531 / AAASM-5536 rather than fixed
here, because hardening the guard is manifest work, not artifact work.

1. **A deleted Coverage term passes unnoticed.** The Markdown/YAML comparison
   skips any row whose cell carries no bolded term (`if not want or not seen:
   continue`), which is why it compares 79 rows and not 80 — `N5` legitimately
   splits its coverage across a qualifier. Deleting a term outright would look
   identical to that. Fix: assert presence, with `N5` allowlisted.
2. **An extra, stronger term alongside the correct one passes.** The check is
   `want in seen`, so a cell reading `**Denied before execution** / **Redacted**`
   would have satisfied it — exactly the shape of blocker A. Fix: compare the
   cell's term set against `{coverage} | set(qualifiers.values())` exactly.
3. **`RETRACTED` is hand-maintained.** It caught blockers A, C, D and I because
   someone remembered to add those phrases, and missed the fifth separator-
   citation site because nobody added `1071-1092` — in the same round the guard
   was introduced. Fix: generate the list from the "Correction to an earlier
   revision" blocks the document already contains.
4. **The section split is heading-level fragile.** `md.split("## Covered by an
   existing issue")` works only because `##` is a substring of `###` — the same
   fragility that made two notes silently fail to insert in round 2 — and raises
   `IndexError` rather than failing cleanly on a miss. Fix: anchor on
   `^#{2,4} ` and assert the section was found.
5. **`RETRACTION_CONTEXT` is line-scoped.** A genuinely fresh assertion passes if
   its line happens to contain the word "correction".
6. **Nothing runs this.** `verification-reports/**` appears in no workflow's
   `on.*.paths`, so this is pre-push discipline, not a CI gate. Treat an
   unexecuted guard as absent.
"""

from __future__ import annotations
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent
MD = ROOT / "AAASM-5527-capability-coverage-matrix-and-threat-model.md"
YML = ROOT / "AAASM-5527-capability-coverage-matrix.yaml"

# ADR 0033 §6 term -> the Title Case form used in the Markdown cells.
TERM_MD = {
    "observed": "Observed",
    "detected": "Detected",
    "evaluated": "Evaluated",
    "denied_before_execution": "Denied before execution",
    "redacted": "Redacted",
    "approval_required": "Approval required",
    "degraded": "Degraded",
    "unmeasured": "Unmeasured",
    "experimental": "Experimental",
    "planned": "Planned",
    "unsupported": "Unsupported",
}

# Sentences this artifact has retracted. Each must appear NOWHERE in either
# file — a retraction that reaches the note and not the row is the dominant
# failure mode, and it produced blockers A, C and D in round 3 alone.
RETRACTED = [
    "reachable_in_release",
    "not in the release artifact set",
    "unreachable in a released build",
    "The only supported route to M1",
    "the only supported way to get M1",
    "a tokenless call keeps the client-supplied org/team",
    "Six Python adapters",
    "lifecycle.rs:1354",
    "as published at v0.0.1-rc.6",
    "Epic exit criterion",
    "14 targets",
    # Added after it shipped past the guard in the very round the guard was
    # introduced — the fifth site of the separator-residual citation. This is
    # the entry that proves limitation 3 below is real, not theoretical.
    "1071-1092",
]
# Occurrences that are legitimately explaining the retraction rather than
# repeating the claim. Keyed by substring of the surrounding line.
RETRACTION_CONTEXT = (
    "earlier revision", "Withdrawn", "withdrawn", "Correction", "correction",
    "Replaces a boolean", "was wrong", "which conflated", "RETRACTED",
)


def main() -> int:
    md = MD.read_text()
    doc = yaml.safe_load(YML.read_text())
    rows = doc["capabilities"]
    schema = doc["schema"]
    enums = schema["enums"]
    cov_terms = set(enums["coverage"])
    fail: list[str] = []
    note: list[str] = []

    def check(cond, msg):
        if not cond:
            fail.append(msg)

    # ── 1. schema integrity ────────────────────────────────────────────────
    declared = set(schema["required_fields"]) | set(schema["recommended_additions"]) | {"id", "domain"}
    for key in sorted({k for r in rows for k in r} - declared):
        fail.append(f"undeclared field: {key}")
    for field, allowed in enums.items():
        if not isinstance(allowed, list):
            continue
        for r in rows:
            v = r.get(field)
            if v is None:
                continue
            for x in (v if isinstance(v, list) else [v]):
                check(x in allowed, f"{r['id']}: {field} = {x!r} outside its enum")
    for r in rows:
        for aspect, term in (r.get("coverage_qualifiers") or {}).items():
            check(term in cov_terms, f"{r['id']}: coverage_qualifiers.{aspect} = {term!r} outside the ADR 0033 §6 enum")

    ids = [r["id"] for r in rows]
    check(len(ids) == len(set(ids)), "duplicate row ids")
    note.append(f"{len(rows):>4}  rows, schema clean")

    # ── 2. reachability is per channel AND per platform ────────────────────
    # The original defect. released_matrix must reconcile with the flat fields.
    matrixed = [r for r in rows if r.get("released_matrix")]
    for r in matrixed:
        m = r["released_matrix"]
        check(set(m) == set(r.get("released_channels") or []),
              f"{r['id']}: released_matrix keys != released_channels")
        union = set().union(*m.values()) if m else set()
        check(union == set(r.get("released_platforms") or []),
              f"{r['id']}: released_matrix platform union != released_platforms")
        check("macos" not in m.get("homebrew", []),
              f"{r['id']}: claims macOS via homebrew — aa-proxy is Linux-only packaged (release.yml:274)")
    note.append(f"{len(matrixed):>4}  rows carry a channel x platform matrix, all reconciling")
    note.append(f"{sum(1 for r in rows if r.get('reachability') == 'shipped_crates_io_only'):>4}  crates.io-only rows")

    # ── 3. THE ROUND-3 RULE: a coverage change must reach every site ───────
    # Blocker A: C2 was retyped in the YAML and not the Markdown.
    md_cov = {}
    for line in md.splitlines():
        m = re.match(r"\|\s+\*\*([A-Z]+\d+)\*\*\s+\|", line)
        if not m:
            continue
        cells = [c.strip() for c in line.split("|")]
        hits = [t for t in TERM_MD.values() if f"**{t}**" in line]
        if hits:
            md_cov.setdefault(m.group(1), set()).update(hits)
    compared = 0
    for r in rows:
        want = TERM_MD.get(r.get("coverage"))
        seen = md_cov.get(r["id"])
        if not want or not seen:
            continue
        compared += 1
        check(want in seen,
              f"{r['id']}: YAML coverage={r['coverage']!r} but the Markdown cell carries {sorted(seen)} "
              f"and not '{want}' — a retype that reached one file only")
    note.append(f"{compared:>4}  rows with a Markdown Coverage cell, all agreeing with the YAML")

    # ── 4. the row-count table must be real, not stale ─────────────────────
    # Blocker C: the table said "machine-counted" and was two terms out of date.
    # Both distributions summed to 80, so a total-only check passed wrongly.
    actual: dict[str, int] = {}
    for r in rows:
        actual[r["coverage"]] = actual.get(r["coverage"], 0) + 1
    tbl = re.search(r"\| Coverage \(ADR 0033 §6\) \| Rows \|\n\|[-| ]+\|\n((?:\|.*\n)+)", md)
    if not tbl:
        fail.append("row-count table not found — it is cited as machine-counted and must be parseable")
    else:
        stated: dict[str, int] = {}
        for line in tbl.group(1).strip().splitlines():
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if len(cells) != 2:
                continue
            label = cells[0].replace("**", "").strip()
            try:
                n = int(cells[1])
            except ValueError:
                continue
            for term, disp in TERM_MD.items():
                if label == disp:
                    stated[term] = n
        for term, n in sorted(stated.items()):
            check(actual.get(term, 0) == n,
                  f"row-count table says {TERM_MD[term]} = {n}, YAML has {actual.get(term, 0)}")
        missing = {t for t, n in actual.items() if n and t not in stated}
        check(not missing, f"row-count table omits non-zero terms: {sorted(missing)}")
        note.append(f"{len(stated):>4}  coverage terms in the row-count table, all matching the YAML")

    # ── 5. a retracted claim must appear nowhere as a live assertion ───────
    # Blocker D: F7's retraction reached the note and not the follow-up row.
    for phrase in RETRACTED:
        for path in (MD, YML):
            for i, line in enumerate(path.read_text().splitlines(), 1):
                if phrase in line and not any(c in line for c in RETRACTION_CONTEXT):
                    fail.append(f"{path.name}:{i}: retracted claim still asserted: {phrase!r}")
    note.append(f"{len(RETRACTED):>4}  retracted claims, none re-asserted")

    # ── 6. prose counts that name a row set must be machine-true ───────────
    m = re.search(r"(\d+) existing issues, (\d+) new follow-ups, (\d+) accepted limitations", md)
    if m:
        seg = md.split("## Covered by an existing issue")[1].split("## New follow-ups")[0]
        n_tbl = len([l for l in seg.splitlines() if l.startswith("| ") and "---" not in l]) - 1
        check(int(m.group(1)) == n_tbl,
              f"prose says {m.group(1)} existing issues; the table has {n_tbl}")
        note.append(f"{n_tbl:>4}  existing-issue rows, matching the prose")

    for label, flag in (("Q3", "q3_changed_answer"), ("Q4", "q4_changed_answer")):
        # Count DISTINCT rows: a row appears in both its domain tables, so raw
        # occurrence counts double some rows and would fail for the wrong reason.
        md_ids = set()
        for line in md.splitlines():
            m = re.match(r"\|\s+\*\*([A-Z]+\d+)\*\*\s+\|", line)
            if m and f"⚠ {label}" in line:
                md_ids.add(m.group(1))
        y_ids = {r["id"] for r in rows if r.get(flag)}
        check(y_ids == md_ids,
              f"{label}: YAML flags {sorted(y_ids - md_ids)} that the Markdown does not, "
              f"and the Markdown flags {sorted(md_ids - y_ids)} that the YAML does not")
    n_up = sum(1 for r in rows if r.get("q4_changed_answer_in_product_favour"))
    m_up = re.search(r"(three|two|four) corrections upward", md)
    if m_up:
        want = {"two": 2, "three": 3, "four": 4}[m_up.group(1)]
        check(n_up == want, f"prose says {m_up.group(1)} corrections upward; YAML flags {n_up}")
    note.append(f"{n_up:>4}  corrections-upward flags, matching the prose")

    # ── 7. every cross-reference to a note must resolve ────────────────────
    # Two notes silently failed to insert in round 2 because the heading level
    # had changed under the marker. No link check can see this: it is prose.
    for what, needle in (
        ("T3 privilege note", "spawn_ebpf_tls"),
        ("P3 tautology note", "pass-through tautology"),
        ("rc.6 divergence table", "still live in the published rc.6"),
        ("channel scoping section", "Reachability is per channel and per platform"),
    ):
        check(needle in md, f"{what}: the text it points at is absent ({needle!r})")
    note.append(f"{4:>4}  cross-referenced notes, all present")

    # ── report ─────────────────────────────────────────────────────────────
    for line in note:
        print(line)
    if fail:
        print(f"\nFAIL — {len(fail)} problem(s):")
        for f in fail:
            print("  -", f)
        return 1
    print("\nscope guard: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
