#!/usr/bin/env python3
"""Emit docs/release/qa-signoff/v<version>.evidence.json (AAASM-5878/5898).

This is the machine-readable half of the release-QA sign-off — it exists so
a later checker (AAASM-5900, not built by this subtask) can bind a release
candidate SHA, an exact `qa/golden-journeys.yaml` requirements set, and each
required journey's result together instead of a human re-deriving that
binding from prose. Subtask A (this script) does no gating: it faithfully
records whatever the existing sign-off artifacts already say, including a
BLOCK verdict, and never invents leniency to make its own output look green.

Inputs (all pre-existing artifacts — this does not introduce a new
hand-authored input):
  - `qa/golden-journeys.yaml` — the release-blocking requirement set
    (AAASM-5874 registry fields), via `registry_digest.py`.
  - `docs/release/qa-signoff/v<version>.md` — the committed QA sign-off.
    Per-journey status is read from its "Selected journeys" table (the
    durable record of each AAASM-5819/5828 worker's compact
    `STATUS: COMPLETE | PARTIAL | BLOCKED` result — that schema itself is
    prose meant to live only in a coordinator's context for one run, per
    docs/src/qa/evidence-and-worker-result-contract.md; the sign-off table
    is where its per-journey verdict already lands durably, so that table —
    not a new artifact — is this script's real input).
  - `docs/release/security-signoff/v<version>.md` — for the `signoffs`
    cross-reference only; this script does not re-derive a security verdict.

Usage:
  python3 scripts/qa/build-release-evidence.py --version 0.0.1-rc.7
  python3 scripts/qa/build-release-evidence.py --version 0.0.1-rc.7 \
      --candidate-sha <sha>   # override `git rev-parse HEAD`, for testing

Writes docs/release/qa-signoff/v<version>.evidence.json.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from typing import Any

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry_digest  # noqa: E402  (sys.path must be set first)

# The scripts whose behavior this evidence record's truth actually depends
# on: registry_digest.py computes the digests embedded below,
# build-release-evidence.py (this file) assembles the record, and
# validate-golden-journeys.py is what enforces the registry fields the
# digests are taken over. Pinning their blob SHAs means a later checker can
# tell "the harness changed since this evidence was generated" apart from
# "the catalog changed" — the two invalidation reasons need to stay
# distinguishable, not collapsed into one generic staleness flag.
HARNESS_SCRIPTS = [
    "scripts/qa/registry_digest.py",
    "scripts/qa/build-release-evidence.py",
    "scripts/qa/validate-golden-journeys.py",
]

_STATUS_TOKEN_RULES: list[tuple[str, str]] = [
    # Order matters: checked top to bottom, first match wins. Two distinct
    # concerns drive the order, and both must hold:
    #
    #  1. A rule whose token is a substring of a later rule's token (e.g.
    #     "UNTESTED_OR_BLOCKED" contains "BLOCKED") must be listed first.
    #
    #  2. FAIL/BLOCKED must be checked before PASS. A Result cell's prose
    #     routinely narrates a failure using language that itself contains
    #     the word "pass" with no relation to the row's actual status (e.g.
    #     "the PASS criteria were not met", "cannot run until PASS criteria
    #     are defined") — checking PASS first would let that unrelated
    #     substring silently overrule the row's real FAIL/BLOCKED token,
    #     which is exactly the "non-PASS states ... cannot silently become
    #     PASS" failure AAASM-5878's AC exists to prevent. PASS itself has
    #     no equivalent risk of masking a real failure (a genuinely-passing
    #     row's prose has no reason to also contain "FAIL"/"BLOCKED"), so
    #     checking the higher-severity tokens first is safe both ways.
    (r"UNTESTED_OR_BLOCKED", "UNTESTED"),
    (r"\bPARTIAL\b", "UNTESTED"),
    (r"\bFAILS?\b", "FAIL"),
    (r"\bBLOCKED\b", "BLOCKED"),
    (r"\bPASS\b", "PASS"),
    (r"\bSKIPPED\b", "SKIPPED"),
    (r"\bXFAIL\b|\bKNOWN[- ]FAIL\b", "XFAIL"),
    (r"\bSTALE\b", "STALE"),
    (r"\bUNTESTED\b", "UNTESTED"),
]

VALID_STATUSES = {
    "PASS", "FAIL", "BLOCKED", "SKIPPED", "XFAIL", "NOT_RUN", "UNTESTED", "STALE",
}


def _run_git(repo_root: str, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", repo_root, *args], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _load_catalog(catalog_path: str) -> list[dict[str, Any]]:
    with open(catalog_path) as f:
        doc = yaml.safe_load(f)
    return doc.get("journeys", [])


def _extract_selected_journeys_table(md_text: str) -> dict[str, str]:
    """Map journey id -> raw "Result" markdown cell text from the sign-off's
    "Selected journeys" table.

    The Result column is located by its header text, not by a hardcoded cell
    index — a reordered or inserted column (e.g. Evidence moving ahead of
    Result) would otherwise make this silently start reading the wrong
    cell, and the real sign-off's Evidence prose routinely contains the word
    "PASS" for journeys whose actual Result is something else. Only that one
    column is returned raw; `_map_journey_status` below turns it into the
    8-token vocabulary. Rows outside a `| J<n> | ... |` shape (the header
    row, the `|---|---|` separator) are skipped.
    """
    section = re.search(r"^## Selected journeys\n(.*?)(?=\n## |\Z)", md_text, re.S | re.M)
    if not section:
        return {}
    table_lines = [
        line.strip() for line in section.group(1).splitlines() if line.strip().startswith("|")
    ]
    if not table_lines:
        return {}
    header_cells = [c.strip() for c in table_lines[0].strip("|").split("|")]
    result_idx = next(
        (i for i, c in enumerate(header_cells) if c.strip().lower() == "result"), None
    )
    if result_idx is None:
        raise ValueError(
            "Selected journeys table has no 'Result' column header — found "
            f"columns {header_cells!r}"
        )
    results: dict[str, str] = {}
    for line in table_lines[1:]:
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) <= result_idx:
            continue
        jid = cells[0]
        if not re.match(r"^J\d+[A-Za-z]?$", jid):
            continue  # not a data row (header, separator, malformed row)
        results[jid] = cells[result_idx]
    return results


def _map_journey_status(jid: str, raw_cell: str) -> str:
    """Map one sign-off table "Result" cell to the 8-token status vocabulary.

    The sign-off table is prose written for humans, not a clean enum — a
    re-verified row reads like
    `~~UNTESTED_OR_BLOCKED~~ -> **PASS (re-verified)**` (struck-through
    original finding, arrow, final call). Only the text after the last
    `->`/`→` is the row's *final* call; text before it is a superseded
    finding and must not leak into the status. See
    docs/src/qa/release-qa-policy.md's status-vocabulary mapping table for
    the full 5828-worker-schema -> evidence-enum mapping this mirrors.

    `NOT_RUN` is reserved for a journey genuinely absent from the table (the
    "selected-but-absent -> NOT_RUN" rule) — a row that IS present but whose
    text this parser cannot classify must fail loudly instead of silently
    collapsing into `NOT_RUN`. Otherwise a reworded result, a new vocabulary
    token, or a reordered column would be indistinguishable from "this
    journey was never run at all," which a later checker's exception
    handling could launder into an admissible non-result — exactly the
    failure this campaign exists to prevent, inverted.
    """
    text = raw_cell
    for arrow in ("→", "->"):
        if arrow in text:
            text = text.rsplit(arrow, 1)[1]
    text = text.replace("~~", "").replace("**", "").replace("*", "")
    upper = text.upper()
    for pattern, status in _STATUS_TOKEN_RULES:
        if re.search(pattern, upper):
            return status
    raise ValueError(
        f"{jid}: could not classify sign-off Result cell into the status "
        f"vocabulary — raw cell: {raw_cell!r}"
    )


def _extract_verdict_line(md_text: str) -> str | None:
    m = re.search(r"^Verdict:\s*(\S+)\s*$", md_text, re.M)
    return m.group(1) if m else None


def build_evidence(
    version: str,
    repo_root: str,
    candidate_sha: str | None,
    catalog_path: str,
    qa_signoff_path: str,
    security_signoff_path: str,
) -> dict[str, Any]:
    entries = _load_catalog(catalog_path)
    catalog_doc = yaml.safe_load(open(catalog_path))

    required = sorted(
        (
            e
            for e in entries
            if e.get("release_blocking", False) and e.get("lifecycle_state") != "retired"
        ),
        key=lambda e: e["id"],
    )
    requirements_digest = registry_digest.catalog_requirements_digest(entries)

    qa_signoff_text = ""
    if os.path.isfile(qa_signoff_path):
        with open(qa_signoff_path) as f:
            qa_signoff_text = f.read()
    else:
        print(f"warning: {qa_signoff_path} not found — every required journey "
              f"will be recorded NOT_RUN", file=sys.stderr)
    table = _extract_selected_journeys_table(qa_signoff_text)

    journeys = []
    for entry in required:
        jid = entry["id"]
        raw_cell = table.get(jid)
        status = _map_journey_status(jid, raw_cell) if raw_cell is not None else "NOT_RUN"
        assert status in VALID_STATUSES, f"{jid}: mapped to invalid status {status!r}"
        journeys.append({
            "id": jid,
            "status": status,
            "digest": registry_digest.per_journey_digest(entry),
            "lifecycle_state": entry.get("lifecycle_state"),
            "execution_lanes": sorted(entry.get("execution_lanes") or []),
            "fidelity": entry.get("fidelity"),
            "platforms": sorted(entry.get("platforms") or []),
            "negative_control": entry.get("negative_control") or None,
            "evidence_ref": raw_cell,
        })

    if candidate_sha is None:
        candidate_sha = _run_git(repo_root, "rev-parse", "HEAD")

    harness = {}
    for path in HARNESS_SCRIPTS:
        try:
            harness[path] = "git-blob:" + _run_git(repo_root, "rev-parse", f"HEAD:{path}")
        except subprocess.CalledProcessError:
            harness[path] = None
            print(f"warning: could not resolve HEAD:{path} for harness digest", file=sys.stderr)

    def _signoff_entry(path: str) -> dict[str, Any]:
        verdict = None
        if os.path.isfile(path):
            with open(path) as f:
                verdict = _extract_verdict_line(f.read())
        else:
            print(f"warning: sign-off {path} not found", file=sys.stderr)
        return {"path": path, "verdict": verdict}

    all_pass = bool(journeys) and all(j["status"] == "PASS" for j in journeys)

    return {
        "evidence_version": "1",
        "version": version,
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "candidate": {
            "repo": "ai-agent-assembly/agent-assembly",
            "candidate_sha": candidate_sha,
        },
        "catalog": {
            "path": os.path.relpath(catalog_path, repo_root) if os.path.isabs(catalog_path) else catalog_path,
            "catalog_version": str(catalog_doc.get("catalog_version", "")),
            "requirements_digest": requirements_digest,
        },
        "harness": harness,
        "journeys": journeys,
        "signoffs": {
            "qa": _signoff_entry(qa_signoff_path),
            "security": _signoff_entry(security_signoff_path),
        },
        "artifacts": {},
        "published": None,
        "verdict": "PASS" if all_pass else "BLOCK",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="e.g. 0.0.1-rc.7")
    parser.add_argument("--candidate-sha", default=None,
                         help="override 'git rev-parse HEAD' (testing / fixture generation)")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--catalog", default=None,
                         help="default: <repo-root>/qa/golden-journeys.yaml")
    parser.add_argument("--qa-signoff", default=None,
                         help="default: <repo-root>/docs/release/qa-signoff/v<version>.md")
    parser.add_argument("--security-signoff", default=None,
                         help="default: <repo-root>/docs/release/security-signoff/v<version>.md")
    parser.add_argument("--out", default=None,
                         help="default: <repo-root>/docs/release/qa-signoff/v<version>.evidence.json")
    args = parser.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    catalog_path = args.catalog or os.path.join(repo_root, "qa", "golden-journeys.yaml")
    qa_signoff_path = args.qa_signoff or os.path.join(
        repo_root, "docs", "release", "qa-signoff", f"v{args.version}.md"
    )
    security_signoff_path = args.security_signoff or os.path.join(
        repo_root, "docs", "release", "security-signoff", f"v{args.version}.md"
    )
    out_path = args.out or os.path.join(
        repo_root, "docs", "release", "qa-signoff", f"v{args.version}.evidence.json"
    )

    try:
        evidence = build_evidence(
            version=args.version,
            repo_root=repo_root,
            candidate_sha=args.candidate_sha,
            catalog_path=catalog_path,
            qa_signoff_path=qa_signoff_path,
            security_signoff_path=security_signoff_path,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    with open(out_path, "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"wrote {out_path} (verdict: {evidence['verdict']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
