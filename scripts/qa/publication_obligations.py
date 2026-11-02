#!/usr/bin/env python3
"""Shared publication-obligation validation for release-evidence records (AAASM-6419).

A journey whose verification genuinely needs a published artifact cannot be
PASS before publication, and a blanket waiver is the wrong tool (it excuses
the check instead of recording that it is still owed). The release gate
therefore has a third, narrow state: `PUBLICATION_PENDING`, admitted only
when a committed obligation record says exactly what is still owed, what was
already verified on the candidate, and what happens if the post-publication
check fails.

Like `registry_digest.py`, this lives in one importable module so the emitter
(`build-release-evidence.py`) and the verifier (`check-release-evidence.py`)
cannot drift on what an admissible obligation is. The checker never trusts the
emitter's output: it re-runs `validate_obligation` against the obligation file
read from git and the registry entry at the tag target.

Safety invariant: nothing here (or anywhere that imports it) turns pending
into PASS. A pending row yields the `CANDIDATE_VERIFIED` verdict, which the
checker reports with a distinct non-zero exit code so every consumer that
requires exit 0 (release.yml's evidence gate, release-tag-guard.sh) keeps
refusing.
"""
from __future__ import annotations

import re
from typing import Any

PENDING_STATUS = "PUBLICATION_PENDING"
PENDING_FIDELITY = "published_artifact"
CANDIDATE_STATUS_OK = "PASS"
# Candidate-side checks run before publication, so they cannot themselves claim
# the one fidelity that requires a published artifact.
CANDIDATE_FIDELITIES = {
    "mock", "controlled_fake", "real_local_process", "container",
}


DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_PENDING_TOKEN_RE = re.compile(r"\bPUBLICATION_PENDING\b")


def final_call(raw_cell: str) -> str:
    """Upper-cased text of a sign-off Result cell's final call: after the last
    arrow, markdown emphasis stripped. Mirrors what the emitter classifies, so
    the emitter and the checker agree on which text decides a row."""
    text = raw_cell or ""
    for arrow in ("→", "->"):
        if arrow in text:
            text = text.rsplit(arrow, 1)[1]
    return text.replace("~~", "").replace("**", "").replace("*", "").upper()


def cell_claims_pending(raw_cell: str) -> bool:
    return bool(_PENDING_TOKEN_RE.search(final_call(raw_cell)))


# A pending cell whose prose ALSO names any other state is ambiguous, and the
# token rules would let PUBLICATION_PENDING win over a non-FAIL/BLOCKED word
# (`\bFAILS?\b` does not match FAILED/FAILURE, `\bBLOCKED\b` not BLOCKING).
# An ambiguous pending cell is refused rather than guessed at.
_CONFLICTING_STATE_RE = re.compile(
    r"\bFAIL\w*|\bBLOCK\w*|\bUNTESTED\w*|\bPARTIAL\w*|\bSKIPPED\b|\bXFAIL\b|\bSTALE\b|\bNOT_RUN\b"
)


def pending_cell_conflict(raw_cell: str) -> str | None:
    m = _CONFLICTING_STATE_RE.search(final_call(raw_cell))
    return m.group(0) if m else None


def obligation_path(version: str) -> str:
    return f"docs/release/qa-signoff/v{version}.publication-obligations.json"


def _nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def index_obligations(doc: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Map journey id -> obligation entry from a parsed obligation file, plus
    structural problems (duplicate ids, wrong shape)."""
    problems: list[str] = []
    if not isinstance(doc, dict) or not isinstance(doc.get("journeys"), list):
        return {}, ["obligation file must be an object with a 'journeys' list"]
    out: dict[str, dict[str, Any]] = {}
    for entry in doc["journeys"]:
        jid = entry.get("journey") if isinstance(entry, dict) else None
        if not _nonempty_str(jid):
            problems.append("obligation entry without a 'journey' id")
            continue
        if jid in out:
            problems.append(f"duplicate obligation entry for journey {jid}")
            continue
        out[jid] = entry
    return out, problems


def validate_obligation(
    jid: str,
    obligation: dict[str, Any],
    catalog_entry: dict[str, Any],
    expected_registry_digest: str,
) -> list[str]:
    """Problems that make `obligation` inadmissible for journey `jid`.

    `catalog_entry` is the journey's registry entry at the commit being
    checked, never anything read from the evidence record.
    """
    p: list[str] = []

    if catalog_entry.get("fidelity") != PENDING_FIDELITY:
        p.append(
            f"journey {jid} fidelity is {catalog_entry.get('fidelity')!r}; only "
            f"{PENDING_FIDELITY!r} journeys can owe a publication check"
        )

    declared = catalog_entry.get("publication_checks")
    declared_ids: list[str] = []
    if not isinstance(declared, list) or not declared:
        p.append(f"journey {jid} registry entry declares no publication_checks")
    else:
        declared_ids = [c.get("id") for c in declared if isinstance(c, dict)]

    if obligation.get("registry_digest") != expected_registry_digest:
        p.append(f"journey {jid} obligation registry_digest does not match the registry entry")

    pending = obligation.get("pending_checks")
    pending_ids: list[str] = []
    if not isinstance(pending, list) or not pending:
        p.append(f"journey {jid} obligation has no pending_checks")
    else:
        for c in pending:
            if not isinstance(c, dict):
                p.append(f"journey {jid} has a malformed pending check")
                continue
            for field in ("id", "channel", "why_publication_only", "command", "expected"):
                if not _nonempty_str(c.get(field)):
                    p.append(f"journey {jid} pending check {c.get('id')!r} is missing {field!r}")
            pending_ids.append(c.get("id"))
        if len(set(pending_ids)) != len(pending_ids):
            p.append(f"journey {jid} obligation has duplicate pending check ids")
    if sorted(map(str, pending_ids)) != sorted(map(str, declared_ids)):
        p.append(
            f"journey {jid} obligation pending_checks ids {sorted(map(str, pending_ids))} do "
            f"not equal registry publication_checks ids {sorted(map(str, declared_ids))}"
        )

    candidate = obligation.get("candidate_checks")
    cand_ids: list[str] = []
    if not isinstance(candidate, list) or not candidate:
        p.append(f"journey {jid} obligation has no candidate_checks — nothing was verified pre-publication")
    else:
        saw_negative_control = False
        for c in candidate:
            if not isinstance(c, dict):
                p.append(f"journey {jid} has a malformed candidate check")
                continue
            cand_ids.append(c.get("id"))
            if not _nonempty_str(c.get("id")):
                p.append(f"journey {jid} has a candidate check with no id")
            if c.get("status") != CANDIDATE_STATUS_OK:
                p.append(
                    f"journey {jid} candidate check {c.get('id')!r} status is "
                    f"{c.get('status')!r}, not {CANDIDATE_STATUS_OK}"
                )
            if c.get("fidelity") not in CANDIDATE_FIDELITIES:
                p.append(
                    f"journey {jid} candidate check {c.get('id')!r} fidelity "
                    f"{c.get('fidelity')!r} is not a pre-publication fidelity"
                )
            if not _nonempty_str(c.get("evidence_ref")):
                p.append(f"journey {jid} candidate check {c.get('id')!r} has no evidence_ref")
            if _nonempty_str(c.get("negative_control")):
                saw_negative_control = True
            # Every candidate check here claims PASS before publication, so it
            # must name the exact artifacts it verified: an obligation with no
            # digests would admit a CANDIDATE_VERIFIED record that is bound to
            # nothing. Format only: no candidate build-digest manifest exists
            # to cross-check against (documented gap, Core ADR 0042).
            digests = c.get("artifact_digests")
            if not (
                isinstance(digests, dict)
                and digests
                and all(_nonempty_str(k) and isinstance(v, str) and DIGEST_RE.fullmatch(v)
                        for k, v in digests.items())
            ):
                p.append(
                    f"journey {jid} candidate check {c.get('id')!r} must carry a non-empty "
                    "artifact_digests map of name -> sha256:<64 hex>"
                )
        if len(set(cand_ids)) != len(cand_ids):
            p.append(f"journey {jid} obligation has duplicate candidate check ids")
        if set(cand_ids) & set(pending_ids):
            p.append(f"journey {jid} reuses an id as both a candidate and a pending check")
        if catalog_entry.get("negative_control") and not saw_negative_control:
            p.append(
                f"journey {jid} registry declares a negative_control but no candidate check "
                "records one"
            )

    deps = obligation.get("depends_on")
    if not isinstance(deps, list) or not all(
        isinstance(d, dict) and _nonempty_str(d.get("repo")) and _nonempty_str(d.get("event"))
        for d in deps
    ):
        p.append(f"journey {jid} obligation depends_on must be a list of {{repo, event}}")

    fr = obligation.get("failure_response")
    if not isinstance(fr, dict):
        p.append(f"journey {jid} obligation has no failure_response")
    else:
        actions = fr.get("proposed_actions")
        notify = fr.get("notify")
        hours = fr.get("deadline_hours")
        if not (isinstance(actions, list) and actions and all(_nonempty_str(a) for a in actions)):
            p.append(f"journey {jid} failure_response.proposed_actions must be a non-empty list")
        if not (isinstance(notify, list) and notify and all(_nonempty_str(a) for a in notify)):
            p.append(f"journey {jid} failure_response.notify must be a non-empty list")
        if not (isinstance(hours, int) and not isinstance(hours, bool) and hours > 0):
            p.append(f"journey {jid} failure_response.deadline_hours must be a positive integer")

    return p


def candidate_artifact_digests(obligation: dict[str, Any]) -> dict[str, dict[str, str]]:
    """check id -> artifact digests, for the evidence record's `artifacts`
    field. Derived, never hand-authored, so the checker can recompute it."""
    out: dict[str, dict[str, str]] = {}
    for c in obligation.get("candidate_checks") or []:
        if isinstance(c, dict) and c.get("artifact_digests"):
            out[c["id"]] = dict(sorted(c["artifact_digests"].items()))
    return out
