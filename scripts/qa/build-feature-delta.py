#!/usr/bin/env python3
"""Feature-delta discovery: Jira/Git/PR reconciliation (AAASM-5843).

Answers "what product capabilities actually completed in the baseline to
candidate window" by cross-checking two individually-unreliable signals
against each other instead of trusting either alone:

  * Jira status ("Done") can be set with the implementation PR still open,
    or with the ticket's only remaining item being this Epic's own QA-gate
    sign-off (circular — see the anti-circularity rule below).
  * A merged PR title matching "[<ticket>]" can reference work that never
    reached the candidate build (PR merged to a stale branch, cherry-picked
    elsewhere, or the candidate build predates the merge).

A ticket is only ``RELEASE_ELIGIBLE`` when Jira status, a real merged PR,
and that PR's merge commit being an actual ancestor of candidate HEAD all
agree.

Tool choice: bash + jq (matching build-verification-manifest.sh's style) was
considered first but rejected — this repo has no existing bash-based Jira
REST access pattern, ADF (Atlassian Document Format) description/comment
bodies need real tree-walking to extract plain text for the anti-circularity
check, and Python's stdlib (``urllib``, ``json``) handles that far more
robustly than jq. No new dependency is introduced: only ``urllib.request``
(stdlib) is used for the Jira REST calls, not ``requests`` (not installed in
this environment).

Jira access: read-only calls against ``$JIRA_URL/rest/api/3/...`` — reads
are fine on API v3 (only writes need ADF bodies, and this script performs
none). Search uses ``POST /rest/api/3/search/jql`` — the legacy
``GET /rest/api/2/search`` endpoint is gone (410) and must not be used.
Auth: HTTP Basic with ``$JIRA_USERNAME`` / ``$JIRA_API_TOKEN`` (an Atlassian
API token, not a password) against ``$JIRA_URL``. These three env vars are
this repo's only Jira-access convention (there was no prior one to match).

Selection strategy: a bounded ``resolutiondate`` lookback window with
``status = Done`` is the *primary* strategy, not ``fixVersion`` — verified
empirically against this ticket's own real ground-truth window (2026-08-23):
of AAASM-5819/5831/5832/5833, two (5832, 5833) have an *empty* fixVersions
field despite being real, shipped, merged fixes for v0.0.1-rc.7. Requiring
fixVersion as the primary key would have silently dropped them. ``--fix-
version`` remains available as an opt-in override for a release lineage
where the field is populated consistently.

Usage:
  python3 scripts/qa/build-feature-delta.py [options]

Options:
  --baseline-sha SHA       Override the manifest's baseline SHA.
  --head-sha SHA           Override the manifest's head SHA.
  --manifest PATH          Verification manifest to read baseline/head from
                            when not given explicitly (default:
                            .qa/verification-manifest.json).
  --repo-path PATH         Git checkout to run merge-base checks in
                            (default: .).
  --project KEY            Jira project key (default: AAASM).
  --fix-version NAME       Use `fixVersion = "<name>"` instead of the
                            lookback window (opt-in override).
  --lookback-days N        Lookback window in days for the default
                            resolutiondate-based query (default: 14).
  --tickets KEY,KEY,...    Bypass Jira JQL discovery and reconcile exactly
                            these ticket keys instead (explicit args always
                            override discovery — useful for a targeted
                            re-run or a fixture/counter-example check).
  --out PATH               Output path (default: .qa/feature-delta.json).

Writes: .qa/feature-delta.json (git-ignored, per-run — same convention as
  scripts/qa/build-verification-manifest.sh's output).

Requires: git, gh, python3. $JIRA_URL/$JIRA_USERNAME/$JIRA_API_TOKEN in the
  environment — their absence is reported as an escalation, not silently
  faked; whatever is reachable (git ancestor checks) still runs.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

SCHEMA_VERSION = "1"

ANTI_CIRCULARITY_PATTERN = re.compile(
    r"qa sign-?off|release qa gate|qa-complete", re.IGNORECASE
)
UNCHECKED_AC_LINE = re.compile(r"^\s*[-*]\s*\\?\[\s?\\?\]\s*(.+)$")


def run(cmd: list[str], cwd: str | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def resolve_repo_slug(repo_path: str) -> str | None:
    # Mirrors build-verification-manifest.sh: prefer the "remote" remote
    # (canonical org repo), fall back to "origin" (personal fork).
    for remote_name in ("remote", "origin"):
        rc, url, _ = run(["git", "-C", repo_path, "remote", "get-url", remote_name])
        if rc == 0 and url:
            match = re.search(r"[:/]([^/:]+/[^/]+?)(\.git)?$", url)
            if match:
                return match.group(1)
    return None


def load_manifest_shas(manifest_path: str) -> tuple[str | None, str | None]:
    if not os.path.isfile(manifest_path):
        return None, None
    with open(manifest_path) as f:
        manifest = json.load(f)
    repos = manifest.get("repos", [])
    if not repos:
        return None, None
    repo = repos[0]
    baseline_sha = (repo.get("baseline") or {}).get("sha")
    head_sha = repo.get("head_sha")
    return baseline_sha, head_sha


def jira_request(method: str, path: str, body: dict | None = None) -> dict:
    jira_url = os.environ["JIRA_URL"].rstrip("/")
    username = os.environ["JIRA_USERNAME"]
    token = os.environ["JIRA_API_TOKEN"]
    auth = base64.b64encode(f"{username}:{token}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{jira_url}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def jira_search(jql: str) -> list[dict]:
    body = {
        "jql": jql,
        "fields": ["summary", "status", "resolutiondate", "fixVersions", "description", "comment"],
        "maxResults": 100,
    }
    result = jira_request("POST", "/rest/api/3/search/jql", body)
    return result.get("issues", [])


def jira_get_issue(key: str) -> dict:
    fields = "summary,status,resolutiondate,fixVersions,description,comment"
    return jira_request("GET", f"/rest/api/3/issue/{key}?fields={fields}")


def adf_to_text(node) -> str:
    """Flatten an Atlassian Document Format node tree to plain text, one
    block-level node per line — enough fidelity to regex-scan for AC
    checkbox lines and anti-circularity keywords without a full ADF parser.
    """
    if node is None:
        return ""
    if isinstance(node, list):
        return "\n".join(adf_to_text(n) for n in node)
    if not isinstance(node, dict):
        return ""
    parts = []
    if node.get("type") == "text":
        parts.append(node.get("text", ""))
    for child in node.get("content", []) or []:
        parts.append(adf_to_text(child))
    joiner = "\n" if node.get("type") in {"paragraph", "listItem", "taskItem"} else ""
    return joiner.join(p for p in parts if p) if joiner else "".join(parts)


def issue_full_text(issue: dict) -> str:
    fields = issue.get("fields", {})
    description_text = adf_to_text(fields.get("description"))
    comments_text = "\n".join(
        adf_to_text(c.get("body")) for c in (fields.get("comment") or {}).get("comments", [])
    )
    return f"{description_text}\n{comments_text}"


def check_anti_circularity(full_text: str) -> tuple[bool, list[str]]:
    """Return (override_applies, unchecked_lines).

    override_applies is True only when at least one unchecked AC-style line
    ("- [ ] ..." / "* [ ] ...", including the escaped "\\[ \\]" form MCP/API
    responses render) exists, AND every unchecked line matches the anti-
    circularity keyword pattern (QA sign-off / release QA gate / QA-
    complete, case-insensitive). A ticket with any other genuinely
    unfinished AC does NOT get the override — this is a real per-line
    check, not a blanket "ticket mentions QA somewhere" match.
    """
    unchecked = []
    for line in full_text.splitlines():
        m = UNCHECKED_AC_LINE.match(line)
        if m:
            unchecked.append(m.group(1).strip())
    if not unchecked:
        return False, []
    all_circular = all(ANTI_CIRCULARITY_PATTERN.search(item) for item in unchecked)
    return all_circular, unchecked


def find_merged_prs(repo_slug: str, ticket: str) -> list[dict]:
    rc, out, err = run(
        [
            "gh", "pr", "list", "--repo", repo_slug,
            "--search", f"[{ticket}] in:title",
            "--state", "merged",
            "--json", "number,title,mergeCommit,baseRefName,url",
        ]
    )
    if rc != 0:
        raise RuntimeError(f"gh pr list failed for {ticket}: {err}")
    return json.loads(out) if out else []


def is_ancestor(repo_path: str, commit: str, head_sha: str) -> bool:
    rc, _, _ = run(["git", "-C", repo_path, "merge-base", "--is-ancestor", commit, head_sha])
    return rc == 0


def classify_ticket(
    ticket: str,
    summary: str,
    status_name: str,
    full_text: str,
    repo_slug: str,
    repo_path: str,
    head_sha: str,
) -> dict:
    is_done = status_name == "Done"
    override_applies, unchecked = check_anti_circularity(full_text)

    prs = find_merged_prs(repo_slug, ticket)
    if not prs:
        classification = "OUT_OF_CURRENT_RELEASE_QA_SCOPE"
        reason = "no merged PR found referencing this ticket"
        if not is_done and not override_applies:
            reason = "ticket not Done"
        return {
            "ticket": ticket, "summary": summary, "classification": classification,
            "evidence": {
                "status": status_name, "reason": reason,
                "anti_circularity_override": override_applies,
                "anti_circularity_unchecked_lines": unchecked,
            },
            "pr_ref": None, "merge_commit": None,
        }

    # Prefer the PR whose merge commit is a real ancestor of candidate HEAD;
    # if several merged PRs reference the ticket, evaluate each and keep the
    # first that satisfies ancestry, so a stale/superseded PR referencing
    # the same ticket key doesn't mask a later, real one.
    for pr in prs:
        commit = (pr.get("mergeCommit") or {}).get("oid")
        if not commit:
            continue
        ancestor = is_ancestor(repo_path, commit, head_sha)
        if not ancestor:
            continue
        if is_done:
            return {
                "ticket": ticket, "summary": summary, "classification": "RELEASE_ELIGIBLE",
                "evidence": {
                    "status": status_name, "reason": "Done, merged PR, merge commit is an ancestor of candidate HEAD",
                    "anti_circularity_override": False,
                    "anti_circularity_unchecked_lines": unchecked,
                },
                "pr_ref": f"#{pr['number']} {pr['title']}", "merge_commit": commit,
            }
        if override_applies:
            return {
                "ticket": ticket, "summary": summary, "classification": "RELEASE_ELIGIBLE",
                "evidence": {
                    "status": status_name,
                    "reason": (
                        "not formally Done, but implementation is genuinely complete: "
                        "merged PR's merge commit is an ancestor of candidate HEAD, and "
                        "the only remaining unchecked item(s) reference this Epic's own "
                        "QA-gate sign-off (anti-circularity override, AAASM-5842)"
                    ),
                    "anti_circularity_override": True,
                    "anti_circularity_unchecked_lines": unchecked,
                },
                "pr_ref": f"#{pr['number']} {pr['title']}", "merge_commit": commit,
            }

    # No PR both merged and ancestor-confirmed.
    any_merge_commit = next(
        ((pr.get("mergeCommit") or {}).get("oid") for pr in prs if pr.get("mergeCommit")), None
    )
    if any_merge_commit is not None:
        reason = "merge commit not an ancestor of candidate HEAD"
        pr = next(pr for pr in prs if (pr.get("mergeCommit") or {}).get("oid") == any_merge_commit)
        pr_ref = f"#{pr['number']} {pr['title']}"
    else:
        reason = "no merged PR found referencing this ticket"
        pr_ref = None
    if not is_done and not override_applies:
        reason = "ticket not Done"
    return {
        "ticket": ticket, "summary": summary, "classification": "OUT_OF_CURRENT_RELEASE_QA_SCOPE",
        "evidence": {
            "status": status_name, "reason": reason,
            "anti_circularity_override": override_applies,
            "anti_circularity_unchecked_lines": unchecked,
        },
        "pr_ref": pr_ref, "merge_commit": any_merge_commit,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--manifest", default=".qa/verification-manifest.json")
    parser.add_argument("--repo-path", default=".")
    parser.add_argument("--project", default="AAASM")
    parser.add_argument("--fix-version")
    parser.add_argument("--lookback-days", type=int, default=14)
    parser.add_argument("--tickets")
    parser.add_argument("--out", default=".qa/feature-delta.json")
    args = parser.parse_args()

    escalations = []

    baseline_sha, head_sha = args.baseline_sha, args.head_sha
    if not baseline_sha or not head_sha:
        m_baseline, m_head = load_manifest_shas(args.manifest)
        baseline_sha = baseline_sha or m_baseline
        head_sha = head_sha or m_head
    if not head_sha:
        print("error: no head SHA given and none resolvable from the manifest", file=sys.stderr)
        return 2
    if not baseline_sha:
        print(
            f"warning: no baseline SHA given and manifest baseline is unknown — "
            f"proceeding, but PR-ancestor checks are still valid against head_sha={head_sha} alone",
            file=sys.stderr,
        )

    repo_slug = resolve_repo_slug(args.repo_path)
    if not repo_slug:
        print("error: could not resolve a repo slug via `remote`/`origin`", file=sys.stderr)
        return 2

    have_jira_creds = all(os.environ.get(v) for v in ("JIRA_URL", "JIRA_USERNAME", "JIRA_API_TOKEN"))
    features = []

    if not have_jira_creds:
        escalations.append({
            "kind": "jira_credentials_missing",
            "detail": "JIRA_URL/JIRA_USERNAME/JIRA_API_TOKEN not all set in the environment — "
                       "no Jira ticket discovery or status/comment lookup performed. "
                       "This run cannot classify anything without live Jira access.",
        })
    else:
        try:
            if args.tickets:
                keys = [t.strip() for t in args.tickets.split(",") if t.strip()]
                issues = [jira_get_issue(k) for k in keys]
            elif args.fix_version:
                jql = f'project = {args.project} AND fixVersion = "{args.fix_version}"'
                issues = jira_search(jql)
            else:
                jql = (
                    f"project = {args.project} AND status = Done "
                    f"AND resolutiondate >= -{args.lookback_days}d ORDER BY resolutiondate DESC"
                )
                issues = jira_search(jql)
        except (urllib.error.URLError, KeyError) as exc:
            escalations.append({"kind": "jira_query_failed", "detail": str(exc)})
            issues = []

        for issue in issues:
            key = issue["key"]
            fields = issue["fields"]
            summary = fields.get("summary", "")
            status_name = fields.get("status", {}).get("name", "unknown")
            full_text = issue_full_text(issue)
            try:
                entry = classify_ticket(
                    key, summary, status_name, full_text, repo_slug, args.repo_path, head_sha
                )
            except RuntimeError as exc:
                escalations.append({"kind": "gh_pr_lookup_failed", "ticket": key, "detail": str(exc)})
                continue
            features.append(entry)

    out_dir = os.path.dirname(args.out) or "."
    os.makedirs(out_dir, exist_ok=True)
    rc, generated_ref, _ = run(["git", "-C", args.repo_path, "rev-parse", "HEAD"])
    generated_at_ref = generated_ref if rc == 0 else "unknown"

    output = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_ref": generated_at_ref,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_sha": baseline_sha,
        "head_sha": head_sha,
        "features": features,
        "escalations": escalations,
    }
    with open(args.out, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
