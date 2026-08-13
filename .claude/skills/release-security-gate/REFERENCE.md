# release-security-gate — detailed reference

The per-tier detail behind the concise tier table in [SKILL.md](SKILL.md). The
tiers are **additive**: minor runs everything in patch first, major runs
everything in minor first.

> **This gate composes Anthropic's tooling — it does not reinvent diff
> scanning.** The release-diff step (patch tier and up) invokes the built-in
> **`/security-review`** scanner on the release delta; the major tier additionally
> runs the official
> [`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review)
> GitHub Action on the release branch. Both feed their findings into the
> PASS/BLOCK sign-off, and any unaddressed High/Critical from either is a
> **BLOCK**.

## Contents

- [Inputs (all tiers)](#inputs-all-tiers)
- [Tier: patch](#tier-patch)
- [Tier: minor](#tier-minor-patch--attack-surface)
- [Tier: major](#tier-major-minor--threat-model-refresh--pen-test)
- [Severity classification](#severity-classification)
- [Writing the sign-off artifact](#writing-the-sign-off-artifact)

## Inputs (all tiers)

Real, in-repo sources the review pulls from:

- **`deny.toml`** + `cargo deny check advisories` — the workspace advisory
  policy and live RustSec audit.
- **`.github/workflows/codeql.yml`** — the committed CodeQL workflow; check open
  code-scanning alerts (`gh api repos/ai-agent-assembly/agent-assembly/code-scanning/alerts --jq '.[].rule.id'`).
- **Open Dependabot alerts** —
  `gh api repos/ai-agent-assembly/agent-assembly/dependabot/alerts --jq '.[] | select(.state=="open")'`.
- **The release diff** — `git log --oneline <prev-tag>..HEAD` and
  `git diff <prev-tag>..HEAD --stat` for the release window.
- **`SECURITY.md`** — the disclosure policy and supported-versions table.

> If `cargo deny` is not installed locally, do not silently skip: record it as an
> **Info** finding in the artifact and review `deny.toml` + the RustSec advisory
> DB manually before signing off.

## Tier: patch

The baseline every release runs.

1. **Advisory audit** — `cargo deny check advisories`. Any reported advisory is a
   finding; severity tracks the advisory's CVSS / RustSec severity.
2. **Open security alerts** — enumerate open CodeQL + Dependabot alerts. Each
   open High/Critical alert that ships in this release is a finding.
3. **Release-diff review (native `/security-review`)** — run the built-in
   **`/security-review`** (Anthropic's diff vulnerability scanner) against the
   release delta `<prev-tag>..HEAD`. Do **not** hand-roll diff scanning here — this
   step *wraps* the native scanner. To scope it to the release window, check out
   the release branch tip (or a worktree at HEAD) and invoke `/security-review`;
   it scans the pending changes. Then read `git log <prev-tag>..HEAD` to make sure
   every commit touching a security-relevant path (`aa-security/`,
   `aa-runtime/src/pipeline/`, `aa-gateway/src/policy/`,
   `aa-gateway/src/sanitizer/`, `aa-gateway/src/budget/`, `aa-ebpf*`) is covered.
   **Fold each finding the native scanner reports into the sign-off findings
   table**, classified by severity; an unaddressed High/Critical from the scanner
   is a **BLOCK** like any other.
4. Record the findings table (including the native `/security-review` output) +
   `Verdict`.

## Tier: minor (patch + attack-surface)

Everything in **patch**, then:

5. **Trust-boundary delta review** — fill in the
   [trust-boundary review checklist](../../../docs/src/security/trust-boundary-review-checklist.md)
   against the release diff. For each boundary row, mark Changed? (Y/N), cite the
   commit/PR, add a reviewer note. Paste the completed table into the sign-off
   artifact.
6. **Guarded-NO invariant** — row 2 ("did any field gain a wire-level trust
   marker?") MUST stay **N**. A **Y** is an automatic **BLOCK**.
7. **Changed-surface drill-down** — for every **Y** row, confirm the *next* layer
   in the release threat-model "assume previous breached" chain still holds.

## Tier: major (minor + threat-model refresh + pen-test)

Everything in **minor**, then:

8. **Full threat-model refresh** — rewrite
   [release-threat-model.md](../../../docs/src/security/release-threat-model.md):
   re-derive the 6-layer map from current crates, **advance the
   `Threat-model version` field**, and add a row to its revision table. A major
   whose version field did not advance is itself a **finding**.
9. **Pen-test checklist** — exercise (or confirm coverage of) each:
   - [ ] **SDK-bypass** — an event sent with a forged "clean" marker is still
     scanned + redacted by `aa-runtime` (cf. `aa-runtime/tests/aaasm_2568_gate_verification.rs`).
   - [ ] **Egress allowlist** — a request to an off-allowlist host is denied at
     the gateway and at the proxy wire.
   - [ ] **Fail-closed** — an empty policy cascade returns `Deny`.
   - [ ] **Oversized field** — a secret-bearing field over the scan cap is
     redacted whole, not forwarded raw.
   - [ ] **Audit poisoning** — raw prompts / banned keys are stripped by the
     write-boundary sanitizer before persistence.
   - [ ] **Budget exhaustion** — a runaway agent is denied/suspended on exceed.
   - [ ] **eBPF floor** — direct TLS (SDK + proxy bypassed) is still observed by
     the kernel uprobes (Linux).
10. **Official Claude Code Security Review Action** — run the official
    [`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review)
    GitHub Action against the release branch (e.g. dispatch the security-review
    workflow on the branch, or run the Action's reusable workflow over the release
    delta). This is the CI-driven, auditable counterpart to the interactive
    `/security-review` from the patch tier. **Fold its reported findings into the
    sign-off findings table**; an unaddressed High/Critical from the Action is a
    **BLOCK**. Record the Action run URL in the artifact for auditability.

## Severity classification

| Severity | Meaning | Gate effect |
|---|---|---|
| **Critical** | Exploitable now, high impact (RCE, secret exfil, auth bypass) | **BLOCK** until fixed |
| **High** | Serious, likely exploitable | **BLOCK** until fixed or accepted-with-justification |
| **Medium** | Real but limited / mitigated | Record; does not block |
| **Low** | Minor / defense-in-depth | Record; does not block |
| **Info** | Observation, no action required | Record |

A finding is **addressed** when it is either fixed in this release, or accepted
with an owner + written justification in the sign-off artifact. An **unaddressed
Critical or High forces `Verdict: BLOCK`.**

## Writing the sign-off artifact

1. Copy the template:
   `cp docs/release/security-signoff/TEMPLATE.md docs/release/security-signoff/v<version>.md`.
2. Fill reviewer, date, release type, previous tag, the findings table, and (for
   minor+) the completed trust-boundary checklist.
3. Set the final line to exactly `Verdict: PASS` or `Verdict: BLOCK` — the token
   `Verdict: PASS` is what `scripts/release-readiness.sh` greps for.
4. Commit: `📝 (release): Security sign-off for v<version>`.

`release-readiness.sh <version>` then passes its security-sign-off check only when
`docs/release/security-signoff/v<version>.md` exists **and** contains
`Verdict: PASS`.
