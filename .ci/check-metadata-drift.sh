#!/usr/bin/env bash
# check-metadata-drift.sh
#
# ADR 0014 (canonical metadata registry & drift gate) — hardcoded-value lint mode.
# Fails CI if a registry-owned canonical literal drifts back into the tree. The
# canonical values live in the `.github` registry (`metadata/org-profile.yaml` ->
# `metadata/generated/registry.json`); their values are decided by ADR 0007/0008.
#
# Scope (AAASM-4922): the two highest-fan-out canonical values reconciled in this
# repo that have ZERO legitimate occurrence anywhere here, so the lint stays
# false-positive-free:
#   * the `.github` governance-doc branch — canonical is `master`, not `main`
#     (registry `governance.baseline_doc_base`);
#   * the `.dev` alternate installer host — it serves the script at its host ROOT
#     (a `custom_domain` route, ADR 0007), so `tool.agent-assembly.dev/install.sh`
#     is a wrong path (registry `urls.installer_alt`).
#
# ADRs are excluded: they quote these drifts as examples. The broader org-wide
# orphan-literal audit (repo names, display names, Jira IDs) is owned by the
# `.github` registry widen (ADR 0014 Appendix B item 1), not this repo-local lint.
#
# Usage: bash .ci/check-metadata-drift.sh   (from the repository root).
# Exit 0 — clean; exit 1 — a registry-owned canonical value drifted.
set -euo pipefail

status=0

# $1 = human description, $2 = ERE pattern, $3 = canonical-fix hint.
check() {
  local desc="$1" pat="$2" fix="$3" hits
  hits=$(git grep -nE "$pat" -- \
    ':(exclude)docs/src/adr/*' \
    ':(exclude).ci/check-metadata-drift.sh' || true)
  if [ -n "$hits" ]; then
    echo "──────────────────────────────────────────────────────"
    echo "Metadata drift: ${desc}"
    echo "${hits}"
    echo "Fix: ${fix}"
    echo "──────────────────────────────────────────────────────"
    status=1
  fi
}

check "'.github' governance link uses 'blob/main' (canonical branch is 'master')" \
  'ai-agent-assembly/\.github/blob/main' \
  "use .../.github/blob/master/... (registry governance.baseline_doc_base)"

check "'.dev' installer alt carries an '/install.sh' path (it serves at host root)" \
  'tool\.agent-assembly\.dev/install\.sh' \
  "use https://tool.agent-assembly.dev (registry urls.installer_alt, ADR 0007)"

if [ "$status" -eq 0 ]; then
  echo "Metadata-drift check passed."
fi
exit "$status"
