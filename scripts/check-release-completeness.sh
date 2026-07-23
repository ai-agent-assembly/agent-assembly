#!/usr/bin/env bash
# AAASM-4456: release-artifact completeness gate.
#
# WHY: `release.yml`'s build list (`-p aa-cli -p aa-gateway ...`) and the
# `components.json` filename glob are hand-maintained and have NO structural
# link to the workspace's actual binary crates. That gap let `aa-api-server`
# (AAASM-4449) ship in zero releases, undetected, across every rc so far.
#
# This gate derives the set of binaries the workspace can produce from
# `cargo metadata` (the source of truth) and fails when a binary-producing
# crate is neither shipped by `release.yml` nor explicitly allowlisted as
# intentionally-unreleased. Run on PRs that touch the workspace manifests or
# `release.yml`, so a new binary crate fails fast — before it ships, not after.
#
# Usage: check-release-completeness.sh [path-to-release.yml]
#   (the optional arg lets CI / tests point the drift check at an alternate
#    release.yml; defaults to the committed one.)
set -euo pipefail

RELEASE_YML="${1:-.github/workflows/release.yml}"

# Binaries the release pipeline MUST build, package and upload. This is the
# single introspectable list AAASM-4456 asks for (vs. the duplicated, hardcoded
# `-p` args + glob buried inside release.yml). bin name -> cargo package below.
RELEASE_BINARIES="aasm aa-gateway aa-runtime aa-proxy aa-api-server"

pkg_of() {
  case "$1" in
    aasm)          echo aa-cli ;;
    aa-gateway)    echo aa-gateway ;;
    aa-runtime)    echo aa-runtime ;;
    aa-proxy)      echo aa-proxy ;;
    aa-api-server) echo aa-api ;;
    *) echo "::error::no package mapping for release binary '$1'" >&2; return 1 ;;
  esac
}

# Workspace binaries deliberately NOT shipped as release artifacts, each with
# the reason it is held back. A binary target absent from BOTH this list and
# RELEASE_BINARIES fails the gate: the classification must be explicit and
# visible, never a silent gap (the whole point of AAASM-4456).
#   generate_openapi          aa-api dev tool: regenerates openapi/v1.yaml
#   generate_policy_rbac_doc  aa-api dev tool: regenerates policy RBAC docs
#   generate_golden           conformance dev tool: regenerates golden vectors
#   aa-ebpf-loaderd           eBPF loader daemon: not part of the release
#                             artifact set (tracked separately if it ever ships)
UNRELEASED_BINARIES="generate_openapi generate_policy_rbac_doc generate_golden aa-ebpf-loaderd"

fail=0
err() { echo "::error::$*" >&2; fail=1; }

# 1. Source of truth: every bin target across workspace members (--no-deps so
#    only THIS workspace's crates, not transitive deps).
all_bins="$(cargo metadata --no-deps --format-version=1 \
  | jq -r '.packages[].targets[] | select(.kind | index("bin")) | .name' \
  | sort -u)"

known=" $RELEASE_BINARIES $UNRELEASED_BINARIES "

# 2. Completeness/classification: every workspace bin must be classified as
#    either released or explicitly-unreleased.
while IFS= read -r b; do
  [ -n "$b" ] || continue
  case "$known" in
    *" $b "*) ;;
    *) err "workspace binary '$b' is neither in RELEASE_BINARIES nor the intentionally-unreleased allowlist. Wire it into $RELEASE_YML (see AAASM-4449) or document it in check-release-completeness.sh's UNRELEASED_BINARIES." ;;
  esac
done <<EOF
$all_bins
EOF

# 3. Drift: every RELEASE binary must actually be built + packaged in
#    release.yml. Catches the AAASM-4449 class (a shipped binary silently
#    dropped from the build list, e.g. removing `-p aa-gateway`).
yml="$(cat "$RELEASE_YML")"
for b in $RELEASE_BINARIES; do
  pkg="$(pkg_of "$b")"
  case "$yml" in
    *"-p $pkg"*) ;;
    *) err "release binary '$b' (package '$pkg') is not built in $RELEASE_YML (missing '-p $pkg'); a release would ship without it (AAASM-4449 class)." ;;
  esac
  case "$yml" in
    *"$b"*) ;;
    *) err "release binary '$b' is never packaged/verified in $RELEASE_YML (no reference to its binary name)." ;;
  esac
done

# 4. Downstream bot-PR base-branch drift (AAASM-4955 / AAASM-4957).
#    release.yml opens a bot PR into each downstream repo (homebrew-tap + the
#    three SDKs) via peter-evans/create-pull-request, each with a hardcoded
#    `base:`. When a downstream repo's default branch is renamed (master → main),
#    a stale `base:` here silently breaks that repo's release PR — the
#    homebrew-tap migration hit exactly this. Pin each downstream's expected base
#    to its CURRENT default branch; a mismatch in either direction fails the gate,
#    so release.yml and this map must be updated together, in lockstep with each
#    repo's migration.
expected_base_for() {
  # bot-token secret name -> that repo's current default branch
  case "$1" in
    HOMEBREW_TAP_TOKEN)   echo main ;;    # migrated (AAASM-4957)
    NODE_SDK_BOT_TOKEN)   echo main ;;    # migrated (AAASM-4960)
    PYTHON_SDK_BOT_TOKEN) echo main ;;    # migrated (AAASM-4959)
    GO_SDK_BOT_TOKEN)     echo master ;;  # migrates under AAASM-4961
    *) echo "" ;;
  esac
}

# Pair each create-pull-request `base:` with the bot token most recently seen in
# the same step (portable awk — no gawk match(s,re,arr)).
while IFS="$(printf '\t')" read -r tok base; do
  [ -n "${base:-}" ] || continue
  exp="$(expected_base_for "$tok")"
  if [ -z "$exp" ]; then
    err "release.yml opens a bot PR (token '$tok') with base '$base' but check-release-completeness.sh has no expected-base mapping for it — add one so its target branch can't silently go stale (AAASM-4955)."
  elif [ "$base" != "$exp" ]; then
    err "downstream bot-PR base for '$tok' is '$base' but that repo's default branch is '$exp' — a release would open the PR against a non-existent branch. Update $RELEASE_YML 'base:' and this map together, in lockstep with the repo's master→main migration (AAASM-4955)."
  fi
done < <(awk '
  /token: \$\{\{ secrets\./ { line=$0; sub(/.*secrets\./,"",line); sub(/[[:space:]]*\}\}.*/,"",line); tok=line }
  /^[[:space:]]*base:[[:space:]]*[A-Za-z]/ { b=$0; sub(/^[[:space:]]*base:[[:space:]]*/,"",b); sub(/[[:space:]].*$/,"",b); print tok"\t"b }
' "$RELEASE_YML")

if [ "$fail" -ne 0 ]; then
  echo "release-artifact completeness gate: FAILED" >&2
  exit 1
fi

echo "release-artifact completeness gate: OK"
echo "  workspace bins : $(printf '%s' "$all_bins" | tr '\n' ' ')"
echo "  release binaries present in $RELEASE_YML: $RELEASE_BINARIES"
