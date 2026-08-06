#!/usr/bin/env bash
#
# measure-claude-code-managed-enforcement.sh — AAASM-5308
#
# Measures the file-level half of AAASM-5276 condition C6 on a host that has
# genuinely been provisioned with Claude Code's endpoint managed-settings file,
# and refuses to run anywhere else.
#
# WHY THE REFUSAL IS THE POINT
#
#   C6's open half is "do the managed-only keys resist a real override attempt".
#   The one way to get that wrong is to produce something that *looks* like
#   managed enforcement on a host where nothing is managed. So this script does
#   not have a simulation mode, a --dry-run that emits results, or an override
#   flag. Every gate below is a precondition for the evidence being real, and a
#   failed gate exits non-zero before a single PASS line is printed. There is no
#   code path from an unprovisioned host to a pass.
#
# WHAT IT DOES NOT MEASURE
#
#   Whether Claude Code honours each managed-only key at runtime. That needs an
#   interactive Claude Code session per key and an operator judging the result;
#   the script emits those steps as MANUAL and records them as unmeasured.
#   Exit 0 from this script never means C6 is closed.
#
# Usage: scripts/measure-claude-code-managed-enforcement.sh [--out FILE]
#
set -euo pipefail

readonly MANAGED_DIR="/Library/Application Support/ClaudeCode"
readonly MANAGED_FILE="${MANAGED_DIR}/managed-settings.json"
readonly MANAGED_ONLY_KEYS=(
  allowManagedPermissionRulesOnly
  disableBypassPermissionsMode
  allowManagedMcpServersOnly
  allowManagedHooksOnly
)

# Exit codes are distinct so a CI log or a Jira paste says which precondition
# failed without needing the surrounding text.
readonly EXIT_NOT_MACOS=2
readonly EXIT_TEST_SEAM=3
readonly EXIT_RUNNING_AS_ROOT=4
readonly EXIT_NOT_PROVISIONED=5
readonly EXIT_NOT_ROOT_OWNED=6
readonly EXIT_WORLD_WRITABLE=7
readonly EXIT_USER_CAN_REWRITE=8
readonly EXIT_MALFORMED=9
# AAASM-5628: evidence recorded against an unidentified runtime proves nothing
# about the build it is attributed to, so this is a refusal like the others.
readonly EXIT_RUNTIME_UNVERIFIED=11

out_file=""
probe_path=""

cleanup() {
  # The directory write probe creates a real file. Leaving one behind inside a
  # managed policy directory would be this script vandalising the thing it is
  # measuring.
  if [[ -n "${probe_path}" && -e "${probe_path}" ]]; then
    rm -f -- "${probe_path}" || true
  fi
}
trap cleanup EXIT

say() { printf '%s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; }
note() { printf 'NOTE  %s\n' "$*"; }
manual() { printf 'MANUAL %s\n' "$*"; }

refuse() {
  local code="$1"
  shift
  fail "$*"
  printf '\n' >&2
  printf 'REFUSED — this host cannot produce real evidence for AAASM-5308.\n' >&2
  printf 'Nothing was measured and nothing was written. See\n' >&2
  printf 'docs/src/devtools/managed-device-measurement.md for how to provision a host.\n' >&2
  exit "${code}"
}

usage() {
  cat <<'USAGE'
measure-claude-code-managed-enforcement.sh [--out FILE]

  --out FILE   Write the evidence skeleton to FILE
               (default: AAASM-5308-evidence-<YYYY-MM-DD>.md in the cwd).
  --help       This text.

Refuses, with a distinct non-zero exit code, unless all of the following hold:
  * the host is macOS                                            (exit 2)
  * AASM_CLAUDE_MANAGED_ROOT is unset or canonical               (exit 3)
  * the script is not running as root                            (exit 4)
  * the canonical managed-settings file exists                   (exit 5)
  * it is owned by uid 0                                         (exit 6)
  * no account other than its owner can rewrite it               (exit 7)
  * the invoking user cannot rewrite it or replace it            (exit 8)
  * it is a parseable managed-settings document                  (exit 9)
  * the aasm runtime that answers is verifiably this build,
    and is the only one reachable                                (exit 11)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || refuse 64 "--out needs a file path"
      out_file="$2"
      shift 2
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "${out_file}" ]]; then
  out_file="AAASM-5308-evidence-$(date -u +%Y-%m-%d).md"
fi

say "AAASM-5308 — Claude Code endpoint managed-settings enforcement measurement"
say "Preconditions first; nothing is measured until every one of them holds."
say ""

# ---------------------------------------------------------------------------
# Gate 0 — macOS. The mechanism does not exist anywhere else.
# ---------------------------------------------------------------------------
if [[ "$(uname -s)" != "Darwin" ]]; then
  refuse "${EXIT_NOT_MACOS}" "endpoint managed settings are a macOS mechanism; this host is $(uname -s)."
fi
pass "host is macOS"

# ---------------------------------------------------------------------------
# Gate 1 — the test seam must not be in play.
#
# AASM_CLAUDE_MANAGED_ROOT redirects where the adapter *addresses* the managed
# file. Under a redirect the adapter anchors its ownership check to the invoking
# user instead of root, so a measurement taken with it set would be a
# measurement of a file Claude Code never reads.
# ---------------------------------------------------------------------------
seam="${AASM_CLAUDE_MANAGED_ROOT-}"
if [[ -n "${seam}" && "${seam}" != "${MANAGED_DIR}" ]]; then
  refuse "${EXIT_TEST_SEAM}" \
    "AASM_CLAUDE_MANAGED_ROOT is set to '${seam}'. That is a test seam: the file there is not the one Claude Code reads. Unset it and re-run."
fi
pass "AASM_CLAUDE_MANAGED_ROOT is not redirecting the managed surface"

# ---------------------------------------------------------------------------
# Gate 2 — not root.
#
# The property under measurement is "the user running Claude Code cannot rewrite
# this file". Root can rewrite it, so a root run would measure nothing and would
# make the directory write probe destructive rather than a probe.
# ---------------------------------------------------------------------------
uid="$(id -u)"
if [[ "${uid}" == "0" ]]; then
  refuse "${EXIT_RUNNING_AS_ROOT}" \
    "this is running as root. The measurement is what an unprivileged user cannot do, so a root run is vacuous. Run it as the developer account."
fi
pass "running unprivileged (uid ${uid})"

# ---------------------------------------------------------------------------
# Gate 3 — the file must actually be there. This is the gate an unmanaged,
# unprovisioned host stops at, and it is why no simulation can reach a pass.
# ---------------------------------------------------------------------------
if [[ ! -e "${MANAGED_FILE}" ]]; then
  refuse "${EXIT_NOT_PROVISIONED}" \
    "${MANAGED_FILE} does not exist. This host has no endpoint-managed policy, so there is nothing whose enforcement could be measured."
fi
pass "${MANAGED_FILE} exists"

# ---------------------------------------------------------------------------
# Gate 4 — root-owned. AAASM-5298 left uid == 0 specifically unexercised; this
# is the check that closes it, and it is read off the real host, not asserted.
# ---------------------------------------------------------------------------
owner_uid="$(stat -f '%u' "${MANAGED_FILE}")"
owner_gid="$(stat -f '%g' "${MANAGED_FILE}")"
file_mode="$(stat -f '%Lp' "${MANAGED_FILE}")"
if [[ "${owner_uid}" != "0" ]]; then
  refuse "${EXIT_NOT_ROOT_OWNED}" \
    "${MANAGED_FILE} is owned by uid ${owner_uid}, not root. A file the invoking user's side owns is a file that side can rewrite."
fi
pass "owned by uid 0 (gid ${owner_gid}), mode ${file_mode}"

# ---------------------------------------------------------------------------
# Gate 5 — nobody but the owner may write it.
# ---------------------------------------------------------------------------
if (( 8#${file_mode} & 8#22 )); then
  refuse "${EXIT_WORLD_WRITABLE}" \
    "mode ${file_mode} lets an account other than the owner rewrite ${MANAGED_FILE}."
fi
pass "mode ${file_mode} grants write to the owner only"

# ---------------------------------------------------------------------------
# Gate 6 — the real, OS-enforced refusal.
#
# Two separate properties, because either one alone is defeatable:
#   (a) the invoking user cannot write the file;
#   (b) the invoking user cannot create an entry in its directory — otherwise
#       the file can be replaced by rename without ever being written to.
# The directory probe is a real create attempt, not an inspection of mode bits,
# because mode bits are not the only thing that decides (ACLs, SIP, sandbox).
# ---------------------------------------------------------------------------
if [[ -w "${MANAGED_FILE}" ]]; then
  refuse "${EXIT_USER_CAN_REWRITE}" \
    "uid ${uid} can write ${MANAGED_FILE} directly. 'installed where the user cannot rewrite it' does not hold on this host."
fi
pass "uid ${uid} cannot write the file directly"

probe_path="${MANAGED_DIR}/.aasm-5308-write-probe.$$"
if : > "${probe_path}" 2>/dev/null; then
  rm -f -- "${probe_path}" || true
  probe_path=""
  refuse "${EXIT_USER_CAN_REWRITE}" \
    "uid ${uid} can create files in ${MANAGED_DIR}, so it can replace the managed file by rename even though the file itself is not writable."
fi
probe_path=""
pass "uid ${uid} cannot create an entry in ${MANAGED_DIR} (directory replace is refused too)"

# The containing directory matters as much as the two above: a user who can
# write /Library/Application Support can rename ClaudeCode aside and put their
# own directory there, and the file's own mode bits would still look correct.
# On macOS 26 this is `drwxr-xr-x root:admin`, so an admin account is refused —
# but that is a host fact to measure, not one to assume.
parent_dir="$(dirname "${MANAGED_DIR}")"
probe_path="${parent_dir}/.aasm-5308-write-probe.$$"
if : > "${probe_path}" 2>/dev/null; then
  rm -f -- "${probe_path}" || true
  probe_path=""
  refuse "${EXIT_USER_CAN_REWRITE}" \
    "uid ${uid} can create files in ${parent_dir}, so it can rename ${MANAGED_DIR} aside and substitute its own policy directory."
fi
probe_path=""
pass "uid ${uid} cannot create an entry in ${parent_dir} either"

# ---------------------------------------------------------------------------
# Gate 7 — it must be a managed-settings document carrying managed-only keys.
# A root-owned JSON file with none of them is an elevation with no enforcement
# purpose, and there would be nothing to attempt an override against.
# ---------------------------------------------------------------------------
sha256="$(shasum -a 256 "${MANAGED_FILE}" | awk '{print $1}')"
present_keys=()
for key in "${MANAGED_ONLY_KEYS[@]}"; do
  if grep -q "\"${key}\"" "${MANAGED_FILE}"; then
    present_keys+=("${key}")
  fi
done
if [[ ${#present_keys[@]} -eq 0 ]]; then
  refuse "${EXIT_MALFORMED}" \
    "${MANAGED_FILE} carries none of the managed-only keys (${MANAGED_ONLY_KEYS[*]}), so there is no enforcement to measure."
fi
pass "carries managed-only keys: ${present_keys[*]}"
say ""

# ---------------------------------------------------------------------------
# Preconditions hold. Everything below is a recorded fact, not a gate.
# ---------------------------------------------------------------------------
say "Preconditions hold. Recording host facts."
say ""

os_version="$(sw_vers -productVersion) ($(sw_vers -buildVersion))"
hw_model="$(sysctl -n hw.model 2>/dev/null || echo unknown)"
enrollment="$(/usr/bin/profiles status -type enrollment 2>/dev/null | tr '\n' '; ' || echo 'unavailable')"

# Provenance is recorded, never used as a gate. An administrator-provisioned
# host and an MDM-enrolled one produce the same artifact through the same
# mechanism, and the evidence has to say which one it was rather than let a
# reader assume the stronger of the two.
if /usr/bin/profiles status -type enrollment 2>/dev/null | grep -q 'MDM enrollment: Yes'; then
  provenance="mdm-enrolled"
else
  provenance="admin-provisioned (NOT MDM-enrolled — see the runbook's scope note)"
fi

note "macOS:        ${os_version}"
note "hardware:     ${hw_model}"
note "provenance:   ${provenance}"
note "enrollment:   ${enrollment}"
note "sha256:       ${sha256}"

claude_version="not installed"
if command -v claude >/dev/null 2>&1; then
  claude_version="$(claude --version 2>&1 | head -1)"
fi
note "claude:       ${claude_version}"

aasm_version="not on PATH"
if command -v aasm >/dev/null 2>&1; then
  aasm_version="$(aasm --version 2>&1 | head -1)"
fi
note "aasm:         ${aasm_version}"

commit_sha="unknown"
if git rev-parse --short HEAD >/dev/null 2>&1; then
  commit_sha="$(git rev-parse HEAD)"
fi
note "commit:       ${commit_sha}"
say ""

# ---------------------------------------------------------------------------
# The documented trap: a provider variable set *in the shell* suppresses Claude
# Code's server-managed-settings fetch entirely, so anything measured about
# remote settings in this shell is measuring the suppression, not the setting.
# ---------------------------------------------------------------------------
suppressors=()
for var in ANTHROPIC_BASE_URL ANTHROPIC_API_KEY CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX; do
  if [[ -n "${!var-}" ]]; then
    suppressors+=("${var}")
  fi
done
if [[ ${#suppressors[@]} -gt 0 ]]; then
  fail "server-managed-settings fetch is suppressed in this shell by: ${suppressors[*]}"
  note "Record the remote-settings items as NOT MEASURED, or re-run from a shell without them."
  remote_settings_measurable="no — suppressed by ${suppressors[*]}"
else
  pass "no provider variable in this shell is suppressing the server-managed-settings fetch"
  remote_settings_measurable="yes"
fi
say ""

# ---------------------------------------------------------------------------
# Agent Assembly's own reading, captured verbatim. Non-fatal: the runtime may
# not be running, and that is a recorded fact rather than a measurement failure.
# ---------------------------------------------------------------------------
# AAASM-5628: which runtime answered is part of the evidence, not a detail.
# A runtime from another checkout, or one whose executable has been deleted,
# answers perfectly well and describes *its* host — that is how a healthy
# Claude Code got reported as `not_installed` during AAASM-5453. `aasm` exits
# 10 rather than answer in that case, and this script must not record a
# result it produced under any other circumstances either.
aasm_status="not captured (aasm not on PATH)"
aasm_runtime_pid="not captured"
aasm_runtime_build="not captured"
aasm_runtime_verdict="not captured"
if command -v aasm >/dev/null 2>&1; then
  if aasm_status="$(aasm integrations status claude-code --output json 2>&1)"; then
    note "captured 'aasm integrations status claude-code --output json'"
    if command -v jq >/dev/null 2>&1; then
      aasm_runtime_verdict="$(printf '%s' "${aasm_status}" | jq -r '.runtime.provenance.verdict // "absent"')"
      aasm_runtime_pid="$(printf '%s' "${aasm_status}" | jq -r '.runtime.provenance.pid // "absent"')"
      aasm_runtime_build="$(printf '%s' "${aasm_status}" | jq -r '.runtime.provenance.build_sha // "absent"')"
      reachable="$(printf '%s' "${aasm_status}" | jq -r '.runtime.provenance.reachable_runtimes // 0')"
      if [[ "${aasm_runtime_verdict}" != "verified" ]]; then
        # Refuse rather than record. Evidence attributed to an unidentified
        # runtime proves nothing about the build it names, and this file is
        # the artifact a reviewer trusts.
        refuse "${EXIT_RUNTIME_UNVERIFIED}" "the runtime that answered aasm is '${aasm_runtime_verdict}', not verified"
      fi
      if [[ "${reachable}" != "1" ]]; then
        refuse "${EXIT_RUNTIME_UNVERIFIED}" "${reachable} Agent Assembly runtimes are reachable — this result names one of several"
      fi
      pass "aasm answered from runtime pid ${aasm_runtime_pid}, build ${aasm_runtime_build}"
    else
      # No jq: the provenance cannot be checked, so it must not be claimed.
      note "jq is not installed — runtime provenance was NOT verified; install jq and re-run"
      aasm_runtime_verdict="NOT VERIFIED (jq missing)"
    fi
  else
    aasm_exit=$?
    if [[ ${aasm_exit} -eq 10 ]]; then
      refuse "${EXIT_RUNTIME_UNVERIFIED}" "aasm refused: the runtime that answered is not verifiably this build (exit 10)"
    fi
    note "'aasm integrations status claude-code' did not succeed; its output is recorded as-is"
  fi
fi
say ""

# ---------------------------------------------------------------------------
# What this script cannot do.
# ---------------------------------------------------------------------------
say "The four managed-only key override attempts are NOT performed here."
say "Each needs an interactive Claude Code session and an operator judging the"
say "result. They are written into the evidence file as unfilled verdicts."
say ""
for key in "${MANAGED_ONLY_KEYS[@]}"; do
  manual "${key} — override attempt NOT MEASURED by this script"
done
say ""

# ---------------------------------------------------------------------------
# Evidence skeleton.
#
# The backticks below are Markdown code spans in the emitted document, not
# command substitution, which is why the single-quoted format strings are
# correct here.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2016
{
  printf '# AAASM-5308 — managed-settings enforcement evidence\n\n'
  printf 'Generated by `scripts/measure-claude-code-managed-enforcement.sh` at %s.\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '> This file records what was measured. Every `<!-- FILL -->` is an item the\n'
  printf '> script could not measure; leaving one unfilled means that item is unmeasured,\n'
  printf '> not that it passed.\n\n'
  printf '## Host\n\n'
  printf '| Field | Value |\n|---|---|\n'
  printf '| Commit | `%s` |\n' "${commit_sha}"
  printf '| macOS | %s |\n' "${os_version}"
  printf '| Hardware | %s |\n' "${hw_model}"
  printf '| Provisioning provenance | %s |\n' "${provenance}"
  printf '| Enrollment (`profiles status -type enrollment`) | `%s` |\n' "${enrollment}"
  printf '| MDM vendor | <!-- FILL --> |\n'
  printf '| Invoking uid | %s |\n' "${uid}"
  printf '| Claude Code | %s |\n' "${claude_version}"
  printf '| `aasm --version` | %s |\n' "${aasm_version}"
  printf '\n## Item 1 — the installed file is root-owned and not user-writable\n\n'
  printf '| Check | Result |\n|---|---|\n'
  printf '| Path | `%s` |\n' "${MANAGED_FILE}"
  printf '| sha256 | `%s` |\n' "${sha256}"
  printf '| Owner uid / gid | %s / %s |\n' "${owner_uid}" "${owner_gid}"
  printf '| Mode | %s |\n' "${file_mode}"
  printf '| Invoking user can write the file | no (measured) |\n'
  printf '| Invoking user can create an entry in the directory | no (measured) |\n'
  printf '| Managed-only keys present | %s |\n' "${present_keys[*]}"
  printf '\n**Verdict: MEASURED — PASS.** uid 0 ownership is observed on a real host,\n'
  printf 'not inferred.\n'
  printf '\n## Item 2 — `MacOsAdminAuthority` success path and rollback\n\n'
  printf 'Paste the verbatim output of the install and the removal.\n\n'
  printf '```console\n<!-- FILL: aasm integrations install claude-code --install-managed-settings -->\n```\n\n'
  printf '```console\n<!-- FILL: aasm integrations remove claude-code -->\n```\n\n'
  printf 'Verdict: <!-- FILL -->\n'
  printf '\n## Item 3 — each managed-only key against a real override attempt\n\n'
  printf '| Managed-only key | Override attempted | Refused? | Evidence |\n|---|---|---|---|\n'
  for key in "${MANAGED_ONLY_KEYS[@]}"; do
    printf '| `%s` | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |\n' "${key}"
  done
  printf '\n**These are unmeasured until every cell is filled from a real session.**\n'
  printf '\n## Item 4 — server-managed-settings fetch and `forceRemoteSettingsRefresh`\n\n'
  printf '| Field | Value |\n|---|---|\n'
  printf '| Measurable in the capture shell | %s |\n' "${remote_settings_measurable}"
  printf '| `forceRemoteSettingsRefresh` fails closed at startup | <!-- FILL --> |\n'
  printf '\n## Item 5 — Agent Assembly'"'"'s own reading\n\n'
  printf '| Which runtime produced this reading | Value |\n|---|---|\n'
  printf '| Provenance verdict | %s |\n' "${aasm_runtime_verdict}"
  printf '| Runtime pid | %s |\n' "${aasm_runtime_pid}"
  printf '| Runtime build | `%s` |\n\n' "${aasm_runtime_build}"
  printf '```json\n%s\n```\n' "${aasm_status}"
  printf '\n## Bypasses this mechanism closes, and those it does not\n\n'
  printf '| Bypass | Closed by the managed file? | Evidence |\n|---|---|---|\n'
  printf '| `--dangerously-skip-permissions` | <!-- FILL --> | <!-- FILL --> |\n'
  printf '| `defaultMode: "bypassPermissions"` in user settings | <!-- FILL --> | <!-- FILL --> |\n'
  printf '| User-scoped permission rules widening the managed ones | <!-- FILL --> | <!-- FILL --> |\n'
  printf '| An unmanaged launch (`claude` started directly) | <!-- FILL --> | <!-- FILL --> |\n'
  printf '| `ANTHROPIC_BASE_URL` redirection | <!-- FILL --> | <!-- FILL --> |\n'
} > "${out_file}"

pass "evidence skeleton written to ${out_file}"
say ""
say "======================================================================"
say "C6 IS NOT CLOSED BY THIS SCRIPT."
say "It measured the file-level facts only. The four managed-only key"
say "verdicts and the MacOsAdminAuthority success path are unfilled in"
say "${out_file} until an operator records them from a real session."
say "======================================================================"
