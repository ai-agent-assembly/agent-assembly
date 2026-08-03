#!/usr/bin/env bash
# Report how much of a test lane actually measured something — AAASM-5465.
#
# The problem
# -----------
# A scenario whose precondition is absent (no `claude` binary, wrong platform)
# prints `SKIP [...]` and returns. The test runner counts that as a pass, so
# `26 tests run: 26 passed` is emitted whether the lane measured twenty-six
# things or zero. In the worst case — `aa-cli/tests/integrations_claude_code.rs`
# on Linux, where *every* case is gated on the tool — a lane that asserted
# nothing at all reports five green tests.
#
# The fix
# -------
# Two independent sources, netted against each other:
#
#   * nextest's JUnit report says how many cases the runner ran and how many
#     passed. It is the only thing that knows the denominator, and it cannot
#     drift when a test is added.
#   * The evidence ledger (`aa-integration-tests/tests/evidence/mod.rs`) carries
#     one record per case that *declined* to measure, with the reason separated
#     into `unsupported_platform` (a) and `tool_absent` (b) — because a lane that
#     provisions the binary and still reports (b) is broken, while the same lane
#     reporting (a) is merely on the wrong runner, and the two need different
#     fixes.
#
# substantive = passed − declined. That number, its breakdown, and every
# individual record are written to the job summary, so a reader of CI output does
# not have to reconstruct any of it from `--no-capture` stdout.
#
# When the lane exists in order to take a measurement, `--require-evidence` makes
# substantive == 0 a failure. Without it, substantive == 0 is still reported —
# loudly, as NO EVIDENCE PRODUCED, with a workflow warning annotation — but does
# not fail the job. Silence is never an option; only the severity is.
#
# Usage:
#   .ci/test-evidence-summary.sh --lane <name> --junit <file> \
#       --evidence-dir <dir> [--require-evidence]
#
# Exit status:
#   0  the lane measured something, or measured nothing without --require-evidence
#   1  --require-evidence and the lane measured nothing
#   2  usage error, or the JUnit report is missing/unparseable

set -euo pipefail

lane=""
junit=""
evidence_dir=""
require_evidence=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --lane) lane="${2:?--lane needs a value}"; shift 2 ;;
        --junit) junit="${2:?--junit needs a value}"; shift 2 ;;
        --evidence-dir) evidence_dir="${2:?--evidence-dir needs a value}"; shift 2 ;;
        --require-evidence) require_evidence=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "${lane}" ] || [ -z "${junit}" ] || [ -z "${evidence_dir}" ]; then
    echo "usage: $0 --lane <name> --junit <file> --evidence-dir <dir> [--require-evidence]" >&2
    exit 2
fi

# A missing report is itself an absence of evidence, and the one failure mode
# this script must not paper over: a summary computed from nothing would report
# "0 ran, 0 declined, 0 substantive" and look exactly like a lane whose tests all
# declined. Fail loudly instead.
if [ ! -f "${junit}" ]; then
    echo "::error title=Test evidence unavailable (${lane})::no JUnit report at ${junit}; nothing can be said about what this lane measured."
    exit 2
fi

# The `<testsuites>` root carries the run-wide totals. Read the first occurrence
# of each attribute on it, which is the aggregate rather than a per-suite figure.
#
# `|| true` on each grep: an absent attribute is a legitimate answer this script
# handles below, and under `pipefail` a non-matching grep would abort instead.
attr() {
    { grep -m1 -o "<testsuites[^>]*" "${junit}" || true; } \
        | { grep -o " $1=\"[0-9]*\"" || true; } \
        | head -1 \
        | tr -dc '0-9'
}

ran="$(attr tests)"
failures="$(attr failures)"
errors="$(attr errors)"
: "${ran:=}" "${failures:=0}" "${errors:=0}"

if [ -z "${ran}" ]; then
    echo "::error title=Test evidence unparseable (${lane})::${junit} has no <testsuites tests=...> total; the runner's own count could not be read."
    exit 2
fi

passed=$(( ran - failures - errors ))

# One file per scenario, so a count of files matching an outcome is a count of
# scenarios. `grep -l` over the ledger keeps this free of a JSON dependency,
# matching the writer, which has none either.
count_outcome() {
    if ! compgen -G "${evidence_dir}/*.json" > /dev/null 2>&1; then
        echo 0
        return
    fi
    # `|| true`: zero scenarios with this outcome is the common, expected answer,
    # and grep reports it as exit 1 — which `pipefail` would turn into an abort.
    { grep -l "\"outcome\": \"$1\"" "${evidence_dir}"/*.json 2>/dev/null || true; } | wc -l | tr -dc '0-9'
}

unsupported="$(count_outcome unsupported_platform)"
tool_absent="$(count_outcome tool_absent)"
not_measured="$(count_outcome not_measured)"
declared_measured="$(count_outcome measured)"
: "${unsupported:=0}" "${tool_absent:=0}" "${not_measured:=0}" "${declared_measured:=0}"

declined=$(( unsupported + tool_absent ))
substantive=$(( passed - declined ))
if [ "${substantive}" -lt 0 ]; then
    # More declarations than passes: a scenario recorded a decline and then
    # failed for an unrelated reason. Clamp rather than report a negative — the
    # failure is already reported by the runner.
    substantive=0
fi

# ── the report ──────────────────────────────────────────────────────────────
#
# Written to stdout unconditionally and to the job summary when there is one, so
# the numbers are in the log for a local run and on the run's front page in CI.
summary_file="${GITHUB_STEP_SUMMARY:-/dev/null}"

{
    echo "### Test evidence — ${lane}"
    echo
    echo "| | count |"
    echo "|---|---:|"
    echo "| cases the runner ran | ${ran} |"
    echo "| …of which passed | ${passed} |"
    echo "| **substantive cases (executed and asserted)** | **${substantive}** |"
    echo "| declined — unsupported platform | ${unsupported} |"
    echo "| declined — tool binary absent | ${tool_absent} |"
    echo "| committed to measure and produced nothing | ${not_measured} |"
    echo "| explicitly recorded a measurement | ${declared_measured} |"
    echo
    if [ "${declined}" -gt 0 ] || [ "${not_measured}" -gt 0 ] || [ "${declared_measured}" -gt 0 ]; then
        echo "<details><summary>Per-scenario records</summary>"
        echo
        for record in "${evidence_dir}"/*.json; do
            [ -f "${record}" ] || continue
            field() { grep -o "\"$1\": \"[^\"]*\"" "${record}" | head -1 | sed "s/\"$1\": \"//; s/\"$//"; }
            printf -- '- `%s` — **%s** (%s) — %s\n' "$(field scenario)" "$(field outcome)" "$(field platform)" "$(field detail)"
        done
        echo
        echo "</details>"
        echo
    fi
} | tee -a "${summary_file}"

# ── the verdict ─────────────────────────────────────────────────────────────

if [ "${substantive}" -gt 0 ]; then
    echo "::notice title=Test evidence (${lane})::${substantive} of ${passed} passing case(s) were substantive; ${declined} declined (${unsupported} unsupported platform, ${tool_absent} tool absent)."
    exit 0
fi

verdict="every one of this lane's ${passed} passing case(s) declined to measure (${unsupported} unsupported platform, ${tool_absent} tool binary absent). A green result here establishes nothing about the product."

printf '\n> **NO EVIDENCE PRODUCED** — %s\n\n' "${verdict}" | tee -a "${summary_file}"

if [ "${require_evidence}" -eq 1 ]; then
    echo "::error title=Lane measured nothing (${lane})::${verdict} This lane exists to take a measurement and did not take one."
    exit 1
fi

echo "::warning title=Lane measured nothing (${lane})::${verdict}"
exit 0
