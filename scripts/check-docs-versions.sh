#!/usr/bin/env bash
# Verify that version-dependent agent-assembly docs match a release line.
# AAASM-3453 (release-docs-sync — "docs never go stale on release").
#
# Usage:
#   bash scripts/check-docs-versions.sh <version>
#     e.g. bash scripts/check-docs-versions.sh 0.0.1-beta.2
#          bash scripts/check-docs-versions.sh v0.0.1-beta.3
#
# Why this exists
# ---------------
# `release-tag-cut` bumps the Cargo workspace version literals on a release, but
# it does NOT touch documentation/content version references. The drift that
# AAASM-3372 found (compatibility.md stuck at alpha.5, installation.md sample
# versions stale) happens because that update is a manual, forgettable step.
# This script makes a forgotten update fail mechanically instead of shipping.
#
# What it checks (scoped to the LIVE install examples + compat matrix only)
# ------------------------------------------------------------------------
# A. docs/src/quick-start/installation.md
#      - AASM_VERSION=v<ver>     (pin-a-version example)
#      - VERSION=v<ver>          (manual-download example)
#      - `aasm <ver>`            (--version sample output)
#      - cli | <ver> table cell  (aasm version table sample)
# B. docs/src/compatibility.md
#      - the live Compatibility Matrix must contain a row for the target
#        runtime version (i.e. a new row was added for this release)
# C. README.md (repo root)
#      - AASM_VERSION=v<ver>     (quick-install snippet)
#      - the "latest [`v<ver>`]" Project Status line
#
# Precision: this script does NOT scan release-notes / CHANGELOG / the
# "Workspace changes" history table — those legitimately name older versions.
# It only asserts the designated live-example lines and that a matrix ROW for
# the target version exists; it never asserts that older rows are absent.
#
# Exit codes: 0 = all designated refs match the target version; 1 = at least
# one stale/missing ref; 2 = usage / file-not-found error.

set -uo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>  (e.g. 0.0.1-beta.2 or v0.0.1-beta.3)" >&2
  exit 2
fi

# Normalize: strip a leading "v" so we can build both "<ver>" and "v<ver>".
RAW="$1"
VER="${RAW#v}"
VVER="v${VER}"

# Resolve the repo root so the script runs from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

INSTALL="${ROOT}/docs/src/quick-start/installation.md"
COMPAT="${ROOT}/docs/src/compatibility.md"
README="${ROOT}/README.md"

FAIL=0
pass() { printf '\xE2\x9C\x93 %s\n' "$1"; }
fail() { printf '\xE2\x9C\x97 %s: %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

require_file() {
  if [ ! -f "$1" ]; then
    echo "error: required file not found: $1" >&2
    exit 2
  fi
}
require_file "$INSTALL"
require_file "$COMPAT"
require_file "$README"

# A fixed-string grep helper (literal match, anywhere in the file).
has() { grep -qF -- "$2" "$1"; }

echo "Checking docs version refs against release line: ${VVER}"
echo "  (files: installation.md, compatibility.md, README.md)"
echo

# --- A. installation.md -----------------------------------------------------
if has "$INSTALL" "AASM_VERSION=${VVER} "; then
  pass "installation.md: AASM_VERSION pin example -> ${VVER}"
else
  fail "installation.md: AASM_VERSION pin example" \
       "expected 'AASM_VERSION=${VVER} ' — update the pin-a-version snippet"
fi

if has "$INSTALL" "VERSION=${VVER}"; then
  pass "installation.md: manual-download VERSION example -> ${VVER}"
else
  fail "installation.md: manual-download VERSION example" \
       "expected 'VERSION=${VVER}' — update the pre-built-binaries snippet"
fi

if has "$INSTALL" "aasm ${VER}"; then
  pass "installation.md: 'aasm --version' sample output -> ${VER}"
else
  fail "installation.md: 'aasm --version' sample output" \
       "expected 'aasm ${VER}' — update the verify-the-install sample"
fi

if has "$INSTALL" "| cli       | ${VER} "; then
  pass "installation.md: 'aasm version' table sample -> ${VER}"
else
  fail "installation.md: 'aasm version' table sample" \
       "expected a '| cli       | ${VER} ' row — update the version-table sample"
fi

# --- B. compatibility.md: a matrix row for this runtime version exists -------
# A matrix row starts with '| v<ver> |' (leading cell = the aa-runtime version).
if grep -qE "^\| ${VVER} \|" "$COMPAT"; then
  pass "compatibility.md: Compatibility Matrix has a row for ${VVER}"
else
  fail "compatibility.md: Compatibility Matrix row for ${VVER}" \
       "no '| ${VVER} | ...' row found — add the new compatibility-matrix row for this release"
fi

# --- C. README.md -----------------------------------------------------------
if has "$README" "AASM_VERSION=${VVER} "; then
  pass "README.md: AASM_VERSION quick-install snippet -> ${VVER}"
else
  fail "README.md: AASM_VERSION quick-install snippet" \
       "expected 'AASM_VERSION=${VVER} ' — update the README quick-install example"
fi

# The Project Status line reads:  latest [`v<ver>`](.../tag/v<ver>)
if has "$README" "[\`${VVER}\`]"; then
  pass "README.md: Project Status 'latest' line -> ${VVER}"
else
  fail "README.md: Project Status 'latest' line" \
       "expected a '[\`${VVER}\`]' reference — update the Project Status latest-release line"
fi

echo
if [ "$FAIL" -ne 0 ]; then
  echo "FAILED: ${FAIL} stale/missing docs version ref(s) for ${VVER}." >&2
  echo "Run the release-docs-sync skill to fix them, then re-run this check." >&2
  exit 1
fi
echo "OK: all designated docs version refs match ${VVER}."
