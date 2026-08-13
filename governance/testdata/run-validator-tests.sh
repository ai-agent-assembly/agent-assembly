#!/usr/bin/env bash
#
# Proves the capability-manifest gate can go red, and for the right reason.
#
# AAASM-5531. A gate nobody has watched fail is not known to work. Each
# invalid-<rule>-*.yaml in this directory is valid-minimal.yaml with exactly one
# thing wrong, and this harness asserts three things per fixture:
#
#   1. the validator exits non-zero,
#   2. the failure names the rule the filename claims — not merely some rule, so
#      a fixture cannot pass by tripping an unrelated check,
#   3. valid-minimal.yaml itself still exits zero, so the harness is not simply
#      always red.
#
# The schema half of the gate is exercised too: the fixtures that break a closed
# vocabulary or add a banned key must also fail `ajv validate`.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
validator="${repo}/scripts/validate_capability_manifest.py"
schema="${repo}/schemas/capability-manifest/v1/capability-manifest.schema.json"

pass=0
fail=0

ok()   { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  FAIL  %s — %s\n' "$1" "$2"; fail=$((fail + 1)); }

#
# Credited by what actually RAN, never a flat +1. R3-F1: crediting this file
# `pass+1` meant emptying its PROBES list left the harness total unchanged at 51
# with every hazard regression gone and CI green. The sub-counts are now folded
# in, so a probe that stops running moves the number it is counted in.
credit() {  # $1 = label, $2 = script output
  local line p f
  line="$(printf '%s\n' "$2" | grep -E '^HARNESS_COUNTS ' | tail -1)"
  if [ -z "${line}" ]; then
    bad "$1" "emitted no HARNESS_COUNTS trailer, so its results cannot be counted"
    return
  fi
  p="$(printf '%s' "${line}" | sed -E 's/.*passed=([0-9]+).*/\1/')"
  f="$(printf '%s' "${line}" | sed -E 's/.*failed=([0-9]+).*/\1/')"
  pass=$((pass + p))
  fail=$((fail + f))
}

# Positive controls. Globbed rather than naming valid-minimal alone, so a rule
# whose green counterpart is a separate file (R15's one-line-diff pair) is
# asserted to PASS and not merely asserted to fail — a gate nobody has watched
# pass for the right reason is no better evidenced than one nobody has watched
# fail.
echo "positive controls"
for fixture in "${here}"/valid-*.yaml; do
  name="$(basename "${fixture}")"
  if out="$(python3 "${validator}" --manifest "${fixture}" 2>&1)"; then
    ok "${name} exits 0"
  else
    bad "${name}" "expected exit 0: ${out}"
  fi
done

echo "negative controls (validator)"
for fixture in "${here}"/invalid-*.yaml; do
  name="$(basename "${fixture}")"
  # invalid-r8b-... -> R8b ; invalid-r7-ladder-... -> R7. The trailing variant
  # letter stays lower case, so only the leading r is upper-cased.
  rule="R$(printf '%s' "${name}" | sed -E 's/^invalid-r([0-9]+b?)-.*/\1/')"
  out="$(python3 "${validator}" --manifest "${fixture}" 2>&1)"
  code=$?
  if [ "${code}" -eq 0 ]; then
    bad "${name}" "expected a non-zero exit, got 0"
  elif ! printf '%s' "${out}" | grep -q "\[${rule}\]"; then
    bad "${name}" "exited ${code} but no [${rule}] finding; got: $(printf '%s' "${out}" | head -1)"
  else
    ok "${name} -> ${rule}"
  fi
done

# R15's other three branches turn on the state of the REPOSITORY — whether any
# tag resolves, whether the evidence tree is inside the newest one, whether
# --no-git was passed — so no manifest fixture can express them. They live in a
# script beside this one, with a positive control proving its zeros are measured.
echo "negative controls (R15 repository-state branches)"
if out="$(python3 "${here}/r15_branch_probes.py" 2>&1)"; then
  printf '%s\n' "${out}" | sed -n 's/^  ok    /  ok    /p'
  credit "r15_branch_probes.py" "${out}"
else
  bad "r15_branch_probes.py" "$(printf '%s' "${out}" | tail -3)"
fi

# The input class the fixtures above CANNOT express: the real manifest, minus one
# key. Every instance of the "driver lives inside the artifact it gates" hazard —
# R17 clause 3's absence block, R16's seed repoint, and the two-edit variant that
# survived the first fix — lives in that class, and all three reached review
# because nothing here ever ran the validator against the canonical document.
# A suite blind to an input class is silent about it, and silence reads as green.
echo "negative controls (real manifest, mutated in place)"
if out="$(python3 "${here}/real_manifest_probes.py" 2>&1)"; then
  printf '%s\n' "${out}" | sed -n 's/^  ok    /  ok    /p'
  credit "real_manifest_probes.py" "${out}"
else
  # A refusal (dirty manifest, or a shrunken PROBES list) is reported as a
  # failure on purpose: a probe that did not run must never read as one that
  # passed.
  bad "real_manifest_probes.py" "$(printf '%s' "${out}" | grep -E '^  FAIL|RESTORE|Refusing|expected' | head -3)"
fi

# Two claims no fixture file can state, because every fixture IS a manifest:
# that a document which is not one is refused rather than crashed on or
# opinionated about, and that "the tool did not validate" (exit 2) and "the
# document is invalid" (exit 1) stay different numbers. Plus the four
# array-of-object fields beyond the one the AAASM-5692 crash was reported
# against, which would otherwise be four near-identical fixture files.
echo "negative controls (input scope and structure)"
if out="$(python3 "${here}/input_shape_probes.py" 2>&1)"; then
  printf '%s\n' "${out}" | sed -n 's/^  ok    /  ok    /p'
  credit "input_shape_probes.py" "${out}"
else
  bad "input_shape_probes.py" "$(printf '%s' "${out}" | grep -E '^  FAIL' | head -3)"
fi

# The README pastes the gate's own count: lines. Round 1 shipped them stale, in a
# document whose thesis is that the counts are printed on every run. Correcting
# them was not a mechanism; this is.
echo "governance/README.md count block matches the live gate"
if out="$(python3 "${here}/readme_counts_probe.py" 2>&1)"; then
  printf '%s\n' "${out}" | sed -n 's/^  ok    /  ok    /p'
  credit "readme_counts_probe.py" "${out}"
else
  bad "readme_counts_probe.py" "$(printf '%s' "${out}" | grep -E '^  FAIL' | head -3)"
fi

# Fixtures whose defect is structural rather than semantic must ALSO be caught
# by the schema, because ajv is the half of the gate that runs first.
echo "negative controls (schema)"
for name in \
  invalid-r6-unknown-claim-term.yaml \
  invalid-r7-ladder-rung-as-claim.yaml \
  invalid-r7-ticket-coined-term.yaml \
  invalid-r7-ceiling-as-state.yaml \
  invalid-r10-collapsed-boolean.yaml \
  invalid-r3-branch-evidence-tree.yaml \
  invalid-r1-string-evidence-item.yaml \
  invalid-r1-scalar-where-list-declared.yaml
do
  if npx --yes ajv-cli@5 validate --strict -s "${schema}" -d "${here}/${name}" >/dev/null 2>&1; then
    bad "${name}" "ajv accepted it; the schema should reject this too"
  else
    ok "${name} rejected by ajv"
  fi
done

for fixture in "${here}"/valid-*.yaml; do
  name="$(basename "${fixture}")"
  if npx --yes ajv-cli@5 validate --strict -s "${schema}" -d "${fixture}" >/dev/null 2>&1; then
    ok "${name} accepted by ajv"
  else
    bad "${name}" "ajv rejected a positive control"
  fi
done

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"

# R3-F1, the general form. Nothing asserted this suite's own denominator, so
# `mv invalid-r17-absence-block-deleted.yaml /tmp/` — the regression test for
# round 1's F1 — gave "50 passed, 0 failed" and exit 0. A check silently no
# longer running is the failure mode every rule in this directory exists to
# prevent; the harness has to hold itself to it.
#
# Bump this deliberately when adding or removing a fixture or a probe. The
# breakdown is here so the next person can see WHICH part moved:
#   4  valid-*.yaml through the validator
#  36  invalid-*.yaml through the validator
#   4  r15_branch_probes.py    (one per R15 repository-state branch)
#   8  real_manifest_probes.py   (5 mutations + 1 attribution control + positive + restore)
#  20  input_shape_probes.py     (positive + seed scope + exit-code discrimination
#                                 + the derivation floor + one bare-string mutation per
#                                 field the SCHEMA declares a mapping or list-of-mappings:
#                                 7 + 9 today. This one MOVES WITH THE SCHEMA by design —
#                                 adding such a field makes the probe emit one more check
#                                 and turns this total red until it is bumped on purpose.)
#   8  readme_counts_probe.py    (one per quoted count: line + the EXPECTED_TOTAL cross-check)
#   8  schema negative controls through ajv
#   4  valid-*.yaml through ajv
EXPECTED_TOTAL=92
if [ "$((pass + fail))" -ne "${EXPECTED_TOTAL}" ]; then
  printf 'FAIL  the harness ran %d checks, expected %d. A check that stops running is
' \
    "$((pass + fail))" "${EXPECTED_TOTAL}"
  printf '      indistinguishable from one that passes unless the total is asserted.\n'
  exit 1
fi

[ "${fail}" -eq 0 ]
