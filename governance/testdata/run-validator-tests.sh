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
  ok "r15_branch_probes.py — 4 branches"
else
  bad "r15_branch_probes.py" "$(printf '%s' "${out}" | tail -3)"
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
  invalid-r3-branch-evidence-tree.yaml
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
[ "${fail}" -eq 0 ]
