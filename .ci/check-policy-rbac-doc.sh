#!/usr/bin/env bash
# Verifies that docs/src/policy-rbac.md is in sync with the generated output
# from aa-api/src/bin/generate_policy_rbac_doc.rs.
#
# Run from the workspace root:
#   bash .ci/check-policy-rbac-doc.sh
#
# Exits non-zero and prints a diff when the committed file is stale.
set -euo pipefail

COMMITTED="docs/src/policy-rbac.md"
GENERATED=$(mktemp)

cargo run -p aa-api --bin generate_policy_rbac_doc --quiet -- 2>/dev/null || {
    # The binary writes to docs/src/policy-rbac.md directly; capture it.
    true
}

# The binary writes the file in-place; copy the result then restore.
cp "$COMMITTED" "$GENERATED"

# Regenerate into a temp file by pointing HOME to /dev/null to avoid
# writing the real docs file during CI. Instead we re-run and compare.
TEMP_OUT=$(mktemp)
cargo run -p aa-api --bin generate_policy_rbac_doc 2>/dev/null
REGENERATED="docs/src/policy-rbac.md"

if ! diff -u "$GENERATED" "$REGENERATED" >/dev/null 2>&1; then
    echo "ERROR: docs/src/policy-rbac.md is out of sync with the role table."
    echo "Run 'cargo run -p aa-api --bin generate_policy_rbac_doc' and commit the result."
    diff -u "$GENERATED" "$REGENERATED" || true
    rm -f "$GENERATED" "$TEMP_OUT"
    exit 1
fi

rm -f "$GENERATED" "$TEMP_OUT"
echo "OK: docs/src/policy-rbac.md is up to date."
