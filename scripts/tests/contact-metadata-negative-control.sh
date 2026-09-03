#!/usr/bin/env bash
# AAASM-5756 negative-control harness for scripts/check_contact_metadata.py.
#
# Proves the `--check` gate is genuinely load-bearing, not merely present —
# same "assert on exit codes, not narrative" convention already established
# by scripts/qa/validate-golden-journeys-negative-control.sh and
# scripts/tests/release-evidence-negative-control.sh. Every case below runs
# against a disposable fixture copy in a tmpdir via `--root`
# (scripts/check_contact_metadata.py's --root option, added in this same
# ticket for exactly this purpose) — the live tree under this repo's own
# SECURITY.md/README.md is never mutated.
#
# The gate's own exit-code convention (read from its source, not assumed):
#   0 = in sync
#   1 = --check mode, a bounded region is intact but its rendered content
#       drifted from the pinned registry (ContentDriftError not raised;
#       `drifted` list non-empty)
#   2 = a bounded region/sentinel or a target file is structurally missing,
#       or README.md's single-literal regex matched zero or more than one
#       time (ContactDriftError / FileNotFoundError / OSError, caught in
#       main() and reported as ERROR)
#
# Case 2 below is the AC#4 case this ticket requires to unambiguously exist:
# the generated region entirely removed must turn the gate red.
#
# Usage: bash scripts/tests/contact-metadata-negative-control.sh
# Run from the repo root (uses the real, post-fix SECURITY.md/README.md as
# the clean baseline).
set -euo pipefail

CHECKER="scripts/check_contact_metadata.py"
FAILED=0

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BASELINE="$WORKDIR/baseline"
mkdir -p "$BASELINE"
cp SECURITY.md "$BASELINE/SECURITY.md"
cp README.md "$BASELINE/README.md"

# Sanity: the baseline itself must be clean before any case can be trusted.
if ! python3 "$CHECKER" --check --root "$BASELINE" >/dev/null 2>&1; then
  echo "FATAL: baseline fixture (copied from the live, post-fix tree) is not clean." >&2
  echo "This harness cannot certify anything until the live tree is clean." >&2
  exit 2
fi

# fresh_fixture <name>: copy the clean baseline into $WORKDIR/<name> and echo
# the path. Each case mutates its own private copy — no cross-case leakage.
fresh_fixture() {
  local name="$1"
  local dir="$WORKDIR/$name"
  rm -rf "$dir"
  mkdir -p "$dir"
  cp "$BASELINE/SECURITY.md" "$dir/SECURITY.md"
  cp "$BASELINE/README.md" "$dir/README.md"
  echo "$dir"
}

assert_exit() {
  local label="$1" dir="$2" expected="$3"
  local out
  set +e
  out=$(python3 "$CHECKER" --check --root "$dir" 2>&1)
  local actual=$?
  set -e
  if [ "$actual" -eq "$expected" ]; then
    echo "  PASS: $label (exit $actual, expected $expected)"
  else
    echo "  FAIL: $label (exit $actual, expected $expected)"
    echo "    output: $out"
    FAILED=1
  fi
}

echo "== Case 1: clean fixture (copy of the real, post-fix tree) =="
d="$(fresh_fixture case1-clean)"
assert_exit "clean fixture" "$d" 0

echo "== Case 2 (AC#4 required case): security_sla BEGIN sentinel removed — generated region entirely missing =="
d="$(fresh_fixture case2-missing-sla-begin)"
sed -i.bak '/<!-- BEGIN GENERATED: security_sla -->/d' "$d/SECURITY.md" && rm -f "$d/SECURITY.md.bak"
assert_exit "security_sla BEGIN sentinel removed" "$d" 2

echo "== Case 3: security_contact_email END sentinel removed — generated region entirely missing =="
d="$(fresh_fixture case3-missing-email-end)"
sed -i.bak '/<!-- END GENERATED: security_contact_email -->/d' "$d/SECURITY.md" && rm -f "$d/SECURITY.md.bak"
assert_exit "security_contact_email END sentinel removed" "$d" 2

echo "== Case 4: whole security_contact_email block (both sentinels + body) deleted =="
d="$(fresh_fixture case4-missing-email-block)"
python3 - "$d/SECURITY.md" <<'EOF'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
new_text = re.sub(
    r"<!-- BEGIN GENERATED: security_contact_email -->.*?<!-- END GENERATED: security_contact_email -->\n?",
    "",
    text,
    flags=re.DOTALL,
)
assert new_text != text, "fixture mutation did not change the file"
open(path, "w", encoding="utf-8").write(new_text)
EOF
assert_exit "whole security_contact_email block deleted" "$d" 2

echo "== Case 5: canonical email inside the block edited to the legacy .dev domain (region intact, value drifted) =="
d="$(fresh_fixture case5-email-drift)"
sed -i.bak 's/Alternatively, email \*\*security@agent-assembly\.com\*\*/Alternatively, email **security@agent-assembly.dev**/' "$d/SECURITY.md" && rm -f "$d/SECURITY.md.bak"
assert_exit "canonical email edited to legacy .dev domain" "$d" 1

echo "== Case 6: an SLA day-count edited (region intact, value drifted) =="
d="$(fresh_fixture case6-daycount-drift)"
sed -i.bak 's/Within 2 business days/Within 3 business days/' "$d/SECURITY.md" && rm -f "$d/SECURITY.md.bak"
assert_exit "SLA day-count edited" "$d" 1

echo "== Case 7: an SLA row label edited (region intact, value drifted) =="
d="$(fresh_fixture case7-label-drift)"
sed -i.bak 's/| Acknowledgement |/| Ack |/' "$d/SECURITY.md" && rm -f "$d/SECURITY.md.bak"
assert_exit "SLA row label edited" "$d" 1

echo "== Case 8: README.md's security email literal deleted (regex matches zero times) =="
d="$(fresh_fixture case8-readme-missing)"
sed -i.bak 's/security@agent-assembly\.com/security@agent-assembly.example/' "$d/README.md" && rm -f "$d/README.md.bak"
assert_exit "README.md security email literal missing" "$d" 2

echo "== Case 9: README.md's security email literal duplicated (regex matches more than once) =="
d="$(fresh_fixture case9-readme-duplicated)"
python3 - "$d/README.md" <<'EOF'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
pattern = re.compile(r"email `security@agent-assembly\.(dev|com)`")
m = pattern.search(text)
assert m, "fixture setup: expected literal not found in README.md"
new_text = text[: m.end()] + " " + m.group(0) + text[m.end() :]
assert new_text != text, "fixture mutation did not change the file"
open(path, "w", encoding="utf-8").write(new_text)
EOF
assert_exit "README.md security email literal duplicated" "$d" 2

if [ "$FAILED" -ne 0 ]; then
  echo ""
  echo "contact-metadata-negative-control: FAILED — the gate is not load-bearing for one or more cases"
  exit 1
fi

echo ""
echo "contact-metadata-negative-control: all 9 assertions passed"
