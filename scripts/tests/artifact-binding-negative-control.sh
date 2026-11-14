#!/usr/bin/env bash
# AAASM-6468: prove scripts/tests/test_artifact_binding.py can fail. Each case
# applies ONE mutation to a scratch copy of artifact_binding.py (the real one is
# never touched) and requires the unit tests to go red; the unmutated copy must
# stay green, so a failure is attributable to the mutation alone.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/scripts/release" "$work/scripts/tests"
cp "$here/scripts/tests/test_artifact_binding.py" "$work/scripts/tests/"
run_tests() { python3 -I "$work/scripts/tests/test_artifact_binding.py" >/dev/null 2>&1; }

cp "$here/scripts/release/artifact_binding.py" "$work/scripts/release/"
run_tests || { echo "FAIL: unmutated script does not pass its own tests"; exit 1; }
echo "ok   unmutated baseline is green"

fails=0
mutate() { # name, old, new
  cp "$here/scripts/release/artifact_binding.py" "$work/scripts/release/artifact_binding.py"
  python3 -I - "$work/scripts/release/artifact_binding.py" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1:]
s = open(p).read()
assert s.count(old) == 1, f"mutation anchor not found exactly once: {old!r}"
open(p, "w").write(s.replace(old, new))
PY
  if run_tests; then echo "FAIL: mutation '$1' went undetected"; fails=$((fails + 1)); else echo "ok   mutation '$1' is caught"; fi
}

mutate "ignore extra files" 'for name in sorted(set(present) - set(digests)):' 'for name in []:'
mutate "ignore missing files" 'for name in sorted(set(digests) - set(present)):' 'for name in []:'
mutate "skip hash comparison" 'if actual != digests[name]:' 'if False:'
mutate "accept symlinks and directories" 'if entry.is_symlink() or not entry.is_file(follow_symlinks=False):' 'if False:'
mutate "accept empty digest output" 'return {}, [f"{label}: digest output is empty or unset"]' 'return {}, []'
mutate "skip expected-name check" 'if set(data) != expected:' 'if False:'
mutate "ebpf: ignore its digests" 'return problems + verify_dir(directory, data)' 'return []'

[ "$fails" -eq 0 ] || { echo "artifact-binding negative control: $fails mutation(s) undetected"; exit 1; }
echo "artifact-binding negative control: all mutations detected"
