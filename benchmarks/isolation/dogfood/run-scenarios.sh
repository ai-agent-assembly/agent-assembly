#!/usr/bin/env bash
# AAASM-5809 — real dogfood scenario driver for `aasm run`'s isolation runtime.
#
# This is NOT a new benchmark framework (that's AAASM-5805's already-closed
# scope, benchmarks/isolation/harness/). It is a short, linear shell script
# that walks the ticket's scenario list once per backend, invoking `aasm run
# exec` exactly the way an operator would from a terminal, and records what
# actually happened — exit code, stdout, stderr (which carries the
# machine-readable isolation report, AAASM-5710), and wall-clock timing — as
# evidence a human can read afterward. It asserts nothing about pass/fail
# itself; AAASM-5809's acceptance criteria are about recorded evidence, not a
# green check (see the ticket's "Testing / Verification" section).
#
# Every denial scenario is paired with a negative control: the identical
# command, same backend, same scratch tree, run under a policy that grants
# what the confined run denies. Without that pairing a "denied" result cannot
# be told apart from "the command itself is broken" — the discipline
# aa-cli/tests/run_isolation_linux.rs's module doc names directly, and the one
# this driver borrows.
#
# Usage: run-scenarios.sh <scratch_root> <out_dir> [backend ...]
#   scratch_root  absolute, already-created directory (like the confined-arm
#                 benchmark's own scratch root — the write grant in the
#                 rendered policies names this path, so it must exist first)
#   out_dir       absolute directory this driver writes its evidence into
#   backend...    backend ids to exercise explicit pinning against, in
#                 addition to `--isolation auto`. Defaults to "sandlock
#                 aasm-native" (both compiled-in backends, AAASM-5805 /
#                 AAASM-5802). A backend this host cannot provide records its
#                 own decline rather than being skipped silently — see
#                 record_result()'s `outcome` field.
#
# Required environment:
#   AABENCH_AASM_BIN   path to the `aasm` binary this driver exercises
#   REPO_ROOT           the checkout `git`/read-only scenarios inspect
set -euo pipefail

SCRATCH_ROOT="${1:?usage: run-scenarios.sh <scratch_root> <out_dir> [backend ...]}"
OUT_DIR="${2:?usage: run-scenarios.sh <scratch_root> <out_dir> [backend ...]}"
shift 2
BACKENDS=("$@")
if [ "${#BACKENDS[@]}" -eq 0 ]; then
    BACKENDS=(sandlock aasm-native)
fi

AASM_BIN="${AABENCH_AASM_BIN:?AABENCH_AASM_BIN must point at the aasm binary this driver exercises}"
REPO_ROOT="${REPO_ROOT:?REPO_ROOT must point at the repository checkout scenarios inspect}"

SELF_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
POLICY_DIR="$SELF_DIR/policy"

mkdir -p "$OUT_DIR" "$SCRATCH_ROOT/permitted" "$SCRATCH_ROOT/forbidden"

# `benchmarks/isolation/policy/render.sh` is not reused here directly — it
# hardcodes its own template's filename, and this driver renders three. The
# substitution it performs (`__SCRATCH_ROOT__` -> the scratch root, via `sed`)
# is one line and is applied identically to all three below.
CONFINED_POLICY="$OUT_DIR/confined.yaml"
CONFINED_NO_EXEC_POLICY="$OUT_DIR/confined-no-exec.yaml"
PERMISSIVE_POLICY="$OUT_DIR/permissive.yaml"
sed "s|__SCRATCH_ROOT__|${SCRATCH_ROOT}|g" "$POLICY_DIR/confined.yaml.tmpl" > "$CONFINED_POLICY"
sed "s|__SCRATCH_ROOT__|${SCRATCH_ROOT}|g" "$POLICY_DIR/confined-no-exec.yaml.tmpl" > "$CONFINED_NO_EXEC_POLICY"
sed "s|__SCRATCH_ROOT__|${SCRATCH_ROOT}|g" "$POLICY_DIR/permissive.yaml.tmpl" > "$PERMISSIVE_POLICY"

# A small, realistic workload fixture: source the compiler scenario compiles,
# and a test file the interpreter scenario runs. Written once into
# `permitted/`, which every confined policy above already grants write access
# to, so fixture setup itself is not confounded with what a scenario measures.
FIXTURE="$SCRATCH_ROOT/permitted/fixture"
mkdir -p "$FIXTURE"
cat > "$FIXTURE/greet.c" <<'EOF'
#include <stdio.h>
int main(void) { printf("hello from compiled fixture\n"); return 0; }
EOF
cat > "$FIXTURE/test_sample.py" <<'EOF'
import unittest

class SampleTest(unittest.TestCase):
    def test_arithmetic(self):
        self.assertEqual(2 + 2, 4)

if __name__ == "__main__":
    unittest.main()
EOF

RESULT_COUNT=0

# record_result: parse one invocation's captured output into a JSON record.
#
# python3 does the JSON encoding (not hand-quoted heredocs) because stdout and
# stderr are real command output — a compiler diagnostic or a refusal sentence
# can carry quotes or backslashes a shell-built JSON string would mangle
# silently instead of erroring.
record_result() {
    scenario="$1" backend="$2" isolation_flag="$3" expect="$4" negative_control_of="$5"
    exit_code="$6" duration_ms="$7" stdout_file="$8" stderr_file="$9" cmd_str="${10}"

    outcome="unexpected"
    backend_id=""
    posture=""
    if [ -f "$stderr_file" ]; then
        backend_id="$(sed -n 's/^backend_id=\(.*\)$/\1/p' "$stderr_file" | tail -n1)"
        posture="$(sed -n 's/^posture=\(.*\)$/\1/p' "$stderr_file" | tail -n1)"
    fi
    if [ "$expect" = "allow" ] && [ "$exit_code" = "0" ]; then
        outcome="as-expected"
    elif [ "$expect" = "deny" ] && [ "$exit_code" != "0" ]; then
        outcome="as-expected"
    fi

    RESULT_COUNT=$((RESULT_COUNT + 1))
    out_json="$OUT_DIR/${scenario}.json"
    AA_SCENARIO="$scenario" AA_BACKEND="$backend" AA_ISOLATION_FLAG="$isolation_flag" \
    AA_EXPECT="$expect" AA_NEGATIVE_CONTROL_OF="$negative_control_of" AA_EXIT_CODE="$exit_code" \
    AA_DURATION_MS="$duration_ms" AA_STDOUT_FILE="$stdout_file" AA_STDERR_FILE="$stderr_file" \
    AA_CMD_STR="$cmd_str" AA_OUTCOME="$outcome" AA_BACKEND_ID="$backend_id" AA_POSTURE="$posture" \
    python3 - "$out_json" <<'PYEOF'
import json, os, sys

def read(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""

record = {
    "scenario": os.environ["AA_SCENARIO"],
    "backend_pinned": os.environ["AA_BACKEND"],
    "isolation_flag": os.environ["AA_ISOLATION_FLAG"],
    "expect": os.environ["AA_EXPECT"],
    "negative_control_of": os.environ["AA_NEGATIVE_CONTROL_OF"] or None,
    "exit_code": os.environ["AA_EXIT_CODE"],
    "duration_ms": int(os.environ["AA_DURATION_MS"]),
    "outcome": os.environ["AA_OUTCOME"],
    "backend_id_reported": os.environ["AA_BACKEND_ID"] or None,
    "posture_reported": os.environ["AA_POSTURE"] or None,
    "command": os.environ["AA_CMD_STR"],
    "stdout": read(os.environ["AA_STDOUT_FILE"])[:4000],
    "stderr": read(os.environ["AA_STDERR_FILE"])[:8000],
}
with open(sys.argv[1], "w") as f:
    json.dump(record, f, indent=2)
    f.write("\n")
PYEOF
    echo "[$scenario] backend=$backend isolation=$isolation_flag expect=$expect exit=$exit_code outcome=$outcome (${duration_ms}ms)"
}

# run_case: invoke `aasm run exec` once and hand the captured output to
# record_result(). `--no-proxy`: establishing the sidecar proxy's trusted CA
# is Layer 2 of the product's own interception model (see repo CLAUDE.md) and
# an orthogonal cost this driver is not measuring — the same reasoning
# benchmarks/isolation/launchers/sandlock.sh already documents.
run_case() {
    scenario="$1" backend="$2" isolation_flag="$3" policy_file="$4" expect="$5" negative_control_of="$6"
    shift 6
    stdout_file="$OUT_DIR/${scenario}.stdout"
    stderr_file="$OUT_DIR/${scenario}.stderr"
    backend_args=()
    if [ -n "$backend" ]; then
        backend_args=(--isolation-backend "$backend")
    fi
    cmd_str="$*"

    start_ms=$(date +%s%3N)
    set +e
    # `${backend_args[@]+"${backend_args[@]}"}`: portable empty-array
    # expansion under `set -u` — bash < 4.4 (still the default `/bin/bash` on
    # macOS) treats `"${arr[@]}"` on a zero-element array as an unbound
    # variable; this idiom is a no-op expansion instead on every bash version.
    "$AASM_BIN" run exec --isolation "$isolation_flag" ${backend_args[@]+"${backend_args[@]}"} --no-proxy \
        --policy "$policy_file" -- "$@" >"$stdout_file" 2>"$stderr_file"
    exit_code=$?
    set -e
    end_ms=$(date +%s%3N)
    duration_ms=$((end_ms - start_ms))

    record_result "$scenario" "${backend:-auto-unpinned}" "$isolation_flag" "$expect" \
        "$negative_control_of" "$exit_code" "$duration_ms" "$stdout_file" "$stderr_file" "$cmd_str"
}

for backend in "${BACKENDS[@]}"; do
    # --- inspect repository ---------------------------------------------
    run_case "inspect-repo-${backend}" "$backend" process "$CONFINED_POLICY" allow "" \
        ls -la "$REPO_ROOT"

    # --- edit a permitted file --------------------------------------------
    run_case "edit-permitted-file-${backend}" "$backend" process "$CONFINED_POLICY" allow "" \
        sh -c "echo 'edited by dogfood driver' > '$FIXTURE/edit-target.txt' && cat '$FIXTURE/edit-target.txt'"

    # --- create + delete a permitted file -----------------------------------
    run_case "create-delete-permitted-file-${backend}" "$backend" process "$CONFINED_POLICY" allow "" \
        sh -c "touch '$FIXTURE/scratch-file.txt' && test -f '$FIXTURE/scratch-file.txt' && rm '$FIXTURE/scratch-file.txt' && test ! -f '$FIXTURE/scratch-file.txt' && echo create-delete-ok"

    # --- run tests (interpreter tooling) ------------------------------------
    run_case "run-tests-${backend}" "$backend" process "$CONFINED_POLICY" allow "" \
        python3 -m unittest "$FIXTURE/test_sample.py" -v

    # --- invoke git ----------------------------------------------------------
    run_case "invoke-git-${backend}" "$backend" process "$CONFINED_POLICY" allow "" \
        git -C "$REPO_ROOT" status --porcelain --untracked-files=no

    # --- launch compiler tooling + spawn the resulting child process --------
    run_case "launch-compiler-${backend}" "$backend" process "$CONFINED_POLICY" allow "" \
        cc -o "$FIXTURE/greet" "$FIXTURE/greet.c"
    run_case "spawn-child-process-${backend}" "$backend" process "$CONFINED_POLICY" allow "" \
        sh -c "'$FIXTURE/greet' && echo parent-observed-child-exit=\$?"

    # --- attempt a prohibited filesystem access, with negative control ------
    run_case "prohibited-fs-write-denied-${backend}" "$backend" process "$CONFINED_POLICY" deny "" \
        sh -c "echo leak > '$SCRATCH_ROOT/forbidden/leak.txt'"
    run_case "prohibited-fs-write-negative-control-${backend}" "$backend" process "$PERMISSIVE_POLICY" allow \
        "prohibited-fs-write-denied-${backend}" \
        sh -c "echo leak > '$SCRATCH_ROOT/forbidden/leak-control.txt' && rm '$SCRATCH_ROOT/forbidden/leak-control.txt'"

    # --- verify descendant confinement: a grandchild inherits the same denial
    run_case "descendant-confinement-denied-${backend}" "$backend" process "$CONFINED_POLICY" deny "" \
        sh -c "sh -c \"echo grandchild-leak > '$SCRATCH_ROOT/forbidden/grandchild-leak.txt'\""
    run_case "descendant-confinement-negative-control-${backend}" "$backend" process "$PERMISSIVE_POLICY" allow \
        "descendant-confinement-denied-${backend}" \
        sh -c "sh -c \"echo grandchild-leak > '$SCRATCH_ROOT/forbidden/grandchild-leak-control.txt' && rm '$SCRATCH_ROOT/forbidden/grandchild-leak-control.txt'\""

    # --- attempt a capability outside the policy (process spawn denied), with
    #     negative control ---------------------------------------------------
    run_case "capability-denied-spawn-${backend}" "$backend" process "$CONFINED_NO_EXEC_POLICY" deny "" \
        sh -c "echo should-not-run"
    run_case "capability-negative-control-spawn-${backend}" "$backend" process "$CONFINED_POLICY" allow \
        "capability-denied-spawn-${backend}" \
        sh -c "echo spawn-allowed-under-confined-policy"

    # --- verify explicit backend pinning is honored -------------------------
    run_case "explicit-pin-honored-${backend}" "$backend" process "$CONFINED_POLICY" allow "" \
        true

    # --- verify exit code propagation ----------------------------------------
    run_case "exit-code-propagation-${backend}" "$backend" process "$CONFINED_POLICY" deny "" \
        sh -c "exit 42"
done

# --- verify `--isolation auto` selects the expected backend (AAASM-5808) ----
# Unpinned: no --isolation-backend, so auto's own selection logic runs.
run_case "auto-selects-backend" "" auto "$CONFINED_POLICY" allow "" \
    true

# --- unknown backend refuses before launch, with the discovery output as its
#     own comparison point (no side effects expected either way) -----------
run_case "unknown-backend-refuses-before-launch" "does-not-exist" process "$CONFINED_POLICY" deny "" \
    sh -c "echo should-never-print > '$FIXTURE/should-not-exist.txt'"

echo "=== ${RESULT_COUNT} scenario records written to ${OUT_DIR} ==="
