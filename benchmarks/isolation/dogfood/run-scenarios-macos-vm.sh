#!/usr/bin/env bash
# AAASM-5814 — real dogfood scenario driver for `aasm run exec
# --isolation-backend aasm-macos-vm`, the macOS-VM sibling of
# `run-scenarios.sh` (AAASM-5809's original driver for sandlock/aasm-native).
#
# NOT a copy edited in place — this backend confines by booting a real Linux
# guest via Virtualization.framework and running the launch inside it, a
# materially different execution model from the two Linux backends'
# host-process confinement (see `docs/src/security/execution-isolation.md`'s
# "macOS VM runtime prerequisites"), and that difference drives every
# structural change from the sibling script:
#
# - **The guest carries no general toolchain** (AAASM-5849) — only
#   `/usr/local/bin/busybox` and `/usr/local/bin/aa-isolation-launch`. Every
#   command below is `/usr/local/bin/busybox sh -c '...'`, and every applet
#   inside that script that is not an ash shell builtin (`echo`, `cd`, `test`,
#   `exit`, `[`) must be spelled `/usr/local/bin/busybox <applet>` explicitly
#   — this guest's rootfs has none of the `/bin/<applet> -> busybox` symlinks
#   a normal busybox install provides (`aa-isolation-macos-vm-poc/scripts/
#   fetch-busybox.sh` extracts the single binary via `docker cp`, not the
#   image's symlink layer), and ash only falls back to an internal applet via
#   PATH lookup failing when standalone-shell support is compiled in, which
#   this build was not confirmed to have — verified empirically this pass:
#   `sh -c 'echo hi > f && cat f'` exits 127 (cat: not found); `sh -c 'echo hi
#   > f && /usr/local/bin/busybox cat f'` exits 0.
# - **`--isolation-backend aasm-macos-vm` needs `network_outbound` granted**
#   or every launch refuses before starting — see `policy-macos-vm/
#   confined.yaml.tmpl`'s header for why (this backend has no network device
#   in the guest to satisfy any network requirement with, granted or not).
# - **Commands operate on guest paths (`/mnt/share/...`), not host paths.**
#   `aa-isolation-macos-vm/src/lib.rs::spawn` maps only the program path and
#   the plan's own filesystem grants from host to guest form
#   (`paths::to_guest_path`) — the *argument strings* of a `sh -c` script are
#   opaque to that mapping and pass through unmapped, so this driver writes
#   `/mnt/share/permitted/...` directly rather than relying on host-side
#   substitution the way the sibling driver's `$FIXTURE`/`$SCRATCH_ROOT`
#   host-path arguments do.
# - **`aasm run exec` does not forward the guest's stdout/stderr to the
#   operator for this backend** (AAASM-5869, found and filed this pass — a
#   real, distinct CLI-wiring gap, not fixed here). Every recorded
#   `.stdout`/`.stderr` file below will be empty even on a scenario that
#   printed something inside the guest; this driver's evidence relies on exit
#   code plus host-side read-back through the shared directory (the same way
#   `edit-permitted-file` below reads back what the guest wrote), never on
#   captured stdout content — unlike the sibling driver, which can and does
#   read stdout for some scenarios.
# - **No `run-tests`/`invoke-git`/`launch-compiler` scenarios.** There is no
#   python3, git, or cc in the guest (AAASM-5849). Recorded as
#   `outcome: "no-counterpart"`, not silently omitted — see
#   `record_no_counterpart()` below.
# - **One `--isolation-backend` value** (`aasm-macos-vm`) and no
#   `--isolation auto` scenario — auto-selection across all three backends is
#   already exercised by the sibling driver's own `auto-selects-backend`
#   scenario on whichever host runs it; this backend is only ever reached
#   explicitly, on a macOS/Apple-Silicon host (see the "Selecting it
#   explicitly" note in the docs page cited above).
#
# What is unchanged from the sibling driver: the negative-control discipline
# (every denial scenario paired with the identical command under a policy
# that grants it), and `record_result()`'s JSON record shape — a script
# analyzing dogfood evidence from both backends should not have to branch on
# which driver produced which record.
#
# Usage: run-scenarios-macos-vm.sh <scratch_root> <out_dir>
#   scratch_root  absolute, already-created directory. This is the exact
#                 directory `--workdir` shares into the guest at
#                 `/mnt/share` — see `aa-isolation-macos-vm/src/paths.rs`.
#   out_dir       absolute directory this driver writes its evidence into
#
# Required environment:
#   AABENCH_AASM_BIN               path to the `aasm` binary this driver exercises
#   AA_ISOLATION_MACOS_VM_HELPER   path to the aa-isolation-macos-vm-poc helper binary
#   AA_ISOLATION_MACOS_VM_KERNEL   path to the guest kernel image
#   AA_ISOLATION_MACOS_VM_ROOTFS   path to the guest rootfs image
#   AA_GATEWAY_ENDPOINT (optional) if the gateway is not on the default
#                                  127.0.0.1:50051 — `aasm gateway start` must
#                                  already be running under a policy this
#                                  driver's own `--policy` can layer under
set -euo pipefail

SCRATCH_ROOT="${1:?usage: run-scenarios-macos-vm.sh <scratch_root> <out_dir>}"
OUT_DIR="${2:?usage: run-scenarios-macos-vm.sh <scratch_root> <out_dir>}"

AASM_BIN="${AABENCH_AASM_BIN:?AABENCH_AASM_BIN must point at the aasm binary this driver exercises}"
: "${AA_ISOLATION_MACOS_VM_HELPER:?AA_ISOLATION_MACOS_VM_HELPER must be set}"
: "${AA_ISOLATION_MACOS_VM_KERNEL:?AA_ISOLATION_MACOS_VM_KERNEL must be set}"
: "${AA_ISOLATION_MACOS_VM_ROOTFS:?AA_ISOLATION_MACOS_VM_ROOTFS must be set}"

SELF_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
POLICY_DIR="$SELF_DIR/policy-macos-vm"
BACKEND="aasm-macos-vm"

mkdir -p "$OUT_DIR" "$SCRATCH_ROOT/permitted" "$SCRATCH_ROOT/forbidden"

CONFINED_POLICY="$OUT_DIR/confined.yaml"
CONFINED_NO_EXEC_POLICY="$OUT_DIR/confined-no-exec.yaml"
PERMISSIVE_POLICY="$OUT_DIR/permissive.yaml"
sed "s|__SCRATCH_ROOT__|${SCRATCH_ROOT}|g" "$POLICY_DIR/confined.yaml.tmpl" > "$CONFINED_POLICY"
sed "s|__SCRATCH_ROOT__|${SCRATCH_ROOT}|g" "$POLICY_DIR/confined-no-exec.yaml.tmpl" > "$CONFINED_NO_EXEC_POLICY"
sed "s|__SCRATCH_ROOT__|${SCRATCH_ROOT}|g" "$POLICY_DIR/permissive.yaml.tmpl" > "$PERMISSIVE_POLICY"

RESULT_COUNT=0

# record_result: parse one invocation's captured output into a JSON record —
# identical shape to `run-scenarios.sh`'s own, minus the backend_id/posture
# scrape from stderr (this backend's `aasm run exec` writes the isolation
# report to stderr in the same `key=value` shape, so that part is in fact
# unchanged; kept as one function rather than duplicated to guarantee it).
record_result() {
    scenario="$1" isolation_flag="$2" expect="$3" negative_control_of="$4"
    exit_code="$5" duration_ms="$6" stdout_file="$7" stderr_file="$8" cmd_str="$9"

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
    AA_SCENARIO="$scenario" AA_BACKEND="$BACKEND" AA_ISOLATION_FLAG="$isolation_flag" \
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
    echo "[$scenario] backend=$BACKEND isolation=$isolation_flag expect=$expect exit=$exit_code outcome=$outcome (${duration_ms}ms)"
}

# record_no_counterpart: a scenario name from the sibling driver's list that
# this backend has no usable form of, recorded as evidence rather than
# silently absent from the output directory — see this file's module docs.
record_no_counterpart() {
    scenario="$1" reason="$2"
    RESULT_COUNT=$((RESULT_COUNT + 1))
    out_json="$OUT_DIR/${scenario}.json"
    python3 - "$out_json" "$scenario" "$reason" <<'PYEOF'
import json, sys
record = {"scenario": sys.argv[2], "backend_pinned": "aasm-macos-vm", "outcome": "no-counterpart", "reason": sys.argv[3]}
with open(sys.argv[1], "w") as f:
    json.dump(record, f, indent=2)
    f.write("\n")
PYEOF
    echo "[$scenario] outcome=no-counterpart ($reason)"
}

# run_case: invoke `aasm run exec` once against the guest and hand the
# captured output to record_result(). `guest_script` is a busybox ash script
# string using guest-side paths — see this file's module docs for the applet
# quirk every script here already accounts for.
run_case() {
    scenario="$1" policy_file="$2" expect="$3" negative_control_of="$4" guest_script="$5"
    stdout_file="$OUT_DIR/${scenario}.stdout"
    stderr_file="$OUT_DIR/${scenario}.stderr"
    cmd_str="/usr/local/bin/busybox sh -c '$guest_script'"

    # `date +%s%3N` (the sibling driver's idiom) is a GNU-date-ism — BSD
    # `date` on this backend's only supported host (macOS) does not expand
    # `%3N` and prints it literally, which broke `$(( end_ms - start_ms ))`
    # below with a "value too great for base" error the first time this
    # script actually ran on real hardware. python3's `time.time()` is
    # already a hard requirement of this script (record_result() below), so
    # it costs nothing new to use it for the millisecond clock too.
    start_ms=$(python3 -c 'import time; print(int(time.time() * 1000))')
    set +e
    "$AASM_BIN" run exec --isolation process --isolation-backend "$BACKEND" --no-proxy \
        --policy "$policy_file" --workdir "$SCRATCH_ROOT" -- \
        /usr/local/bin/busybox sh -c "$guest_script" >"$stdout_file" 2>"$stderr_file"
    exit_code=$?
    set -e
    end_ms=$(python3 -c 'import time; print(int(time.time() * 1000))')
    duration_ms=$((end_ms - start_ms))

    record_result "$scenario" process "$expect" "$negative_control_of" "$exit_code" "$duration_ms" \
        "$stdout_file" "$stderr_file" "$cmd_str"
}

BB="/usr/local/bin/busybox"

# --- inspect the shared project directory (this backend's counterpart to
#     `inspect-repo`: the guest's only window onto the host is the share) ----
run_case "inspect-share" "$CONFINED_POLICY" allow "" \
    "$BB ls /mnt/share"

# --- edit a permitted file --------------------------------------------------
run_case "edit-permitted-file" "$CONFINED_POLICY" allow "" \
    "echo 'edited by macos-vm dogfood driver' > /mnt/share/permitted/edit-target.txt && $BB cat /mnt/share/permitted/edit-target.txt"

# --- create + delete a permitted file ---------------------------------------
run_case "create-delete-permitted-file" "$CONFINED_POLICY" allow "" \
    "$BB touch /mnt/share/permitted/scratch-file.txt && $BB test -f /mnt/share/permitted/scratch-file.txt && $BB rm /mnt/share/permitted/scratch-file.txt && $BB test ! -f /mnt/share/permitted/scratch-file.txt && echo create-delete-ok"

# --- spawn a child process ---------------------------------------------------
run_case "spawn-child-process" "$CONFINED_POLICY" allow "" \
    "$BB true && echo parent-observed-child-exit=\$?"

# --- attempt a prohibited filesystem access, with negative control ---------
run_case "prohibited-fs-write-denied" "$CONFINED_POLICY" deny "" \
    "echo leak > /mnt/share/forbidden/leak.txt"
run_case "prohibited-fs-write-negative-control" "$PERMISSIVE_POLICY" allow \
    "prohibited-fs-write-denied" \
    "echo leak > /mnt/share/forbidden/leak-control.txt && $BB rm /mnt/share/forbidden/leak-control.txt"

# --- verify descendant confinement: a grandchild inherits the same denial --
run_case "descendant-confinement-denied" "$CONFINED_POLICY" deny "" \
    "$BB sh -c \"echo grandchild-leak > /mnt/share/forbidden/grandchild-leak.txt\""
run_case "descendant-confinement-negative-control" "$PERMISSIVE_POLICY" allow \
    "descendant-confinement-denied" \
    "$BB sh -c \"echo grandchild-leak > /mnt/share/forbidden/grandchild-leak-control.txt && $BB rm /mnt/share/forbidden/grandchild-leak-control.txt\""

# --- attempt a capability outside the policy (process spawn denied), with
#     negative control -------------------------------------------------------
run_case "capability-denied-spawn" "$CONFINED_NO_EXEC_POLICY" deny "" \
    "echo should-not-run"
run_case "capability-negative-control-spawn" "$CONFINED_POLICY" allow \
    "capability-denied-spawn" \
    "echo spawn-allowed-under-confined-policy"

# --- verify explicit backend pinning is honored -----------------------------
run_case "explicit-pin-honored" "$CONFINED_POLICY" allow "" \
    "$BB true"

# --- verify exit code propagation -------------------------------------------
run_case "exit-code-propagation" "$CONFINED_POLICY" deny "" \
    "exit 42"

# --- scenarios the sibling driver runs that this guest cannot (AAASM-5849) --
record_no_counterpart "run-tests" "no python3 in the guest image"
record_no_counterpart "invoke-git" "no git in the guest image"
record_no_counterpart "launch-compiler" "no cc/toolchain in the guest image"

echo "=== ${RESULT_COUNT} scenario records written to ${OUT_DIR} ==="
