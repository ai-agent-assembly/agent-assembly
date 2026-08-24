#!/usr/bin/env sh
# The aasm-macos-vm confined arm — cold/warm-start informational measurement
# only (AAASM-5814), NOT a fourth arm of the AAASM-5805 three-arm comparison
# `../METHODOLOGY.md` documents. Do not add this to `three-arm.yaml.tmpl`,
# `compare.py`, or `thresholds.py` — see this file's own header for why.
#
# # Why this cannot be a drop-in launcher like sandlock.sh/native.sh
#
# The harness's contract (see `unconfined.sh`) is `<launcher> -- <argv...>`,
# execute argv and exit with its status — and `runner.py::run_family` always
# builds that argv as `sh <script> <scratch> <repo_root>`, three literal host
# paths. Every other launcher can `exec "$@"` those paths directly because
# every other backend confines the *host* process. `aasm-macos-vm` confines a
# *guest* process instead, and its host→guest path mapping
# (`aa-isolation-macos-vm/src/paths.rs::to_guest_path`) can reach exactly two
# kinds of path: something under the one directory `--workdir` shares, or one
# of the guest's own fixed resident binaries
# (`/usr/local/bin/busybox`, `/usr/local/bin/aa-isolation-launch`). `sh` is
# neither (not shared, not resident), and the workload script itself lives
# under `../workloads/`, a sibling of `<scratch>` rather than something under
# it — so a literal `exec "$@"` here would refuse at `spawn()` before
# anything ran, for every family, informational or not.
#
# # What this launcher actually does instead
#
# Recognizes exactly one family by its script's basename —
# `startup_nop.sh`, whose entire payload is `exit 0`
# (`../workloads/startup_nop.sh`) — and replaces it with the guest-reachable
# equivalent, `/usr/local/bin/busybox true`, which is exactly as trivial and
# exits 0 exactly as fast from the guest's own side. This is not a
# reinterpretation of the workload; `startup_nop.sh`'s own header states its
# entire purpose is "isolate the launcher's fixed per-invocation cost" — a
# workload with a guest-side equivalent that has the identical property
# (immediate, unconditional success, no filesystem/process work) is not a
# different measurement, it is the same measurement through a
# `--isolation-backend`-appropriate program.
#
# **No other family is supported.** The guest has no python3, `rg`, git,
# cc, or general shell utilities beyond a handful of busybox applets
# (AAASM-5849) — `many_small_files`, `rust_cargo_check`,
# `python_pkg_test`, etc. cannot run in the guest at all, honestly or
# otherwise, and this launcher refuses them loudly (nonzero exit, a clear
# stderr message) rather than attempting something broken and reporting a
# number for it.
#
# `--workdir "$scratch"` is what makes `<scratch>` (the harness's own
# per-repetition directory, see `runner.py`) the guest's shared directory —
# without it there is nothing shared, and even `/usr/local/bin/busybox`
# would still resolve (guest-resident), but any real workload would refuse.
set -eu

if [ "${1:-}" = "--" ]; then
    shift
fi

# Positional contract from `runner.py::run_family`: sh <script> <scratch> <repo_root>.
if [ "${1:-}" != "sh" ]; then
    echo "launchers/macos-vm.sh: expected \"sh <script> <scratch> <repo_root>\" (runner.py's own argv shape), got: $*" >&2
    exit 2
fi
script="${2:?launchers/macos-vm.sh: missing <script> argument}"
scratch="${3:?launchers/macos-vm.sh: missing <scratch> argument}"

script_name="$(basename "$script")"
if [ "$script_name" != "startup_nop.sh" ]; then
    echo "launchers/macos-vm.sh: only the startup_nop family is supported on this backend (AAASM-5849 — no general guest toolchain); refusing $script_name rather than mismeasuring it" >&2
    exit 2
fi

AASM_BIN="${AABENCH_AASM_BIN:-aasm}"
AASM_POLICY="${AABENCH_MACOS_VM_POLICY:?AABENCH_MACOS_VM_POLICY must point at the policy artifact this arm runs under — see ../policy-macos-vm/confined.yaml.tmpl for why it needs network_outbound granted}"

exec "$AASM_BIN" run exec --isolation process --isolation-backend aasm-macos-vm --no-proxy \
    --policy "$AASM_POLICY" --workdir "$scratch" -- /usr/local/bin/busybox true
