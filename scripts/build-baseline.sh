#!/usr/bin/env bash
# Build-time baseline harness for the agent-assembly Cargo workspace.
# AAASM-2557 (Epic AAASM-2551 — Rust build & compile-time performance).
#
# Usage: bash scripts/build-baseline.sh
#
# Captures a reproducible before/after build-time profile so the
# profile / linker / dedup / CI Stories (AAASM-2553/2554/2555/2556) can be
# re-measured against the same harness. Four measurements are taken:
#
#   1. Cold build      — cargo clean, then `cargo build --workspace --timings`.
#   2. Warm rebuild    — touch one leaf source file, then rebuild (link-bound).
#   3. Test build+run  — `cargo nextest run --workspace` wall-clock.
#   4. Duplicate deps  — `cargo tree -d` duplicate-version report.
#
# Raw outputs (logs, timing HTML, top-crate extraction, tree -d) are written
# to target/build-baseline/ (gitignored). Re-run on any commit to compare.
#
# Environment overrides:
#   CARGO                       cargo binary (default: cargo)
#   BUILD_BASELINE_OUT          output dir (default: target/build-baseline)
#   BUILD_BASELINE_WARM_FILE    file to touch for the warm rebuild
#                               (default: aa-cli/src/main.rs)
#   BUILD_BASELINE_INCLUDE_EBPF set to 1 to drop the `--exclude aa-ebpf` guard
#                               (aa-ebpf needs a nightly toolchain + bpf-linker;
#                               excluded by default to match `make build-workspace`)
#   BUILD_BASELINE_TOP_N        crates listed in the top-crates report (default: 10)

set -uo pipefail

CARGO="${CARGO:-cargo}"
OUT="${BUILD_BASELINE_OUT:-target/build-baseline}"
WARM_FILE="${BUILD_BASELINE_WARM_FILE:-aa-cli/src/main.rs}"
TOP_N="${BUILD_BASELINE_TOP_N:-10}"

# aa-ebpf requires a nightly toolchain + bpf-linker; the workspace's own
# `make build-workspace` / `make test` exclude it, so the baseline does too.
EXCLUDE=(--exclude aa-ebpf)
if [ "${BUILD_BASELINE_INCLUDE_EBPF:-0}" = "1" ]; then
  EXCLUDE=()
fi

# Resolve to the repository root regardless of the caller's cwd.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
mkdir -p "$OUT"

echo "=== agent-assembly build-time baseline ==="
echo "root:    $ROOT"
echo "cargo:   $($CARGO --version)"
echo "host:    $(uname -srm)"
echo "exclude: ${EXCLUDE[*]:-<none>}"
echo "out:     $OUT"
echo

# --- 1. Cold build (clean tree) -------------------------------------------
echo ">>> cargo clean"
$CARGO clean
mkdir -p "$OUT"  # `cargo clean` wipes target/, including a pre-created $OUT
COLD_LOG="$OUT/cold-build.log"
echo ">>> cold build: $CARGO build --workspace ${EXCLUDE[*]} --timings"
COLD_START=$SECONDS
$CARGO build --workspace "${EXCLUDE[@]}" --timings >"$COLD_LOG" 2>&1
COLD_REAL=$(( SECONDS - COLD_START ))
echo "    cold build: ${COLD_REAL}s  (log: $COLD_LOG)"

# Archive the generated --timings HTML next to the rest of the baseline
# (pick the most recently modified one without parsing `ls`).
TIMING_HTML=""
for f in target/cargo-timings/cargo-timing-*.html; do
  [ -e "$f" ] || continue
  if [ -z "$TIMING_HTML" ] || [ "$f" -nt "$TIMING_HTML" ]; then
    TIMING_HTML="$f"
  fi
done
if [ -n "$TIMING_HTML" ]; then
  cp "$TIMING_HTML" "$OUT/cargo-timing.html"
  echo "    timings:    $OUT/cargo-timing.html"
fi

# --- top-N longest-compiling crates from the timings HTML ------------------
TOP_LOG="$OUT/top-crates.txt"
if [ -n "$TIMING_HTML" ] && command -v python3 >/dev/null 2>&1; then
  python3 - "$OUT/cargo-timing.html" "$TOP_N" >"$TOP_LOG" <<'PY'
import json, re, sys
html = open(sys.argv[1], encoding="utf-8", errors="replace").read()
top_n = int(sys.argv[2])
# cargo embeds the per-unit timing data as JSON objects carrying both a
# "name" and a "duration" key; pull them out tolerantly of the surrounding JS.
units = {}
for m in re.finditer(r'\{[^{}]*?"duration":[0-9.]+[^{}]*?\}', html):
    try:
        o = json.loads(m.group(0))
    except Exception:
        continue
    if "name" in o and "duration" in o:
        # A crate may compile twice (lib + test/bench); keep the largest unit.
        key = "%s %s" % (o.get("name"), o.get("version", ""))
        units[key] = max(units.get(key, 0.0), float(o["duration"]))
ranked = sorted(units.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
print("rank  duration(s)  crate")
for i, (name, dur) in enumerate(ranked, 1):
    print("%4d  %11.1f  %s" % (i, dur, name.strip()))
PY
  echo "    top crates: $TOP_LOG"
else
  echo "(top-crate extraction skipped: no timings HTML or python3)" >"$TOP_LOG"
fi

# --- 2. Warm incremental rebuild (one-line / mtime touch) ------------------
WARM_LOG="$OUT/warm-rebuild.log"
if [ -f "$WARM_FILE" ]; then
  touch "$WARM_FILE"
  echo ">>> warm rebuild after touching $WARM_FILE"
  WARM_START=$SECONDS
  $CARGO build --workspace "${EXCLUDE[@]}" >"$WARM_LOG" 2>&1
  WARM_REAL=$(( SECONDS - WARM_START ))
  echo "    warm rebuild: ${WARM_REAL}s  (log: $WARM_LOG)"
else
  WARM_REAL=""
  echo "(warm rebuild skipped: $WARM_FILE not found)" >"$WARM_LOG"
fi

# --- 3. Test build + run wall-clock ---------------------------------------
TEST_LOG="$OUT/nextest.log"
echo ">>> test build+run: $CARGO nextest run --workspace ${EXCLUDE[*]}"
TEST_START=$SECONDS
$CARGO nextest run --workspace "${EXCLUDE[@]}" >"$TEST_LOG" 2>&1
TEST_REAL=$(( SECONDS - TEST_START ))
echo "    test build+run: ${TEST_REAL}s  (log: $TEST_LOG)"

# --- 4. Duplicate-dependency report ---------------------------------------
DUPS_LOG="$OUT/cargo-tree-dups.txt"
echo ">>> cargo tree -d (duplicate versions)"
$CARGO tree -d >"$DUPS_LOG" 2>&1 || true
DUP_COUNT="$(grep -cE '^[a-zA-Z0-9_-]+ v[0-9]' "$DUPS_LOG" 2>/dev/null || echo 0)"
echo "    duplicate roots: ${DUP_COUNT}  (report: $DUPS_LOG)"

# --- Summary ---------------------------------------------------------------
SUMMARY="$OUT/summary.md"
{
  echo "# Build-time baseline — raw run"
  echo
  echo "- host: \`$(uname -srm)\`"
  echo "- cargo: \`$($CARGO --version)\`"
  echo "- exclude: \`${EXCLUDE[*]:-<none>}\`"
  echo
  echo "| Measurement | Wall-clock |"
  echo "|---|---|"
  echo "| Cold build (\`build --workspace --timings\`) | ${COLD_REAL}s |"
  echo "| Warm rebuild (touch \`${WARM_FILE}\`) | ${WARM_REAL:-n/a}s |"
  echo "| Test build+run (\`nextest run --workspace\`) | ${TEST_REAL}s |"
  echo "| \`cargo tree -d\` duplicate roots | ${DUP_COUNT} |"
} >"$SUMMARY"

echo
echo "=== done — summary written to $SUMMARY ==="
cat "$SUMMARY"
