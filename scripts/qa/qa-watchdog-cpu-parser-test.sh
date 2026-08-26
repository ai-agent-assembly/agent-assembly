#!/usr/bin/env bash
# String-fixture unit tests for qa-watchdog.py's parse_ps_time() (AAASM-5949,
# first slice of AAASM-5891's resource-aware QA-campaign scheduler).
#
# No live process needed — parse_ps_time() is a pure function over `ps -o
# time=`-style strings, so these fixtures exercise the shapes the two
# platforms this repo cares about are documented/observed to emit, without
# needing a process old enough to have accumulated hours of real CPU time.
#
# Usage: bash scripts/qa/qa-watchdog-cpu-parser-test.sh
# Run from the repo root.
set -uo pipefail

WATCHDOG_PY="scripts/qa/qa-watchdog.py"
FAILED=0

assert_parse() {
  local desc="$1" input="$2" expected="$3"
  local actual
  actual="$(python3 - "$input" <<'PY'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("qa_watchdog", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
result = m.parse_ps_time(sys.argv[1])
print("None" if result is None else f"{result:.2f}")
PY
)"
  if [ "$actual" = "$expected" ]; then
    echo "  ✓ $desc (got $actual)"
  else
    echo "  ✗ $desc (got $actual, expected $expected)"
    FAILED=1
  fi
}

echo "== parse_ps_time: macOS steady-state MM:SS.ss (minutes never roll to hours) =="
assert_parse "0:00.01 (fresh process)" "0:00.01" "0.01"
assert_parse "0:00.00 (genuinely idle — must not be treated as unknown)" "0:00.00" "0.00"
assert_parse "1:05.30 (1m 5.3s)" "1:05.30" "65.30"
assert_parse "290:33.96 (4h50m33.96s, still flat MM:SS on macOS)" "290:33.96" "17433.96"
assert_parse "leading-space form, as ps actually emits it" " 0:00.01" "0.01"

echo "== parse_ps_time: Linux/procps HH:MM:SS (past 1h) =="
assert_parse "01:05:30 (1h5m30s)" "01:05:30" "3930.00"
assert_parse "00:00:00 (idle, hour-form)" "00:00:00" "0.00"

echo "== parse_ps_time: Linux/procps DD-HH:MM:SS (past 24h) =="
assert_parse "1-00:00:00 (exactly 1 day)" "1-00:00:00" "86400.00"
assert_parse "2-03:04:05 (2d 3h 4m 5s)" "2-03:04:05" "183845.00"

echo "== parse_ps_time: bare seconds (defensive, no colon at all) =="
assert_parse "bare seconds must NOT match (no MM: prefix — ps never emits this)" "45" "None"

echo "== parse_ps_time: malformed/unexpected input returns None, not 0 =="
assert_parse "empty string" "" "None"
assert_parse "garbage text" "not-a-time" "None"

echo "== parse_ps_time: Python None input (not exercisable via a shell string arg) =="
none_result="$(python3 -c '
import importlib.util
spec = importlib.util.spec_from_file_location("qa_watchdog", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
print("ok" if m.parse_ps_time(None) is None else "unexpectedly-not-None")
')"
if [ "$none_result" = "ok" ]; then
  echo "  ✓ parse_ps_time(None) returns None, doesn't raise"
else
  echo "  ✗ parse_ps_time(None) returned $none_result"
  FAILED=1
fi

echo "== get_cpu_time: live-process smoke check =="
actual_self="$(python3 - <<'PY'
import os, importlib.util
spec = importlib.util.spec_from_file_location("qa_watchdog", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
t = m.get_cpu_time(os.getpid())
print("ok" if isinstance(t, float) and t >= 0 else f"unexpected: {t!r}")
PY
)"
if [ "$actual_self" = "ok" ]; then
  echo "  ✓ get_cpu_time(os.getpid()) returns a non-negative float for a real, live process"
else
  echo "  ✗ get_cpu_time(os.getpid()) returned $actual_self"
  FAILED=1
fi
dead_pid_probe="$(python3 - <<'PY'
import os, importlib.util, subprocess
spec = importlib.util.spec_from_file_location("qa_watchdog", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
p = subprocess.Popen(["true"])
p.wait()
print("None" if m.get_cpu_time(p.pid) is None else "unexpectedly-not-None")
PY
)"
if [ "$dead_pid_probe" = "None" ]; then
  echo "  ✓ get_cpu_time on a pid that has already exited returns None, not a stale/zero value"
else
  echo "  ✗ get_cpu_time on a dead pid returned $dead_pid_probe"
  FAILED=1
fi

echo "== live_jobs: never raises (review finding — was unguarded, now matches get_cpu_time's convention) =="
timeout_probe="$(python3 - <<'PY'
import importlib.util, subprocess
spec = importlib.util.spec_from_file_location("qa_watchdog", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# Monkeypatch subprocess.run to simulate a hung/timed-out
# `resource-lock.py status --json` — the exact failure mode the review
# finding reproduced against the unguarded call.
def fake_run(*args, **kwargs):
    raise subprocess.TimeoutExpired(cmd="resource-lock.py", timeout=10)

m.subprocess.run = fake_run
try:
    result = m.live_jobs()
    print("ok" if result == [] else f"unexpected-non-empty: {result!r}")
except Exception as e:
    print(f"raised: {type(e).__name__}: {e}")
PY
)"
if [ "$timeout_probe" = "ok" ]; then
  echo "  ✓ live_jobs() returns [] (not a raised exception) when the status subprocess times out"
else
  echo "  ✗ live_jobs() on a simulated timeout: $timeout_probe"
  FAILED=1
fi

missing_probe="$(python3 - <<'PY'
import importlib.util, subprocess
spec = importlib.util.spec_from_file_location("qa_watchdog", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# A plain nonexistent script path (e.g. python3 /nonexistent/x.py) does NOT
# raise in the parent — python3 itself starts fine and just exits nonzero,
# already covered by the pre-existing returncode!=0 path. FileNotFoundError
# is what get_cpu_time()'s subprocess.run raises when the EXECUTABLE itself
# can't be found — simulate that directly, the actual gap this fix closes.
def fake_run(*args, **kwargs):
    raise FileNotFoundError("simulated: sys.executable not found")

m.subprocess.run = fake_run
try:
    result = m.live_jobs()
    print("ok" if result == [] else f"unexpected-non-empty: {result!r}")
except Exception as e:
    print(f"raised: {type(e).__name__}: {e}")
PY
)"
if [ "$missing_probe" = "ok" ]; then
  echo "  ✓ live_jobs() returns [] when the status subprocess can't even be started"
else
  echo "  ✗ live_jobs() with a simulated FileNotFoundError: $missing_probe"
  FAILED=1
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All qa-watchdog.py CPU-time-parser cases passed."
else
  echo "One or more qa-watchdog.py CPU-time-parser cases FAILED."
fi
exit "$FAILED"
