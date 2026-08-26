#!/usr/bin/env bash
# Negative-control tests for qa-watchdog.py's progress-classification signals
# (AAASM-5950, second slice of AAASM-5891's resource-aware QA-campaign
# scheduler): get_child_pids(), get_artifact_mtimes(), get_log_signal(), and
# classify_progress(). Separate file from qa-watchdog-cpu-parser-test.sh
# (AAASM-5949) — distinct concern, same naming convention as
# resource-scheduler-negative-control.sh's peers.
#
# Usage: bash scripts/qa/qa-watchdog-progress-signals-test.sh
# Run from the repo root.
set -uo pipefail

FAILED=0

check() {
  local desc="$1" script="$2"
  local actual
  actual="$(python3 - <<PY
import importlib.util
spec = importlib.util.spec_from_file_location("qa_watchdog", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
$script
PY
)"
  if [ "$actual" = "ok" ]; then
    echo "  ✓ $desc"
  else
    echo "  ✗ $desc ($actual)"
    FAILED=1
  fi
}

echo "== get_child_pids: proves the cargo-doc shape (near-zero own CPU, live children = progressing) =="
check "a process with a live child returns that child's pid" '
import subprocess, time
p = subprocess.Popen(["bash", "-c", "sleep 5 & wait"])
time.sleep(0.3)
kids = m.get_child_pids(p.pid)
p.terminate(); p.wait()
print("ok" if len(kids) >= 1 else f"got {kids!r}, expected at least 1 child pid")
'

check "a childless process returns an empty list" '
import subprocess
p = subprocess.Popen(["true"])
p.wait()
kids = m.get_child_pids(p.pid)
# the pid has already exited too, but pgrep against a reaped pid with no
# children still correctly reports zero children, not an error
print("ok" if kids == [] else f"got {kids!r}, expected []")
'

check "get_child_pids never raises when pgrep itself cannot run (simulated)" '
import subprocess
def fake_run(*a, **k):
    raise FileNotFoundError("simulated: pgrep not found")
m.subprocess.run = fake_run
try:
    result = m.get_child_pids(1)
    print("ok" if result == [] else f"unexpected-non-empty: {result!r}")
except Exception as e:
    print(f"raised: {type(e).__name__}: {e}")
'

echo "== get_artifact_mtimes =="
check "an existing file returns its real mtime, a missing path returns None" '
import os, tempfile
fd, path = tempfile.mkstemp()
os.close(fd)
try:
    result = m.get_artifact_mtimes([path, "/nonexistent/does/not/exist"])
    ok = (
        isinstance(result[path], float)
        and result["/nonexistent/does/not/exist"] is None
    )
    print("ok" if ok else f"got {result!r}")
finally:
    os.unlink(path)
'

check "mtime genuinely advances after a real write (not stubbed)" '
import os, tempfile, time
fd, path = tempfile.mkstemp()
os.close(fd)
try:
    first = m.get_artifact_mtimes([path])[path]
    time.sleep(1.05)  # mtime resolution on some filesystems is 1s
    with open(path, "w") as f:
        f.write("x")
    second = m.get_artifact_mtimes([path])[path]
    print("ok" if second > first else f"got first={first} second={second}, expected second > first")
finally:
    os.unlink(path)
'

echo "== get_log_signal =="
check "no log path recorded (None) returns None" '
print("ok" if m.get_log_signal(None) is None else "unexpectedly-not-None")
'

check "a log path that does not exist yet returns None" '
result = m.get_log_signal("/nonexistent/does/not/exist.log")
print("ok" if result is None else f"unexpectedly-not-None: {result!r}")
'

check "an existing log file returns its real size and mtime" '
import os, tempfile
fd, path = tempfile.mkstemp()
os.write(fd, b"hello")
os.close(fd)
try:
    result = m.get_log_signal(path)
    ok = isinstance(result, dict) and result["size"] == 5 and isinstance(result["mtime"], float)
    print("ok" if ok else f"got {result!r}")
finally:
    os.unlink(path)
'

echo "== classify_progress: declared priority order (cpu, children, artifact_mtime, log_growth) =="
check "children present (even with prev=None) classifies as progressing — the cargo-doc case" '
curr = {"cpu_time_secs": 0.01, "child_count": 1, "artifact_mtimes": {}, "log_signal": None}
print("ok" if m.classify_progress(None, curr) == "progressing" else f"got {m.classify_progress(None, curr)!r}")
'

check "no prev snapshot and no children classifies as no_signal, never stalled" '
curr = {"cpu_time_secs": 0.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": None}
print("ok" if m.classify_progress(None, curr) == "no_signal" else f"got {m.classify_progress(None, curr)!r}")
'

check "cpu increase since prev classifies as progressing" '
prev = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": None}
curr = {"cpu_time_secs": 2.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": None}
print("ok" if m.classify_progress(prev, curr) == "progressing" else f"got {m.classify_progress(prev, curr)!r}")
'

check "cpu unchanged (no other signal) classifies as no_signal" '
prev = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": None}
curr = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": None}
print("ok" if m.classify_progress(prev, curr) == "no_signal" else f"got {m.classify_progress(prev, curr)!r}")
'

check "artifact mtime advance classifies as progressing" '
prev = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {"/a": 100.0}, "log_signal": None}
curr = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {"/a": 200.0}, "log_signal": None}
print("ok" if m.classify_progress(prev, curr) == "progressing" else f"got {m.classify_progress(prev, curr)!r}")
'

check "an artifact appearing since prev (was absent, now has an mtime) classifies as progressing" '
prev = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {"/a": None}, "log_signal": None}
curr = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {"/a": 200.0}, "log_signal": None}
print("ok" if m.classify_progress(prev, curr) == "progressing" else f"got {m.classify_progress(prev, curr)!r}")
'

check "log size growth classifies as progressing" '
prev = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": {"size": 10, "mtime": 100.0}}
curr = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": {"size": 20, "mtime": 100.0}}
print("ok" if m.classify_progress(prev, curr) == "progressing" else f"got {m.classify_progress(prev, curr)!r}")
'

check "log appearing since prev (was None, now present) classifies as progressing" '
prev = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": None}
curr = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {}, "log_signal": {"size": 5, "mtime": 100.0}}
print("ok" if m.classify_progress(prev, curr) == "progressing" else f"got {m.classify_progress(prev, curr)!r}")
'

check "every signal silent (with prev present) classifies as no_signal, never stalled" '
prev = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {"/a": 100.0}, "log_signal": {"size": 10, "mtime": 100.0}}
curr = {"cpu_time_secs": 1.0, "child_count": 0, "artifact_mtimes": {"/a": 100.0}, "log_signal": {"size": 10, "mtime": 100.0}}
print("ok" if m.classify_progress(prev, curr) == "no_signal" else f"got {m.classify_progress(prev, curr)!r}")
'

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All qa-watchdog.py progress-signal cases passed."
else
  echo "One or more qa-watchdog.py progress-signal cases FAILED."
fi
exit "$FAILED"
