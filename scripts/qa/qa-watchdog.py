#!/usr/bin/env python3
"""Mechanical liveness/ownership watchdog for resource-lock.py jobs
(AAASM-5949/5950/5951, first three slices of AAASM-5891's resource-aware
QA-campaign scheduler — split from the original AAASM-5894 subtask by
opus-architect design review, since watchdog + progress signals + stall
termination + breaker + harness wiring was too large for one commit).

AAASM-5949: liveness/ownership tracking (reusing resource-lock.py's own
`status --json`, not duplicating its pid/start-token verification — see
"Why this shells out" below) and a cross-platform CPU-time parser.

AAASM-5950: the remaining progress signals — `cpu` (AAASM-5949), `children`,
`artifact_mtime`, `log_growth` — plus classify_progress(), which says
whether a job is *currently* showing activity on any signal. Every signal
is OR'd (the first one showing activity wins), so the order they're
evaluated in doesn't change the verdict; see classify_progress()'s own
docstring for why `children` is checked first regardless.

AAASM-5951: `enforce` — turns classify_progress()'s "progressing"/
"no_signal" verdicts into soft-stall reporting and hard-stall termination.
This is where `list`/`cmd_list`'s design (shell out to `resource-lock.py
status --json`, `[]`-on-error is benign) stops being sufficient: a
kill-capable subcommand that treats "resource-lock.py is broken" the same
as "no jobs are running" would silently stop enforcing timeouts. `enforce`
therefore enumerates and re-verifies ownership **in-process**, via a
dynamically-loaded `resource-lock.py` module (see `_lock_mod()`) — `list`
and `live_jobs()` are untouched and keep shelling out; only `enforce` needs
the stronger fail-closed guarantee, and only `enforce` pays the ongoing
maintenance cost of tracking `resource-lock.py`'s internal functions
directly rather than its stable `status --json` CLI surface.

`enforce` is a **single-shot, stateless-per-invocation** CLI check (no
daemon, no internal polling loop — matches this module's established
"cost of a subprocess/disk-read per poll is fine, don't run a hot loop"
design, and AAASM-5891's "no unbounded foreground block" rule): the calling
campaign harness (AAASM-5953) is responsible for invoking it repeatedly.
**A single invocation can never kill a job on its own** — the first
observation of a job only seeds its snapshot; only a *later* invocation
that still finds no progress can escalate. If a harness invokes `enforce`
only once per campaign, no job is ever terminated — this is a hand-off
contract, not an implementation detail, and belongs in that harness's own
acceptance criteria.

Why this shells out to `resource-lock.py status --json` for `list`/
`live_jobs()` instead of importing its liveness functions directly:
`resource-lock.py` is a script module (hyphenated filename, not a valid
Python import target without importlib gymnastics), and its own liveness
verification (dead-pid check + proc_start_token equality, guarding against
PID reuse) is already the single source of truth `status`/`sweep` use —
re-deriving it here via a second code path risks the two silently drifting
apart. Shelling out keeps `list` a thin consumer of that one source of
truth, at the cost of a subprocess per poll — acceptable for a periodic
mechanical watchdog, not a hot loop.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_SOFT_STALL = 3
EXIT_HARD_STALL = 4
EXIT_NOT_OWNED = 5

_LOCK_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource-lock.py")
_STATE_DIR_NAME = "watchdog"  # sibling of resource-lock.py's own jobs/slots dirs

# Matches every shape `ps -o time=` is documented/observed to emit:
#   SS                      (bare seconds — rare, defensive)
#   MM:SS[.ff]              (macOS's steady-state form; minutes are NOT
#                            capped at 59 and never roll into an hours
#                            field — confirmed empirically: a process with
#                            290 minutes of CPU time on this machine still
#                            printed "290:33.96", not an "H:MM:SS" form)
#   HH:MM:SS[.ff]           (Linux/procps once cumulative time exceeds an
#                            hour — not reproduced on this machine, this
#                            repo has no macOS CI leg either; documented
#                            procps behavior, defensive coverage)
#   DD-HH:MM:SS[.ff]        (Linux/procps past 24h — same caveat)
_TIME_RE = re.compile(
    r"^\s*(?:(?P<days>\d+)-)?(?:(?P<hours>\d+):)?(?P<minutes>\d+):(?P<seconds>\d+(?:\.\d+)?)\s*$"
)


def parse_ps_time(raw: str) -> float | None:
    """Parse a `ps -o time=`-style cumulative-CPU-time string into total
    seconds. Returns None for anything that doesn't match a recognized
    shape — callers must treat that as "unknown", never as zero (zero is a
    real, meaningful value: a process that has used no CPU yet)."""
    if raw is None:
        return None
    m = _TIME_RE.match(raw)
    if not m:
        return None
    days = int(m.group("days") or 0)
    hours = int(m.group("hours") or 0)
    minutes = int(m.group("minutes"))
    seconds = float(m.group("seconds"))
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def get_cpu_time(pid: int) -> float | None:
    """Live `ps -o time=` lookup for `pid`. None if the process is gone or
    `ps` itself fails/times out — never raises, matching resource-lock.py's
    own `ps_start_token()` convention for the same reason (a watchdog must
    not crash because a job it's observing exited mid-check)."""
    try:
        out = subprocess.run(
            ["ps", "-p", str(pid), "-o", "time="],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return parse_ps_time(out.stdout)


def live_jobs(cls: str | None = None) -> list[dict]:
    """Re-verified-live job records, via resource-lock.py's own `status
    --json` — see the module docstring for why this shells out rather than
    importing resource-lock.py's liveness functions directly."""
    args = [sys.executable, _LOCK_PY, "status", "--json"]
    if cls:
        args += ["--class", cls]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except Exception:
        # Matches get_cpu_time()'s convention below — a watchdog observing
        # jobs must not itself crash because resource-lock.py hung, timed
        # out, or wasn't found. Caught this exact gap in review: this call
        # was unguarded while get_cpu_time()'s equivalent call already was.
        return []
    if out.returncode != 0:
        return []
    try:
        return json.loads(out.stdout)
    except ValueError:  # json.JSONDecodeError is a ValueError subclass
        return []


def get_child_pids(pid: int) -> list[int]:
    """Direct child pids of `pid`, via `pgrep -P` — POSIX, identical on macOS
    and Linux, unlike listing all processes and filtering by ppid (which
    needs OS-specific `ps` column names/flags). Empty list when the process
    has no children, `pgrep` itself is unavailable, or the lookup fails —
    never raises. Matches this module's other liveness helpers: a watchdog
    checking for children must not crash, and "no children found" and
    "genuinely childless" are the same actionable state to the caller
    (absence of a children-signal), so they don't need to be distinguished."""
    try:
        out = subprocess.run(
            ["pgrep", "-P", str(pid)], capture_output=True, text=True, timeout=5
        )
    except Exception:
        return []
    # pgrep exits 1 for "no processes matched" (empty stdout either way, so
    # this branch is behaviorally a no-op against just checking stdout —
    # kept as an explicit distinction from other nonzero codes, e.g. 2 =
    # usage error, for readability, not because it changes what's returned).
    if out.returncode not in (0, 1):
        return []
    return [int(p) for p in out.stdout.split() if p.isdigit()]


def get_artifact_mtimes(paths: list[str]) -> dict[str, float | None]:
    """mtime (epoch seconds) for each path in `paths`, or None if it doesn't
    exist yet — a build that hasn't produced output yet isn't an error, it's
    just "no artifact-signal yet"."""
    result: dict[str, float | None] = {}
    for p in paths:
        try:
            result[p] = os.stat(p).st_mtime
        except OSError:
            result[p] = None
    return result


def get_log_signal(path: str | None) -> dict | None:
    """(size, mtime) for a job's `--log` file (resource-lock.py records this
    path on the job but doesn't act on it yet — AAASM-5894's forward-compat
    groundwork this signal now consumes). None if no log path was recorded
    on the job, or the file doesn't exist yet."""
    if not path:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return {"size": st.st_size, "mtime": st.st_mtime}


def classify_progress(prev: dict | None, curr: dict) -> str:
    """Classify a job's progress signals — cpu, children, artifact_mtime,
    log_growth — where any ONE signal showing activity is enough to call it
    "progressing"; since they're OR'd, the order they're checked in doesn't
    change the verdict (children is checked first only because, unlike the
    others, it doesn't need a `prev` snapshot to be meaningful — see below).
    `prev`/`curr` are snapshot
    dicts shaped like a single enriched record from cmd_list (must carry
    cpu_time_secs, child_count, artifact_mtimes, log_signal); `prev` may be
    None (first-ever snapshot — no delta signals available yet).

    Returns "progressing" or "no_signal" — deliberately never "stalled".
    A stall verdict needs elapsed-time + grace-period + re-verified
    ownership before killing anything; that needs a polling loop that owns
    snapshot persistence across calls, which is AAASM-5951's scope. This
    function only names what the signals say about the two snapshots it was
    given.
    """
    # children: presence alone counts, not a transition — a process whose
    # own CPU time is near-zero because the real work happens in forked
    # children (cargo doc's rustdoc-per-crate shape) is progressing for as
    # long as it currently has live children, not only at the instant a new
    # one appears. Checked before the prev-snapshot-gated signals below so a
    # first-ever (prev=None) snapshot can still classify a children-having
    # job as progressing.
    if curr.get("child_count", 0) > 0:
        return "progressing"

    if prev is None:
        return "no_signal"

    # cpu: an increase since the last reading proves scheduler activity
    # happened, regardless of what that activity was.
    prev_cpu, curr_cpu = prev.get("cpu_time_secs"), curr.get("cpu_time_secs")
    if prev_cpu is not None and curr_cpu is not None and curr_cpu > prev_cpu:
        return "progressing"

    # artifact_mtime: any tracked artifact whose mtime advanced, or that
    # appeared since the last snapshot.
    prev_artifacts = prev.get("artifact_mtimes") or {}
    for path, curr_mtime in (curr.get("artifact_mtimes") or {}).items():
        if curr_mtime is None:
            continue
        prev_mtime = prev_artifacts.get(path)
        if prev_mtime is None or curr_mtime > prev_mtime:
            return "progressing"

    # log_growth: the job's --log file grew or its mtime advanced, or it
    # appeared since the last snapshot.
    prev_log, curr_log = prev.get("log_signal"), curr.get("log_signal")
    if curr_log is not None:
        if prev_log is None:
            return "progressing"
        if curr_log["size"] > prev_log["size"] or curr_log["mtime"] > prev_log["mtime"]:
            return "progressing"

    return "no_signal"


def cmd_list(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="qa-watchdog.py list")
    parser.add_argument("--class", dest="cls", default=None)
    parser.add_argument(
        "--artifact",
        dest="artifacts",
        action="append",
        default=[],
        help="path to watch for the artifact_mtime signal; may be repeated",
    )
    args = parser.parse_args(rest)

    enriched = []
    for rec in live_jobs(args.cls):
        pid = rec.get("pid")
        is_pid = isinstance(pid, int)
        enriched.append(
            {
                **rec,
                "cpu_time_secs": get_cpu_time(pid) if is_pid else None,
                "child_count": len(get_child_pids(pid)) if is_pid else 0,
                "artifact_mtimes": get_artifact_mtimes(args.artifacts),
                "log_signal": get_log_signal(rec.get("log")),
            }
        )

    print(json.dumps(enriched, indent=2))
    return EXIT_OK


_lock_mod_cache: object | None = None


def _lock_mod():
    """Load resource-lock.py as an importable module (cached) — `enforce`
    needs its actual functions (list_job_records, verify_liveness,
    load_registry_raw, resolve_class), not the `status --json` CLI surface
    `list`/`live_jobs()` use, since `enforce` must fail closed rather than
    silently treat "resource-lock.py is broken" as "no jobs are running".
    Raises on failure — callers must catch and exit EXIT_BAD_INPUT without
    signaling anything, never treat an unloadable module as "no jobs"."""
    global _lock_mod_cache
    if _lock_mod_cache is None:
        spec = importlib.util.spec_from_file_location("resource_lock", _LOCK_PY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _lock_mod_cache = mod
    return _lock_mod_cache


def enumerate_live(cls: str | None = None) -> list[dict]:
    """All job records currently passing resource-lock.py's own
    verify_liveness() — in-process, unlike live_jobs() above, so a
    corrupt/unreadable job record or a broken resource-lock.py raises
    (via _lock_mod()) rather than reading as "no live jobs"."""
    m = _lock_mod()
    records = m.list_job_records(m.lock_dir())
    return [
        rec
        for rec in records.values()
        if m.verify_liveness(rec) and (cls is None or rec.get("class") == cls)
    ]


def read_job_record(job_id: str) -> dict | None:
    """Fresh-from-disk read of one job record, or None if it's gone —
    used to re-verify ownership immediately before every signal, never
    against a snapshot taken earlier in this invocation."""
    m = _lock_mod()
    path = os.path.join(m.lock_dir(), "jobs", f"{job_id}.json")
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def verify_owned(job_id: str) -> tuple[bool, str]:
    """Re-verify, right now, that this process (still) genuinely belongs to
    our own campaign before it is safe to signal. Returns (True, "") if
    every check passes, else (False, reason). Every check here is required
    — this is the guard against ever calling os.killpg on a pid/pgid we
    don't provably own:

    - the job record must still exist (it may have been swept/completed
      since the caller last looked);
    - resource-lock.py's own verify_liveness() must pass (pid alive AND its
      ps_start_token matches exactly — the PID-reuse guard: a dead pid can
      be recycled by the OS for an unrelated process before we get here);
    - pgid must be a real, non-degenerate process group: `pgid > 1` (a
      record with pgid 0 would make os.killpg(0, ...) signal our OWN
      process group — reachable from a truncated/hand-edited record, not
      just a hypothetical) and `pgid == pid` (always true for a record
      resource-lock.py's cmd_run actually wrote — os.setsid() makes the
      forked child its own group leader — so this also transitively
      confirms verify_liveness's pid check verifies the *group*, not just
      one process in it; any other value means the record does not
      describe a group we can prove we own);
    - `pgid != os.getpgid(0)` — refuse to ever signal our own group.

    There is an irreducible race between this check returning and the
    os.killpg() call that follows it (a few microseconds, without a kernel
    pidfd to close it) — call this immediately before signaling, never
    reuse a verdict across a poll loop.
    """
    rec = read_job_record(job_id)
    if rec is None:
        return False, "record-gone"
    m = _lock_mod()
    if not m.verify_liveness(rec):
        return False, "dead-or-reused"
    pid, pgid = rec.get("pid"), rec.get("pgid")
    if not isinstance(pgid, int) or pgid <= 1:
        return False, "bad-pgid"
    if pgid != pid:
        return False, "pgid-mismatch"
    if pgid == os.getpgid(0):
        return False, "own-process-group"
    return True, ""


def class_config(cls: str) -> dict | None:
    """Effective (pool_name, pool_cfg, class_cfg) for `cls`, or None if the
    registry can't be loaded or the class isn't defined — see cmd_enforce
    for how each case is handled (registry-unloadable is fatal to the whole
    invocation; one job's class being unresolvable only skips that job)."""
    m = _lock_mod()
    data, err = m.load_registry_raw(m.registry_path())
    if err:
        return None
    return m.resolve_class(data, cls)


def state_path(job_id: str) -> str:
    m = _lock_mod()
    return os.path.join(m.lock_dir(), _STATE_DIR_NAME, f"{job_id}.json")


def read_state(job_id: str, proc_start_token: str | None) -> dict | None:
    """Persisted watchdog state for `job_id`, or None if there isn't one, or
    if the job's proc_start_token no longer matches (the pid was reused
    since we last wrote state — a fresh seed is correct, not a bug: from
    the watchdog's perspective this is a job it has never observed)."""
    try:
        with open(state_path(job_id)) as f:
            state = json.load(f)
    except (OSError, ValueError):
        return None
    if state.get("proc_start_token") != proc_start_token:
        return None
    return state


def write_state(job_id: str, state: dict) -> None:
    m = _lock_mod()
    d = os.path.join(m.lock_dir(), _STATE_DIR_NAME)
    os.makedirs(d, exist_ok=True)
    path = state_path(job_id)
    tmp = path + f".tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def gc_state() -> None:
    """Delete watchdog state for any job_id that no longer has a live
    record — mirrors resource-lock.py's own `sweep`. Deliberately takes no
    `cls` filter and always considers every state file, so a
    `--class`-scoped `enforce` invocation doesn't accumulate orphaned state
    for other classes it isn't currently looking at."""
    m = _lock_mod()
    d = os.path.join(m.lock_dir(), _STATE_DIR_NAME)
    if not os.path.isdir(d):
        return
    live_ids = {rec["job_id"] for rec in enumerate_live()}
    for fname in os.listdir(d):
        if not fname.endswith(".json"):
            continue
        job_id = fname[: -len(".json")]
        if job_id not in live_ids:
            try:
                os.unlink(os.path.join(d, fname))
            except OSError:
                pass


def classify_stall(cfg: dict, last_progress_at: float, now: float) -> tuple[str, float]:
    """(verdict, seconds_since_progress) where verdict is "ok", "soft", or
    "hard". Hard is checked before soft so a misconfigured registry
    (hard_timeout_secs <= soft_timeout_secs) still terminates rather than
    being masked forever at "soft"."""
    no_progress = now - last_progress_at
    if no_progress >= cfg.get("hard_timeout_secs", 1800):
        return "hard", no_progress
    if no_progress >= cfg.get("soft_timeout_secs", 600):
        return "soft", no_progress
    return "ok", no_progress


def terminate_job(job_id: str, grace_secs, dry_run: bool) -> tuple[str, str]:
    """Re-verify ownership, SIGTERM, poll for `grace_secs`, SIGKILL if still
    alive. Returns (action, reason) where action is one of "terminated",
    "already_gone", "would_terminate", "skipped". A bounded poll loop, not
    signal.alarm() — unlike resource-lock.py's cmd_run (AAASM-5948), this
    process is not the job's parent, has no waitpid() to interrupt, and
    can't rely on a SIGALRM-driven escalation.

    grace_secs uses the exact same coercion and <=0-means-escalate-
    immediately semantics as cmd_run's relay (AAASM-5948 fixed a real bug
    where signal.alarm(0) silently meant "cancel", not "fire now") —
    both consumers read one registry field, so they agree by construction.
    """
    try:
        grace_secs = int(grace_secs)
    except (TypeError, ValueError):
        grace_secs = 20
    m = _lock_mod()

    owned, reason = verify_owned(job_id)
    if not owned:
        return "skipped", reason
    if dry_run:
        return "would_terminate", ""

    # A second, independent read — verify_owned() above validated against
    # its own internal read, not this one. The record can legitimately
    # disappear in this narrow window (e.g. a concurrent `resource-lock.py
    # sweep`, since nothing prevents one running alongside a repeatedly-
    # invoked `enforce`) — review found this dereferenced unguarded,
    # crashing the whole enforce invocation instead of reporting a clean
    # outcome for this one job.
    rec = read_job_record(job_id)
    if rec is None:
        return "already_gone", ""
    pgid = rec["pgid"]
    try:
        os.killpg(pgid, m.signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return "already_gone", ""

    deadline = time.time() + max(grace_secs, 0)
    while time.time() < deadline:
        owned, _ = verify_owned(job_id)
        if not owned:
            return "terminated", ""
        time.sleep(0.25)

    owned, reason = verify_owned(job_id)
    if not owned:
        return "terminated", ""
    try:
        os.killpg(pgid, m.signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return "terminated", ""
    return "terminated", ""


def cmd_enforce(rest: list[str]) -> int:
    """Deliberately narrower than cmd_list()'s signal set: `enforce` has no
    `--artifact` flag, so the `artifact_mtime` progress signal is always
    empty here (`cpu`/`children`/`log_growth` are the only signals that can
    ever classify a job as progressing under `enforce`). A caller-supplied
    watched-path set would need to be identical across every enforce
    invocation for a given job to behave correctly — classify_progress()
    treats a path present in `curr` but absent from `prev` as progress by
    itself, so an inconsistent set would silently reset last_progress_at
    and could defer termination indefinitely. Revisit only alongside a
    design for keeping that path set stable per-job across invocations."""
    parser = argparse.ArgumentParser(prog="qa-watchdog.py enforce")
    parser.add_argument("--class", dest="cls", default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="classify and report; never signal a process",
    )
    args = parser.parse_args(rest)

    try:
        records = enumerate_live(args.cls)
    except Exception as e:
        sys.stderr.write(f"qa-watchdog enforce: cannot enumerate live jobs: {e}\n")
        return EXIT_BAD_INPUT

    now = time.time()
    results = []
    saw_soft = saw_hard = saw_not_owned = False

    for rec in records:
        job_id = rec["job_id"]
        pid = rec.get("pid")
        cfg_result = class_config(rec.get("class"))
        if cfg_result is None:
            results.append({"job_id": job_id, "verdict": "skipped", "reason": "no-config"})
            sys.stderr.write(f"qa-watchdog enforce: {job_id}: unresolvable class, skipping\n")
            continue
        _, _, cls_cfg = cfg_result

        token = rec.get("proc_start_token")
        state = read_state(job_id, token)
        curr = {
            "cpu_time_secs": get_cpu_time(pid) if isinstance(pid, int) else None,
            "child_count": len(get_child_pids(pid)) if isinstance(pid, int) else 0,
            "artifact_mtimes": {},
            "log_signal": get_log_signal(rec.get("log")),
        }

        if state is None:
            # First-ever observation (or the pid was reused since our last
            # state) — seed only, never kill. Absence of memory must never
            # authorize a kill.
            last_progress_at = now
        else:
            # child_count intentionally omitted here — classify_progress()
            # only ever reads it from `curr` (children is a presence check,
            # not a prev-vs-curr transition), so a prev value would be
            # dead weight.
            prev = {
                "cpu_time_secs": state.get("cpu_time_secs"),
                "artifact_mtimes": {},
                "log_signal": state.get("log_signal"),
            }
            verdict = classify_progress(prev, curr)
            last_progress_at = now if verdict == "progressing" else state["last_progress_at"]

        write_state(
            job_id,
            {
                "job_id": job_id,
                "proc_start_token": token,
                "last_progress_at": last_progress_at,
                "cpu_time_secs": curr["cpu_time_secs"],
                "log_signal": curr["log_signal"],
            },
        )

        stall, no_progress_secs = classify_stall(cls_cfg, last_progress_at, now)
        entry = {
            "job_id": job_id,
            "verdict": stall,
            "no_progress_secs": round(no_progress_secs, 1),
        }
        if stall == "hard":
            action, reason = terminate_job(job_id, cls_cfg.get("grace_secs", 20), args.dry_run)
            entry["action"] = action
            if reason:
                entry["reason"] = reason
            if action == "skipped":
                saw_not_owned = True
            else:
                saw_hard = True
        elif stall == "soft":
            saw_soft = True
        results.append(entry)

    gc_state()
    print(json.dumps(results, indent=2))

    if saw_hard:
        return EXIT_HARD_STALL
    if saw_soft:
        return EXIT_SOFT_STALL
    if saw_not_owned:
        return EXIT_NOT_OWNED
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write("usage: qa-watchdog.py {list,enforce} ...\n")
        return EXIT_BAD_INPUT
    sub, rest = argv[0], argv[1:]
    dispatch = {
        "list": cmd_list,
        "enforce": cmd_enforce,
    }
    handler = dispatch.get(sub)
    if handler is None:
        sys.stderr.write(f"qa-watchdog: unknown subcommand '{sub}'\n")
        return EXIT_BAD_INPUT
    return handler(rest)


if __name__ == "__main__":
    sys.exit(main())
