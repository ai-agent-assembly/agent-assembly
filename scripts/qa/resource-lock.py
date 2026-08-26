#!/usr/bin/env python3
"""Resource-lock wrapper for heavyweight QA jobs (AAASM-5893, Subtask 1 of
AAASM-5891's resource-aware QA-campaign scheduler).

Subcommands:
  run       Acquire a pool slot for a resource class, fork a thin relay
            supervisor (AAASM-5948), then os.execvp() the given command in
            the forked child — the supervisor never parents/babysits the
            job's actual logic. See "Why execvp for the job, and why a
            fork around it" below.
  status    List live jobs (liveness re-verified, never trusted from a
            stale record alone).
  sweep     GC job records whose pid is dead or whose proc_start_token no
            longer matches (stale/orphaned). Never touches slots/* — the
            kernel releases an flock however the holding process dies, so
            sweep only ever cleans up job *records*.
  validate  Structurally validate a resource-classes.yaml registry.

The `breaker` subcommand (circuit-breaker state for a repeatedly-stalling
class) is AAASM-5894's scope, not this file's — the job-record schema below
is written to be forward-compatible with it (retry_count is already
tracked), not to implement it.

Why execvp for the job, and why a fork around it: a naive supervising
parent that gets killed (e.g. by a tool-call timeout) while its child was
launched via a fresh `subprocess.Popen`-style spawn (no shared fd) releases
its own fcntl.flock while the real child keeps running unaware — recreating
the exact AAASM-5877 incident (3 duplicate `cargo doc` invocations silently
deadlocked on the shared CARGO_TARGET_DIR lock for ~50 minutes) this Story
exists to fix. The original AAASM-5893 design avoided any supervisor for
that reason: this process os.execvp()s directly into the job, so the lock
fd and the running job are the same process, guaranteed.

AAASM-5948 reintroduces a thin supervisor — but safely, because it's a
plain os.fork(), not a fresh spawn: the child inherits the PARENT's own
open lock fd via the duplicated fd table, and independently keeps that
open file description (and its flock) held for as long as the child itself
is alive, regardless of what happens to the parent. If the parent is
SIGKILLed, the AAASM-5877 failure mode does NOT recur — the child's own fd
copy keeps the slot correctly marked held. What the parent supervisor adds:
Ctrl-C containment. The job child calls os.setsid() (own process group, so
a future watchdog — AAASM-5951 — can killpg() just this job's tree without
touching siblings), which as a side effect moves it out of the terminal's
foreground process group and therefore out of reach of a directly-typed
Ctrl-C. The parent stays in the original group, relays SIGINT/SIGTERM into
the child's new group, and waits — otherwise Ctrl-C on `git push` would
leave the wrapped build running orphaned in the background for its full
duration, still holding the slot. Case 15 in
resource-scheduler-negative-control.sh is the dedicated regression test.

Either way, `fcntl.flock` IS retained across execvp and released by the
kernel on process death — but ONLY if os.set_inheritable(fd, True) is
called on the lock fd first: os.open() sets FD_CLOEXEC=1 by default, which
silently disables the whole locking mechanism at exec time if that line is
omitted, while everything else still appears to work. Case 11 in
resource-scheduler-negative-control.sh is the dedicated regression test for
this — don't trust this docstring, trust that fixture.

State layout, rooted at $AA_QA_LOCK_DIR (default ~/.cache/aa-qa — deliberately
machine-global, not per-worktree: the bounded resource, e.g. the shared
cargo target-dir, is machine-global across every worktree, and a per-worktree
lock dir would let two worktrees each see a free slot on the same underlying
resource):

  $AA_QA_LOCK_DIR/
    slots/<pool>.<i>      zero-byte files, flock target only — nothing else
                           reads or writes their content.
    jobs/<job_id>.json    written by `run` before exec; see write_job_record()
                           for the exact field set.

Tests MUST set AA_QA_LOCK_DIR to a tempdir — never touch the real one.
"""

import argparse
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

EXIT_OK = 0
EXIT_SATURATED = 75
EXIT_DUPLICATE = 76
EXIT_BAD_REGISTRY = 78

DEFAULT_FIELDS = {
    "wait_secs": 0,
    "soft_timeout_secs": 600,
    "hard_timeout_secs": 1800,
    "max_wallclock_secs": 21600,
    "grace_secs": 20,
    "breaker_open_threshold": 3,
    "degraded_limit": 0,
    "duplicate_policy": "suppress",
}


def eprint(*parts) -> None:
    print(*parts, file=sys.stderr, flush=True)


def marker(code: int, *parts) -> None:
    """Machine-parseable stderr line for a terminal wrapper-level exit.

    After os.execvp() the wrapper's own exit code is replaced by the
    child's, so codes 75/76/78 can only be distinguished from a child's own
    exit code via this line — it is deliberately never emitted on a
    successful run, since after execvp there is no wrapper process left to
    emit anything.
    """
    eprint("aa-qa-lock:", "ERROR", code, *parts)


def lock_dir() -> str:
    return os.environ.get("AA_QA_LOCK_DIR") or os.path.join(
        os.path.expanduser("~"), ".cache", "aa-qa"
    )


def registry_path(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    return os.environ.get("AA_QA_RESOURCE_CLASSES", "qa/resource-classes.yaml")


def _make_unique_key_loader():
    """A yaml.SafeLoader (no arbitrary-object constructors — only the stock
    safe ones, plus the duplicate-key check below) that rejects duplicate
    mapping keys.

    Plain yaml.safe_load silently lets a later duplicate key overwrite an
    earlier one, which would make the duplicate-class-name fixture invisible
    to validate_registry() (it would only ever see the last class).
    """
    import yaml

    class UniqueKeySafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.YAMLError(f"duplicate mapping key: {key!r}")
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    UniqueKeySafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    return UniqueKeySafeLoader


def load_registry_raw(path: str):
    """Return (data, error_string). Exactly one is None."""
    try:
        import yaml
    except ImportError:
        return None, "PyYAML is required (pip install pyyaml)"
    try:
        with open(path) as f:
            data = yaml.load(f, Loader=_make_unique_key_loader())
    except FileNotFoundError:
        return None, f"registry not found: {path}"
    except Exception as exc:  # yaml.YAMLError and friends
        return None, f"registry is not valid YAML: {exc}"
    return data, None


def validate_registry(data) -> list[str]:
    """Return a list of problem strings; empty means valid."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["registry root must be a mapping"]

    pools = data.get("pools")
    if not isinstance(pools, dict) or not pools:
        errors.append("registry must define a non-empty 'pools' mapping")
        pools = {}
    for pool_name, pool in pools.items():
        if not isinstance(pool, dict):
            errors.append(f"pool '{pool_name}' must be a mapping")
            continue
        limit = pool.get("limit")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            errors.append(
                f"pool '{pool_name}' has invalid 'limit' "
                f"(must be a positive integer): {limit!r}"
            )

    classes = data.get("classes")
    if not isinstance(classes, dict) or not classes:
        errors.append("registry must define a non-empty 'classes' mapping")
        classes = {}
    for class_name, cls in classes.items():
        if not isinstance(cls, dict):
            errors.append(f"class '{class_name}' must be a mapping")
            continue
        pool_ref = cls.get("pool")
        if not pool_ref:
            errors.append(f"class '{class_name}' is missing required field 'pool'")
        elif pool_ref not in pools:
            errors.append(
                f"class '{class_name}' references undefined pool '{pool_ref}'"
            )

    return errors


def resolve_class(data: dict, cls_name: str):
    """Return (pool_name, pool_cfg, effective_class_cfg) or None."""
    classes = data.get("classes") or {}
    pools = data.get("pools") or {}
    defaults = {**DEFAULT_FIELDS, **(data.get("defaults") or {})}
    cls = classes.get(cls_name)
    if cls is None:
        return None
    pool_name = cls.get("pool")
    pool = pools.get(pool_name)
    if pool is None:
        return None
    effective = dict(defaults)
    effective.update({k: v for k, v in cls.items() if k != "pool"})
    return pool_name, pool, effective


def _run_git(args: list[str]) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args], capture_output=True, text=True, timeout=5
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def git_common_dir() -> str | None:
    d = _run_git(["rev-parse", "--git-common-dir"])
    return os.path.abspath(d) if d else None


def git_toplevel() -> str | None:
    """The current worktree's own root — distinct per worktree, unlike
    `git_common_dir()` above (AAASM-5947). `--git-common-dir` resolves to
    the SAME shared `.git` for every worktree of a repo, so hashing only
    that into the fingerprint made two different worktrees running the
    same class/argv collide as "duplicates" of each other — a real defect
    found once the pre-push doc hook (AAASM-5895) started giving every
    push the same fixed class+argv. `--show-toplevel` is per-worktree, so
    including it keeps AAASM-5877's original fix intact (same worktree,
    same class/argv still collides) while distinguishing siblings.
    """
    d = _run_git(["rev-parse", "--show-toplevel"])
    return os.path.abspath(d) if d else None


def git_branch() -> str | None:
    return _run_git(["rev-parse", "--abbrev-ref", "HEAD"])


def compute_fingerprint(
    cls_name: str, gcd: str | None, toplevel: str | None, argv: list[str]
) -> str:
    h = hashlib.sha256()
    h.update(cls_name.encode())
    h.update(b"\x00")
    h.update((gcd or "").encode())
    h.update(b"\x00")
    h.update((toplevel or "").encode())
    h.update(b"\x00")
    h.update("\x00".join(argv).encode())
    return "sha256:" + h.hexdigest()


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just owned by someone else
    except OSError:
        return False
    return True


def ps_start_token(pid: int) -> str | None:
    """The verbatim `ps -p <pid> -o lstart=` output — an OPAQUE string.

    macOS and Linux emit different field orders (`Mon 24 Aug ...` vs.
    `Mon Aug 24 ...`); this is compared only for exact equality, never
    parsed as a date. Actual CPU-time-delta parsing for progress signals is
    AAASM-5894's scope.
    """
    try:
        out = subprocess.run(
            ["ps", "-p", str(pid), "-o", "lstart="],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    token = out.stdout.strip()
    return token or None


def verify_liveness(rec: dict) -> bool:
    """Ownership-verified liveness: pid alive AND its start-time token
    matches the recorded one exactly. A dead pid can be recycled by the OS
    for an unrelated process; the start-time check is what tells the two
    apart."""
    pid = rec.get("pid")
    if not isinstance(pid, int) or not pid_alive(pid):
        return False
    token = ps_start_token(pid)
    return token is not None and token == rec.get("proc_start_token")


def ensure_dirs(base: str) -> None:
    os.makedirs(os.path.join(base, "slots"), exist_ok=True)
    os.makedirs(os.path.join(base, "jobs"), exist_ok=True)


def list_job_records(base: str) -> dict:
    jobs_dir = os.path.join(base, "jobs")
    records = {}
    if not os.path.isdir(jobs_dir):
        return records
    for fname in os.listdir(jobs_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(jobs_dir, fname)) as f:
                records[fname] = json.load(f)
        except Exception:
            continue
    return records


def find_live_duplicate(base: str, fingerprint: str) -> dict | None:
    for rec in list_job_records(base).values():
        if rec.get("fingerprint") == fingerprint and verify_liveness(rec):
            return rec
    return None


def best_effort_holders(base: str, pool_name: str, limit: int) -> list[str]:
    holders = []
    for rec in list_job_records(base).values():
        if rec.get("pool") == pool_name and verify_liveness(rec):
            holders.append(f"slot={rec.get('slot')} pid={rec.get('pid')}")
    return holders or ["(unknown — no matching live job record found)"]


def write_job_record(base: str, record: dict) -> str:
    jobs_dir = os.path.join(base, "jobs")
    os.makedirs(jobs_dir, exist_ok=True)
    path = os.path.join(jobs_dir, f"{record['job_id']}.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(record, f, indent=2)
    os.replace(tmp, path)
    return path


def cmd_run(rest: list[str]) -> int:
    if "--" in rest:
        idx = rest.index("--")
        opts, cmd = rest[:idx], rest[idx + 1 :]
    else:
        opts, cmd = rest, []

    parser = argparse.ArgumentParser(prog="resource-lock.py run")
    parser.add_argument("--class", dest="cls", required=True)
    parser.add_argument("--wait", type=float, default=None)
    # --log / --retry: accepted and recorded in the job record now so
    # AAASM-5894's watchdog (which owns log redirection and actual retry
    # behavior) has a stable CLI surface to build on, but this subtask does
    # not act on either — no output redirection happens, retry_count is
    # always written as 0. Forward-compat groundwork, not a capability.
    parser.add_argument(
        "--log", default=None, help="recorded in the job record; not yet acted on (AAASM-5894)"
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="accepted; retry behavior is not yet implemented (AAASM-5894)",
    )
    args = parser.parse_args(opts)

    if not cmd:
        marker(EXIT_BAD_REGISTRY, "no-command-given")
        eprint(
            "aa-qa-lock: usage: run --class <name> [--wait SECS] -- <cmd> [args...]"
        )
        return EXIT_BAD_REGISTRY

    path = registry_path()
    data, err = load_registry_raw(path)
    if err:
        marker(EXIT_BAD_REGISTRY, err)
        return EXIT_BAD_REGISTRY
    reg_errors = validate_registry(data)
    if reg_errors:
        marker(EXIT_BAD_REGISTRY, reg_errors[0])
        return EXIT_BAD_REGISTRY

    resolved = resolve_class(data, args.cls)
    if resolved is None:
        marker(EXIT_BAD_REGISTRY, f"unknown class or pool for class '{args.cls}'")
        return EXIT_BAD_REGISTRY
    pool_name, pool_cfg, cls_cfg = resolved
    limit = pool_cfg["limit"]

    base = lock_dir()
    ensure_dirs(base)

    gcd = git_common_dir()
    toplevel = git_toplevel()
    fingerprint = compute_fingerprint(args.cls, gcd, toplevel, cmd)

    duplicate_policy = cls_cfg.get("duplicate_policy", "suppress")
    if duplicate_policy == "suppress":
        dup = find_live_duplicate(base, fingerprint)
        if dup is not None:
            elapsed = time.time() - dup.get("started_at", time.time())
            marker(EXIT_DUPLICATE, fingerprint, "held-by-pid", dup.get("pid"))
            eprint(
                f"aa-qa-lock: duplicate job already running: "
                f"pid={dup.get('pid')} started={dup.get('started_at_iso')} "
                f"elapsed={elapsed:.0f}s"
            )
            return EXIT_DUPLICATE

    wait_secs = args.wait if args.wait is not None else cls_cfg.get("wait_secs", 0)
    deadline = time.time() + wait_secs
    fd = None
    slot_index = None
    slot_path = None
    while True:
        for i in range(limit):
            candidate = os.path.join(base, "slots", f"{pool_name}.{i}")
            try_fd = os.open(candidate, os.O_CREAT | os.O_RDWR, 0o644)
            try:
                fcntl.flock(try_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(try_fd)
                continue
            fd, slot_index, slot_path = try_fd, i, candidate
            break
        if fd is not None:
            break
        if time.time() >= deadline:
            holders = best_effort_holders(base, pool_name, limit)
            marker(EXIT_SATURATED, "pool-saturated", pool_name)
            eprint(
                f"aa-qa-lock: pool '{pool_name}' saturated (limit={limit}); "
                f"holders: {holders}"
            )
            return EXIT_SATURATED
        time.sleep(0.5)

    # MANDATORY — see the module docstring. os.open() defaults to
    # FD_CLOEXEC, which silently drops this flock at execvp() below if this
    # line is skipped; case 11 in resource-scheduler-negative-control.sh is
    # the dedicated regression test for exactly that regression. Set before
    # the fork below so BOTH the parent's and the child's copy of the fd
    # (fork duplicates the whole fd table) are inheritable — only the
    # child actually execs, but see the fork rationale for why the
    # parent's copy matters too.
    os.set_inheritable(fd, True)

    # AAASM-5948: fork a supervisor instead of setsid()+execvp() in this
    # same process. The child gets its own process group (so a future
    # watchdog, AAASM-5951, can killpg() just this job's tree without
    # touching siblings — same reason AAASM-5893 originally called
    # os.setsid() directly here). The PARENT stays in the ORIGINAL process
    # group — the one the caller's shell/lefthook actually attached to the
    # controlling terminal — so it keeps receiving Ctrl-C. Its only job is
    # to relay SIGINT/SIGTERM into the child's new group and wait.
    #
    # This does NOT reintroduce the AAASM-5877 problem the module docstring
    # warns about (a killed supervisor silently releasing the flock while
    # an unaware child keeps running): fork() duplicates the whole fd
    # table, so the child holds its OWN reference to the same locked open
    # file description. If the parent is SIGKILLed, the kernel closes only
    # the PARENT's copy — the child's copy keeps the lock held, so a third
    # invocation still correctly sees the pool as saturated. The only
    # thing lost when the parent dies is the SIGINT relay itself (no
    # supervisor left to forward Ctrl-C) — strictly better than today,
    # where nothing ever relays it.
    # Ignore (not KeyboardInterrupt-raise) SIGINT/SIGTERM for the brief
    # window between fork() returning and the parent re-arming its real
    # handler below. Without this, a signal landing in that window hits
    # Python's default SIGINT disposition and kills the PARENT via an
    # uncaught KeyboardInterrupt before it ever relays anything —
    # reproducing this same subtask's orphan bug in a narrower window.
    # Ignoring (rather than leaving unset) means a signal here is simply
    # dropped, not relayed — strictly better than an orphaned job with no
    # possible recovery.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    child_pid = os.fork()

    if child_pid == 0:
        # Child inherits the parent's SIG_IGN above via fork — reset to
        # default so the job's own signal handling (or lack thereof)
        # behaves normally, not silently ignoring Ctrl-C forever.
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

        # Own process group first (must happen before exec, and before any
        # signal could plausibly race in) — os.setsid() raises EPERM if
        # this process is already a group leader (e.g. backgrounded with
        # `&` under job control already making it one); that's not a
        # failure, the pgid is ours either way.
        try:
            os.setsid()
        except OSError:
            pass

        pid = os.getpid()
        pgid = os.getpgid(0)
        now = time.time()
        job_id = f"{args.cls}-{pid}-{int(now)}"
        record = {
            "job_id": job_id,
            "class": args.cls,
            "pool": pool_name,
            "pid": pid,
            "pgid": pgid,
            "proc_start_token": ps_start_token(pid),
            "repo": os.getcwd(),
            "git_common_dir": gcd,
            "git_toplevel": toplevel,
            "branch": git_branch(),
            "fingerprint": fingerprint,
            "argv": cmd,
            "slot": slot_index,
            "slot_path": os.path.abspath(slot_path),
            "started_at": now,
            "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "log": args.log,
            "retry_count": 0,
        }
        # Written BEFORE exec — if execvp fails, that's fine: the pid this
        # record names will simply be gone on the next liveness check.
        write_job_record(base, record)

        os.execvp(cmd[0], cmd)
        os._exit(127)  # unreachable — execvp replaces this process on success

    # Parent (relay supervisor): does not need its own copy of the lock fd
    # — the child's copy is what matters — close it to avoid holding it
    # open for this process's own lifetime for no reason.
    os.close(fd)

    # How long to wait after relaying SIGTERM before escalating to SIGKILL
    # — reuses the class's own grace_secs (the same field AAASM-5951's
    # future hard-stall termination will read), so this doesn't invent a
    # second, inconsistent grace-period concept.
    grace_secs = cls_cfg.get("grace_secs", DEFAULT_FIELDS["grace_secs"])
    relayed_once = False

    def _relay(_signum: int, _frame) -> None:
        nonlocal relayed_once
        # Relay as SIGTERM, not necessarily the signal we ourselves
        # received. Observed on this platform/shell: a shell (e.g.
        # `bash -c ...`) that becomes a session/process-group leader via
        # the child's setsid() above can end up not reacting to a relayed
        # SIGINT into that group the way it reacts to SIGTERM — exact
        # conditions not fully pinned down across shells/platforms, and
        # not load-bearing either way: a plain non-shell command (cargo,
        # rustdoc) reacts to SIGTERM the same as SIGINT, so normalizing to
        # SIGTERM here has no correctness downside regardless of why the
        # observation held. Case 15 in resource-scheduler-negative-control
        # .sh is the actual regression guard (child genuinely terminates,
        # no orphan) — treat its exit-code assertion as secondary to that.
        try:
            os.killpg(child_pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        if relayed_once:
            # A second signal (e.g. an impatient double Ctrl-C) escalates
            # immediately rather than waiting out the grace period again.
            try:
                os.killpg(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            relayed_once = True
            signal.alarm(int(grace_secs))

    def _escalate(_signum: int, _frame) -> None:
        # Fired by signal.alarm() if the child hasn't exited grace_secs
        # after the first relay — a job that ignores or is slow to react
        # to SIGTERM must not hang the caller's terminal indefinitely
        # (Ctrl-C pre-AAASM-5948 always returned control instantly; this
        # keeps that property bounded rather than giving it up entirely).
        try:
            os.killpg(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGINT, _relay)
    signal.signal(signal.SIGTERM, _relay)
    signal.signal(signal.SIGALRM, _escalate)

    while True:
        try:
            _, status = os.waitpid(child_pid, 0)
            break
        except InterruptedError:
            continue  # a relayed signal's own delivery can interrupt waitpid
    signal.alarm(0)  # cancel a pending escalation if the child already exited

    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        # Conventional shell exit-code-on-signal-death encoding (128+n) —
        # matches what an interactive terminal would show if the wrapped
        # command had received the signal directly, pre-AAASM-5948.
        return 128 + os.WTERMSIG(status)
    return EXIT_OK  # pragma: no cover — neither exited nor signaled is not
    # a real waitpid outcome for a plain (non-WUNTRACED/WCONTINUED) wait


def cmd_status(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="resource-lock.py status")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--class", dest="cls", default=None)
    args = parser.parse_args(rest)

    base = lock_dir()
    live = []
    for rec in list_job_records(base).values():
        if args.cls and rec.get("class") != args.cls:
            continue
        if verify_liveness(rec):
            live.append(rec)

    if args.json:
        print(json.dumps(live, indent=2))
        return EXIT_OK

    if not live:
        print("no live jobs")
        return EXIT_OK
    for rec in live:
        elapsed = time.time() - rec.get("started_at", time.time())
        print(
            f"{rec.get('job_id')} class={rec.get('class')} pool={rec.get('pool')} "
            f"pid={rec.get('pid')} slot={rec.get('slot')} elapsed={elapsed:.0f}s "
            f"argv={' '.join(rec.get('argv', []))}"
        )
    return EXIT_OK


def cmd_sweep(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="resource-lock.py sweep")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(rest)

    base = lock_dir()
    jobs_dir = os.path.join(base, "jobs")
    removed = []
    if os.path.isdir(jobs_dir):
        for fname in os.listdir(jobs_dir):
            if not fname.endswith(".json"):
                continue
            path = os.path.join(jobs_dir, fname)
            try:
                with open(path) as f:
                    rec = json.load(f)
            except Exception:
                os.remove(path)
                removed.append(fname)
                continue
            if not verify_liveness(rec):
                os.remove(path)
                removed.append(rec.get("job_id", fname))

    for job_id in removed:
        print(f"aa-qa-lock: sweep removed stale record {job_id}")

    if args.strict and removed:
        return 1
    return EXIT_OK


def cmd_validate(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="resource-lock.py validate")
    parser.add_argument("path", nargs="?", default=None)
    args = parser.parse_args(rest)

    path = registry_path(args.path)
    data, err = load_registry_raw(path)
    if err:
        eprint(f"aa-qa-lock: {err}")
        return EXIT_BAD_REGISTRY

    errors = validate_registry(data)
    if errors:
        for e in errors:
            eprint(f"aa-qa-lock: {e}")
        return EXIT_BAD_REGISTRY

    print(f"aa-qa-lock: {path} is valid")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        eprint("usage: resource-lock.py {run,status,sweep,validate} ...")
        return 2
    sub, rest = argv[0], argv[1:]
    dispatch = {
        "run": cmd_run,
        "status": cmd_status,
        "sweep": cmd_sweep,
        "validate": cmd_validate,
    }
    handler = dispatch.get(sub)
    if handler is None:
        eprint(f"aa-qa-lock: unknown subcommand '{sub}'")
        return 2
    return handler(rest)


if __name__ == "__main__":
    sys.exit(main())
