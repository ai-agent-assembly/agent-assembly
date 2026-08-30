#!/usr/bin/env python3
"""Per-ticket pickup claim, closing the TOCTOU gap `resource-lock.py` does not
cover (AAASM-6013).

`resource-lock.py run`'s claim lives exactly as long as the one subprocess it
forks+execvp's into — right shape for a build job, wrong shape here: a ticket
claim must stay valid across an entire ticket's lifecycle (many separate
command invocations over a session, not one subprocess), so this is a
sibling script rather than a new `run` mode. It reuses `resource-lock.py`'s
liveness-verification *idea* — pid alive AND its `ps` start-time token still
matches the one recorded at claim time, so a claim is never trusted just
because a PID happened to be alive, possibly recycled to an unrelated
process — duplicated in miniature below rather than imported, since
`resource-lock.py`'s filename (a hyphen) makes it unimportable as a module
without `importlib` machinery disproportionate to ~15 lines of logic.

Subcommands:
  claim    Atomically claim a ticket key. Fails loudly (exit 76, matching
            resource-lock.py's EXIT_DUPLICATE so tooling that already greps
            for that code recognizes this failure mode too) if a *live*
            claim already exists — never silently proceeds, never queues.
  release  Release a claim this process holds (or `--force` a stale one).
  status   List live claims (liveness re-verified, never trusted from a
            stale record alone) and sweep dead ones as a side effect, same
            as resource-lock.py's own `sweep`/`status` split does for build
            jobs — a status read is also the natural, low-cost point to GC.

State layout, rooted at $AA_QA_LOCK_DIR (default ~/.cache/aa-qa — the SAME
root resource-lock.py uses, per AAASM-6013 AC3, not a second lock directory):

  $AA_QA_LOCK_DIR/
    claims/<ticket>.json   claim record; see write_claim() for the field set.
    claims/.<ticket>.lock  zero-byte flock target guarding the
                            check-then-write critical section below — held
                            only for the duration of one claim/release call,
                            not for the ticket's lifetime (unlike
                            resource-lock.py's build-job slot locks, which
                            ARE held for a whole subprocess's life — a ticket
                            claim outlives any single process, so nothing
                            can hold an flock across the whole claim; the
                            liveness triad on the *owning* pid is what makes
                            the claim durable instead).

Tests MUST set AA_QA_LOCK_DIR to a tempdir — never touch the real one.
"""

import argparse
import fcntl
import json
import os
import sys
import time

EXIT_OK = 0
EXIT_CLAIMED = 76  # matches resource-lock.py's EXIT_DUPLICATE
EXIT_NOT_HELD = 77
EXIT_BAD_ARGS = 2


def eprint(*parts) -> None:
    print(*parts, file=sys.stderr, flush=True)


def lock_dir() -> str:
    return os.environ.get("AA_QA_LOCK_DIR") or os.path.join(
        os.path.expanduser("~"), ".cache", "aa-qa"
    )


def claims_dir() -> str:
    d = os.path.join(lock_dir(), "claims")
    os.makedirs(d, exist_ok=True)
    return d


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
    """Verbatim `ps -p <pid> -o lstart=` output, compared only for exact
    equality — see resource-lock.py's own doc-comment on this same
    technique for why (macOS/Linux field-order differences make it unsafe
    to parse as a date; it doesn't need to be, only to distinguish "the
    same process" from "a different process the OS recycled this pid to")."""
    import subprocess

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
    pid = rec.get("pid")
    if not isinstance(pid, int) or not pid_alive(pid):
        return False
    token = ps_start_token(pid)
    return token is not None and token == rec.get("proc_start_token")


def claim_path(ticket: str) -> str:
    return os.path.join(claims_dir(), f"{ticket}.json")


def lock_path(ticket: str) -> str:
    return os.path.join(claims_dir(), f".{ticket}.lock")


def read_claim(ticket: str) -> dict | None:
    path = claim_path(ticket)
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception:
        return None


def write_claim(ticket: str, rec: dict) -> None:
    path = claim_path(ticket)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f, indent=2)
    os.replace(tmp, path)


def _describe(rec: dict) -> str:
    bits = [f"pid={rec.get('pid')}", f"claimed={rec.get('claimed_at_iso')}"]
    if rec.get("branch"):
        bits.append(f"branch={rec['branch']}")
    if rec.get("pr_url"):
        bits.append(f"pr={rec['pr_url']}")
    if rec.get("worktree"):
        bits.append(f"worktree={rec['worktree']}")
    return " ".join(bits)


def cmd_claim(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ticket-claim.py claim")
    parser.add_argument("ticket")
    parser.add_argument("--pid", type=int, default=None, help="defaults to this process's own pid")
    parser.add_argument("--worktree", default=None)
    parser.add_argument("--branch", default=None)
    parser.add_argument("--pr-url", dest="pr_url", default=None)
    args = parser.parse_args(rest)

    pid = args.pid if args.pid is not None else os.getpid()
    token = ps_start_token(pid)
    if token is None:
        eprint(f"aa-qa-lock: cannot verify pid {pid} is real (ps failed) — refusing to claim")
        return EXIT_BAD_ARGS

    # The flock below is held only across this check-then-write section —
    # it exists purely to close the TOCTOU gap between two concurrent
    # `claim` invocations for the SAME ticket both reading "no live claim"
    # before either has written one. It is released (fd closed) before this
    # function returns; it does not represent ownership of the ticket
    # itself. Ownership is the liveness triad on the record's pid.
    lock_fd = os.open(lock_path(args.ticket), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)  # blocking — this section is sub-millisecond

        existing = read_claim(args.ticket)
        if existing is not None and verify_liveness(existing):
            eprint(
                f"aa-qa-lock: ticket {args.ticket} already claimed: {_describe(existing)}"
            )
            return EXIT_CLAIMED

        now = time.time()
        rec = {
            "ticket": args.ticket,
            "pid": pid,
            "proc_start_token": token,
            "worktree": args.worktree,
            "branch": args.branch,
            "pr_url": args.pr_url,
            "claimed_at": now,
            "claimed_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        }
        write_claim(args.ticket, rec)
        print(f"aa-qa-lock: claimed {args.ticket} for pid {pid}")
        return EXIT_OK
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def cmd_release(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ticket-claim.py release")
    parser.add_argument("ticket")
    parser.add_argument("--pid", type=int, default=None)
    parser.add_argument(
        "--force",
        action="store_true",
        help="release even if the recorded pid isn't this caller (e.g. releasing a dead/stale claim on another lane's behalf)",
    )
    args = parser.parse_args(rest)

    pid = args.pid if args.pid is not None else os.getpid()

    lock_fd = os.open(lock_path(args.ticket), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        existing = read_claim(args.ticket)
        if existing is None:
            eprint(f"aa-qa-lock: no claim recorded for {args.ticket}")
            return EXIT_NOT_HELD

        if not args.force and existing.get("pid") != pid:
            eprint(
                f"aa-qa-lock: claim on {args.ticket} is held by pid={existing.get('pid')}, "
                f"not the calling pid={pid} — pass --force to release it anyway"
            )
            return EXIT_NOT_HELD

        try:
            os.remove(claim_path(args.ticket))
        except FileNotFoundError:
            pass
        print(f"aa-qa-lock: released {args.ticket}")
        return EXIT_OK
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def cmd_status(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ticket-claim.py status")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(rest)

    d = claims_dir()
    live = []
    for fname in os.listdir(d):
        if not fname.endswith(".json"):
            continue
        ticket = fname[: -len(".json")]
        rec = read_claim(ticket)
        if rec is None:
            continue
        if verify_liveness(rec):
            live.append(rec)
        else:
            # Same GC-on-read policy as resource-lock.py's `sweep`: a dead
            # owner's claim is not load-bearing for anything, so remove it
            # here rather than leaving every future `claim` call to pay the
            # liveness check against a record that will never verify again.
            try:
                os.remove(claim_path(ticket))
            except FileNotFoundError:
                pass

    if args.json:
        print(json.dumps(live, indent=2))
        return EXIT_OK

    if not live:
        print("no live claims")
        return EXIT_OK
    for rec in live:
        print(f"{rec.get('ticket')} {_describe(rec)}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        eprint("usage: ticket-claim.py {claim,release,status} ...")
        return EXIT_BAD_ARGS
    sub, rest = argv[0], argv[1:]
    dispatch = {"claim": cmd_claim, "release": cmd_release, "status": cmd_status}
    handler = dispatch.get(sub)
    if handler is None:
        eprint(f"aa-qa-lock: unknown subcommand '{sub}'")
        return EXIT_BAD_ARGS
    return handler(rest)


if __name__ == "__main__":
    sys.exit(main())
