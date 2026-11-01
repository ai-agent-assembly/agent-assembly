"""Shared mechanics for the B1 candidate harnesses (AAASM-6419, journeys J53 and J59).

Founder decision B1: a `published_artifact` journey is split into pre-publication
CANDIDATE checks (run here, bound to the candidate SHA and artifact digests) and
checks that need a published artifact, which are recorded PENDING and never PASS.

Invariants this module enforces for every harness built on it:

* The harness is hermetic: no network, no registry writes, every scratch file under
  one mktemp directory that is removed on exit.
* `pending_checks` come from a static table. Nothing here can set their status to
  anything but PENDING, so a publication-dependent check cannot be reported PASS.
* The verdict is derived, never asserted: BLOCK on any FAIL, CANDIDATE_INCOMPLETE
  when a candidate-executable check was not covered, CANDIDATE_VERIFIED otherwise.
  Only CANDIDATE_VERIFIED exits 0, and it is not PASS (Core ADR 0042).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

PASS, FAIL, PENDING, NOT_COVERED = "PASS", "FAIL", "PENDING", "NOT_COVERED"
SHA40 = re.compile(r"[0-9a-f]{40}")

EXIT_VERIFIED, EXIT_BLOCK, EXIT_USAGE, EXIT_INCOMPLETE = 0, 1, 2, 3


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def git_blob_sha256(repo: Path, sha: str, rel: str) -> str | None:
    """sha256 of `rel` as committed at `sha`, or None when git cannot say."""
    try:
        p = subprocess.run(
            ["/usr/bin/git", "-C", str(repo), "show", f"{sha}:{rel}"],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return "sha256:" + hashlib.sha256(p.stdout).hexdigest()


@dataclass
class Check:
    id: str
    status: str
    fidelity: str
    detail: str
    artifacts: list[str] = field(default_factory=list)
    negative_control: str | None = None


@dataclass
class PendingCheck:
    id: str
    channel: str
    why_publication_only: str
    command: str
    expected: str


class Context:
    """Holds artifact digests, the mktemp dir and the accumulated checks."""

    def __init__(self, journey: str, candidate_sha: str, expected_version: str):
        self.journey = journey
        self.candidate_sha = candidate_sha
        self.expected_version = expected_version
        self.artifacts: dict[str, str] = {}
        self.checks: list[Check] = []
        self.tmp = Path(tempfile.mkdtemp(prefix=f"b1-{journey.lower()}-")).resolve()
        self._children: list[subprocess.Popen[bytes]] = []

    def cleanup(self) -> None:
        for p in self._children:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def register(self, name: str, path: Path) -> str:
        digest = sha256_file(path)
        self.artifacts[name] = digest
        return digest

    def add(self, check_id: str, status: str, fidelity: str, detail: str,
            artifacts: list[str] | None = None, negative_control: str | None = None) -> Check:
        c = Check(check_id, status, fidelity, detail, list(artifacts or []), negative_control)
        self.checks.append(c)
        return c

    def spawn(self, argv: list[str], env: dict[str, str], cwd: Path) -> subprocess.Popen[bytes]:
        p = subprocess.Popen(argv, env=env, cwd=cwd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)
        self._children.append(p)
        return p


def clean_env(home: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    """`env -i` equivalent: nothing from the caller's environment, so no credential
    or proxy variable can leak into, or change, the candidate's behaviour."""
    env = {"HOME": str(home), "TMPDIR": str(home), "PATH": "/usr/bin:/bin"}
    env.update(extra or {})
    return env


def run(argv: list[str], env: dict[str, str], cwd: Path, timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s: {argv[0]}"
    except OSError as e:
        return 127, f"cannot execute {argv[0]}: {e}"
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port: int, timeout: float) -> bool:
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def terminate_group(p: subprocess.Popen[bytes], timeout: float = 10.0) -> int | None:
    """SIGTERM the child's process group and wait. Returns its exit code, or None
    when it had to be killed (it did not stop gracefully)."""
    if p.poll() is not None:
        return p.returncode
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        return p.poll()
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(timeout=5)
        return None


def verdict_of(checks: list[Check]) -> str:
    if any(c.status == FAIL for c in checks):
        return "BLOCK"
    if any(c.status != PASS for c in checks):
        return "CANDIDATE_INCOMPLETE"
    return "CANDIDATE_VERIFIED"


def build_report(ctx: Context, script: str, pending: list[PendingCheck],
                 failure_response: dict[str, Any], depends_on: list[dict[str, str]],
                 expect_in_pending_only: list[str] | None = None) -> dict[str, Any]:
    checks = ctx.checks
    verdict = verdict_of(checks)
    return {
        "schema": "b1-candidate-report/1",
        "journey": ctx.journey,
        "candidate_sha": ctx.candidate_sha,
        "expected_version": ctx.expected_version,
        "verdict": verdict,
        "verdict_note": (
            "CANDIDATE_VERIFIED is not PASS: every pending check below is still owed "
            "(Core ADR 0042). Only a published-artifact run can discharge them."
        ),
        "artifacts": dict(sorted(ctx.artifacts.items())),
        "candidate_checks": [
            {
                "id": c.id, "status": c.status, "fidelity": c.fidelity, "detail": c.detail,
                "evidence_ref": f"{script}::{c.id}@{ctx.candidate_sha}",
                "negative_control": c.negative_control,
                "artifact_digests": {n: ctx.artifacts[n] for n in sorted(c.artifacts) if n in ctx.artifacts},
            }
            for c in checks
        ],
        "pending_checks": [
            {"id": p.id, "status": PENDING, "channel": p.channel,
             "why_publication_only": p.why_publication_only, "command": p.command,
             "expected": p.expected}
            for p in pending
        ],
        "depends_on": depends_on,
        "failure_response": failure_response,
    }


def obligation_fragment(report: dict[str, Any]) -> dict[str, Any] | None:
    """The journey entry for a `publication-obligations.json`, in the exact shape
    `scripts/qa/publication_obligations.py` (PR #2798) validates. Returned only when
    every candidate check is PASS: the obligation admits no other status. Fields the
    emitter owns (`registry_digest`) are deliberately left out."""
    if report["verdict"] != "CANDIDATE_VERIFIED":
        return None
    return {
        "journey": report["journey"],
        "candidate_checks": [
            {k: c[k] for k in ("id", "status", "fidelity", "evidence_ref",
                               "negative_control", "artifact_digests")}
            for c in report["candidate_checks"]
        ],
        "pending_checks": [
            {k: p[k] for k in ("id", "channel", "why_publication_only", "command", "expected")}
            for p in report["pending_checks"]
        ],
        "depends_on": report["depends_on"],
        "failure_response": report["failure_response"],
    }


def finish(ctx: Context, report: dict[str, Any], out: str | None, fragment_out: str | None) -> int:
    text = json.dumps(report, indent=2, sort_keys=False)
    if out:
        Path(out).write_text(text + "\n")
    else:
        print(text)
    if fragment_out:
        frag = obligation_fragment(report)
        if frag is not None:
            Path(fragment_out).write_text(json.dumps({"journeys": [frag]}, indent=2) + "\n")
    return {"CANDIDATE_VERIFIED": EXIT_VERIFIED, "BLOCK": EXIT_BLOCK,
            "CANDIDATE_INCOMPLETE": EXIT_INCOMPLETE}[report["verdict"]]


def check_artifact_binding(ctx: Context, check_id: str, binaries: dict[str, Path],
                           sources: dict[str, str], repo: Path | None,
                           expected_digests: dict[str, str] | None,
                           negative_control: str | None) -> None:
    """Bind the consumed artifacts to the candidate.

    Sources (tracked files) are compared with the blob committed at the candidate
    SHA, which is independent of the working tree. Binaries are compared with an
    expected-digests record produced by the candidate build. A digest that is only
    recorded and never compared could not fail, so a binary with no expected digest
    makes the check NOT_COVERED rather than PASS.
    """
    problems: list[str] = []
    uncovered: list[str] = []
    for name, rel in sources.items():
        committed = git_blob_sha256(repo, ctx.candidate_sha, rel) if repo else None
        if committed is None:
            uncovered.append(f"{name}: cannot read {rel} at {ctx.candidate_sha[:12]}")
        elif committed != ctx.artifacts.get(name):
            problems.append(f"{name}: working copy {ctx.artifacts.get(name)} != committed {committed}")
    for name in binaries:
        want = (expected_digests or {}).get(name)
        if want is None:
            uncovered.append(f"{name}: no expected digest supplied")
        elif want != ctx.artifacts.get(name):
            problems.append(f"{name}: sha256 {ctx.artifacts.get(name)} != expected {want}")
    names = sorted(list(binaries) + list(sources))
    if problems:
        ctx.add(check_id, FAIL, "real_local_process", "; ".join(problems), names, negative_control)
    elif uncovered:
        ctx.add(check_id, NOT_COVERED, "real_local_process", "; ".join(uncovered), names, negative_control)
    else:
        ctx.add(check_id, PASS, "real_local_process",
                f"{len(sources)} source file(s) equal their blobs at {ctx.candidate_sha[:12]}; "
                f"{len(binaries)} binary(ies) equal the expected digests", names, negative_control)


def parse_common_args(argv: list[str], extra: Callable[[Any], None]) -> Any:
    import argparse
    ap = argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--candidate-sha", required=True, help="40-hex candidate commit")
    ap.add_argument("--expected-version", required=True, help="e.g. 0.0.1-rc.8")
    ap.add_argument("--repo", required=True, help="checkout containing the candidate sources")
    ap.add_argument("--expected-digests", help="JSON {artifact name: sha256:<hex>} from the candidate build")
    ap.add_argument("--out", help="write the JSON report here instead of stdout")
    ap.add_argument("--obligation-fragment", help="write the obligation journey entry here (only when CANDIDATE_VERIFIED)")
    extra(ap)
    args = ap.parse_args(argv)
    if not SHA40.fullmatch(args.candidate_sha):
        ap.error("--candidate-sha must be 40 lowercase hex characters")
    return args


def load_expected(path: str | None) -> dict[str, str] | None:
    if not path:
        return None
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise SystemExit("--expected-digests must be a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def main_guard(fn: Callable[[list[str]], int]) -> None:
    try:
        rc = fn(sys.argv[1:])
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)
