#!/usr/bin/env python3
"""J27 SDK-path lane (AAASM-6469): a `redact_only` secret must never reach a tool body.

Owner decision for rc.8, "scrub where the layer can, otherwise deny": on the non-proxy
path every SDK takes (SDK -> runtime socket -> gateway) nothing carries scrubbed
arguments back to the SDK, so when a `redact_only` decision cannot be applied the runtime
must deny the call and the SDK must not execute the tool. This lane proves that with the
real artifacts, as local processes, and with a side effect the SDK cannot fake: the tool
body writes a sentinel file.

Inputs are artifacts, not source: the candidate `aa-gateway` and `aa-runtime` binaries and
a python-sdk wheel built from the pinned SDK SHA. Nothing is built here, so the same lane
qualifies whichever final candidate the release coordinator freezes.

Checks, in order (each is a real observation, none is derived from another):

  allowed-control          clean arguments under the same `redact_only` policy: the tool body RAN
                           (sentinel written). Without this, "sentinel absent" below could mean a broken stack.
  redact-only-secret-deny  a fabricated AWS-style key in the arguments: the SDK raised a typed deny and the
                           tool body did NOT run (sentinel absent), and the error text does not carry the key.
  audit-finding-visible    the gateway audit log holds a CredentialLeakBlocked event for the secret call.
  no-raw-secret-at-rest    the raw key appears in no file under the run's HOME, in no process log and not in
                           this report.

Mutation check (`--mutate-sdk-redact-allow`): rewrites the installed SDK so a `redact` verdict is treated as an
allow, which is the defect AAASM-6352 fixed. Run it with a runtime that relays `Redact` (a mutated
`normalize_gateway_decision`) and the lane must FAIL on `redact-only-secret-deny`; with only one layer mutated
the other still denies and the lane must still PASS. See docs for the recorded matrix.

Usage:
  python3 -I scripts/qa/j27-sdk-scrub-or-deny-lane.py --gateway <aa-gateway> --runtime <aa-runtime> \
      --wheel <agent_assembly-*.whl> [--wheelhouse <dir>] [--python <python3.13>] [--mutate-sdk-redact-allow] \
      [--out report.json]

Exit: 0 every check PASS, 1 any check FAIL, 2 usage or setup error.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "fixtures" / "j27" / "sdk_driver.py"
# Fabricated AWS-style access key: pattern-matching only, not a credential.
FAKE_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
POLICY = """\
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: j27-redact-only
  version: "0.1.0"
spec:
  tools:
    write_file:
      allow: true
  data:
    credential_action: redact_only
"""
# A syntactically valid key for a throwaway loopback stack; not a credential.
TEST_KEY = "aa_0123456789abcdef0123456789abcdef"
LANGCHAIN_PACKAGES = ("langchain", "langchain-core")
MUTATION_NEEDLE = 'if decision == "redact":\n            return self._on_query_failure(_REDACT_UNSUPPORTED_REASON)'
MUTATION_REPLACEMENT = 'if decision == "redact":\n            return {"status": "allow"}'


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def run(argv: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
    p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout, check=False)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def version_of(binary: Path) -> list[str]:
    """`--version` output (version and build-sha), so a PASS is tied to a candidate rather than to a file name."""
    try:
        # Generous: a binary the host has not seen can sit in first-launch validation for minutes.
        rc, out = run([str(binary), "--version"], {"PATH": "/usr/bin:/bin"}, 600)
    except (OSError, subprocess.SubprocessError) as e:
        return [f"not probed: {type(e).__name__}"]
    return out.strip().splitlines() if rc == 0 else [f"--version exited {rc}"]


def wait_for(pred: Callable[[], bool], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.2)
    return False


class Stack:
    """Real gateway + real runtime, isolated HOME, loopback port, per-run runtime socket."""

    def __init__(self, tmp: Path, gateway: Path, runtime: Path):
        self.tmp, self.gateway, self.runtime = tmp, gateway, runtime
        self.home = tmp / "home"
        self.home.mkdir()
        self.agent = f"j27-{os.getpid()}-{int(time.time())}"
        self.port = free_port()
        self.sock = Path(f"/tmp/aa-runtime-{self.agent}.sock")
        self.procs: list[subprocess.Popen[bytes]] = []
        self.logs: list[Path] = []
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(self.home)}

    def _spawn(self, name: str, argv: list[str], env: dict[str, str]) -> subprocess.Popen[bytes]:
        log = self.tmp / f"{name}.log"
        self.logs.append(log)
        # A file, never a pipe: an undrained pipe stalls a chatty process.
        p = subprocess.Popen(argv, env=env, cwd=self.tmp, stdout=log.open("wb"), stderr=subprocess.STDOUT,
                             start_new_session=True)
        self.procs.append(p)
        return p

    def start(self) -> str | None:
        policy = self.tmp / "policy.yaml"
        policy.write_text(POLICY)
        addr = f"127.0.0.1:{self.port}"
        gw = self._spawn("aa-gateway", [str(self.gateway), "--policy", str(policy), "--listen", addr], self.env)
        # A freshly seen binary can sit in the host's first-launch validation for minutes; that says nothing about it.
        if not wait_for(lambda: self._listening() or gw.poll() is not None, 600) or gw.poll() is not None:
            return f"aa-gateway did not listen on {addr} (exit {gw.poll()})"
        env = {**self.env, "AA_AGENT_ID": self.agent, "AA_POLICY_PATH": "", "RUST_LOG": "warn",
               "AA_GATEWAY_ENDPOINT": f"http://{addr}", "AA_METRICS_ADDR": f"127.0.0.1:{free_port()}",
               "AA_AUDIT_BUFFER_PATH": str(self.home / "audit-buffer.db")}
        rt = self._spawn("aa-runtime", [str(self.runtime)], env)
        if not wait_for(lambda: self.sock.exists() or rt.poll() is not None, 600) or rt.poll() is not None:
            return f"aa-runtime did not bind {self.sock} (exit {rt.poll()})"
        return None

    def _listening(self) -> bool:
        with socket.socket() as s:
            s.settimeout(0.3)
            return s.connect_ex(("127.0.0.1", self.port)) == 0

    def sdk_env(self) -> dict[str, str]:
        return {**self.env, "AA_RUNTIME_SOCKET": str(self.sock), "AA_GATEWAY_ENDPOINT": f"http://127.0.0.1:{self.port}"}

    def stop(self) -> None:
        # Only processes this lane spawned, each in its own session; the runtime may have children (its proxy).
        for p in reversed(self.procs):
            if p.poll() is None:
                # The group may exit between poll() and killpg(); it is then already gone, which is the goal.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(p.pid, signal.SIGTERM)
        for p in self.procs:
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
        # aa-runtime removes its own socket on a clean shutdown, so absence is the normal case.
        self.sock.unlink(missing_ok=True)


def build_venv(tmp: Path, python: str, wheel: Path, wheelhouse: Path, mutate: bool) -> tuple[Path | None, str]:
    venv = tmp / "venv"
    env = {"PATH": "/usr/bin:/bin", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1"}
    rc, out = run([python, "-m", "venv", str(venv)], env, 120)
    if rc != 0:
        return None, f"venv: {out[-300:]}"
    # --no-index: a missing dependency must fail loudly, never be fetched, so the run stays offline.
    rc, out = run([str(venv / "bin" / "python"), "-m", "pip", "install", "--no-index", "--find-links",
                   str(wheelhouse), str(wheel), *LANGCHAIN_PACKAGES], env, 300)
    if rc != 0:
        return None, f"pip install: {out[-400:]}"
    if mutate:
        rc, out = run([str(venv / "bin" / "python"), "-I", "-c",
                       "import agent_assembly.core.runtime_interceptor as m; print(m.__file__)"], env, 60)
        target = Path(out.strip().splitlines()[-1])
        text = target.read_text()
        if MUTATION_NEEDLE not in text:
            return None, "mutation target not found in the installed SDK; the lane's mutation is stale"
        target.write_text(text.replace(MUTATION_NEEDLE, MUTATION_REPLACEMENT, 1))
    return venv, ""


def call(stack: Stack, venv: Path, name: str, args_json: str, tool: str = "write_file") -> dict[str, Any]:
    args_file = stack.tmp / f"{name}.args.json"
    args_file.write_text(args_json)
    sentinel = stack.tmp / f"{name}.sentinel"
    sentinel.unlink(missing_ok=True)
    rc, out = run([str(venv / "bin" / "python"), "-I", str(DRIVER), "--agent", stack.agent, "--tool", tool,
                   "--control-plane-url", "http://127.0.0.1:1", "--key", TEST_KEY,
                   "--args-file", str(args_file), "--sentinel", str(sentinel)], stack.sdk_env(), 180)
    result: dict[str, Any] = {"error": "driver-no-result", "detail": f"exit {rc}: {out.strip()[-200:]}"}
    for line in reversed(out.splitlines()):
        if line.startswith("RESULT "):
            try:
                result = json.loads(line[len("RESULT "):])
            except ValueError:
                # Not swallowed: the pre-set error result stands, so the check that reads it fails the lane.
                result = {"error": "driver-result-unparseable", "detail": f"exit {rc}"}
            break
    result["sentinel_exists"] = sentinel.exists()
    return result


def audit_events(stack: Stack) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for f in stack.home.rglob("*.jsonl"):
        for line in f.read_text(errors="replace").splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                # A torn or non-JSON line carries no event. It cannot make the audit check pass: that check
                # needs a parsed CredentialLeakBlocked event, so a lost line can only fail it.
                continue
    return events


def files_containing(root: Path, needle: bytes, extra: list[Path]) -> tuple[list[str], list[str]]:
    """Files holding `needle`, and files that could not be read. An unreadable file could be hiding the key, so the
    caller must treat it as a failure rather than as a clean scan."""
    hits: list[str] = []
    unreadable: list[str] = []
    for p in [*root.rglob("*"), *extra]:
        try:
            if p.is_file() and needle in p.read_bytes():
                hits.append(str(p))
        except OSError:
            unreadable.append(str(p))
    return hits, unreadable


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", required=True, type=Path)
    ap.add_argument("--runtime", required=True, type=Path)
    ap.add_argument("--wheel", required=True, type=Path)
    ap.add_argument("--wheelhouse", type=Path, help="directory holding the wheel's dependencies (default: the wheel's directory)")
    ap.add_argument("--python", default=sys.executable, help="interpreter matching the wheel's ABI tag")
    ap.add_argument("--mutate-sdk-redact-allow", action="store_true")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    for label, p in (("--gateway", a.gateway), ("--runtime", a.runtime), ("--wheel", a.wheel)):
        if not p.is_file():
            print(f"usage: {label} {p} is not a file", file=sys.stderr)
            return 2

    tmp = Path(tempfile.mkdtemp(prefix="j27-lane-"))
    stack: Stack | None = None
    checks: list[dict[str, str]] = []

    def record(cid: str, ok: bool, detail: str) -> None:
        checks.append({"id": cid, "status": "PASS" if ok else "FAIL", "detail": detail})

    try:
        venv, why = build_venv(tmp, a.python, a.wheel, a.wheelhouse or a.wheel.parent, a.mutate_sdk_redact_allow)
        if venv is None:
            print(f"setup error: {why}", file=sys.stderr)
            return 2
        stack = Stack(tmp, a.gateway, a.runtime)
        start_error = stack.start()
        if start_error:
            print(f"setup error: {start_error}", file=sys.stderr)
            return 2

        control = call(stack, venv, "allowed-control", json.dumps({"path": "/tmp/x.txt", "note": "nothing sensitive"}))
        record("allowed-control", control.get("executed") is True and control["sentinel_exists"],
               f"executed={control.get('executed')} sentinel_written={control['sentinel_exists']} error={control.get('error')}")

        secret = call(stack, venv, "redact-only-secret-deny", json.dumps({"path": "/tmp/x.txt", "aws_key": FAKE_AWS_KEY}))
        denied = (secret.get("executed") is False and not secret["sentinel_exists"] and secret.get("typed") is True
                  and FAKE_AWS_KEY not in json.dumps(secret))
        record("redact-only-secret-deny", denied,
               f"executed={secret.get('executed')} sentinel_written={secret['sentinel_exists']} "
               f"error={secret.get('error')} typed={secret.get('typed')} reason={secret.get('message')!r}")

        kinds = [e.get("event_type") for e in audit_events(stack)]
        record("audit-finding-visible", "CredentialLeakBlocked" in kinds,
               f"gateway audit event types: {sorted(set(map(str, kinds)))}")

        stack.stop()
        hits, unreadable = files_containing(stack.home, FAKE_AWS_KEY.encode(), stack.logs)
        record("no-raw-secret-at-rest", not hits and not unreadable,
               f"files containing the raw key: {hits or 'none'}; unreadable files: {unreadable or 'none'}")
        stack = None
    finally:
        if stack is not None:
            stack.stop()
        # The args files in tmp hold the synthetic key; remove them on every path, early returns included.
        shutil.rmtree(tmp, ignore_errors=True)

    verdict = "LANE_PASS" if all(c["status"] == "PASS" for c in checks) else "LANE_FAIL"
    artifacts = {"aa-gateway": sha256(a.gateway), "aa-runtime": sha256(a.runtime), "sdk-wheel": sha256(a.wheel)}
    report: dict[str, Any] = {
        "schema": "j27-sdk-scrub-or-deny-lane/1",
        "verdict": verdict,
        "mutation": "sdk-redact-allow" if a.mutate_sdk_redact_allow else "none",
        "artifacts": artifacts,
        "versions": {"aa-gateway": version_of(a.gateway), "aa-runtime": version_of(a.runtime), "sdk-wheel": a.wheel.name},
        "checks": checks,
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    assert FAKE_AWS_KEY not in text
    if a.out:
        a.out.write_text(text + "\n")
    # Stdout carries only a fixed-shape summary built from fields that never hold tool arguments or driver
    # output; the full report, whose check details quote the SDK's deny reason, goes to --out.
    print(f"{verdict} mutation={report['mutation']}")
    for c in checks:
        print(f"  {c['status']} {c['id']}")
    for name, digest in artifacts.items():
        print(f"  {name} {digest}")
    return 0 if verdict == "LANE_PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
