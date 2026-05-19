#!/usr/bin/env python3
"""Run AI agent fixture scripts against a live aasm gateway.

Developer-facing CLI complement to the Rust E2E test harness. Discovers
Python fixture scripts under this directory, filters by framework /
scenario / glob, runs each subprocess with a timeout, and emits a summary.
"""

from __future__ import annotations

import argparse
import asyncio
import fnmatch
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCENARIOS: list[str] = [
    "single_agent",
    "agent_team",
    "root_sub_agents",
    "secret_leaker",
    "file_operator",
]

FRAMEWORK_PATTERNS: dict[str, str] = {
    "langchain": "*langchain*",
    "langgraph": "*langgraph*",
    "crewai": "*crewai*",
    "pydantic_ai": "*pydantic_ai*",
    "openai_agents": "*openai_agents*",
}

EXCLUDED_FILENAMES: set[str] = {"_shared.py", "run_agents.py"}


@dataclass(frozen=True)
class AgentScript:
    """One discovered fixture script."""

    path: Path
    scenario: str
    framework: str
    name: str


@dataclass
class RunResult:
    """Outcome of running one fixture script."""

    script: AgentScript
    passed: bool
    duration_ms: int
    last_event: dict | None = None
    error: str | None = None
    exit_code: int | None = None
    timed_out: bool = False


@dataclass
class RunConfig:
    """Per-invocation execution settings."""

    timeout: int = 30
    gateway_url: str = "http://127.0.0.1:8080"
    api_key: str = "dev-key"
    proxy_addr: str | None = None
    selftest: bool = False
    verbose: bool = False


def _framework_for(stem: str) -> str:
    """Map a script filename stem to a framework name (or 'unknown')."""
    for framework, pattern in FRAMEWORK_PATTERNS.items():
        if fnmatch.fnmatch(stem, pattern):
            return framework
    return "unknown"


def discover(root: Path) -> list[AgentScript]:
    """Walk ``root`` and collect fixture scripts.

    Skips ``_shared.py`` and ``run_agents.py``. Scenarios are taken from
    :data:`SCENARIOS` so missing directories (e.g. ``secret_leaker`` before
    that fixture set lands) are silently tolerated.
    """
    scripts: list[AgentScript] = []
    for scenario in SCENARIOS:
        scenario_dir = root / scenario
        if not scenario_dir.is_dir():
            continue
        for path in sorted(scenario_dir.glob("*.py")):
            if path.name in EXCLUDED_FILENAMES:
                continue
            scripts.append(
                AgentScript(
                    path=path,
                    scenario=scenario,
                    framework=_framework_for(path.stem),
                    name=path.stem,
                )
            )
    return scripts


def filter_scripts(
    scripts: Iterable[AgentScript],
    frameworks: list[str] | None,
    scenarios: list[str] | None,
    file_glob: str | None,
) -> list[AgentScript]:
    """Apply filter flags with OR-within-group / AND-between-groups semantics.

    Empty / ``None`` groups disable that filter axis. ``file_glob`` is
    matched against the filename stem only (not the full path).
    """
    result: list[AgentScript] = []
    for script in scripts:
        if frameworks and script.framework not in frameworks:
            continue
        if scenarios and script.scenario not in scenarios:
            continue
        if file_glob and not fnmatch.fnmatch(script.name, file_glob):
            continue
        result.append(script)
    return result


def _strip_scheme(addr: str) -> str:
    """Drop a leading ``http://`` / ``https://`` / ``grpc://`` so the fixture
    helpers see a bare ``host:port`` for the ``AA_GATEWAY_ADDR`` env var."""
    for prefix in ("http://", "https://", "grpc://"):
        if addr.startswith(prefix):
            return addr[len(prefix):]
    return addr


def _env_for(script: AgentScript, cfg: RunConfig) -> dict[str, str]:
    """Build the environment for a fixture subprocess."""
    env = os.environ.copy()
    if cfg.selftest:
        env["AA_SELFTEST"] = "1"
        env.setdefault("AA_GATEWAY_ADDR", "dummy")
    else:
        env["AA_GATEWAY_ADDR"] = _strip_scheme(cfg.gateway_url)
    env["AA_API_KEY"] = cfg.api_key
    env["AA_AGENT_ID"] = f"e2e-{script.name}"
    env["AA_TASK"] = "hello"
    if cfg.proxy_addr:
        env["AA_PROXY_ADDR"] = cfg.proxy_addr
    return env


def _last_json_line(stdout: str | bytes | None) -> dict | None:
    """Return the last JSON-decodable line of stdout, or ``None``."""
    if stdout is None:
        return None
    text = stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else stdout
    last: object | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            last = json.loads(stripped)
        except json.JSONDecodeError:
            continue
    return last if isinstance(last, dict) else None


def run_script(script: AgentScript, cfg: RunConfig) -> RunResult:
    """Spawn one fixture subprocess via ``uv run`` and capture the outcome.

    Honours ``cfg.timeout`` — on expiry the subprocess is killed and a
    :class:`RunResult` with ``timed_out=True`` is returned.
    """
    python_root = script.path.parents[1]  # .../agents/python
    rel_path = script.path.relative_to(python_root)
    start = time.monotonic()

    try:
        proc = subprocess.run(
            [
                "uv", "run", "--frozen",
                "--extra", "runner", "--extra", "all",
                str(rel_path),
            ],
            cwd=python_root,
            env=_env_for(script, cfg),
            capture_output=True,
            text=True,
            timeout=cfg.timeout,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return RunResult(
            script=script,
            passed=False,
            duration_ms=duration_ms,
            last_event=_last_json_line(exc.stdout),
            error=f"timeout after {cfg.timeout}s",
            timed_out=True,
        )

    duration_ms = int((time.monotonic() - start) * 1000)
    error: str | None = None
    if proc.returncode != 0:
        stderr_tail = (proc.stderr or "").strip().splitlines()
        last_line = stderr_tail[-1] if stderr_tail else ""
        error = f"exit {proc.returncode}: {last_line}".rstrip(": ").rstrip()
    return RunResult(
        script=script,
        passed=proc.returncode == 0,
        duration_ms=duration_ms,
        last_event=_last_json_line(proc.stdout),
        error=error,
        exit_code=proc.returncode,
    )


def _format_result_line(result: RunResult) -> str:
    """One-line PASS/FAIL summary suitable for sequential streaming."""
    mark = "✓" if result.passed else "✗"
    label = f"{result.script.scenario:<15} / {result.script.name:<26}"
    if result.timed_out:
        detail = f"TIMEOUT ({result.script.path.name} after {result.duration_ms} ms)"
    elif result.error:
        detail = result.error
    else:
        detail = f"{result.duration_ms} ms"
    return f" {mark}  {label}  {detail}"


def run_all_sequential(
    scripts: list[AgentScript],
    cfg: RunConfig,
    stream: "object | None" = None,
) -> list[RunResult]:
    """Run scripts one at a time, printing PASS/FAIL after each.

    ``stream`` defaults to ``sys.stdout``. Callers (e.g. ``--json`` mode)
    pass ``sys.stderr`` so stdout stays reserved for the JSON payload.
    """
    out = stream if stream is not None else sys.stdout
    results: list[RunResult] = []
    for script in scripts:
        result = run_script(script, cfg)
        print(_format_result_line(result), file=out, flush=True)
        results.append(result)
    return results


async def _run_script_async(script: AgentScript, cfg: RunConfig) -> RunResult:
    """Thin async adapter so run_script can join an asyncio.gather group."""
    return await asyncio.to_thread(run_script, script, cfg)


async def run_all_parallel(
    scripts: list[AgentScript],
    cfg: RunConfig,
    stream: "object | None" = None,
) -> list[RunResult]:
    """Run all scripts concurrently and stream PASS/FAIL as each finishes."""
    out = stream if stream is not None else sys.stdout
    pending: dict[asyncio.Task[RunResult], AgentScript] = {
        asyncio.create_task(_run_script_async(s, cfg)): s for s in scripts
    }
    results: list[RunResult] = []
    while pending:
        done, _ = await asyncio.wait(
            pending.keys(), return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            del pending[task]
            result = task.result()
            print(_format_result_line(result), file=out, flush=True)
            results.append(result)
    # Preserve input order for the final summary.
    order = {script.path: idx for idx, script in enumerate(scripts)}
    results.sort(key=lambda r: order[r.script.path])
    return results


def _find_gateway_binary(repo_root: Path) -> Path | None:
    """Return the first existing aa-gateway binary under target/."""
    for candidate in (
        repo_root / "target" / "debug" / "aa-gateway",
        repo_root / "target" / "release" / "aa-gateway",
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _free_port() -> int:
    """Pick a free localhost TCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


class AutoGateway:
    """Context manager that spawns aa-gateway and tears it down on exit.

    Writes a temporary allow-all policy file, picks a free port, and
    starts the gateway as a subprocess. SIGTERM on exit; SIGKILL if the
    process refuses to leave within 5 seconds.
    """

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.proc: subprocess.Popen[bytes] | None = None
        self.policy_path: Path | None = None
        self.addr: str = ""

    def __enter__(self) -> "AutoGateway":
        binary = _find_gateway_binary(self.repo_root)
        if binary is None:
            raise RuntimeError(
                "aa-gateway binary not found under target/{debug,release}. "
                "Run `cargo build -p aa-gateway` from the repo root first."
            )
        port = _free_port()
        self.addr = f"127.0.0.1:{port}"

        fd, policy_str = tempfile.mkstemp(prefix="aa-allow-all-", suffix=".yaml")
        with os.fdopen(fd, "w") as policy_file:
            policy_file.write('version: "1"\nglobal:\n  default_action: allow\n')
        self.policy_path = Path(policy_str)

        self.proc = subprocess.Popen(
            [
                str(binary),
                "--policy",
                str(self.policy_path),
                "--listen",
                self.addr,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Brief sleep so the gateway has time to bind before fixtures connect.
        time.sleep(1.0)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.proc is not None:
            try:
                self.proc.send_signal(signal.SIGTERM)
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            except ProcessLookupError:
                pass
            self.proc = None
        if self.policy_path is not None:
            try:
                self.policy_path.unlink(missing_ok=True)
            except OSError:
                pass
            self.policy_path = None


def print_summary(results: list[RunResult]) -> int:
    """Emit final pass/fail tally and return the process exit code."""
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    print()
    print(f" Results: {passed} passed · {failed} failed")
    if failed:
        print()
        print(" Failed scripts:")
        for result in results:
            if result.passed:
                continue
            if result.timed_out:
                reason = f"timeout after {result.duration_ms} ms"
            else:
                reason = result.error or "exit non-zero"
            print(f"   {result.script.scenario}/{result.script.name}.py  — {reason}")
    return 0 if failed == 0 else 1


def _print_list_table(scripts: list[AgentScript]) -> None:
    """Render the --list dry-run table (Rich if available, plain otherwise)."""
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        print(f"  {'FRAMEWORK':<14}  {'SCENARIO':<20}  PATH")
        print(f"  {'---------':<14}  {'--------':<20}  ----")
        for script in scripts:
            print(
                f"  {script.framework:<14}  {script.scenario:<20}  {script.path.name}"
            )
        return

    console = Console()
    table = Table(show_header=True, header_style="bold")
    table.add_column("framework")
    table.add_column("scenario")
    table.add_column("script")
    for script in scripts:
        table.add_row(script.framework, script.scenario, script.path.name)
    console.print(table)


def _results_as_json(results: list[RunResult]) -> str:
    """Serialise results as a JSON array suitable for ``--json`` output."""
    payload = [
        {
            "script": str(r.script.path),
            "scenario": r.script.scenario,
            "framework": r.script.framework,
            "name": r.script.name,
            "passed": r.passed,
            "duration_ms": r.duration_ms,
            "exit_code": r.exit_code,
            "timed_out": r.timed_out,
            "error": r.error,
            "last_event": r.last_event,
        }
        for r in results
    ]
    return json.dumps(payload)


def _build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser matching the CLI documented in AAASM-1543."""
    parser = argparse.ArgumentParser(
        prog="run_agents.py",
        description="Run AI agent fixture scripts against a live aasm gateway.",
    )

    parser.add_argument(
        "-f", "--framework", action="append", default=[],
        choices=sorted(FRAMEWORK_PATTERNS.keys()),
        help="Framework filter (repeatable; OR within group).",
    )
    parser.add_argument(
        "-s", "--scenario", action="append", default=[], choices=SCENARIOS,
        help="Scenario filter (repeatable; OR within group).",
    )
    parser.add_argument(
        "--file", default=None,
        help='Glob match on filename stem, e.g. "*hierarchy*".',
    )

    parser.add_argument("--gateway-url", default="http://127.0.0.1:8080",
                        help="Gateway base URL.")
    parser.add_argument("--api-key", default="dev-key", help="API key.")
    parser.add_argument("--proxy-addr", default=None,
                        help="Proxy address for Layer 2 tests (optional).")
    parser.add_argument("--auto-gateway", action="store_true",
                        help="Spawn aa-gateway automatically; tear down on exit.")

    parser.add_argument("--parallel", action="store_true",
                        help="Run all scripts concurrently (default: sequential).")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Per-script timeout in seconds (default: 30).")
    parser.add_argument("--selftest", action="store_true",
                        help="Hermetic mode: no gateway required.")

    parser.add_argument("--list", dest="list_only", action="store_true",
                        help="Print matching scripts and exit (dry-run).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Stream each script's stdout.")
    parser.add_argument("--json", dest="json_out", action="store_true",
                        help="Emit machine-readable JSON results to stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 on full success, non-zero otherwise."""
    args = _build_arg_parser().parse_args(argv)

    root = Path(__file__).resolve().parent
    # python/ → agents/ → fixtures/ → tests/ → aa-integration-tests/ → repo root
    repo_root = root.parents[4]

    all_scripts = discover(root)
    selected = filter_scripts(
        all_scripts,
        args.framework or None,
        args.scenario or None,
        args.file,
    )

    if not selected:
        print("[run_agents] No matching scripts found.", file=sys.stderr)
        return 1

    if args.list_only:
        _print_list_table(selected)
        return 0

    if args.auto_gateway and args.selftest:
        print("[run_agents] --auto-gateway is incompatible with --selftest",
              file=sys.stderr)
        return 2

    cfg = RunConfig(
        timeout=args.timeout,
        gateway_url=args.gateway_url,
        api_key=args.api_key,
        proxy_addr=args.proxy_addr,
        selftest=args.selftest,
        verbose=args.verbose,
    )

    # Mirror run_agents_ts.sh: if no gateway is configured and the user did
    # not ask for --auto-gateway, fall back to selftest so the script is
    # never silently waiting on a missing gateway.
    if (
        not args.auto_gateway
        and not args.selftest
        and "AA_GATEWAY_ADDR" not in os.environ
        and args.gateway_url == "http://127.0.0.1:8080"
    ):
        cfg.selftest = True
        print("[run_agents] No gateway specified; running in --selftest mode.",
              file=sys.stderr)

    info_stream = sys.stderr if args.json_out else sys.stdout
    auto: AutoGateway | None = None
    try:
        if args.auto_gateway:
            auto = AutoGateway(repo_root)
            auto.__enter__()
            cfg.gateway_url = f"http://{auto.addr}"
            print(f"[run_agents] Gateway started on {auto.addr}", file=info_stream)

        header = (
            f" Running {len(selected)} agent scripts  "
            f"({'parallel' if args.parallel else 'sequential'} · "
            f"timeout {cfg.timeout}s)"
        )
        print(header, file=info_stream)
        print(file=info_stream)

        if args.parallel:
            results = asyncio.run(run_all_parallel(selected, cfg, info_stream))
        else:
            results = run_all_sequential(selected, cfg, info_stream)
    finally:
        if auto is not None:
            auto.__exit__(None, None, None)

    if args.json_out:
        print(_results_as_json(results))
        # Compute exit code without printing the human summary to stdout.
        failed = sum(1 for r in results if not r.passed)
        return 0 if failed == 0 else 1

    return print_summary(results)


if __name__ == "__main__":
    raise SystemExit(main())
