#!/usr/bin/env python3
"""Run AI agent fixture scripts against a live aasm gateway.

Developer-facing CLI complement to the Rust E2E test harness. Discovers
Python fixture scripts under this directory, filters by framework /
scenario / glob, runs each subprocess with a timeout, and emits a summary.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import subprocess
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
            ["uv", "run", "--extra", "runner", "--extra", "all", str(rel_path)],
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
    scripts: list[AgentScript], cfg: RunConfig
) -> list[RunResult]:
    """Run scripts one at a time, printing PASS/FAIL after each."""
    results: list[RunResult] = []
    for script in scripts:
        result = run_script(script, cfg)
        print(_format_result_line(result), flush=True)
        results.append(result)
    return results


async def _run_script_async(script: AgentScript, cfg: RunConfig) -> RunResult:
    """Thin async adapter so run_script can join an asyncio.gather group."""
    return await asyncio.to_thread(run_script, script, cfg)


async def run_all_parallel(
    scripts: list[AgentScript], cfg: RunConfig
) -> list[RunResult]:
    """Run all scripts concurrently and stream PASS/FAIL as each finishes."""
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
            print(_format_result_line(result), flush=True)
            results.append(result)
    # Preserve input order for the final summary.
    order = {script.path: idx for idx, script in enumerate(scripts)}
    results.sort(key=lambda r: order[r.script.path])
    return results
