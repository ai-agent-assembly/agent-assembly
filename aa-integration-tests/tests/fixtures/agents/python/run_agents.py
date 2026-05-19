#!/usr/bin/env python3
"""Run AI agent fixture scripts against a live aasm gateway.

Developer-facing CLI complement to the Rust E2E test harness. Discovers
Python fixture scripts under this directory, filters by framework /
scenario / glob, runs each subprocess with a timeout, and emits a summary.
"""

from __future__ import annotations

import fnmatch
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
