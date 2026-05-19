#!/usr/bin/env python3
"""Run AI agent fixture scripts against a live aasm gateway.

Developer-facing CLI complement to the Rust E2E test harness. Discovers
Python fixture scripts under this directory, filters by framework /
scenario / glob, runs each subprocess with a timeout, and emits a summary.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
