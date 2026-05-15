#!/usr/bin/env python3
"""Topology integration-test Python driver (AAASM-1078 / ST-2).

Spawned by the Rust harness (see ``tests/common/sdk_driver.rs``). Uses the
Python SDK to register a parent agent, builds a 2-node LangGraph
(``parent_node`` -> ``child_node``), and emits the resulting agent IDs as
JSON for the Rust assertions module to consume.

Usage::

    AAASM_GATEWAY_URL=http://127.0.0.1:PORT \\
    AAASM_API_KEY=test-key \\
        python3 sdk_driver.py

    python3 sdk_driver.py --selftest   # hermetic, no Rust required

The package name in the real Python SDK is ``agent_assembly`` (the ticket
text uses ``aa_sdk`` as a placeholder; the published package on PyPI will
also be ``agent-assembly``). See
``python-sdk/agent_assembly/__init__.py``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

# Constant team id used end-to-end by ST-3's assertions.
TEAM_ID = "topology-it"

# Path the Rust harness reads on failure to inspect the agent IDs the driver
# observed before exit.
RECOVERY_FILE = Path(tempfile.gettempdir()) / "aa-topology-it-agents.json"


def _emit(agent_ids: dict[str, str]) -> None:
    """Print agent IDs as JSON to stdout and write a recovery file."""
    payload = json.dumps(agent_ids)
    print(payload)
    sys.stdout.flush()
    try:
        RECOVERY_FILE.write_text(payload + "\n", encoding="utf-8")
    except OSError as exc:
        # The recovery file is a debugging aid; failure to write it should
        # not fail the run.
        print(f"warning: could not write recovery file: {exc}", file=sys.stderr)


def _run_real(gateway_url: str, api_key: str) -> int:
    """Real mode: drive the published ``agent_assembly`` SDK against a live gateway."""
    import agent_assembly  # noqa: F401  (verifies install)
    from agent_assembly import init_assembly
    from langgraph.graph import StateGraph

    parent_ctx = init_assembly(
        gateway_url=gateway_url,
        api_key=api_key,
        team_id=TEAM_ID,
        mode="sdk-only",
    )
    parent_agent_id = parent_ctx.agent_id

    # Minimal 2-node graph: parent → child. The framework hook installed by
    # ``init_assembly`` registers the child agent on its first node entry.
    def parent_node(state: dict[str, Any]) -> dict[str, Any]:
        state["seen_by_parent"] = True
        return state

    def child_node(state: dict[str, Any]) -> dict[str, Any]:
        # Spawn a child Assembly context inside the child node so the SDK
        # records the parent → child edge.
        child_ctx = init_assembly(
            gateway_url=gateway_url,
            api_key=api_key,
            team_id=TEAM_ID,
            parent_agent_id=parent_agent_id,
            mode="sdk-only",
        )
        state["child_agent_id"] = child_ctx.agent_id
        return state

    graph = StateGraph(dict)
    graph.add_node("parent_node", parent_node)
    graph.add_node("child_node", child_node)
    graph.set_entry_point("parent_node")
    graph.add_edge("parent_node", "child_node")
    graph.set_finish_point("child_node")

    result = graph.compile().invoke({})
    child_agent_id = result["child_agent_id"]

    _emit({"parent_agent_id": parent_agent_id, "child_agent_id": child_agent_id})
    return 0


def _run_selftest() -> int:
    """Hermetic selftest: skip SDK init + LangGraph, emit synthetic IDs.

    The Rust harness only checks that ``--selftest`` exits 0 with the JSON
    contract intact; this lets ST-2 ship without requiring a venv, the
    real SDK install, or a running gateway.
    """
    parent_agent_id = f"selftest-parent-{uuid.uuid4().hex[:8]}"
    child_agent_id = f"selftest-child-{uuid.uuid4().hex[:8]}"
    _emit({"parent_agent_id": parent_agent_id, "child_agent_id": child_agent_id})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AAASM topology integration-test driver.")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Run in hermetic mode without contacting a gateway or installing the SDK.",
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return _run_selftest()

    gateway_url = os.environ.get("AAASM_GATEWAY_URL")
    api_key = os.environ.get("AAASM_API_KEY", "topology-it-test-key")
    if not gateway_url:
        print(
            "error: AAASM_GATEWAY_URL env var is required in real mode (use --selftest for hermetic runs)",
            file=sys.stderr,
        )
        return 2

    return _run_real(gateway_url, api_key)


if __name__ == "__main__":
    sys.exit(main())
