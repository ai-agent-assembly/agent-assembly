"""Single CrewAI agent fixture — F116 E2E acceptance (AAASM-1513).

Scenario: single_agent / framework: crewai
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _shared import emit, load_config


def run_real(cfg: dict) -> None:
    import asyncio

    from agent_assembly import init_assembly

    ctx = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=cfg["agent_id"],
        team_id="f116-e2e",
        mode="sdk-only",
    )
    emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "crewai"})

    try:
        asyncio.run(ctx.client.register_agent())
        emit({"event": "tool_call", "tool": "crewai_mock_tool", "input": cfg["task"]})
    finally:
        ctx.shutdown()

    emit({"event": "done", "result": f"crewai single_agent {cfg['agent_id']}"})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "crewai"})
        emit({"event": "tool_call", "tool": "crewai_mock_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok"})
        sys.exit(0)
    run_real(cfg)
