"""Two-agent LangGraph team fixture — F116 E2E acceptance (AAASM-1513).

Scenario: agent_team / framework: langgraph
Registers a root agent + one team member in the same process.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _shared import emit, load_config


def run_real(cfg: dict) -> None:
    import asyncio

    from agent_assembly import init_assembly

    root_id = cfg["agent_id"] + "-root"
    member_id = cfg["agent_id"] + "-member"

    ctx_root = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=root_id,
        team_id="f116-e2e",
        mode="sdk-only",
    )
    emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "langgraph"})
    asyncio.run(ctx_root.client.register_agent())

    ctx_member = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=member_id,
        team_id="f116-e2e",
        mode="sdk-only",
    )
    emit({"event": "started", "agent_id": member_id, "role": "member", "framework": "langgraph"})
    asyncio.run(ctx_member.client.register_agent())

    emit({"event": "tool_call", "tool": "langgraph_team_tool", "input": cfg["task"]})
    ctx_member.shutdown()
    ctx_root.shutdown()
    emit({"event": "done", "result": "langgraph agent_team", "agent_count": 2})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        root_id = cfg["agent_id"] + "-root"
        member_id = cfg["agent_id"] + "-member"
        emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "langgraph"})
        emit({"event": "started", "agent_id": member_id, "role": "member", "framework": "langgraph"})
        emit({"event": "tool_call", "tool": "langgraph_team_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok", "agent_count": 2})
        sys.exit(0)
    run_real(cfg)
