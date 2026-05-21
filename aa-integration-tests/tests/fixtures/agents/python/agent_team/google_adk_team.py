"""Two-agent Google ADK team fixture — F116 E2E acceptance (AAASM-1550).

Scenario: agent_team / framework: google_adk
Registers a root agent + one team member in the same process, sequentially.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _shared import emit, load_config


def run_real(cfg: dict) -> None:
    import asyncio

    from google.adk.agents import Agent

    from agent_assembly import init_assembly

    root_id = cfg["agent_id"] + "-root"
    member_id = cfg["agent_id"] + "-member"

    # init_assembly() supports one active context per process; each agent's
    # context is shut down before the next is created so the global slot is free.
    ctx_root = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=root_id,
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx_root.client.register_agent())
    emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "google_adk"})
    Agent(name="root-agent", instruction="Coordinate team.")
    ctx_root.shutdown()

    ctx_member = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=member_id,
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx_member.client.register_agent())
    emit({"event": "started", "agent_id": member_id, "role": "member", "framework": "google_adk"})
    Agent(name="member-agent", instruction="Execute member task.")
    emit({"event": "tool_call", "tool": "google_adk_team_tool", "input": cfg["task"]})
    ctx_member.shutdown()
    emit({"event": "done", "result": "google_adk agent_team", "agent_count": 2})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        root_id = cfg["agent_id"] + "-root"
        member_id = cfg["agent_id"] + "-member"
        emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "google_adk"})
        emit({"event": "started", "agent_id": member_id, "role": "member", "framework": "google_adk"})
        emit({"event": "tool_call", "tool": "google_adk_team_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok", "agent_count": 2})
        sys.exit(0)
    run_real(cfg)
