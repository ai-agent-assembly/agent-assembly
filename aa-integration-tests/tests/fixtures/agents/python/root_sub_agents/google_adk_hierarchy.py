"""Root + sub-agent Google ADK hierarchy fixture — F116 E2E acceptance (AAASM-1550).

Scenario: root_sub_agents / framework: google_adk
Root agent declares a child via `sub_agents=[child]`. Supports AA_TASK=crash
to exercise exception handling after deregister.
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
    child_id = cfg["agent_id"] + "-child"

    # init_assembly() supports one active context per process; root is shut down
    # before child is created so the child can re-init with its own agent_id.
    ctx_root = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=root_id,
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx_root.client.register_agent())
    emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "google_adk"})
    child_agent = Agent(name="child-agent", instruction="Execute task.")
    Agent(name="root-agent", instruction="Delegate to child.", sub_agents=[child_agent])
    ctx_root.shutdown()

    ctx_child = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=child_id,
        team_id="f116-e2e",
        parent_agent_id=root_id,
        mode="sdk-only",
    )
    asyncio.run(ctx_child.client.register_agent())
    emit(
        {"event": "started", "agent_id": child_id, "role": "child", "parent": root_id, "framework": "google_adk"}
    )

    if cfg["task"] == "crash":
        ctx_child.shutdown()
        emit({"event": "done", "result": "google_adk root_sub_agents crash-handled", "depth": 1})
        raise RuntimeError("simulated crash after deregister")

    emit({"event": "tool_call", "tool": "google_adk_hierarchy_tool", "input": cfg["task"]})
    ctx_child.shutdown()
    emit({"event": "done", "result": f"echo: {cfg['task']}", "depth": 1})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        root_id = cfg["agent_id"] + "-root"
        child_id = cfg["agent_id"] + "-child"
        emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "google_adk"})
        emit(
            {
                "event": "started",
                "agent_id": child_id,
                "role": "child",
                "parent": root_id,
                "framework": "google_adk",
            }
        )
        emit({"event": "tool_call", "tool": "google_adk_hierarchy_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok", "depth": 1})
        sys.exit(0)
    run_real(cfg)
