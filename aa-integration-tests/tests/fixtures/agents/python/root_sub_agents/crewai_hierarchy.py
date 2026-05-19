"""Root + sub-agent CrewAI hierarchy fixture — F116 E2E acceptance (AAASM-1513).

Scenario: root_sub_agents / framework: crewai
Root agent spawns a child sub-agent. Supports AA_TASK=crash to test exception handling.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _shared import emit, load_config


def run_real(cfg: dict) -> None:
    import asyncio

    from crewai import Agent, Task
    from crewai.tools import BaseTool

    from agent_assembly import init_assembly

    root_id = cfg["agent_id"] + "-root"
    child_id = cfg["agent_id"] + "-child"

    # init_assembly() supports one active context per process; root is shut down
    # before child is created so the child can re-init with its own agent_id.
    class HierarchyTool(BaseTool):
        name: str = "crewai_hierarchy_tool"
        description: str = "Hierarchy tool for root/child delegation."

        def _run(self, **kwargs: object) -> str:
            return f"echo: {cfg['task']}"

    ctx_root = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=root_id,
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx_root.client.register_agent())
    emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "crewai"})
    root_agent = Agent(role="root-agent", goal="orchestrate child", backstory="Root E2E fixture")
    Task(description=cfg["task"], expected_output="delegation result", agent=root_agent, tools=[HierarchyTool()])
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
    emit({"event": "started", "agent_id": child_id, "role": "child", "parent": root_id, "framework": "crewai"})

    if cfg["task"] == "crash":
        ctx_child.shutdown()
        emit({"event": "done", "result": "crewai root_sub_agents crash-handled", "depth": 1})
        raise RuntimeError("simulated crash after deregister")

    tool = HierarchyTool()
    child_agent = Agent(role="child-agent", goal="execute task", backstory="Child E2E fixture")
    Task(description=cfg["task"], expected_output="echo result", agent=child_agent, tools=[tool])
    result = tool.run()  # exercises governance-patched BaseTool.run
    emit({"event": "tool_call", "tool": tool.name, "input": cfg["task"]})
    ctx_child.shutdown()
    emit({"event": "done", "result": str(result), "depth": 1})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        root_id = cfg["agent_id"] + "-root"
        child_id = cfg["agent_id"] + "-child"
        emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "crewai"})
        emit({"event": "started", "agent_id": child_id, "role": "child", "parent": root_id, "framework": "crewai"})
        emit({"event": "tool_call", "tool": "crewai_hierarchy_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok", "depth": 1})
        sys.exit(0)
    run_real(cfg)
