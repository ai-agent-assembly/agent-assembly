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
    from typing import TypedDict

    from langgraph.graph import END, StateGraph

    from agent_assembly import init_assembly

    root_id = cfg["agent_id"] + "-root"
    member_id = cfg["agent_id"] + "-member"

    class State(TypedDict):
        task: str
        result: str

    def process_node(state: State) -> dict[str, str]:
        return {"task": state["task"], "result": f"processed: {state['task']}"}

    # init_assembly() supports one active context per process; each agent context is
    # shut down before the next is created so the global context slot is free.
    for agent_id, role in [(root_id, "root"), (member_id, "member")]:
        ctx = init_assembly(
            gateway_url=cfg["gateway_addr"],
            api_key="e2e-test-key",
            agent_id=agent_id,
            team_id="f116-e2e",
            mode="sdk-only",
        )
        asyncio.run(ctx.client.register_agent())
        emit({"event": "started", "agent_id": agent_id, "role": role, "framework": "langgraph"})
        # StateGraph.compile() is patched by LangGraphPatch; node wrappers fire governance hooks.
        graph = StateGraph(State)
        graph.add_node("process", process_node)
        graph.set_entry_point("process")
        graph.add_edge("process", END)
        graph.compile().invoke({"task": cfg["task"], "result": ""})
        ctx.shutdown()

    emit({"event": "tool_call", "tool": "langgraph_team_tool", "input": cfg["task"]})
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
