"""Root + sub-agent LangGraph hierarchy fixture — F116 E2E acceptance (AAASM-1513).

Scenario: root_sub_agents / framework: langgraph
Root agent spawns a child sub-agent and delegates a task.
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
    child_id = cfg["agent_id"] + "-child"

    class State(TypedDict):
        task: str
        result: str

    def process_node(state: State) -> dict[str, str]:
        return {"task": state["task"], "result": f"processed: {state['task']}"}

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
    emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "langgraph"})
    root_graph = StateGraph(State)
    root_graph.add_node("process", process_node)
    root_graph.set_entry_point("process")
    root_graph.add_edge("process", END)
    root_graph.compile().invoke({"task": cfg["task"], "result": ""})
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
    emit({"event": "started", "agent_id": child_id, "role": "child", "parent": root_id, "framework": "langgraph"})
    child_graph = StateGraph(State)
    child_graph.add_node("process", process_node)
    child_graph.set_entry_point("process")
    child_graph.add_edge("process", END)
    child_graph.compile().invoke({"task": cfg["task"], "result": ""})
    emit({"event": "tool_call", "tool": "langgraph_hierarchy_tool", "input": cfg["task"]})
    ctx_child.shutdown()
    emit({"event": "done", "result": "langgraph root_sub_agents", "depth": 1})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        root_id = cfg["agent_id"] + "-root"
        child_id = cfg["agent_id"] + "-child"
        emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "langgraph"})
        emit({"event": "started", "agent_id": child_id, "role": "child", "parent": root_id, "framework": "langgraph"})
        emit({"event": "tool_call", "tool": "langgraph_hierarchy_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok", "depth": 1})
        sys.exit(0)
    run_real(cfg)
