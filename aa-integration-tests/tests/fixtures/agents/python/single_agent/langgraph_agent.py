"""Single LangGraph agent fixture — F116 E2E acceptance (AAASM-1513).

Scenario: single_agent / framework: langgraph
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

    ctx = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=cfg["agent_id"],
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx.client.register_agent())
    emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "langgraph"})

    # Minimal StateGraph — init_assembly() patches StateGraph.compile() via
    # LangGraphPatch so node wrappers fire governance hooks on every invocation.
    class State(TypedDict):
        task: str
        result: str

    def process_node(state: State) -> dict[str, str]:
        return {"task": state["task"], "result": f"processed: {state['task']}"}

    graph = StateGraph(State)
    graph.add_node("process", process_node)
    graph.set_entry_point("process")
    graph.add_edge("process", END)
    output = graph.compile().invoke({"task": cfg["task"], "result": ""})
    emit({"event": "tool_call", "tool": "langgraph_process_node", "input": cfg["task"]})
    ctx.shutdown()
    emit({"event": "done", "result": output["result"]})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "langgraph"})
        emit({"event": "tool_call", "tool": "langgraph_mock_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok"})
        sys.exit(0)
    run_real(cfg)
