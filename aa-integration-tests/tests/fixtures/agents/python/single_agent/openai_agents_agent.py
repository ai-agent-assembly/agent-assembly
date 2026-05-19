"""Single OpenAI Agents SDK fixture — F116 E2E acceptance (AAASM-1513).

Scenario: single_agent / framework: openai_agents
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _shared import emit, load_config


def run_real(cfg: dict) -> None:
    import asyncio
    from types import SimpleNamespace

    from openai.agents import Agent, function_tool

    from agent_assembly import init_assembly

    ctx = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=cfg["agent_id"],
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx.client.register_agent())
    emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "openai_agents"})

    # init_assembly() patches FunctionTool.__call__ globally via OpenAIAgentsPatch;
    # governance hooks fire on every direct tool invocation.
    @function_tool
    def echo_tool(task_input: str) -> str:
        """Echo the task input."""
        return f"echo: {task_input}"

    Agent(name="e2e-agent", instructions="Echo user input.", tools=[echo_tool])

    # Call tool directly — Runner.run requires an OpenAI API key; direct invocation
    # exercises the patched FunctionTool.__call__ without an LLM round-trip.
    tool_ctx = SimpleNamespace(agent_id=cfg["agent_id"])
    result = asyncio.run(echo_tool(tool_ctx, cfg["task"]))
    emit({"event": "tool_call", "tool": echo_tool.name, "input": cfg["task"]})
    ctx.shutdown()
    emit({"event": "done", "result": str(result)})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "openai_agents"})
        emit({"event": "tool_call", "tool": "openai_agents_echo_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok"})
        sys.exit(0)
    run_real(cfg)
