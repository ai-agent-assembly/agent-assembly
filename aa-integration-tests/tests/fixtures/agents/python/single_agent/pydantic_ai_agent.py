"""Single Pydantic AI agent fixture — F116 E2E acceptance (AAASM-1513).

Scenario: single_agent / framework: pydantic_ai
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _shared import emit, load_config


def run_real(cfg: dict) -> None:
    import asyncio

    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel

    from agent_assembly import init_assembly

    ctx = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=cfg["agent_id"],
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx.client.register_agent())
    emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "pydantic_ai"})

    # TestModel drives the agent without an LLM API key. init_assembly() patches
    # Tool._run globally via PydanticAIPatch so governance hooks fire on every
    # tool invocation that Agent.run_sync triggers.
    agent: Agent[None, str] = Agent(TestModel(), system_prompt="Echo the user task.")

    @agent.tool_plain
    def echo_tool(task_input: str) -> str:
        return f"echo: {task_input}"

    result = agent.run_sync(cfg["task"])
    emit({"event": "tool_call", "tool": "echo_tool", "input": cfg["task"]})
    ctx.shutdown()
    emit({"event": "done", "result": str(result.output)})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "pydantic_ai"})
        emit({"event": "tool_call", "tool": "pydantic_ai_echo_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok"})
        sys.exit(0)
    run_real(cfg)
