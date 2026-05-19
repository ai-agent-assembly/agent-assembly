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

    from crewai import Agent, Task
    from crewai.tools import BaseTool

    from agent_assembly import init_assembly

    ctx = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=cfg["agent_id"],
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx.client.register_agent())
    emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "crewai"})

    # Minimal CrewAI setup — init_assembly() patches BaseTool.run globally via
    # CrewAIPatch so governance hooks fire on every tool invocation.
    class EchoTool(BaseTool):
        name: str = "echo_tool"
        description: str = "Echo the input."

        def _run(self, **kwargs: object) -> str:
            return f"echo: {cfg['task']}"

    tool = EchoTool()
    agent = Agent(role="e2e-agent", goal="echo user input", backstory="E2E fixture agent")
    Task(description=cfg["task"], expected_output="echo result", agent=agent, tools=[tool])
    result = tool.run()  # exercises governance-patched BaseTool.run
    emit({"event": "tool_call", "tool": tool.name, "input": cfg["task"]})
    ctx.shutdown()
    emit({"event": "done", "result": str(result)})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "crewai"})
        emit({"event": "tool_call", "tool": "crewai_mock_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok"})
        sys.exit(0)
    run_real(cfg)
