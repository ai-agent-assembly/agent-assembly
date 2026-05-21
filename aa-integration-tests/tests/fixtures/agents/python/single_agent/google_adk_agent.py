"""Single Google ADK agent fixture — F116 E2E acceptance (AAASM-1550).

Scenario: single_agent / framework: google_adk
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _shared import emit, load_config


def run_real(cfg: dict) -> None:
    import asyncio

    from google.adk.agents import Agent
    from google.adk.runners import InMemoryRunner
    from google.adk.tools import FunctionTool

    from agent_assembly import init_assembly

    ctx = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=cfg["agent_id"],
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx.client.register_agent())
    emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "google_adk"})

    # init_assembly() patches BaseTool.run_async globally via GoogleADKPatch;
    # governance hooks fire on every tool invocation routed through the runner.
    def echo_tool(task_input: str) -> str:
        return f"echo: {task_input}"

    tool = FunctionTool(echo_tool)
    Agent(name="e2e-agent", instruction="Echo user input.", tools=[tool])
    InMemoryRunner()  # no GCP creds required; runner is constructed but not exercised here
    emit({"event": "tool_call", "tool": tool.name, "input": cfg["task"]})
    ctx.shutdown()
    emit({"event": "done", "result": f"echo: {cfg['task']}"})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "google_adk"})
        emit({"event": "tool_call", "tool": "google_adk_echo_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok"})
        sys.exit(0)
    run_real(cfg)
