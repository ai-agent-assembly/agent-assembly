"""Two-agent LangChain team fixture — F116 E2E acceptance (AAASM-1513).

Scenario: agent_team / framework: langchain
Registers a root agent + one team member in the same process.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _shared import emit, load_config


def run_real(cfg: dict) -> None:
    import asyncio

    from langchain_core.language_models.fake import FakeListLLM
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import PromptTemplate

    from agent_assembly import init_assembly
    from agent_assembly.adapters.langchain import get_active_callback_handler

    root_id = cfg["agent_id"] + "-root"
    member_id = cfg["agent_id"] + "-member"

    # init_assembly() supports one active context per process; each agent context is
    # shut down before the next is created so the global context slot is free.
    ctx_root = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=root_id,
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx_root.client.register_agent())
    emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "langchain"})
    root_chain = PromptTemplate.from_template("{input}") | FakeListLLM(responses=["root-done"]) | StrOutputParser()
    handler = get_active_callback_handler()
    root_chain.invoke({"input": cfg["task"]}, config={"callbacks": [handler]} if handler else {})
    ctx_root.shutdown()

    ctx_member = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=member_id,
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx_member.client.register_agent())
    emit({"event": "started", "agent_id": member_id, "role": "member", "framework": "langchain"})
    member_chain = PromptTemplate.from_template("{input}") | FakeListLLM(responses=["member-done"]) | StrOutputParser()
    handler = get_active_callback_handler()
    member_chain.invoke({"input": cfg["task"]}, config={"callbacks": [handler]} if handler else {})
    emit({"event": "tool_call", "tool": "langchain_team_tool", "input": cfg["task"]})
    ctx_member.shutdown()
    emit({"event": "done", "result": "langchain agent_team", "agent_count": 2})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        root_id = cfg["agent_id"] + "-root"
        member_id = cfg["agent_id"] + "-member"
        emit({"event": "started", "agent_id": root_id, "role": "root", "framework": "langchain"})
        emit({"event": "started", "agent_id": member_id, "role": "member", "framework": "langchain"})
        emit({"event": "tool_call", "tool": "langchain_team_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok", "agent_count": 2})
        sys.exit(0)
    run_real(cfg)
