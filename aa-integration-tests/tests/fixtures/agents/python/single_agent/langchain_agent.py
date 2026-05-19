"""Single LangChain agent fixture — F116 E2E acceptance (AAASM-1513).

Scenario: single_agent / framework: langchain
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

    ctx = init_assembly(
        gateway_url=cfg["gateway_addr"],
        api_key="e2e-test-key",
        agent_id=cfg["agent_id"],
        team_id="f116-e2e",
        mode="sdk-only",
    )
    asyncio.run(ctx.client.register_agent())
    emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "langchain"})

    # Minimal LCEL chain with FakeListLLM — no real API key needed.
    # init_assembly() wires AssemblyCallbackHandler via LangChainPatch; passing it
    # as a callback here exercises the governance hook path on chain invocation.
    llm = FakeListLLM(responses=[f"Result: {cfg['task']}"])
    chain = PromptTemplate.from_template("{input}") | llm | StrOutputParser()
    handler = get_active_callback_handler()
    result = chain.invoke(
        {"input": cfg["task"]},
        config={"callbacks": [handler]} if handler else {},
    )
    emit({"event": "tool_call", "tool": "langchain_chain_invoke", "input": cfg["task"]})
    ctx.shutdown()
    emit({"event": "done", "result": result})


if __name__ == "__main__":
    cfg = load_config()
    if os.environ.get("AA_SELFTEST") == "1":
        emit({"event": "started", "agent_id": cfg["agent_id"], "framework": "langchain"})
        emit({"event": "tool_call", "tool": "langchain_mock_tool", "input": ""})
        emit({"event": "done", "result": "selftest-ok"})
        sys.exit(0)
    run_real(cfg)
