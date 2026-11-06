"""Python-SDK driver for the J08/J56 candidate harness (AAASM-6439).

Runs inside the clean venv the harness built, against the wheel under test. Every
op prints exactly one line `RESULT <json>` so the harness can parse it without
trusting anything else the SDK writes to stdout. The tool bodies do their side
effect on a sentinel path, which lets the harness observe "the forbidden action
did not happen" independently of what the SDK reports.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

TYPED = ("ToolExecutionBlockedError", "PolicyViolationError", "MCPToolBlockedError")


def emit(**fields):
    print("RESULT " + json.dumps(fields, sort_keys=True), flush=True)


def op_import_core(_a):
    import importlib.metadata as md

    import agent_assembly
    import agent_assembly._core  # noqa: F401  # the import is the check
    emit(ok=True, sdk_version=md.version("agent-assembly"), module=agent_assembly.__file__)


def _init(a):
    from agent_assembly import init_assembly

    return init_assembly(gateway_url=a.gateway_url, api_key=a.key, agent_id=a.agent, mode="sdk-only")


def op_register(a):
    ctx = _init(a)
    emit(registered=bool(getattr(ctx, "registered", False)), agent=a.agent)


def _body(tool, sentinel: Path):
    if tool == "delete_file":
        sentinel.unlink(missing_ok=True)
    elif tool == "send_email":
        Path(str(sentinel) + ".sent").write_text("sent\n")
    else:
        sentinel.read_text()


def op_call(a):
    from agent_assembly import exceptions as ex
    from agent_assembly.adapters.langchain.runtime import get_active_callback_handler

    _init(a)
    sentinel = Path(a.sentinel)
    handler = get_active_callback_handler()
    try:
        if not a.unwired:
            if handler is None:
                emit(executed=False, error="NoActiveHandler", typed=False, tool=a.tool)
                return
            # The call LangChain would make before running a tool.
            handler.on_tool_start({"name": a.tool}, "{}", run_id=uuid.uuid4())
        _body(a.tool, sentinel)
    except Exception as e:  # noqa: BLE001  # classified, never swallowed: the harness reads it
        typed = isinstance(e, ex.ToolExecutionBlockedError) or type(e).__name__ in TYPED
        emit(executed=False, error=type(e).__name__, typed=typed, message=str(e)[:200], tool=a.tool)
        return
    emit(executed=True, error=None, typed=False, tool=a.tool, unwired=a.unwired)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("op", choices=["import-core", "register", "call"])
    ap.add_argument("--gateway-url")
    ap.add_argument("--key")
    ap.add_argument("--agent")
    ap.add_argument("--tool")
    ap.add_argument("--sentinel")
    ap.add_argument("--unwired", action="store_true")
    a = ap.parse_args()
    try:
        {"import-core": op_import_core, "register": op_register, "call": op_call}[a.op](a)
    except Exception as e:  # noqa: BLE001
        emit(ok=False, registered=False, executed=False, error=type(e).__name__, typed=False, message=str(e)[:200])
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
