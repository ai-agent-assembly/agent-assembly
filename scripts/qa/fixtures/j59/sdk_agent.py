"""The ungoverned-by-construction agent of the J59 live-agent rows (AAASM-6439).

Runs in the clean venv the harness built, against the wheel under test. This file is the
"agent application": it is byte-identical for every policy version and every agent id the
harness runs it as, which is what lets step 12 say a behaviour change needed no agent change.
It contains no policy logic. Every op prints exactly one `RESULT <json>` line.
"""
from __future__ import annotations

import argparse
import inspect
import json
import sys
import uuid
from pathlib import Path

TYPED = ("ToolExecutionBlockedError", "PolicyViolationError", "MCPToolBlockedError")


def emit(**fields):
    print("RESULT " + json.dumps(fields, sort_keys=True), flush=True)


def _init(a):
    from agent_assembly import init_assembly

    kw = {"team_id": a.team} if a.team else {}
    if a.org:
        kw["org_id"] = a.org  # only passed when asked: the SDK may not accept it (see op_org_probe)
    if a.registration_key_file:
        # The operator key the gateway binds to an organization. Read from a file the harness wrote owner-only, so the
        # secret is never on a command line or in a transcript.
        kw["registration_key"] = Path(a.registration_key_file).read_text().strip()
    return init_assembly(gateway_url=a.gateway_url, api_key=a.key, agent_id=a.agent, mode="sdk-only", **kw)


def op_import_core(_a):
    import importlib.metadata as md

    import agent_assembly._core  # noqa: F401  # the import is the check

    emit(ok=True, sdk_version=md.version("agent-assembly"))


def op_register(a):
    emit(registered=bool(getattr(_init(a), "registered", False)), agent=a.agent, team=a.team)


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
        if handler is None:
            emit(executed=False, error="NoActiveHandler", typed=False, tool=a.tool)
            return
        # The call LangChain makes before it runs a tool; the agent code below it is the unchanged tool body.
        handler.on_tool_start({"name": a.tool}, "{}", run_id=uuid.uuid4())
        _body(a.tool, sentinel)
    except Exception as e:  # noqa: BLE001  # classified, never swallowed: the harness reads it
        typed = isinstance(e, ex.ToolExecutionBlockedError) or type(e).__name__ in TYPED
        emit(executed=False, error=type(e).__name__, typed=typed, message=str(e)[:200], tool=a.tool)
        return
    emit(executed=True, error=None, typed=False, tool=a.tool)


def op_org_probe(a):
    """Can the SDK carry an org at all? Reads the public signature, then tries the documented call."""
    from agent_assembly import init_assembly

    params = list(inspect.signature(init_assembly).parameters)
    attempt = {}
    try:
        init_assembly(gateway_url=a.gateway_url, api_key=a.key, agent_id=a.agent, mode="sdk-only", org_id="acme")
        attempt = {"accepted": True}
    except Exception as e:  # noqa: BLE001  # the exception type is the evidence
        attempt = {"accepted": False, "error": type(e).__name__, "message": str(e)[:160]}
    emit(params=params, has_org_param="org_id" in params, has_team_param="team_id" in params, **{"org_attempt": attempt})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("op", choices=["import-core", "register", "call", "org-probe"])
    ap.add_argument("--gateway-url")
    ap.add_argument("--key")
    ap.add_argument("--agent")
    ap.add_argument("--team")
    ap.add_argument("--org")
    ap.add_argument("--registration-key-file")
    ap.add_argument("--unwired", action="store_true")  # accepted so the J56 check helpers can drive this agent; unused
    ap.add_argument("--tool")
    ap.add_argument("--sentinel")
    a = ap.parse_args()
    try:
        {"import-core": op_import_core, "register": op_register, "call": op_call, "org-probe": op_org_probe}[a.op](a)
    except Exception as e:  # noqa: BLE001
        emit(ok=False, registered=False, executed=False, error=type(e).__name__, typed=False, message=str(e)[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
