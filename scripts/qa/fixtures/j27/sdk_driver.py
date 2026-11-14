"""Python-SDK driver for the J27 scrub-or-deny lane (AAASM-6469).

Runs inside the clean venv the lane built, against the wheel under test. It prints
exactly one line `RESULT <json>` so the lane never has to trust anything else the SDK
writes. The tool body's side effect is a sentinel file, which lets the lane observe
"the tool body never ran" independently of what the SDK reports.

The tool arguments are passed to the SDK's own LangChain pre-execution hook, the call
LangChain makes before it runs a tool, so the decision path under test is the real one:
SDK -> native shim -> runtime socket -> gateway.
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    ap.add_argument("--control-plane-url", required=True, help="an unused loopback URL: this lane has no REST control plane")
    ap.add_argument("--key", required=True, help="a syntactically valid throwaway key, not a credential")
    ap.add_argument("--tool", required=True)
    ap.add_argument("--args-file", required=True, help="file holding the JSON tool arguments; keeps a value off argv")
    ap.add_argument("--sentinel", required=True)
    a = ap.parse_args()

    try:
        from agent_assembly import exceptions as ex
        from agent_assembly import init_assembly
        from agent_assembly.adapters.langchain.runtime import get_active_callback_handler

        # Registration and the policy check both go over the native shim, which resolves the runtime socket and
        # the gateway gRPC endpoint from AA_RUNTIME_SOCKET / AA_GATEWAY_ENDPOINT. The URL is passed explicitly
        # only so the SDK does not probe, or auto-start, whatever `aasm` is installed on the host.
        ctx = init_assembly(gateway_url=a.control_plane_url, api_key=a.key, agent_id=a.agent, mode="sdk-only",
                            enforcement_mode="enforce")
        handler = get_active_callback_handler()
        if handler is None:
            emit(executed=False, error="NoActiveHandler", typed=False, tool=a.tool)
            return 0
        input_str = Path(a.args_file).read_text()
        try:
            handler.on_tool_start({"name": a.tool}, input_str, run_id=uuid.uuid4())
            Path(a.sentinel).write_text("tool body ran\n")  # the tool body
        except Exception as e:  # noqa: BLE001  # classified, never swallowed: the lane reads it
            typed = isinstance(e, ex.ToolExecutionBlockedError) or type(e).__name__ in TYPED
            emit(executed=False, error=type(e).__name__, typed=typed, message=_scrub(str(e), input_str), tool=a.tool,
                 registered=bool(getattr(ctx, "registered", False)))
            return 0
        emit(executed=True, error=None, typed=False, tool=a.tool, registered=bool(getattr(ctx, "registered", False)))
    except Exception as e:  # noqa: BLE001
        emit(executed=False, error=type(e).__name__, typed=False, message=str(e)[:200], init_failed=True)
    return 0


def _scrub(message: str, input_str: str) -> str:
    """Never echo the secret-bearing arguments, even if an error message quoted them."""
    return message.replace(input_str, "<args>")[:200]


if __name__ == "__main__":
    sys.exit(main())
