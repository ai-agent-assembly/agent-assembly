"""Per-example enforcement control for the J08 framework matrix (AAASM-6439).

Runs with the example's own venv interpreter. It loads the example's `src.policy`, finds
its client-side policy engine and shows, with a real side effect (a sentinel file), that
the effect occurs when nothing governs it and is absent when the engine denies it. It
covers the example's LocalPolicyEngine wiring only, not gateway policy (that is J56).

The examples disagree on how `check_tool_start` is called (`serialized=` vs `tool_name=`)
and on which tool names they deny, so both are probed instead of hard-coded per example.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import json
import sys
import uuid
from pathlib import Path

DENY_DEFAULTS = ["send_http_request", "write_to_disk", "write_file", "delete_files", "delete_file", "shell", "execute_code"]
# Some engines (the LangChain research example) deny by what a tool is asked to do, not by its name,
# so a denying input is probed with an allowed tool when no tool name is denied.
DENY_INPUTS = ['{"url": "https://evil.example.net/exfil"}', "api_key=sk-AAAAAAAAAAAAAAAAAAAAAAAA"]
ALLOW_DEFAULTS = ["compute_sum", "fetch_stock_price", "read_file", "search", "web_search", "calculator"]


def emit(**f):
    print("RESULT " + json.dumps(f, sort_keys=True), flush=True)


def find_engine(mod):
    cands = [o for o in vars(mod).values() if inspect.isclass(o) and o.__module__ == mod.__name__
             and callable(getattr(o, "check_tool_start", None))]
    cands.sort(key=lambda o: (o.__name__ != "LocalPolicyEngine", o.__name__))
    return cands[0] if cands else None


def verdict(cls, conv, tool, inp="{}"):
    try:
        eng = cls()  # fresh per probe: budget-style engines keep state between calls
        if conv == "serialized":
            r = eng.check_tool_start(serialized={"name": tool, "type": "tool"}, input_str=inp, run_id=uuid.uuid4())
        else:
            r = eng.check_tool_start(tool_name=tool, input_str=inp)
        if inspect.isawaitable(r):  # the async adapters (Google ADK, Microsoft Agent Framework, Pydantic AI)
            r = asyncio.run(r)
    except Exception:  # noqa: BLE001  # a convention that does not fit is skipped, not fatal
        return None
    if isinstance(r, dict):
        return r.get("status")
    return getattr(r, "status", None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--example-dir", required=True)
    ap.add_argument("--sentinel-dir", required=True)
    a = ap.parse_args()
    sys.path.insert(0, a.example_dir)
    try:
        mod = importlib.import_module("src.policy")
    except Exception as e:  # noqa: BLE001
        emit(error="policy-import-failed", message=f"{type(e).__name__}: {e}"[:200])
        return 0
    cls = find_engine(mod)
    if cls is None:
        emit(error="no-engine-with-check_tool_start")
        return 0
    deny = (sorted(getattr(mod, "DENIED_TOOLS", ())) + sorted(getattr(mod, "PENDING_TOOLS", ()))
            + sorted(getattr(mod, "APPROVAL_REQUIRED_TOOLS", ())) + DENY_DEFAULTS)
    allow = list(getattr(mod, "TOOL_COSTS", {})) + ALLOW_DEFAULTS
    d = deny_inp = None
    for conv in ("serialized", "tool_name"):
        ok = next((t for t in allow if verdict(cls, conv, t) == "allow"), None)
        d = next((t for t in deny if verdict(cls, conv, t) in ("deny", "pending")), None)
        deny_inp = "{}"
        if d is None and ok:
            # Denial by input: the same allowed tool, asked to do something the policy forbids.
            deny_inp = next((i for i in DENY_INPUTS if verdict(cls, conv, ok, i) in ("deny", "pending")), None)
            d = ok if deny_inp else None
        if d and ok and deny_inp:
            break
    else:
        emit(error="no-denied-and-allowed-tool-found", engine=cls.__name__)
        return 0
    sd = Path(a.sentinel_dir)

    def body(name):
        (sd / f"{name}.sentinel").write_text("executed\n")

    body("ungoverned")  # control: the effect exists when nothing governs it
    if verdict(cls, conv, d, deny_inp) == "allow":
        body("denied")
    if verdict(cls, conv, ok) == "allow":
        body("allowed")
    emit(engine=cls.__name__, convention=conv, deny_tool=d, deny_input=deny_inp, allow_tool=ok,
         deny_status=verdict(cls, conv, d, deny_inp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
