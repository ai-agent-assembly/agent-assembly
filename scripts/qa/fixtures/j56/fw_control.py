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
import importlib
import inspect
import json
import sys
import uuid
from pathlib import Path

DENY_DEFAULTS = ["send_http_request", "write_to_disk", "write_file", "delete_files", "delete_file", "shell", "execute_code"]
ALLOW_DEFAULTS = ["compute_sum", "fetch_stock_price", "read_file", "search", "web_search", "calculator"]


def emit(**f):
    print("RESULT " + json.dumps(f, sort_keys=True), flush=True)


def find_engine(mod):
    cands = [o for o in vars(mod).values() if inspect.isclass(o) and o.__module__ == mod.__name__
             and callable(getattr(o, "check_tool_start", None))]
    cands.sort(key=lambda o: (o.__name__ != "LocalPolicyEngine", o.__name__))
    return cands[0] if cands else None


def verdict(cls, conv, tool):
    try:
        eng = cls()  # fresh per probe: budget-style engines keep state between calls
        if conv == "serialized":
            r = eng.check_tool_start(serialized={"name": tool, "type": "tool"}, input_str="{}", run_id=uuid.uuid4())
        else:
            r = eng.check_tool_start(tool_name=tool, input_str="{}")
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
        return emit(error="policy-import-failed", message=f"{type(e).__name__}: {e}"[:200])
    cls = find_engine(mod)
    if cls is None:
        return emit(error="no-engine-with-check_tool_start")
    deny = sorted(getattr(mod, "DENIED_TOOLS", ())) + sorted(getattr(mod, "APPROVAL_REQUIRED_TOOLS", ())) + DENY_DEFAULTS
    allow = list(getattr(mod, "TOOL_COSTS", {})) + ALLOW_DEFAULTS
    for conv in ("serialized", "tool_name"):
        d = next((t for t in deny if verdict(cls, conv, t) in ("deny", "pending")), None)
        ok = next((t for t in allow if verdict(cls, conv, t) == "allow"), None)
        if d and ok:
            break
    else:
        return emit(error="no-denied-and-allowed-tool-found", engine=cls.__name__)
    sd = Path(a.sentinel_dir)

    def body(name):
        (sd / f"{name}.sentinel").write_text("executed\n")

    body("ungoverned")  # control: the effect exists when nothing governs it
    if verdict(cls, conv, d) == "allow":
        body("denied")
    if verdict(cls, conv, ok) == "allow":
        body("allowed")
    emit(engine=cls.__name__, convention=conv, deny_tool=d, allow_tool=ok, deny_status=verdict(cls, conv, d))


if __name__ == "__main__":
    sys.exit(main() or 0)
