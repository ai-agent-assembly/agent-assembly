#!/usr/bin/env python3
"""Python-SDK fixture for the J81 lease-gate end-to-end harness (AAASM-6259).

Driven by ``scripts/qa/j81-sdk-lease-e2e.sh`` with the python-sdk virtualenv
interpreter. It performs real tool calls through the SDK's real governance path:

    llama_index FunctionTool.call
      -> LlamaIndexPatch (agent_assembly.adapters.llamaindex.patch)
      -> RuntimeQueryInterceptor.check_tool_start
      -> native RuntimeClient.query_policy over the runtime's IPC socket
      -> aa-runtime handle_policy_query -> PolicyLeaseGate

Nothing here stands in for the gate. The tool body writes one sentinel file under
a per-run directory, which is what makes "the forbidden side effect did not
occur" observable independently of the verdict the SDK reports.

Subcommands (each prints exactly one line starting ``RESULT `` of ``key=value``
tokens, ``reason`` last, so the shell can parse it without a JSON dependency):

    call        one governed tool call
    raw         one raw ``query_policy`` with an agent-chosen action_type
    watch       call in a loop while ``aasm lease revoke --wait-health`` runs
    lease-id    print the lease id for a domain from a state record
    health      print one field of a runtime's ``/health`` ``lease_governance``
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


GATE_REASON = "capability lease required"


def _emit(**fields: Any) -> None:
    reason = str(fields.pop("reason", "")).replace("\n", " ")
    parts = [f"{k}={v}" for k, v in fields.items()]
    print("RESULT " + " ".join(parts) + f" reason={reason}", flush=True)


def _sentinel(sentinel_dir: Path, tool: str) -> Path:
    # The tool name is only ever a fixture-chosen identifier; keep it a single
    # path component whatever the caller passed (e.g. "Net_Fetch", "x y").
    safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in tool)
    return sentinel_dir / f"{safe}.sentinel"


def _build_governed_tool(agent_id: str, tool: str, sentinel_dir: Path) -> Any:
    """Return a FunctionTool whose call path is the SDK's real interceptor path."""
    from llama_index.core.tools import FunctionTool

    from agent_assembly.adapters.llamaindex.patch import LlamaIndexPatch
    from agent_assembly.core.runtime_interceptor import build_governance_interceptor

    class _Client:
        """Stand-in for the gateway client: the interceptor only delegates to it."""

    # Production wiring: connect_runtime_client() -> RuntimeQueryInterceptor
    # (enforce posture: an unreachable runtime or an unclear verdict denies).
    interceptor = build_governance_interceptor(_Client(), agent_id, "enforce")
    patch = LlamaIndexPatch(callback_handler=interceptor, process_agent_id=agent_id)
    if not patch.apply():
        raise SystemExit("llama-index patch was not installed")

    marker = _sentinel(sentinel_dir, tool)

    def body(**kwargs: Any) -> str:
        marker.write_text("executed\n")
        return "executed"

    return FunctionTool.from_defaults(fn=body, name=tool, description="J81 fixture tool")


def _one_call(tool_obj: Any, tool: str, sentinel_dir: Path, kwargs: dict[str, Any]) -> dict[str, Any]:
    marker = _sentinel(sentinel_dir, tool)
    marker.unlink(missing_ok=True)
    sent = time.time()
    out = tool_obj.call(**kwargs)
    recv = time.time()
    executed = marker.exists()
    content = str(getattr(out, "content", out))
    blocked = bool(getattr(out, "is_error", False)) and "BLOCKED" in content
    # ``executed`` is the ground truth; ``blocked`` is only what the SDK reported.
    status = "deny" if blocked else "allow"
    return {
        "status": status,
        "executed": int(executed),
        "sent": sent,
        "recv": recv,
        "reason": content if blocked else "",
    }


def cmd_call(a: argparse.Namespace) -> int:
    sdir = Path(a.sentinel_dir)
    kwargs = json.loads(a.args) if a.args else {}
    tool_obj = _build_governed_tool(a.agent, a.tool, sdir)
    r = _one_call(tool_obj, a.tool, sdir, kwargs)
    _emit(status=r["status"], executed=r["executed"], reason=r["reason"])
    return 0


def cmd_raw(a: argparse.Namespace) -> int:
    """Relabel probe: ask the runtime directly with an agent-chosen action_type."""
    from agent_assembly.core.runtime_interceptor import connect_runtime_client

    rc = connect_runtime_client(a.agent)
    if rc is None:
        _emit(status="unreachable", executed=0, reason="no runtime client")
        return 0
    # An empty --tool sends tool_name=None: the native shim then builds NO typed context,
    # which is the omit-context relabel ADR 0038 section 36 names as the residual.
    res = rc.query_policy(a.agent, a.action_type, a.tool or None, a.args or None)
    _emit(status=str(res.get("decision", "")), executed=0, reason=str(res.get("reason", "")))
    return 0


def cmd_watch(a: argparse.Namespace) -> int:
    """Call in a loop; mid-way run ``aasm lease revoke --wait-health`` and time its return.

    The revoke runs in a helper thread so its completion time is taken the instant the
    process returns, not at the next poll of the call loop. Only the call loop touches
    the governed tool: the llama-index patch keeps the process agent id in a
    ``threading.local``, so a worker thread would not be governed as this agent.
    Calls sent between the revoke write and the /health acknowledgement may be allowed by
    design; the claim is only about calls sent at or after the acknowledgement.
    """
    import threading

    sdir = Path(a.sentinel_dir)
    tool_obj = _build_governed_tool(a.agent, a.tool, sdir)
    log: list[dict[str, Any]] = []
    done: dict[str, Any] = {}

    def revoke() -> None:
        proc = subprocess.run(
            [a.aasm, "lease", "revoke", "--state", a.state, "--lease-id", a.lease_id,
             "--wait-health", a.health_url, "--wait-timeout-secs", "10"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )  # fmt: skip
        done["t_ack"] = time.time()
        done["rc"] = proc.returncode

    worker = threading.Thread(target=revoke)
    started = False
    start = time.time()
    deadline = start + a.duration
    while time.time() < deadline:
        if not started and time.time() - start >= a.revoke_after:
            worker.start()
            started = True
        log.append(_one_call(tool_obj, a.tool, sdir, {}))
    if started:
        worker.join(timeout=15)
    t_ack = done.get("t_ack")
    allows_before = sum(1 for r in log if r["status"] == "allow" and (t_ack is None or r["sent"] < t_ack))
    sent_after = [r for r in log if t_ack is not None and r["sent"] >= t_ack]
    allows_after = sum(1 for r in sent_after if r["status"] == "allow")
    executed_after = sum(r["executed"] for r in sent_after)
    gate_denies_after = sum(1 for r in sent_after if r["status"] == "deny" and GATE_REASON in r["reason"])
    _emit(
        status="ok",
        executed=executed_after,
        revoke_rc=done.get("rc"),
        calls=len(log),
        allows_before_ack=allows_before,
        calls_after_ack=len(sent_after),
        allows_after_ack=allows_after,
        executed_after_ack=executed_after,
        gate_denies_after_ack=gate_denies_after,
    )
    return 0


def cmd_lease_id(a: argparse.Namespace) -> int:
    rec = json.loads(Path(a.state).read_text())
    subject = rec["subject"].replace("%", "%25").replace(":", "%3A")
    print(f"{subject}:{rec['policy_digest'][:12]}:{rec['run_id']}:{rec['issued_at']}:{a.domain}")
    return 0


def cmd_health(a: argparse.Namespace) -> int:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(a.url.rstrip("/") + "/health", timeout=5) as resp:
        doc = json.load(resp)
    gov = doc.get("lease_governance")
    if gov is None:
        print("none")
    else:
        print(gov.get(a.field, ""))
    return 0


def main() -> int:
    for var in ("AA_RUNTIME_SOCKET", "AA_PROXY_SYSTEM_TRUST_INSTALL", "AA_GATEWAY_ENDPOINT"):
        os.environ.pop(var, None)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("call")
    c.add_argument("--agent", required=True)
    c.add_argument("--tool", required=True)
    c.add_argument("--sentinel-dir", required=True)
    c.add_argument("--args", default="")
    c.set_defaults(fn=cmd_call)

    r = sub.add_parser("raw")
    r.add_argument("--agent", required=True)
    r.add_argument("--tool", default="")
    r.add_argument("--action-type", required=True)
    r.add_argument("--args", default="")
    r.set_defaults(fn=cmd_raw)

    w = sub.add_parser("watch")
    w.add_argument("--agent", required=True)
    w.add_argument("--tool", required=True)
    w.add_argument("--sentinel-dir", required=True)
    w.add_argument("--aasm", required=True)
    w.add_argument("--state", required=True)
    w.add_argument("--lease-id", required=True)
    w.add_argument("--health-url", required=True)
    w.add_argument("--revoke-after", type=float, default=1.5)
    w.add_argument("--duration", type=float, default=5.0)
    w.set_defaults(fn=cmd_watch)

    li = sub.add_parser("lease-id")
    li.add_argument("--state", required=True)
    li.add_argument("--domain", required=True)
    li.set_defaults(fn=cmd_lease_id)

    h = sub.add_parser("health")
    h.add_argument("--url", required=True)
    h.add_argument("--field", required=True)
    h.set_defaults(fn=cmd_health)

    args = p.parse_args()
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
