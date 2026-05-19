#!/usr/bin/env python3
"""Three-layer E2E driver (AAASM-1523 / F116 ST-K).

Spawned by ``aa-integration-tests/tests/e2e_three_layers_together.rs`` to
generate the three kinds of outbound activity an agent process exhibits
during a single session, one phase per interception layer:

* **Phase 1 — Layer 1 / SDK in-process**: simulate the SDK-wrapped
  tool-call codepath by emitting a structured marker line on stdout.
  The real Python SDK lives in a sibling polyrepo and is not pip-installed
  on the integration host; matching the divergence pattern used by
  ``audit_driver.py``, the Rust harness consumes the marker and writes
  the equivalent ``AuditEntry`` into the unified JSONL stream itself.
  The marker carries the synthetic ``agent_id`` / ``session_id`` so the
  Rust side can attribute the entry correctly.

* **Phase 2 — Layer 2 / aa-proxy MitM**: shell out to ``curl
  https://<target>`` with the ``HTTPS_PROXY`` env var honoured. On a
  real deployment ``aa-proxy`` would intercept this transparently; in
  the in-process harness this driver simply records the subprocess'
  child PID + target URL on stdout so the Rust side can synthesise the
  proxy-source ``AuditEntry``. The curl invocation is real so that the
  exec / SSL_write side-effects exist on the host kernel — which the
  Layer-3 probe ST already covers in ST-H.

* **Phase 3 — Layer 3 / eBPF raw-TLS bypass**: open a raw
  ``socket`` + ``ssl`` connection to ``<target>``, write one HTTP/1.1
  request, then close. This bypasses both the SDK wrapping *and*
  ``HTTPS_PROXY`` (which only affects libraries that honour the env
  var; raw sockets do not). The kernel ``SSL_write`` uprobe is what
  catches this in production; the driver marks the event on stdout so
  the Rust side can synthesise the eBPF-source ``AuditEntry``.

Stdout contract
---------------

The driver prints one JSON object per line — one line per phase
completed, plus a final summary line. The Rust harness streams stdout
line-by-line via :py:class:`subprocess.Popen` and parses each line so
the entries land in the audit stream in real chronological order
(matching AC Assertion 4).

Each per-phase line carries::

    {"phase": "sdk"|"proxy"|"ebpf",
     "agent_id": "<32-hex>",
     "session_id": "<32-hex>",
     "url": "...",
     "syscall": "...",
     "tool": "...",
     "timestamp_ns": <int>,
     "decision": "allow"|"redact_only"|"block"}

The final summary line carries::

    {"phase": "summary", "exit": 0, "phases_completed": ["sdk","proxy","ebpf"]}

Stdlib-only — keeps the new test job dependency-free, like
``ebpf_agent_driver.py`` (AAASM-1520).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlparse


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True))
    sys.stdout.flush()


def _ns_now() -> int:
    # ``time.time_ns`` is monotonic-ish but not strictly monotonic — good enough
    # for the per-event ordering Assertion 4 needs (the Rust harness sleeps a
    # millisecond between phases to keep timestamps strictly increasing).
    return time.time_ns()


def phase_sdk(agent_id: str, session_id: str, tool: str) -> None:
    """Phase 1 — in-process SDK tool-call codepath."""
    _emit(
        {
            "phase": "sdk",
            "agent_id": agent_id,
            "session_id": session_id,
            "tool": tool,
            "url": None,
            "syscall": None,
            "timestamp_ns": _ns_now(),
            "decision": "allow",
        }
    )


def phase_proxy(agent_id: str, session_id: str, target: str) -> None:
    """Phase 2 — outbound HTTPS via curl subprocess (HTTPS_PROXY honoured)."""
    # The curl invocation is real to keep the on-host side-effects honest, but
    # we run it ``--max-time 2`` so the test stays fast when the target hangs
    # (CI runners regularly do not have outbound https/example.com). Failure
    # is silent — the assertion we care about is "an entry tagged
    # source=proxy lands in the stream", not "curl succeeded".
    try:
        subprocess.run(
            ["curl", "-sSf", "--http1.1", "--max-time", "2", "-o", "/dev/null", target],
            check=False,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        # No curl on PATH — fine, the marker line is what the Rust side reads.
        pass
    _emit(
        {
            "phase": "proxy",
            "agent_id": agent_id,
            "session_id": session_id,
            "tool": None,
            "url": target,
            "syscall": None,
            "timestamp_ns": _ns_now(),
            "decision": "allow",
        }
    )


def phase_ebpf(agent_id: str, session_id: str, target: str) -> None:
    """Phase 3 — raw socket + ssl, no SDK and no HTTPS_PROXY honoured."""
    parsed = urlparse(target)
    host = parsed.hostname or "example.com"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    syscall = "SSL_write"
    try:
        ctx = ssl.create_default_context()
        # The connection may fail in restricted CI (no DNS / blocked egress) —
        # that is acceptable. The phase line still goes out so the Rust side
        # can synthesise the audit entry.
        with socket.create_connection((host, port), timeout=2) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                req = f"GET {parsed.path or '/'} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                tls.sendall(req.encode("ascii"))
    except OSError:
        # Network blocked / DNS off / TLS handshake refused — fine.
        pass
    _emit(
        {
            "phase": "ebpf",
            "agent_id": agent_id,
            "session_id": session_id,
            "tool": None,
            "url": target,
            "syscall": syscall,
            "timestamp_ns": _ns_now(),
            "decision": "allow",
        }
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--agent-id",
        required=True,
        help="32-char hex string used as the agent identifier across all 3 phases.",
    )
    parser.add_argument(
        "--session-id",
        required=True,
        help="32-char hex string used as the session identifier across all 3 phases.",
    )
    parser.add_argument(
        "--target",
        default="https://example.com/data",
        help="HTTPS URL used by phases 2 (curl) and 3 (raw socket+ssl).",
    )
    parser.add_argument(
        "--tool",
        default="bash",
        help="Synthetic tool name reported by phase 1 (SDK).",
    )
    parser.add_argument(
        "--phases",
        default="sdk,proxy,ebpf",
        help="Comma-separated subset of phases to run, in order. "
        "Used by failure-mode tests to simulate one layer being unavailable.",
    )
    args = parser.parse_args(argv)

    phases = [p.strip() for p in args.phases.split(",") if p.strip()]
    valid = {"sdk", "proxy", "ebpf"}
    bad = [p for p in phases if p not in valid]
    if bad:
        print(f"unknown phase(s): {bad}", file=sys.stderr)
        return 2

    completed: list[str] = []
    for phase in phases:
        if phase == "sdk":
            phase_sdk(args.agent_id, args.session_id, args.tool)
        elif phase == "proxy":
            phase_proxy(args.agent_id, args.session_id, args.target)
        elif phase == "ebpf":
            phase_ebpf(args.agent_id, args.session_id, args.target)
        completed.append(phase)
        # 1 ms gap so timestamps in stdout are strictly monotonic across the
        # phase lines — the Rust harness keys ordering off these.
        time.sleep(0.001)

    _emit({"phase": "summary", "exit": 0, "phases_completed": completed})
    return 0


if __name__ == "__main__":
    # Honour HTTPS_PROXY / SSL_CERT_FILE from the environment — the Rust
    # harness sets them when it spawns this driver, matching the env-var
    # contract in the AC.
    _ = os.environ
    raise SystemExit(main(sys.argv[1:]))
