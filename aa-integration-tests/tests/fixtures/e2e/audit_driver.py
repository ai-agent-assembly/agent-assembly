#!/usr/bin/env python3
"""Audit E2E integration-test Python driver (AAASM-1519 / F116 ST-G).

Spawned by the Rust harness once AAASM-237 is resolved and the HTTP path
auto-writes audit entries. Uses the Python SDK to register an agent and make
``--calls N`` tool calls; the Rust assertions module then reads the audit JSONL
to verify every intercepted call produced an entry.

Usage::

    AAASM_GATEWAY_URL=http://127.0.0.1:PORT \\
    AAASM_API_KEY=test-key \\
        python3 audit_driver.py [--calls N]

    python3 audit_driver.py --selftest   # hermetic, no Rust required

Stdout contract: JSON ``{"agent_id": "<hex>", "calls_made": N}`` so the Rust
harness can assert the expected number of audit JSONL entries.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid

TEAM_ID = "audit-it"


def _emit(payload: dict) -> None:
    print(json.dumps(payload))
    sys.stdout.flush()


def _run_real(gateway_url: str, api_key: str, calls: int) -> int:
    """Drive the published ``agent_assembly`` SDK to generate audit entries."""
    from agent_assembly import init_assembly  # noqa: F401

    ctx = init_assembly(
        gateway_url=gateway_url,
        api_key=api_key,
        team_id=TEAM_ID,
        mode="sdk-only",
    )
    agent_id = ctx.agent_id

    for i in range(calls):
        ctx.check_policy(tool="bash", args={"cmd": f"echo hello_{i}"})

    _emit({"agent_id": agent_id, "calls_made": calls})
    return 0


def _run_selftest(calls: int) -> int:
    """Hermetic selftest: emit synthetic IDs without contacting a gateway."""
    agent_id = f"selftest-audit-{uuid.uuid4().hex[:8]}"
    _emit({"agent_id": agent_id, "calls_made": calls})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AAASM audit E2E driver.")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Run hermetically without contacting a gateway or installing the SDK.",
    )
    parser.add_argument(
        "--calls",
        type=int,
        default=3,
        help="Number of tool calls to make (default: 3).",
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return _run_selftest(args.calls)

    gateway_url = os.environ.get("AAASM_GATEWAY_URL")
    api_key = os.environ.get("AAASM_API_KEY", "audit-it-test-key")
    if not gateway_url:
        print(
            "error: AAASM_GATEWAY_URL is required in real mode (use --selftest for hermetic runs)",
            file=sys.stderr,
        )
        return 2

    return _run_real(gateway_url, api_key, args.calls)


if __name__ == "__main__":
    sys.exit(main())
