#!/usr/bin/env python3
"""Policy enforcement E2E driver for F116 ST-D (AAASM-1516).

Spawned by the Rust harness to exercise Layer 1 (SDK shim) policy allow/deny
behaviour against a live gateway.  In ``--selftest`` mode it runs hermetically
without a gateway or SDK install so the CI smoke suite can verify the JSON
contract without a full environment.

Usage::

    AAASM_GATEWAY_URL=http://127.0.0.1:PORT \\
    AAASM_API_KEY=test-key \\
    AAASM_POLICY_NAME=it-allow-deny-mixed \\
        python3 policy_driver.py

    python3 policy_driver.py --selftest   # hermetic, no gateway required

The real-mode path requires:
  - ``agent_assembly`` SDK installed (``pip install agent-assembly``)
  - A running gateway with the ``it-allow-deny-mixed`` policy active
  - The gateway HTTP endpoint ``POST /api/v1/agents/{id}/policy/check``
    (tracked as a follow-up in AAASM-1516; mark tests ``#[ignore]`` until
    that endpoint ships)

Output (JSON on stdout)::

    {
        "deny_result":  {"decision": "deny",  "reason": "tool denied by policy"},
        "allow_result": {"decision": "allow"}
    }
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from typing import Any


def _run_real(gateway_url: str, api_key: str) -> int:
    """Real mode: call check_policy_compliance via the published SDK against a live gateway."""
    from agent_assembly import init_assembly
    from agent_assembly.exceptions import PolicyViolationError

    ctx = init_assembly(
        gateway_url=gateway_url,
        api_key=api_key,
        agent_id=f"policy-driver-{uuid.uuid4().hex[:8]}",
        mode="sidecar",
    )

    deny_result: dict[str, Any] = {}
    allow_result: dict[str, Any] = {}

    # Denied tool — expect PolicyViolationError (or similar Deny response).
    try:
        ctx.client.check_policy_compliance("tool.call:websearch")
        deny_result = {"decision": "allow", "unexpected": True}
    except PolicyViolationError as exc:
        deny_result = {"decision": "deny", "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001
        deny_result = {"decision": "error", "error": str(exc)}

    # Allowed tool — expect success (no exception).
    try:
        ctx.client.check_policy_compliance("tool.call:read_file")
        allow_result = {"decision": "allow"}
    except PolicyViolationError as exc:
        allow_result = {"decision": "deny", "unexpected": True, "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001
        allow_result = {"decision": "error", "error": str(exc)}

    ctx.shutdown()

    payload = json.dumps({"deny_result": deny_result, "allow_result": allow_result})
    print(payload)
    sys.stdout.flush()
    return 0


def _run_selftest() -> int:
    """Hermetic selftest: emit synthetic results without contacting a gateway."""
    payload = json.dumps(
        {
            "deny_result": {"decision": "deny", "reason": "tool denied by policy"},
            "allow_result": {"decision": "allow"},
        }
    )
    print(payload)
    sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AAASM policy E2E driver (F116 ST-D).")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Hermetic mode: emit synthetic results without contacting a gateway.",
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return _run_selftest()

    gateway_url = os.environ.get("AAASM_GATEWAY_URL")
    api_key = os.environ.get("AAASM_API_KEY", "policy-it-test-key")
    if not gateway_url:
        print(
            "error: AAASM_GATEWAY_URL is required in real mode (use --selftest for hermetic runs)",
            file=sys.stderr,
        )
        return 2

    return _run_real(gateway_url, api_key)


if __name__ == "__main__":
    sys.exit(main())
