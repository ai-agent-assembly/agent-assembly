"""Shared env-var loading and event emission helpers for agent fixture scripts."""

from __future__ import annotations

import json
import os
import sys
import uuid


def load_config() -> dict:
    """Load runtime config from environment variables.

    In selftest mode (AA_SELFTEST=1) the gateway address is not required.
    In real mode AA_GATEWAY_ADDR must be set.
    """
    is_selftest = os.environ.get("AA_SELFTEST") == "1"
    gateway = os.environ.get("AA_GATEWAY_ADDR")
    if not gateway and not is_selftest:
        print("error: AA_GATEWAY_ADDR required", file=sys.stderr)
        sys.exit(2)
    return {
        "gateway_addr": gateway or "",
        "agent_id": os.environ.get("AA_AGENT_ID", f"e2e-{uuid.uuid4().hex[:8]}"),
        "task": os.environ.get("AA_TASK", "noop"),
        "proxy_addr": os.environ.get("AA_PROXY_ADDR"),
    }


def emit(event: dict) -> None:
    """Print a JSON event line to stdout."""
    print(json.dumps(event), flush=True)
