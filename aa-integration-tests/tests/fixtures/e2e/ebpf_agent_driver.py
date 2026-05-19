#!/usr/bin/env python3
"""eBPF E2E integration-test Python driver (AAASM-1520 / F116 ST-H).

Spawned by `aa-integration-tests/tests/e2e_ebpf.rs` to generate the kernel
syscalls the eBPF probes are meant to catch. Stays deliberately small and
dependency-free (stdlib only) so the new `e2e-ebpf-linux` CI job needs no
extra `pip install` step beyond the system curl + openssl already present
on `ubuntu-latest`.

The Rust harness loads the BPF programs, attaches them, then spawns this
driver with one of the modes below, then polls the BPF ring buffer for
the expected event(s). The driver always prints a single JSON object to
stdout describing what it did so the Rust side can correlate (`pid`,
`child_pid`, `payload_hash`, ...).

Modes
-----

* ``--mode ssl-write`` — call ``curl https://<target>`` once. curl uses
  libssl, so the kernel uprobe on ``SSL_write`` should fire with the
  outbound HTTP request bytes (plaintext, pre-encryption).

* ``--mode spawn-curl`` — fork+exec ``curl --version``. Tests the exec
  tracepoint (``sched_process_exec``) catches the child with the right
  ``parent_pid`` / ``child_pid`` / ``exec_path`` attribution.

* ``--mode bypass-proxy`` — same as ``ssl-write`` but explicitly unsets
  ``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``ALL_PROXY`` before the call. Tests
  defence-in-depth: even when no proxy is in the path, the kernel layer
  still sees the traffic.

* ``--mode no-sdk`` — same as ``ssl-write`` but additionally does *not*
  import or initialise the ``agent_assembly`` SDK. Tests that the kernel
  layer fires even when nothing in userspace has registered with the
  gateway.

Usage::

    python3 ebpf_agent_driver.py --mode ssl-write --target https://example.com/data
    python3 ebpf_agent_driver.py --mode spawn-curl
    python3 ebpf_agent_driver.py --mode bypass-proxy --target https://example.com/data
    python3 ebpf_agent_driver.py --mode no-sdk     --target https://example.com/data

Stdout contract: a single JSON object with keys ``mode``, ``pid``, plus
mode-specific fields. The Rust harness greps for the keys it needs and
ignores the rest, so adding fields is non-breaking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from typing import Any


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload))
    sys.stdout.flush()


def _strip_proxy_env(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``env`` with every proxy-related variable removed."""
    proxy_keys = {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    }
    return {k: v for k, v in env.items() if k not in proxy_keys}


def _run_curl(target: str, env: dict[str, str]) -> tuple[int, str, int]:
    """Run ``curl -sSf <target>`` synchronously and return (rc, body, child_pid).

    The child PID is what eBPF will attribute the ssl_write to, so the
    Rust harness needs it to correlate with the captured event.
    """
    # `-w '%{response_code}'` writes the HTTP status after the body; we don't
    # actually need it but it forces curl to talk to the server even if the
    # target hangs up early. ``-s`` for quiet, ``-S`` for errors on stderr.
    proc = subprocess.Popen(
        # `--http1.1` forces a plaintext HTTP/1.1 request line + headers in
        # the SSL_write payload. Without it, curl on ubuntu-latest negotiates
        # HTTP/2 (via ALPN) and the first SSL_write is the binary HTTP/2
        # connection preface ("PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"
        # followed by HPACK frames) — which is what the kernel uprobe
        # captures first, breaking AAASM-1520 test 1's plaintext-content
        # assertion. Forcing HTTP/1.1 makes the captured bytes deterministic
        # and human-readable for the test.
        ["curl", "-sSf", "--http1.1", "--max-time", "10", target],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    child_pid = proc.pid
    stdout, _stderr = proc.communicate(timeout=15)
    return proc.returncode, stdout.decode("utf-8", errors="replace"), child_pid


def cmd_ssl_write(args: argparse.Namespace) -> int:
    rc, body, child_pid = _run_curl(args.target, dict(os.environ))
    _emit(
        {
            "mode": "ssl-write",
            "pid": os.getpid(),
            "child_pid": child_pid,
            "target": args.target,
            "curl_rc": rc,
            "payload_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        }
    )
    return 0 if rc == 0 else rc


def cmd_spawn_curl(args: argparse.Namespace) -> int:
    # `curl --version` is hermetic — no network, no SSL_write — so this mode
    # isolates the exec tracepoint from the TLS uprobe assertions.
    proc = subprocess.Popen(
        ["curl", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    child_pid = proc.pid
    stdout, _stderr = proc.communicate(timeout=10)
    _emit(
        {
            "mode": "spawn-curl",
            "pid": os.getpid(),
            "child_pid": child_pid,
            "exec_path": "/usr/bin/curl",
            "curl_rc": proc.returncode,
            "stdout_head": stdout.decode("utf-8", errors="replace").splitlines()[:1],
        }
    )
    return 0


def cmd_bypass_proxy(args: argparse.Namespace) -> int:
    env = _strip_proxy_env(dict(os.environ))
    rc, body, child_pid = _run_curl(args.target, env)
    _emit(
        {
            "mode": "bypass-proxy",
            "pid": os.getpid(),
            "child_pid": child_pid,
            "target": args.target,
            "proxy_env_present": False,
            "curl_rc": rc,
            "payload_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        }
    )
    return 0 if rc == 0 else rc


def cmd_no_sdk(args: argparse.Namespace) -> int:
    # Same wire-level behaviour as ssl-write but explicit about not touching
    # the SDK. Documenting it as its own mode makes the Rust assertion's
    # intent (Layer 3 fires without Layer 1) self-evident at the call site.
    if "agent_assembly" in sys.modules:
        # Belt-and-braces: a stray import elsewhere in the test process would
        # invalidate the "without SDK" claim. We're a fresh interpreter so
        # this is normally never hit.
        print("agent_assembly was already imported — aborting", file=sys.stderr)
        return 2
    rc, body, child_pid = _run_curl(args.target, dict(os.environ))
    _emit(
        {
            "mode": "no-sdk",
            "pid": os.getpid(),
            "child_pid": child_pid,
            "target": args.target,
            "sdk_imported": False,
            "curl_rc": rc,
            "payload_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        }
    )
    return 0 if rc == 0 else rc


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        required=True,
        choices=["ssl-write", "spawn-curl", "bypass-proxy", "no-sdk"],
    )
    parser.add_argument(
        "--target",
        default="https://example.com/",
        help="HTTPS URL for modes that make outbound requests.",
    )
    args = parser.parse_args(argv)

    if args.mode == "ssl-write":
        return cmd_ssl_write(args)
    if args.mode == "spawn-curl":
        return cmd_spawn_curl(args)
    if args.mode == "bypass-proxy":
        return cmd_bypass_proxy(args)
    if args.mode == "no-sdk":
        return cmd_no_sdk(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
