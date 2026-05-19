#!/usr/bin/env python3
"""File I/O E2E integration-test Python driver (AAASM-1522 / F116 ST-J).

Spawned by ``aa-integration-tests/tests/e2e_file_monitoring.rs`` to drive
the file syscalls the eBPF ``aa-file-io`` kprobes are meant to catch.
Stays deliberately small and dependency-free (stdlib only) so the
``e2e-ebpf-linux`` CI job needs no extra ``pip install`` step.

Spawn / sync protocol
---------------------

The harness needs to register the driver's PID into the BPF ``PID_FILTER``
map *before* the syscall fires; otherwise the probe drops the event. To
make that race deterministic the driver always blocks on a single line
of stdin before performing the operation:

    1. Rust spawns this driver with ``stdin=PIPE``.
    2. Rust reads ``child.id()`` and inserts it into ``PID_FILTER``.
    3. Rust writes ``"go\n"`` to the driver's stdin.
    4. Driver reads one line from stdin, performs the syscall, emits a
       single JSON line on stdout, exits.

The JSON line always contains ``{"mode", "pid", "path"}`` plus any
mode-specific fields the Rust assertion needs. Adding fields is
non-breaking — the harness uses ``serde_json::Value`` and only checks
the keys it cares about.

Modes
-----

* ``create``    — ``open(path, O_WRONLY|O_CREAT, 0o644)``; close.
* ``write``     — open ``path`` for write, ``write(payload)``; close.
* ``read``      — open ``path`` for read, ``read()``; close.
* ``rename``    — ``os.rename(path, new_path)``.
* ``unlink``    — ``os.unlink(path)``.
* ``sequence``  — create → write → read → rename → unlink on ``path``,
                  using ``path + ".renamed"`` as the rename target.
* ``chdir-create`` — ``os.chdir(dirname(path))`` then
                     ``open(basename(path), O_CREAT|O_WRONLY)``; used by
                     the relative-path resolution test.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload))
    sys.stdout.flush()


def _wait_for_go() -> None:
    """Block until the harness writes a line on stdin.

    Returns immediately if stdin is closed (EOF) so a developer running
    the script by hand can still smoke-test it without piping input.
    """
    sys.stdin.readline()


def cmd_create(args: argparse.Namespace) -> int:
    fd = os.open(args.path, os.O_WRONLY | os.O_CREAT, 0o644)
    os.close(fd)
    _emit({"mode": "create", "pid": os.getpid(), "path": args.path})
    return 0


def cmd_write(args: argparse.Namespace) -> int:
    payload = args.payload.encode("utf-8")
    fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    written = os.write(fd, payload)
    os.close(fd)
    _emit(
        {
            "mode": "write",
            "pid": os.getpid(),
            "path": args.path,
            "bytes": written,
        }
    )
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    fd = os.open(args.path, os.O_RDONLY)
    data = os.read(fd, 4096)
    os.close(fd)
    _emit(
        {
            "mode": "read",
            "pid": os.getpid(),
            "path": args.path,
            "bytes": len(data),
        }
    )
    return 0


def cmd_rename(args: argparse.Namespace) -> int:
    if not args.new_path:
        print("--new-path is required for rename mode", file=sys.stderr)
        return 2
    os.rename(args.path, args.new_path)
    _emit(
        {
            "mode": "rename",
            "pid": os.getpid(),
            "path": args.path,
            "new_path": args.new_path,
        }
    )
    return 0


def cmd_unlink(args: argparse.Namespace) -> int:
    os.unlink(args.path)
    _emit({"mode": "unlink", "pid": os.getpid(), "path": args.path})
    return 0


def cmd_sequence(args: argparse.Namespace) -> int:
    new_path = args.path + ".renamed"
    payload = args.payload.encode("utf-8")

    fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    written = os.write(fd, payload)
    os.close(fd)

    fd = os.open(args.path, os.O_RDONLY)
    data = os.read(fd, 4096)
    os.close(fd)

    os.rename(args.path, new_path)
    os.unlink(new_path)

    _emit(
        {
            "mode": "sequence",
            "pid": os.getpid(),
            "path": args.path,
            "new_path": new_path,
            "bytes_written": written,
            "bytes_read": len(data),
        }
    )
    return 0


def cmd_chdir_create(args: argparse.Namespace) -> int:
    abs_path = os.path.abspath(args.path)
    parent = os.path.dirname(abs_path)
    name = os.path.basename(abs_path)
    os.chdir(parent)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT, 0o644)
    os.close(fd)
    _emit(
        {
            "mode": "chdir-create",
            "pid": os.getpid(),
            "cwd": parent,
            "relative": name,
            "absolute": abs_path,
        }
    )
    return 0


_DISPATCH = {
    "create": cmd_create,
    "write": cmd_write,
    "read": cmd_read,
    "rename": cmd_rename,
    "unlink": cmd_unlink,
    "sequence": cmd_sequence,
    "chdir-create": cmd_chdir_create,
}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=sorted(_DISPATCH))
    parser.add_argument(
        "--path",
        required=True,
        help="Absolute path the operation will act on (or be derived from for chdir-create).",
    )
    parser.add_argument(
        "--new-path",
        default=None,
        help="Target path for rename mode.",
    )
    parser.add_argument(
        "--payload",
        default="hello world",
        help="UTF-8 string to write in write/sequence modes (default: 'hello world').",
    )
    args = parser.parse_args(argv)

    _wait_for_go()
    return _DISPATCH[args.mode](args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
