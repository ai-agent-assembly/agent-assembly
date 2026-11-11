#!/usr/bin/env python3
"""Fail when a release leg's archive set is missing a component tarball.

AAASM-4542: the darwin legs of the release matrix used to ship no `aa-proxy`,
and nothing noticed, because the packaging step was `if [ -f aa-proxy ]` and the
installer only learns an artifact is absent when a user asks for it
(`component 'proxy' is not published for <tag>`). A packaging step that skips
what it did not build cannot be its own check, so this one inspects the
tarballs about to be uploaded and requires, for every os/arch it is asked
about, the four component archives each holding its real-named executable:

    aasm-cli-<ver>-<os>-<arch>.tar.gz      aasm aa-gateway
    aasm-runtime-<ver>-<os>-<arch>.tar.gz  aa-runtime
    aasm-api-<ver>-<os>-<arch>.tar.gz      aa-api-server
    aasm-proxy-<ver>-<os>-<arch>.tar.gz    aa-proxy

Usage: check_release_archive_set.py --version V --osarch OS-ARCH [--osarch ...] DIR
Exit 0: every requested leg is complete. Exit 1: something is missing or empty.
Exit 2: usage error.
"""
from __future__ import annotations

import argparse
import sys
import tarfile
from pathlib import Path

COMPONENT_MEMBERS = {
    "cli": ("aasm", "aa-gateway"),
    "runtime": ("aa-runtime",),
    "api": ("aa-api-server",),
    "proxy": ("aa-proxy",),
}
ALL_OSARCH = ("linux-amd64", "linux-arm64", "darwin-arm64", "darwin-amd64")


def check_leg(directory: Path, version: str, osarch: str) -> list[str]:
    problems: list[str] = []
    for comp, members in COMPONENT_MEMBERS.items():
        name = f"aasm-{comp}-{version}-{osarch}.tar.gz"
        path = directory / name
        if not path.is_file():
            problems.append(f"{osarch}: {name} is missing")
            continue
        try:
            with tarfile.open(path, "r:gz") as tar:
                found = {m.name.removeprefix("./"): m for m in tar.getmembers()}
        except (tarfile.TarError, OSError) as exc:
            problems.append(f"{osarch}: {name} is not a readable gzip tarball: {exc}")
            continue
        for member in members:
            info = found.get(member)
            if info is None:
                problems.append(f"{osarch}: {name} has no member {member!r} (has {sorted(found)})")
            elif not info.isfile() or info.size == 0:
                problems.append(f"{osarch}: {name} member {member!r} is not a non-empty regular file")
            elif not info.mode & 0o111:
                problems.append(f"{osarch}: {name} member {member!r} is not executable")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", required=True, help="version token in the archive names (tag, or 0.0.0-dev)")
    ap.add_argument("--osarch", action="append", required=True, help=f"one of {', '.join(ALL_OSARCH)}; repeatable")
    ap.add_argument("directory", type=Path)
    args = ap.parse_args(argv)
    bad = [o for o in args.osarch if o not in ALL_OSARCH]
    if bad or not args.directory.is_dir():
        print(f"usage: unknown os-arch {bad} or {args.directory} is not a directory", file=sys.stderr)
        return 2
    problems = [p for o in args.osarch for p in check_leg(args.directory, args.version, o)]
    for p in problems:
        print(f"::error::{p}", file=sys.stderr)
    if problems:
        print("release archive-set gate: FAILED", file=sys.stderr)
        return 1
    print(f"release archive-set gate: OK ({', '.join(args.osarch)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
