#!/usr/bin/env python3
"""Bind the signing path to the build job's own output, not the artifact store.

AAASM-6468. `publish` signs SHA256SUMS over whatever tarballs sit in artifacts/.
Those arrive through the Actions artifact store, which any later job in the run
can write to with its runtime token (upload-artifact documents that an artifact
"can completely overwrite" a same-named one via `overwrite: true`). Naming the
artifacts does not stop a replacement. What a later job CANNOT change is a JOB
OUTPUT of `build`: only the producing job sets it.

So each `build` matrix leg hashes the tarballs it just packaged (after every
in-leg check, immediately before upload) and exposes the digests as a job
output; every consumer that is about to hash/sign/publish what it downloaded
re-computes those digests and refuses on any difference.

Subcommands
  digest FILE...              print {basename: sha256} JSON (compact, sorted)
  verify-archives --version V --dir D
                              the four build legs' tarballs; digests come from
                              env AA_DIGESTS_<TARGET> (target upper-cased, `-`
                              -> `_`), e.g. AA_DIGESTS_X86_64_UNKNOWN_LINUX_GNU
  verify-ebpf --dir D         the three BPF objects; digests from AA_EBPF_DIGESTS

Verification fails on: an empty/missing/malformed digest output, a digest set
that is not exactly the expected file names, a missing file, a file whose bytes
differ, any EXTRA entry in the directory, and anything that is not a plain
regular file (symlink, directory).
Exit 0 ok, 1 verification failed, 2 usage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

# target -> os/arch token used in component archive names (mirrors build's
# "Archive binaries" step).
TARGET_OSARCH = {
    "x86_64-unknown-linux-gnu": "linux-amd64",
    "aarch64-unknown-linux-gnu": "linux-arm64",
    "aarch64-apple-darwin": "darwin-arm64",
    "x86_64-apple-darwin": "darwin-amd64",
}
COMPONENTS = ("cli", "runtime", "api", "proxy")
EBPF_OBJECTS = ("aa-file-io", "aa-exec-probes", "aa-tls-probes")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def env_name(target: str) -> str:
    return "AA_DIGESTS_" + target.upper().replace("-", "_")


def expected_names(target: str, version: str) -> set[str]:
    osarch = TARGET_OSARCH[target]
    return {f"aasm-{target}.tar.gz"} | {f"aasm-{c}-{version}-{osarch}.tar.gz" for c in COMPONENTS}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_files(paths: list[Path]) -> dict[str, str]:
    return {p.name: sha256_file(p) for p in sorted(paths, key=lambda p: p.name)}


def parse_digests(label: str, raw: str | None, expected: set[str]) -> tuple[dict[str, str], list[str]]:
    if raw is None or not raw.strip():
        return {}, [f"{label}: digest output is empty or unset"]
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return {}, [f"{label}: digest output is not JSON: {exc}"]
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        return {}, [f"{label}: digest output is not a {{name: sha256}} object"]
    problems = []
    if set(data) != expected:
        problems.append(
            f"{label}: digest names differ from expected "
            f"(missing {sorted(expected - set(data))}, unexpected {sorted(set(data) - expected)})"
        )
    for name, digest in data.items():
        if not HEX64.match(digest):
            problems.append(f"{label}: {name} has a malformed sha256")
    return data, problems


def verify_dir(directory: Path, digests: dict[str, str]) -> list[str]:
    """`digests` is the union of every bound {name: sha256}; directory must match it exactly."""
    problems: list[str] = []
    present: dict[str, Path] = {}
    for entry in os.scandir(directory):
        p = Path(entry.path)
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            problems.append(f"{entry.name}: not a plain regular file")
        else:
            present[entry.name] = p
    for name in sorted(set(present) - set(digests)):
        problems.append(f"{name}: unexpected file not produced by the build job")
    for name in sorted(set(digests) - set(present)):
        problems.append(f"{name}: missing from {directory}")
    for name in sorted(set(present) & set(digests)):
        actual = sha256_file(present[name])
        if actual != digests[name]:
            problems.append(f"{name}: sha256 {actual} does not match the build job's {digests[name]}")
    return problems


def verify_archives(directory: Path, version: str, environ: dict[str, str]) -> list[str]:
    problems: list[str] = []
    bound: dict[str, str] = {}
    for target in TARGET_OSARCH:
        data, probs = parse_digests(env_name(target), environ.get(env_name(target)), expected_names(target, version))
        problems += probs
        bound.update(data)
    return problems + verify_dir(directory, bound)


def verify_ebpf(directory: Path, environ: dict[str, str]) -> list[str]:
    data, problems = parse_digests("AA_EBPF_DIGESTS", environ.get("AA_EBPF_DIGESTS"), set(EBPF_OBJECTS))
    return problems + verify_dir(directory, data)


def main(argv: list[str] | None = None, environ: dict[str, str] | None = None) -> int:
    environ = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("digest")
    d.add_argument("files", nargs="+", type=Path)
    va = sub.add_parser("verify-archives")
    va.add_argument("--version", required=True)
    va.add_argument("--dir", required=True, type=Path, dest="directory")
    ve = sub.add_parser("verify-ebpf")
    ve.add_argument("--dir", required=True, type=Path, dest="directory")
    args = ap.parse_args(argv)
    if args.cmd == "digest":
        missing = [str(p) for p in args.files if not p.is_file()]
        if missing:
            print(f"digest: not a file: {missing}", file=sys.stderr)
            return 2
        print(json.dumps(digest_files(args.files), sort_keys=True, separators=(",", ":")))
        return 0
    if not args.directory.is_dir():
        print(f"{args.directory} is not a directory", file=sys.stderr)
        return 2
    problems = (
        verify_archives(args.directory, args.version, environ)
        if args.cmd == "verify-archives"
        else verify_ebpf(args.directory, environ)
    )
    for p in problems:
        print(f"::error::{p}", file=sys.stderr)
    if problems:
        print("artifact binding: FAILED", file=sys.stderr)
        return 1
    print(f"artifact binding: OK ({args.cmd}, {len(list(args.directory.iterdir()))} files match the build job's digests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
