"""Environment capture.

Every result file carries one of these. A timing number without the kernel, CPU,
filesystem and toolchain versions it was produced on is not reproducible, so the
harness refuses to emit a result without one.

The ``fingerprint`` is the mechanism that stops a macOS baseline being compared
against a Linux confined run: ``compare`` requires the two arms' fingerprints to
match.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone

#: Version-probe argv for every binary a workload family may invoke. A family is
#: only skipped for a missing binary, but a *present* binary's version is always
#: recorded — a toolchain upgrade between two runs invalidates their comparison
#: just as surely as a kernel change does.
TOOLCHAIN_PROBES: dict[str, list[str]] = {
    "git": ["git", "--version"],
    "rg": ["rg", "--version"],
    "python3": ["python3", "--version"],
    "node": ["node", "--version"],
    "pnpm": ["pnpm", "--version"],
    "cargo": ["cargo", "--version"],
    "rustc": ["rustc", "--version"],
    "openssl": ["openssl", "version"],
    "curl": ["curl", "--version"],
    "sh": ["sh", "-c", "echo ${BASH_VERSION:-posix-sh}"],
}


def _run(argv: list[str], timeout: float = 10.0) -> str | None:
    """Run ``argv`` and return its first stdout line, or ``None`` if unusable."""
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    output = (completed.stdout or completed.stderr).strip()
    return output.splitlines()[0] if output else None


def _cpu_model() -> str | None:
    if sys.platform == "darwin":
        return _run(["sysctl", "-n", "machdep.cpu.brand_string"])
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def _total_memory_bytes() -> int | None:
    if sys.platform == "darwin":
        raw = _run(["sysctl", "-n", "hw.memsize"])
        return int(raw) if raw and raw.isdigit() else None
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return None


def _filesystem(path: str) -> dict[str, str | None]:
    """Identify the filesystem backing ``path``.

    The scratch filesystem is part of the measurement: an overlayfs, a tmpfs and
    an APFS volume have materially different costs for the many-small-file
    family, and a sandbox's path-resolution overhead is measured relative to
    whichever one was underneath.
    """
    target = path if os.path.exists(path) else os.path.dirname(path) or "."
    if sys.platform == "darwin":
        raw = _run(["stat", "-f", "%T %Sd", target])
        if raw:
            parts = raw.split(None, 1)
            return {
                "type": parts[0],
                "device": parts[1] if len(parts) > 1 else None,
                "source": "stat -f",
            }
        return {"type": None, "device": None, "source": "stat -f (failed)"}
    raw = _run(["findmnt", "--noheadings", "--output", "FSTYPE,SOURCE", "--target", target])
    if raw:
        parts = raw.split(None, 1)
        return {
            "type": parts[0],
            "device": parts[1] if len(parts) > 1 else None,
            "source": "findmnt",
        }
    return {"type": None, "device": None, "source": "findmnt (unavailable)"}


def _repo_state(repo_root: str) -> dict[str, object]:
    commit = _run(["git", "-C", repo_root, "rev-parse", "HEAD"])
    branch = _run(["git", "-C", repo_root, "rev-parse", "--abbrev-ref", "HEAD"])
    try:
        porcelain = subprocess.run(
            ["git", "-C", repo_root, "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        dirty: bool | None = bool(porcelain.stdout.strip()) if porcelain.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        dirty = None
    return {"commit": commit, "branch": branch, "dirty": dirty}


def toolchain_versions(names: set[str] | None = None) -> dict[str, str | None]:
    """Probe versions for ``names`` (default: every known tool)."""
    wanted = sorted(names) if names else sorted(TOOLCHAIN_PROBES)
    versions: dict[str, str | None] = {}
    for name in wanted:
        probe = TOOLCHAIN_PROBES.get(name)
        if probe is None:
            versions[name] = None
            continue
        if shutil.which(probe[0]) is None:
            versions[name] = None
            continue
        versions[name] = _run(probe)
    return versions


def _maxrss_unit() -> str:
    """Units of ``ru_maxrss``, which differ by platform.

    BSD and macOS report bytes; Linux reports KiB. Recording which normalisation
    was applied is the difference between a memory figure and one that is
    silently wrong by 1024x.
    """
    return "bytes" if sys.platform == "darwin" else "kibibytes"


def capture(repo_root: str, scratch_path: str, tools: set[str] | None = None) -> dict[str, object]:
    """Capture the full environment block for a run."""
    uname = platform.uname()
    try:
        load = list(os.getloadavg())
    except OSError:
        load = []
    env: dict[str, object] = {
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "platform": {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "python": sys.version.split()[0],
            "python_implementation": platform.python_implementation(),
        },
        "cpu": {
            "model": _cpu_model(),
            "logical_cores": os.cpu_count(),
        },
        "memory": {
            "total_bytes": _total_memory_bytes(),
            "ru_maxrss_native_unit": _maxrss_unit(),
        },
        "filesystem": {"scratch_path": scratch_path, **_filesystem(scratch_path)},
        "toolchains": toolchain_versions(tools),
        "repo": _repo_state(repo_root),
        "load_average_at_start": load,
    }
    env["fingerprint"] = fingerprint(env)
    return env


def fingerprint(env: dict[str, object]) -> str:
    """Stable hash of the environment facets that invalidate a comparison.

    Load average and timestamps are excluded on purpose: they vary run to run
    without making two runs incomparable. Kernel release, CPU model, core count,
    scratch filesystem type and every toolchain version are included, because a
    change in any of them means a measured difference may be the environment
    rather than the launcher.
    """
    platform_block = env.get("platform")
    cpu_block = env.get("cpu")
    fs_block = env.get("filesystem")
    material = {
        "system": platform_block.get("system") if isinstance(platform_block, dict) else None,
        "release": platform_block.get("release") if isinstance(platform_block, dict) else None,
        "machine": platform_block.get("machine") if isinstance(platform_block, dict) else None,
        "cpu_model": cpu_block.get("model") if isinstance(cpu_block, dict) else None,
        "cores": cpu_block.get("logical_cores") if isinstance(cpu_block, dict) else None,
        "fs_type": fs_block.get("type") if isinstance(fs_block, dict) else None,
        "toolchains": env.get("toolchains"),
    }
    blob = json.dumps(material, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()
