"""CLI driver: recompute versions.json for a docs cut (AAASM-2752).

Usage:  python3 docs/ci/build_versions.py <VERSION> <CHANNEL> <OUTPUT>

Reads the prior live manifest from ``prior-versions.json`` (if present) and the
committed source manifest from ``docs/versions.json`` (if present), computes the
published manifest via :func:`channels.compute_versions` (which applies the
pre-release semver gate), and writes it to ``<OUTPUT>``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from channels import Manifest, compute_versions


def _load(path: str) -> Manifest | None:
    """Load a JSON manifest, returning None if it is missing or unparseable."""
    file = Path(path)
    if not file.exists():
        return None
    try:
        loaded = json.loads(file.read_text())
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def main(argv: list[str]) -> None:
    """Recompute versions.json for one docs cut and write it to ``argv[3]``."""
    version, channel, output = argv[1], argv[2], argv[3]
    prior = _load("prior-versions.json")
    source = _load("docs/versions.json")
    out = compute_versions(version, channel, prior=prior, source=source)
    Path(output).write_text(json.dumps(out, indent=2))
    print("versions.json:", json.dumps(out))


if __name__ == "__main__":
    main(sys.argv)
