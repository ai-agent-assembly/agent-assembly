"""CLI driver: recompute versions.json for a docs cut (AAASM-2752).

Usage:  python3 docs/ci/build_versions.py <VERSION> <CHANNEL> <OUTPUT>

Reads the prior live manifest from ``prior-versions.json`` (if present) and the
committed source manifest from ``docs/versions.json`` (if present), computes the
published manifest via :func:`channels.compute_versions` (which applies the
pre-release semver gate), and writes it to ``<OUTPUT>``.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from channels import compute_versions


def _load(path):
    if os.path.exists(path):
        try:
            with open(path) as fh:
                return json.load(fh)
        except Exception:
            return None
    return None


def main(argv):
    version, channel, output = argv[1], argv[2], argv[3]
    prior = _load("prior-versions.json")
    source = _load("docs/versions.json")
    out = compute_versions(version, channel, prior=prior, source=source)
    with open(output, "w") as fh:
        json.dump(out, fh, indent=2)
    print("versions.json:", json.dumps(out))


if __name__ == "__main__":
    main(sys.argv)
