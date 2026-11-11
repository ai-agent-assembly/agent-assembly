#!/usr/bin/env python3
"""Negative control for check-release-completeness.sh step 3b (AAASM-4542).

The committed release.yml must pass; the same file with aa-proxy moved back
behind the Linux-only branch (the pre-AAASM-4542 shape) must fail, naming
aa-proxy. Needs cargo and jq, as the gate itself does.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/check-release-completeness.sh"
YML = ROOT / ".github/workflows/release.yml"
UNCONDITIONAL = "PKGS=(-p aa-cli -p aa-gateway -p aa-runtime -p aa-api -p aa-proxy)"
LINUX_ONLY = 'PKGS=(-p aa-cli -p aa-gateway -p aa-runtime -p aa-api)\n          if [ "$RUNNER_OS" = "Linux" ]; then\n            PKGS+=(-p aa-proxy)\n          fi'


def run_gate(yml: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(GATE), str(yml)], cwd=ROOT, capture_output=True, text=True, timeout=300)


@unittest.skipUnless(shutil.which("cargo") and shutil.which("jq"), "gate needs cargo and jq")
class ReleaseParity(unittest.TestCase):
    def test_committed_release_yml_passes(self) -> None:
        p = run_gate(YML)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_linux_only_proxy_fails(self) -> None:
        text = YML.read_text()
        self.assertIn(UNCONDITIONAL, text)
        with tempfile.TemporaryDirectory() as d:
            mutated = Path(d) / "release.yml"
            mutated.write_text(text.replace(UNCONDITIONAL, LINUX_ONLY))
            p = run_gate(mutated)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("'aa-proxy'", p.stderr)
        self.assertIn("unconditional PKGS", p.stderr)


if __name__ == "__main__":
    unittest.main()
