#!/usr/bin/env python3
"""Round-trip tests for scripts/propagate_versions.py (AAASM-4910).

Proves the ADR 0013 drift-gate contract on a throwaway fixture tree so the tests
are deterministic and isolated (they never touch the real repo files): a
freshly-stamped tree passes ``--check``; staling any single consumer makes
``--check`` report exactly that consumer and exit non-zero; and a write pass
restores every staled consumer to the SoT value.

Run: ``python3 scripts/test_propagate_versions.py``  (stdlib unittest, no deps).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import propagate_versions as pv

# The SoT values the fixture tree declares; consumers below are authored to match.
CORE_VERSION = "0.0.1-rc.6"
CORE_TAG = "v0.0.1-rc.6"
MDBOOK = "0.5.2"
MERMAID = "0.17.0"

CARGO_TOML = f"""[workspace.package]
version = "{CORE_VERSION}"
edition = "2021"
"""

DOCS_YAML = f"""protocol_version: "protocol/v1"
repo_url: "https://github.com/ai-agent-assembly/agent-assembly"
docs_url: "https://docs.agent-assembly.com/"
install_script_url: "https://agent-assembly.com/install.sh"
mdbook_version: "{MDBOOK}"
mdbook_mermaid_version: "{MERMAID}"
"""

README = f"""# agent-assembly

AASM_VERSION={CORE_TAG} curl -sSf https://agent-assembly.com/install.sh | sh

Releases are published as GitHub pre-releases — latest
[`{CORE_TAG}`](https://github.com/ai-agent-assembly/agent-assembly/releases/tag/{CORE_TAG})
(2026-07-16).

Historical prose that must be LEFT ALONE: `v0.0.1-alpha.1` … `beta.4`, `v0.0.1-rc.1`.
"""

INSTALLATION = f"""# Install

AASM_VERSION={CORE_TAG} curl -sSf https://agent-assembly.com/install.sh | sh

VERSION={CORE_TAG}
ASSET=aasm-aarch64-apple-darwin.tar.gz

$ aasm --version
aasm {CORE_VERSION}

| cli       | {CORE_VERSION}  | -           |
"""

DOCS_YML = f"""jobs:
  build:
    steps:
      - uses: actions/cache@v4
        with:
          key: ${{{{ runner.os }}}}-mdbook-{MDBOOK}-mermaid-{MERMAID}
      - run: cargo install --locked --version {MDBOOK} mdbook
      - run: cargo install --locked --version {MERMAID} mdbook-mermaid
"""

CONTRIBUTING = f"""# Contributing

cargo install --locked --version {MDBOOK} mdbook
cargo install --locked --version {MERMAID} mdbook-mermaid
"""

# Compatibility matrix: a historical row (must be left literal) plus the row for the
# CURRENT anchor. The gate value-checks only that a row exists whose first cell is
# the anchor tag (AAASM-4921).
COMPATIBILITY = f"""# Version Compatibility Matrix

## Compatibility Matrix

| `aa-runtime` | Python SDK | Node.js SDK | Go SDK | Protocol Version |
|---|---|---|---|---|
| v0.0.1-rc.5 | v0.0.1-rc.5 ✓ | v0.0.1-rc.5 ✓ | v0.0.1-rc.5 ✓ | protocol/v1 |
| {CORE_TAG} | {CORE_TAG} ✓ | {CORE_TAG} ✓ | {CORE_TAG} ✓ | protocol/v1 |
"""


def build_fixture(root: Path) -> None:
    """Write a minimal but faithful consumer tree, already synced to the SoT."""
    (root / "Cargo.toml").write_text(CARGO_TOML)
    (root / "metadata").mkdir()
    (root / "metadata" / "docs.yaml").write_text(DOCS_YAML)
    (root / "README.md").write_text(README)
    (root / "CONTRIBUTING.md").write_text(CONTRIBUTING)
    (root / "docs" / "src" / "quick-start").mkdir(parents=True)
    (root / "docs" / "src" / "quick-start" / "installation.md").write_text(INSTALLATION)
    (root / "docs" / "src" / "compatibility.md").write_text(COMPATIBILITY)
    (root / "docs" / "src" / "generated").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "docs.yml").write_text(DOCS_YML)
    # Seed the generated snippets so a synced tree starts clean.
    pv.run(root, check=False)


# Each consumer plus a staling edit and the substring that must reappear after a
# write pass. Covers the core-version tier (README/installation) and the tool-pin
# tier (docs.yml/CONTRIBUTING).
STALINGS = {
    "README.md": (f"AASM_VERSION={CORE_TAG} curl", "AASM_VERSION=v0.0.1-beta.4 curl"),
    "docs/src/quick-start/installation.md": (f"aasm {CORE_VERSION}", "aasm 0.0.1-beta.4"),
    ".github/workflows/docs.yml": (f"--version {MDBOOK} mdbook", "--version 0.4.9 mdbook"),
    "CONTRIBUTING.md": (
        f"--version {MERMAID} mdbook-mermaid",
        "--version 0.16.0 mdbook-mermaid",
    ),
}


class RoundTrip(unittest.TestCase):
    def _fixture(self) -> tuple[TemporaryDirectory, Path]:
        tmp = TemporaryDirectory()
        root = Path(tmp.name)
        build_fixture(root)
        return tmp, root

    def test_synced_tree_passes_check(self) -> None:
        tmp, root = self._fixture()
        with tmp:
            self.assertEqual(pv.run(root, check=True), 0)

    def test_staled_consumer_is_reported_then_restored(self) -> None:
        for rel, (good, bad) in STALINGS.items():
            with self.subTest(consumer=rel):
                tmp, root = self._fixture()
                with tmp:
                    path = root / rel
                    path.write_text(path.read_text().replace(good, bad))

                    # --check must fail and must not write.
                    before = path.read_text()
                    self.assertEqual(pv.run(root, check=True), 1)
                    self.assertEqual(path.read_text(), before, "check mode wrote to disk")

                    # write restores the SoT value; a follow-up --check is green.
                    self.assertEqual(pv.run(root, check=False), 0)
                    self.assertIn(good, path.read_text())
                    self.assertNotIn(bad, path.read_text())
                    self.assertEqual(pv.run(root, check=True), 0)

    def test_cli_table_cell_width_is_preserved(self) -> None:
        # A shorter version must not shrink the fixed-width VERSION cell — the tool
        # re-pads so the grid-table borders stay aligned. Regression for the review
        # finding where beta.4 -> rc.6 left installation.md's table misaligned.
        def version_cell_width(text: str) -> int:
            m = re.search(r"(?m)^\| cli\s+\| (.*?)(?=\|)", text)
            assert m is not None
            return len(m.group(1))

        tmp, root = self._fixture()
        with tmp:
            install = root / "docs" / "src" / "quick-start" / "installation.md"
            # Author the cli row at a LONGER version, cell padded to a set width.
            longer = "| cli       | 0.0.1-beta.4  | -           |"
            install.write_text(
                re.sub(r"(?m)^\| cli\b.*$", longer, install.read_text())
            )
            before = version_cell_width(install.read_text())

            self.assertEqual(pv.run(root, check=False), 0)
            after = install.read_text()
            self.assertIn("0.0.1-rc.6", after)
            self.assertNotIn("0.0.1-beta.4", after)
            self.assertEqual(
                version_cell_width(after),
                before,
                "VERSION cell width changed — grid-table borders misalign",
            )

    def test_compat_current_row_value_check(self) -> None:
        # AAASM-4921: the gate value-checks the CURRENT release's compatibility-matrix
        # row. A wrong runtime value in that row (so no row matches the anchor) — the
        # failure the old presence-only gate let through — must fail --check. The
        # matrix is never written by the propagator (historical rows stay literal), so
        # a write pass must NOT "fix" it.
        compat_rel = "docs/src/compatibility.md"
        tmp, root = self._fixture()
        with tmp:
            compat = root / compat_rel
            # A synced fixture (current row present) passes.
            self.assertEqual(pv.run(root, check=True), 0)

            # Fat-finger the current row's runtime cell so no row carries the anchor.
            good = f"| {CORE_TAG} | {CORE_TAG} ✓"
            bad = f"| v0.0.1-rc.99 | {CORE_TAG} ✓"
            compat.write_text(compat.read_text().replace(good, bad))
            before = compat.read_text()

            self.assertEqual(pv.run(root, check=True), 1)
            # Write mode leaves the literal matrix untouched (no restore).
            self.assertEqual(pv.run(root, check=False), 0)
            self.assertEqual(compat.read_text(), before, "write mode edited the matrix")
            self.assertEqual(pv.run(root, check=True), 1)

    def test_compat_missing_row_fails_check(self) -> None:
        # Anchor bumped but the matrix row never appended — the other failure the
        # presence-only gate let through.
        tmp, root = self._fixture()
        with tmp:
            compat = root / "docs" / "src" / "compatibility.md"
            compat.write_text(
                re.sub(rf"(?m)^\| {re.escape(CORE_TAG)} .*$", "", compat.read_text())
            )
            self.assertEqual(pv.run(root, check=True), 1)

    def test_missing_anchor_is_a_hard_error(self) -> None:
        # A renamed/removed consumer anchor must fail loudly (exit 2), never pass
        # silently — a silently-skipped consumer is the drift this tool prevents.
        tmp, root = self._fixture()
        with tmp:
            readme = root / "README.md"
            readme.write_text(readme.read_text().replace("AASM_VERSION=", "AASM_VER="))
            self.assertEqual(pv.run(root, check=True), 2)


if __name__ == "__main__":
    unittest.main()
