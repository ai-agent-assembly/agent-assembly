#!/usr/bin/env python3
"""Tests for `check_pnpm_overrides_parity.py` (AAASM-6133).

These exist to keep the gate falsifiable. The defect class this checker guards
against — AAASM-6133 here, HORO-377 and AAASM-6032 before it — is exactly "a
security floor stopped being read and nothing went red", so a checker that
cannot tell the migrated state from the unmigrated one reproduces the same
false green the original bug produced. Each test pairs a passing input with the
specific edit that reproduces the real defect and must turn it red.

The `find_manifest_violations` tests cover the assertion this repository's copy
adds over the sibling `ai-agent-assembly/examples` original. Without it the
script was a vacuous pass here: it iterates `rglob("pnpm-workspace.yaml")`,
there were none in the tree, so it exited 0 having checked nothing.
"""

from __future__ import annotations

import json
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_pnpm_overrides_parity as cpop  # noqa: E402

WORKSPACE_YAML = textwrap.dedent(
    """\
    overrides:
      js-yaml: ^4.3.2
      '@babel/core': ^7.29.7
      brace-expansion@1: ^1.1.18

    onlyBuiltDependencies:
      - esbuild
    """
)

MATCHING_LOCKFILE = textwrap.dedent(
    """\
    lockfileVersion: '9.0'

    settings:
      autoInstallPeers: true

    overrides:
      js-yaml: ^4.3.2
      '@babel/core': ^7.29.7
      brace-expansion@1: ^1.1.18

    importers:
      .:
        dependencies: {}
    """
)


class TestParseFlatMapping(unittest.TestCase):
    def test_parses_bare_and_quoted_keys(self) -> None:
        mapping = cpop._parse_flat_mapping(WORKSPACE_YAML.splitlines(), "overrides")
        self.assertEqual(
            mapping,
            {"js-yaml": "^4.3.2", "@babel/core": "^7.29.7", "brace-expansion@1": "^1.1.18"},
        )

    def test_returns_none_when_header_absent(self) -> None:
        self.assertIsNone(cpop._parse_flat_mapping(["onlyBuiltDependencies:", "  - esbuild"], "overrides"))

    def test_indented_comment_does_not_truncate_the_block(self) -> None:
        # An override carrying a justification comment above it is the house
        # style for security-driven pins. Treating that comment as the end of
        # the mapping hid every entry below it from the config side, so the
        # checker reported them as lockfile-only.
        yaml = textwrap.dedent(
            """\
            overrides:
              js-yaml: ^4.3.2
              # GHSA-vhxf-7vqr-mrjg (prototype pollution), fixed in 3.4.13.
              dompurify: ^3.4.13
            """
        )
        mapping = cpop._parse_flat_mapping(yaml.splitlines(), "overrides")
        self.assertEqual(mapping, {"js-yaml": "^4.3.2", "dompurify": "^3.4.13"})

    def test_stops_at_dedent(self) -> None:
        # onlyBuiltDependencies must not be swallowed into the overrides mapping.
        mapping = cpop._parse_flat_mapping(WORKSPACE_YAML.splitlines(), "overrides")
        self.assertNotIn("esbuild", mapping)


class _TreeCase(unittest.TestCase):
    def _write_pair(self, dir_path: Path, workspace_text: str, lock_text: str | None) -> None:
        dir_path.mkdir(parents=True, exist_ok=True)
        (dir_path / "pnpm-workspace.yaml").write_text(workspace_text, encoding="utf-8")
        if lock_text is not None:
            (dir_path / "pnpm-lock.yaml").write_text(lock_text, encoding="utf-8")

    def _write_manifest(self, dir_path: Path, payload: dict[str, object]) -> None:
        dir_path.mkdir(parents=True, exist_ok=True)
        (dir_path / "package.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class TestParity(_TreeCase):
    def test_matching_files_have_no_violation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pair(root / "dashboard", WORKSPACE_YAML, MATCHING_LOCKFILE)
            violations, checked = cpop.find_parity_violations(root)
            self.assertEqual(violations, [])
            self.assertEqual(checked, 1)

    def test_reproduces_dropped_overrides_block(self) -> None:
        # The HORO-377 / AAASM-6032 defect: the relock's lockfile has no
        # overrides block at all while pnpm-workspace.yaml still declares one.
        dropped_lockfile = textwrap.dedent(
            """\
            lockfileVersion: '9.0'

            settings:
              autoInstallPeers: true

            importers:
              .:
                dependencies: {}
            """
        )
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pair(root / "dashboard", WORKSPACE_YAML, dropped_lockfile)
            violations, checked = cpop.find_parity_violations(root)
            self.assertEqual(checked, 1)
            self.assertEqual(len(violations), 1)
            self.assertIn("missing/mismatched overrides", violations[0])
            self.assertIn("js-yaml", violations[0])

    def test_detects_value_drift_not_just_key_absence(self) -> None:
        # A subtler variant: the key survives but the lockfile records a
        # different range than the config declares (an asymmetric relock).
        drifted = MATCHING_LOCKFILE.replace("^4.3.2", "^3.14.1")
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pair(root / "dashboard", WORKSPACE_YAML, drifted)
            violations, _ = cpop.find_parity_violations(root)
            self.assertTrue(any("js-yaml" in v for v in violations))

    def test_missing_lockfile_is_a_violation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pair(root / "dashboard", WORKSPACE_YAML, None)
            violations, checked = cpop.find_parity_violations(root)
            self.assertEqual(checked, 0)
            self.assertEqual(len(violations), 1)
            self.assertIn("no pnpm-lock.yaml exists alongside it", violations[0])

    def test_node_modules_is_not_walked(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pair(root / "node_modules" / "vendored", WORKSPACE_YAML, None)
            violations, checked = cpop.find_parity_violations(root)
            self.assertEqual((violations, checked), ([], 0))


class TestManifestAssertion(_TreeCase):
    """The assertion this repository adds: no package.json may keep pnpm.overrides.

    AAASM-6133's whole point. The sibling script's parity loop skips a tree with
    no pnpm-workspace.yaml entirely, so on the pre-migration state of this repo
    it returned success while 13 floors sat in a field pnpm 11 ignores.
    """

    def test_pre_migration_shape_is_a_violation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(
                root / "dashboard",
                {
                    "name": "dashboard",
                    "packageManager": "pnpm@10.9.0",
                    "pnpm": {"overrides": {"dompurify": "^3.4.13", "undici": "^7.28.0"}},
                },
            )
            violations = cpop.find_manifest_violations(root)
            self.assertEqual(len(violations), 1)
            self.assertIn("dashboard/package.json", violations[0])
            self.assertIn("dompurify", violations[0])
            self.assertIn("pnpm 11", violations[0])

    def test_reports_every_offending_directory_not_just_the_first(self) -> None:
        # Both offending directories had to be named: reporting only one would
        # have let a half-migration read as fixed.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root / "dashboard", {"pnpm": {"overrides": {"esbuild": "^0.28.1"}}})
            self._write_manifest(root / "examples" / "client", {"pnpm": {"overrides": {"nanoid": "^3.3.17"}}})
            violations = cpop.find_manifest_violations(root)
            self.assertEqual(len(violations), 2)
            joined = "\n".join(violations)
            self.assertIn("dashboard/package.json", joined)
            self.assertIn("examples/client/package.json", joined)

    def test_migrated_manifest_passes(self) -> None:
        # pnpm.overrides removed; other pnpm settings may legitimately remain.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(
                root / "dashboard",
                {"name": "dashboard", "pnpm": {"onlyBuiltDependencies": ["esbuild"]}},
            )
            self.assertEqual(cpop.find_manifest_violations(root), [])

    def test_empty_overrides_mapping_is_not_a_violation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root / "dashboard", {"pnpm": {"overrides": {}}})
            self.assertEqual(cpop.find_manifest_violations(root), [])

    def test_manifest_without_pnpm_field_is_not_a_violation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root / "fixture", {"name": "fixture", "dependencies": {"zod": "^3.0.0"}})
            self.assertEqual(cpop.find_manifest_violations(root), [])

    def test_node_modules_manifests_are_not_walked(self) -> None:
        # Installed dependencies carry their own pnpm fields; only first-party
        # manifests are ours to fix.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root / "node_modules" / "some-dep", {"pnpm": {"overrides": {"x": "^1.0.0"}}})
            self.assertEqual(cpop.find_manifest_violations(root), [])

    def test_non_dict_pnpm_field_does_not_crash(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root / "odd", {"pnpm": "not-an-object"})
            self.assertEqual(cpop.find_manifest_violations(root), [])

    def test_unparseable_manifest_is_reported_not_skipped(self) -> None:
        # A manifest that cannot be read is not evidence of compliance.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "broken").mkdir()
            (root / "broken" / "package.json").write_text("{ this is not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                cpop.find_manifest_violations(root)


class TestRealRepositoryState(unittest.TestCase):
    """The gate must hold on this repository, not only on fixtures."""

    def test_repo_root_passes_both_assertions(self) -> None:
        self.assertEqual(cpop.find_manifest_violations(cpop.REPO_ROOT), [])
        violations, checked = cpop.find_parity_violations(cpop.REPO_ROOT)
        self.assertEqual(violations, [])
        # Guards against the vacuous pass: if this ever reads 0, the tree has
        # stopped declaring overrides anywhere and the parity half of the gate
        # is asserting nothing. Two directories carry floors as of AAASM-6133.
        self.assertGreaterEqual(checked, 2)


if __name__ == "__main__":
    unittest.main()
