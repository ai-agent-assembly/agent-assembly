"""Tests for `check_adr_citations.py` (AAASM-5684)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_adr_citations as cac  # noqa: E402


class FindViolationsTest(unittest.TestCase):
    def _write(self, tmp_path: Path, text: str) -> Path:
        p = tmp_path / "sample.md"
        p.write_text(text, encoding="utf-8")
        return p

    def test_bare_citation_is_a_violation(self) -> None:
        old_root = cac.REPO_ROOT
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            cac.REPO_ROOT = Path(tmp)
            path = self._write(Path(tmp), "Per ADR 0007, the domain is canonical.\n")
            violations = cac.find_violations(path, None)
            cac.REPO_ROOT = old_root
        self.assertEqual(len(violations), 1)
        self.assertTrue(violations[0][1])  # blocking
        self.assertIn("ADR 0007", violations[0][0])

    def test_qualified_citation_is_not_a_violation(self) -> None:
        import tempfile

        old_root = cac.REPO_ROOT
        with tempfile.TemporaryDirectory() as tmp:
            cac.REPO_ROOT = Path(tmp)
            path = self._write(Path(tmp), "Per Core ADR 0007, the domain is canonical.\n")
            violations = cac.find_violations(path, None)
            cac.REPO_ROOT = old_root
        self.assertEqual(violations, [])

    def test_relative_link_into_local_adr_dir_is_not_a_violation(self) -> None:
        import tempfile

        old_root = cac.REPO_ROOT
        with tempfile.TemporaryDirectory() as tmp:
            cac.REPO_ROOT = Path(tmp)
            path = self._write(
                Path(tmp), "[ADR 0007](../adr/0007-public-domain-and-url-contract.md)\n"
            )
            violations = cac.find_violations(path, None)
            cac.REPO_ROOT = old_root
        self.assertEqual(violations, [])

    def test_hit_outside_changed_lines_is_pre_existing_not_blocking(self) -> None:
        import tempfile

        old_root = cac.REPO_ROOT
        with tempfile.TemporaryDirectory() as tmp:
            cac.REPO_ROOT = Path(tmp)
            path = self._write(Path(tmp), "Per ADR 0007, the domain is canonical.\n")
            violations = cac.find_violations(path, set())  # no changed lines
            cac.REPO_ROOT = old_root
        self.assertEqual(len(violations), 1)
        self.assertFalse(violations[0][1])  # not blocking
        self.assertIn("pre-existing", violations[0][0])

    def test_hit_on_a_changed_line_is_blocking(self) -> None:
        import tempfile

        old_root = cac.REPO_ROOT
        with tempfile.TemporaryDirectory() as tmp:
            cac.REPO_ROOT = Path(tmp)
            path = self._write(Path(tmp), "Per ADR 0007, the domain is canonical.\n")
            violations = cac.find_violations(path, {1})
            cac.REPO_ROOT = old_root
        self.assertEqual(len(violations), 1)
        self.assertTrue(violations[0][1])


if __name__ == "__main__":
    unittest.main()
