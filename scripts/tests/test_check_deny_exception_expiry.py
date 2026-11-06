"""Tests for scripts/ci/check_deny_exception_expiry.py, including negative controls."""
from __future__ import annotations

import datetime as dt
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("expiry", ROOT / "scripts/ci/check_deny_exception_expiry.py")
expiry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(expiry)

TODAY = dt.date(2026, 11, 6)


def check(body: str, today: dt.date = TODAY) -> list[str]:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "deny.toml"
        p.write_text(body)
        return expiry.problems(p, today)


def entry(reason: str) -> str:
    return f'[advisories]\nignore = [{{ id = "RUSTSEC-2026-0440", reason = "{reason}" }}]\n'


class ExpiryTests(unittest.TestCase):
    def test_empty_ignore_list_passes(self):
        self.assertEqual(check("[advisories]\nignore = []\n"), [])

    def test_future_expiry_passes(self):
        self.assertEqual(check(entry("dev-only; expires: 2026-12-15")), [])

    def test_expiry_day_itself_fails(self):
        self.assertEqual(len(check(entry("expires: 2026-12-15"), dt.date(2026, 12, 15))), 1)

    def test_past_expiry_fails(self):
        self.assertIn("expired", check(entry("expires: 2026-12-15"), dt.date(2027, 1, 1))[0])

    def test_far_future_expiry_fails(self):
        self.assertIn("short-lived", check(entry("expires: 2099-12-31"))[0])

    def test_exactly_the_maximum_horizon_passes(self):
        self.assertEqual(check(entry("expires: 2027-02-04")), [])  # TODAY + 90 days

    def test_entry_without_expiry_fails(self):
        self.assertIn("must end", check(entry("dev-only, no date"))[0])

    def test_bare_string_entry_fails(self):
        self.assertIn("must be a table", check('[advisories]\nignore = ["RUSTSEC-2026-0440"]\n')[0])

    def test_impossible_date_fails(self):
        self.assertIn("not a calendar date", check(entry("expires: 2026-13-45"))[0])

    def test_one_valid_one_expired_still_fails(self):
        body = ('[advisories]\nignore = [{ id = "A", reason = "expires: 2027-01-01" },'
                ' { id = "B", reason = "expires: 2026-01-01" }]\n')
        self.assertEqual(len(check(body)), 1)

    def test_repo_deny_toml_is_currently_valid(self):
        self.assertEqual(expiry.problems(ROOT / "deny.toml", TODAY), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
