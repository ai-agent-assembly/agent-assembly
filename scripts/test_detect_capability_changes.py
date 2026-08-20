"""Tests for `detect_capability_changes.py` (AAASM-5602).

Covers the AC's own named cases explicitly: changed, unchanged, removed and
deprecated capabilities, plus stale/valid/expired waivers. Uses synthetic
manifests (dicts) via `diff_manifests` directly -- no git checkout needed for
these; a separate real-history smoke test exercises `load_manifest_at` against
this repo's own commit history for the manifest.
"""

from __future__ import annotations

import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detect_capability_changes as dcc  # noqa: E402


def _row(id_, **overrides):
    base = {
        "id": id_,
        "domain": "sdk",
        "capability": "a capability",
        "owner": {"repository": "python-sdk", "component": "python-sdk"},
        "coverage": "unmeasured",
        "protection_state": "not_applicable",
        "governance_level_ceiling": "not_applicable",
        "released_channels": ["pypi"],
        "released_platforms": ["linux_x86_64"],
        "default_state": "off",
        "reachability": "shipped",
        "buildable": "unmeasured",
        "boundary_class": "B2",
    }
    base.update(overrides)
    return base


def _doc(rows, retired_ids=None):
    return {
        "manifest_version": "1.0.0",
        "meta": {"retired_ids": retired_ids or []},
        "capabilities": rows,
    }


class DiffTest(unittest.TestCase):
    def test_unchanged_row_produces_no_diagnostic(self) -> None:
        old = _doc([_row("S1")])
        new = _doc([_row("S1")])
        self.assertEqual(dcc.diff_manifests(old, new), [])

    def test_added_row_is_a_finding(self) -> None:
        old = _doc([])
        new = _doc([_row("S1")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, "added")
        self.assertEqual(changes[0].severity, "finding")

    def test_removed_without_retirement_is_blocking(self) -> None:
        old = _doc([_row("S1")])
        new = _doc([])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].kind, "removed")
        self.assertEqual(changes[0].severity, "blocking")

    def test_removed_with_retirement_is_deprecated_finding(self) -> None:
        old = _doc([_row("S1")])
        new = _doc([], retired_ids=["S1"])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].kind, "deprecated")
        self.assertEqual(changes[0].severity, "finding")

    def test_coverage_gaining_a_claim_is_blocking(self) -> None:
        old = _doc([_row("S1", coverage="unmeasured")])
        new = _doc([_row("S1", coverage="observed")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "blocking")
        self.assertIn("coverage", changes[0].fields_changed)

    def test_coverage_losing_a_claim_is_finding(self) -> None:
        old = _doc([_row("S1", coverage="observed")])
        new = _doc([_row("S1", coverage="unmeasured")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "finding")

    def test_coverage_lateral_between_substantive_terms_is_finding(self) -> None:
        old = _doc([_row("S1", coverage="observed")])
        new = _doc([_row("S1", coverage="denied_before_execution")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "finding")

    def test_protection_state_entering_ladder_is_blocking(self) -> None:
        old = _doc([_row("S1", protection_state="not_installed")])
        new = _doc([_row("S1", protection_state="integrated")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "blocking")

    def test_protection_state_within_ladder_is_finding(self) -> None:
        old = _doc([_row("S1", protection_state="host_enforced")])
        new = _doc([_row("S1", protection_state="integrated")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "finding")

    def test_released_channels_gaining_is_blocking(self) -> None:
        old = _doc([_row("S1", released_channels=["pypi"])])
        new = _doc([_row("S1", released_channels=["pypi", "npm"])])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "blocking")

    def test_released_channels_losing_is_finding(self) -> None:
        old = _doc([_row("S1", released_channels=["pypi", "npm"])])
        new = _doc([_row("S1", released_channels=["pypi"])])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "finding")

    def test_default_state_to_on_is_blocking(self) -> None:
        old = _doc([_row("S1", default_state="off")])
        new = _doc([_row("S1", default_state="on")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "blocking")

    def test_reachability_becoming_reachable_is_blocking(self) -> None:
        old = _doc([_row("S1", reachability="dead_code")])
        new = _doc([_row("S1", reachability="shipped")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(changes[0].severity, "blocking")

    def test_unowned_field_change_is_finding_only(self) -> None:
        old = _doc([_row("S1", capability="old description")])
        new = _doc([_row("S1", capability="new description")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].severity, "finding")

    def test_row_with_multiple_field_changes_takes_worst_severity(self) -> None:
        old = _doc([_row("S1", coverage="unmeasured", capability="x")])
        new = _doc([_row("S1", coverage="observed", capability="y")])
        changes = dcc.diff_manifests(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].severity, "blocking")
        self.assertEqual(set(changes[0].fields_changed), {"coverage", "capability"})


class WaiverTest(unittest.TestCase):
    def _waiver(self, **overrides):
        base = {
            "id": "WV-1",
            "rule": "S1",
            "text": "text",
            "scope": "governance/capability-manifest.yaml#S1",
            "justification": "justification",
            "evidence": "evidence",
            "approver": "someone",
            "issued": "2026-08-01",
            "expires": "2026-09-01",
        }
        base.update(overrides)
        return base

    def test_well_formed_waiver_passes(self) -> None:
        errors = dcc.validate_waivers([self._waiver()], today=date(2026, 8, 20))
        self.assertEqual(errors, [])

    def test_missing_field_is_an_error(self) -> None:
        w = self._waiver()
        del w["approver"]
        errors = dcc.validate_waivers([w], today=date(2026, 8, 20))
        self.assertTrue(any("missing fields" in e for e in errors))

    def test_expired_waiver_is_an_error(self) -> None:
        errors = dcc.validate_waivers([self._waiver(expires="2026-01-01")], today=date(2026, 8, 20))
        self.assertTrue(any("expired" in e for e in errors))

    def test_over_90_days_is_an_error(self) -> None:
        errors = dcc.validate_waivers(
            [self._waiver(issued="2026-01-01", expires="2026-12-01")], today=date(2026, 8, 20)
        )
        self.assertTrue(any("at most 90 days" in e for e in errors))

    def test_duplicate_id_is_an_error(self) -> None:
        errors = dcc.validate_waivers([self._waiver(), self._waiver()], today=date(2026, 8, 20))
        self.assertTrue(any("duplicate" in e for e in errors))

    def test_waived_returns_none_for_unwaived_change(self) -> None:
        change = dcc.Change("S2", "changed", "blocking", "detail")
        self.assertIsNone(dcc.waived(change, [self._waiver()], today=date(2026, 8, 20)))

    def test_waived_returns_id_for_valid_waiver(self) -> None:
        change = dcc.Change("S1", "changed", "blocking", "detail")
        self.assertEqual(dcc.waived(change, [self._waiver()], today=date(2026, 8, 20)), "WV-1")

    def test_waived_returns_none_for_expired_waiver(self) -> None:
        change = dcc.Change("S1", "changed", "blocking", "detail")
        self.assertIsNone(dcc.waived(change, [self._waiver(expires="2026-01-01")], today=date(2026, 8, 20)))


class RealHistorySmokeTest(unittest.TestCase):
    """Exercises `load_manifest_at` + `diff_manifests` against this repo's own
    real commit history for the manifest -- the "historical replay" the
    ticket's own AC asks for, using the manifest's real evolution (AAASM-5531
    landed in 18 commits; no tagged release yet carries the file at all, so
    there is no tag-to-tag history to replay instead -- see the module
    docstring / PR description for that bound).
    """

    def test_seed_to_current_produces_only_documented_severities(self) -> None:
        try:
            old = dcc.load_manifest_at("c6ed36a03")
            new = dcc.load_manifest_at("dc8ab13d6")
        except ValueError as exc:
            self.skipTest(f"real history not available in this checkout: {exc}")
            return
        changes = dcc.diff_manifests(old, new)
        self.assertTrue(changes, "expected real changes between these two known commits")
        for c in changes:
            self.assertIn(c.severity, ("blocking", "finding"))
            self.assertIn(c.kind, ("added", "removed", "changed", "deprecated"))

    def test_bootstrap_before_manifest_existed_reports_all_added(self) -> None:
        # v0.0.1-rc.6 predates AAASM-5531 -- the manifest does not exist at any
        # tagged release yet. This is the real shape the release gate hits the
        # first time it runs: --from names a tag with no manifest at all.
        try:
            old = dcc.load_manifest_at("v0.0.1-rc.6", missing_ok=True)
            new = dcc.load_manifest_at("dc8ab13d6")
        except ValueError as exc:
            self.skipTest(f"real history not available in this checkout: {exc}")
            return
        changes = dcc.diff_manifests(old, new)
        self.assertTrue(changes)
        self.assertTrue(all(c.kind == "added" for c in changes))
        self.assertTrue(all(c.severity == "finding" for c in changes))


if __name__ == "__main__":
    unittest.main()
