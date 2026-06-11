"""Unit tests for the doc-versioning channel computation (AAASM-2752).

These assert the pre-release semver gate: the ``pre-release`` channel is
surfaced only when the newest pre-release strictly leads the newest stable
release; otherwise it stays reachable in ``archived[]`` but is not a channel.

Run with:  python3 docs/ci/test_channels.py   (or under pytest)
"""

from __future__ import annotations

import unittest
from collections.abc import Sequence
from typing import Any

from channels import compare_versions, compute_versions


def _channel_map(doc: dict[str, Any]) -> dict[str, str]:
    """Return {channel-id: target} for the channels in a computed versions doc."""
    return {c["id"]: c["target"] for c in doc["channels"]}


def _archived_ids(doc: dict[str, Any]) -> list[str]:
    """Return the archived version ids of a computed versions doc."""
    return [a["id"] for a in doc["archived"]]


def _prior(
    stable: str | None = None,
    pre_release: str | None = None,
    archived: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a prior live manifest seeding the given standing channels."""
    channels = [{"id": "latest", "title": "latest (master)", "target": "latest"}]
    if pre_release is not None:
        channels.append(
            {
                "id": "pre-release",
                "title": f"pre-release ({pre_release})",
                "target": pre_release,
            }
        )
    if stable is not None:
        channels.append(
            {"id": "stable", "title": f"stable ({stable})", "target": stable}
        )
    return {
        "channels": channels,
        "archived": [{"id": v, "title": v} for v in archived],
    }


class SemverComparatorTests(unittest.TestCase):
    def test_pre_release_precedes_release(self) -> None:
        self.assertEqual(compare_versions("v0.1.0-rc.1", "v0.1.0"), -1)
        self.assertEqual(compare_versions("v0.1.0", "v0.1.0-rc.1"), 1)

    def test_pre_release_identifier_order_alpha_beta_rc(self) -> None:
        self.assertEqual(compare_versions("v0.1.0-alpha.5", "v0.1.0-beta.1"), -1)
        self.assertEqual(compare_versions("v0.1.0-beta.2", "v0.1.0-rc.1"), -1)
        self.assertEqual(compare_versions("v0.1.0-alpha.5", "v0.1.0-rc.1"), -1)

    def test_numeric_identifiers_compare_numerically(self) -> None:
        # 5 < 6 numerically, not lexically (where "6" < "10" would fail).
        self.assertEqual(compare_versions("v0.1.0-alpha.6", "v0.1.0-alpha.10"), -1)
        self.assertEqual(compare_versions("v0.1.0-alpha.5", "v0.1.0-alpha.6"), -1)

    def test_core_version_dominates(self) -> None:
        self.assertEqual(compare_versions("v0.2.0-alpha.1", "v0.1.0"), 1)
        self.assertEqual(compare_versions("v0.0.2", "v0.1.0"), -1)

    def test_unparseable_sorts_low(self) -> None:
        self.assertEqual(compare_versions("latest", "v0.1.0"), -1)


class ChannelGateScenarioTests(unittest.TestCase):
    def test_scenario_1_pre_release_leads_stable(self) -> None:
        # Full set: v0.0.2 (stable) plus the v0.1.0-* pre-release line.
        # Newest pre-release (v0.1.0-rc.1) > newest stable (v0.0.2) => shown.
        pres = [
            "v0.1.0-alpha.5",
            "v0.1.0-alpha.6",
            "v0.1.0-beta.1",
            "v0.1.0-beta.2",
            "v0.1.0-rc.1",
        ]
        prior = _prior(
            stable="v0.0.2",
            pre_release="v0.1.0-rc.1",
            archived=["v0.0.2", *pres],
        )
        doc = compute_versions("latest", "latest", prior=prior)
        chans = _channel_map(doc)
        self.assertEqual(chans.get("pre-release"), "v0.1.0-rc.1")
        self.assertEqual(chans.get("stable"), "v0.0.2")
        self.assertEqual(chans.get("latest"), "latest")
        # Channel display order: latest, pre-release, stable.
        self.assertEqual(
            [c["id"] for c in doc["channels"]], ["latest", "pre-release", "stable"]
        )

    def test_scenario_2_stable_supersedes_pre_release(self) -> None:
        # Add v0.1.0 stable. Newest stable (v0.1.0) is NOT < newest pre-release
        # (v0.1.0-rc.1, which precedes v0.1.0) => no pre-release channel.
        pres = [
            "v0.1.0-alpha.5",
            "v0.1.0-alpha.6",
            "v0.1.0-beta.1",
            "v0.1.0-beta.2",
            "v0.1.0-rc.1",
        ]
        prior = _prior(
            stable="v0.0.2",
            pre_release="v0.1.0-rc.1",
            archived=["v0.0.2", *pres],
        )
        # The v0.1.0 stable cut repoints stable; recompute gates pre-release out.
        doc = compute_versions("v0.1.0", "stable", prior=prior)
        chans = _channel_map(doc)
        self.assertNotIn("pre-release", chans)
        self.assertEqual(chans.get("stable"), "v0.1.0")
        self.assertEqual(chans.get("latest"), "latest")
        # The hidden pre-release stays reachable in archived.
        self.assertIn("v0.1.0-rc.1", _archived_ids(doc))

    def test_scenario_3_new_pre_release_line_leads_again(self) -> None:
        # Add v0.2.0-alpha.1 on top of stable v0.1.0. v0.2.0-alpha.1 > v0.1.0
        # => pre-release channel returns, pointing at the new line.
        prior = _prior(
            stable="v0.1.0",
            pre_release="v0.1.0-rc.1",  # stale pre-release still in prior manifest
            archived=["v0.0.2", "v0.1.0", "v0.1.0-rc.1"],
        )
        doc = compute_versions("v0.2.0-alpha.1", "pre-release", prior=prior)
        chans = _channel_map(doc)
        self.assertEqual(chans.get("pre-release"), "v0.2.0-alpha.1")
        self.assertEqual(chans.get("stable"), "v0.1.0")
        self.assertEqual(chans.get("latest"), "latest")

    def test_no_stable_shows_any_pre_release(self) -> None:
        prior = _prior(pre_release="v0.1.0-alpha.1", archived=["v0.1.0-alpha.1"])
        doc = compute_versions("latest", "latest", prior=prior)
        chans = _channel_map(doc)
        self.assertEqual(chans.get("pre-release"), "v0.1.0-alpha.1")
        self.assertNotIn("stable", chans)


if __name__ == "__main__":
    unittest.main(verbosity=2)
