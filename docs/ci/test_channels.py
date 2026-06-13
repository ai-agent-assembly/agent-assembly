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


class ExtraArchivedSeedingTests(unittest.TestCase):
    """Regression: AAASM-2827.

    The live ``versions.json`` lost prior tags after a sequence of failed
    releases meant earlier docs cuts never ran. The next successful cut then
    inherited the truncated ``archived[]`` and the loss became permanent.

    The fix: callers pass the full list of release git tags as
    ``extra_archived`` so ``archived[]`` is reconstituted from the
    authoritative source (git) on every deploy.
    """

    def test_extra_archived_restores_missing_tags(self) -> None:
        # Reproduce the live state at the time of AAASM-2827: prior manifest
        # has only v0.0.1-alpha.8 archived, but git tags v0.0.1-alpha.4..8
        # all exist and are now rebuilt by the workflow.
        prior = _prior(
            pre_release="v0.0.1-alpha.8",
            archived=["v0.0.1-alpha.8"],
        )
        tags = [
            "v0.0.1-alpha.4",
            "v0.0.1-alpha.5",
            "v0.0.1-alpha.6",
            "v0.0.1-alpha.7",
            "v0.0.1-alpha.8",
        ]
        doc = compute_versions(
            "latest", "latest", prior=prior, extra_archived=tags
        )
        ids = _archived_ids(doc)
        for tag in tags:
            self.assertIn(tag, ids)
        # Newest-first ordering — the bumped tag heads the list.
        self.assertEqual(ids[0], "v0.0.1-alpha.8")

    def test_extra_archived_drops_non_version_strings(self) -> None:
        # ``latest`` is the live latest-channel target and must never enter
        # archived[]; ``not-a-version`` is a guard against garbled input.
        doc = compute_versions(
            "latest",
            "latest",
            extra_archived=["latest", "not-a-version", "v0.1.0"],
        )
        ids = _archived_ids(doc)
        self.assertEqual(ids, ["v0.1.0"])

    def test_extra_archived_idempotent_with_prior(self) -> None:
        # An entry already present in prior is not duplicated when also
        # supplied via extra_archived.
        prior = _prior(archived=["v0.1.0"])
        doc = compute_versions(
            "latest", "latest", prior=prior, extra_archived=["v0.1.0", "v0.2.0"]
        )
        self.assertEqual(_archived_ids(doc), ["v0.2.0", "v0.1.0"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
