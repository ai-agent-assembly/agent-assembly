#!/usr/bin/env python3
"""Registry-level controls for publication obligations (AAASM-6419, Core ADR 0042).

Complements the fixture and release-evidence negative controls: those prove the
validator and checker refuse bad input; this proves the REAL registry declares
what B1 requires and that the obligation validator refuses duplicate ids, each
defect isolated from the others and compared with a valid positive control.

Run: python3 -I scripts/tests/test_publication_registry.py
"""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "qa"))
import publication_obligations as po  # noqa: E402
import registry_digest  # noqa: E402

# Pending ids are published by the candidate harnesses (PRs #2801, #2803); J08
# and J56 ids are provisional, no harness emits them yet. Changing this set is
# a deliberate B1 scope change, not a side effect.
B1_PENDING_IDS = {
    "J04": {
        "j04.published_install_sh_default", "j04.published_release_checksums_and_signature",
        "j04.published_homebrew_tap_install", "j04.published_homebrew_runtime",
        "j04.published_latest_resolves_to_candidate", "j04.published_crates_io_aa_cli",
    },
    "J08": {"j08-published-python-sdk-governed-agent"},
    "J17": {
        "j17.published_installer_profile_full_gateway", "j17.published_homebrew_gateway",
        "j17.published_container_image_manifest",
    },
    "J53": {
        "j53-ghcr-tag-resolves", "j53-ghcr-digest-immutable", "j53-ghcr-multiarch",
        "j53-ghcr-sbom-attestation", "j53-published-image-runs-healthy",
    },
    "J56": {"j56-published-python-sdk-canonical-11-step"},
    "J59": {
        "j59-install-release-assets", "j59-ghcr-gateway-image", "j59-ghcr-runtime-image",
        "j59-published-binaries-golden-path",
    },
}


def load_registry() -> dict[str, dict]:
    doc = yaml.safe_load((ROOT / "qa" / "golden-journeys.yaml").read_text())
    return {e["id"]: e for e in doc["journeys"]}


def obligation_for(entry: dict) -> dict:
    digest = "sha256:" + "a" * 64
    return {
        "journey": entry["id"],
        "registry_digest": registry_digest.per_journey_digest(entry),
        "candidate_checks": [{
            "id": "cand-1", "status": "PASS", "fidelity": "real_local_process",
            "evidence_ref": "scripts/qa/x.py::cand-1@abc", "negative_control": "x",
            "artifact_digests": {"art": digest},
        }],
        "pending_checks": [
            {"id": c["id"], "channel": c["channel"], "why_publication_only": "w",
             "command": "cmd", "expected": "e"}
            for c in entry["publication_checks"]
        ],
        "depends_on": [{"repo": "agent-assembly", "event": "publish"}],
        "failure_response": {"proposed_actions": ["a"], "notify": ["release-owner"], "deadline_hours": 24},
    }


class RealRegistry(unittest.TestCase):
    def test_exactly_the_b1_journeys_declare_publication_checks(self):
        reg = load_registry()
        declared = {j: {c["id"] for c in e["publication_checks"]}
                    for j, e in reg.items() if e.get("publication_checks")}
        self.assertEqual(declared, B1_PENDING_IDS)

    def test_each_declaring_journey_is_published_artifact_and_unique(self):
        for j, e in load_registry().items():
            if not e.get("publication_checks"):
                continue
            self.assertEqual(e.get("fidelity"), "published_artifact", j)
            ids = [c["id"] for c in e["publication_checks"]]
            self.assertEqual(len(ids), len(set(ids)), j)

    def test_digest_binds_publication_checks(self):
        entry = load_registry()["J53"]
        before = registry_digest.per_journey_digest(entry)
        mutated = copy.deepcopy(entry)
        mutated["publication_checks"][0]["channel"] = "elsewhere"
        self.assertNotEqual(before, registry_digest.per_journey_digest(mutated))
        dropped = copy.deepcopy(entry)
        dropped["publication_checks"].pop()
        self.assertNotEqual(before, registry_digest.per_journey_digest(dropped))

    def test_every_real_obligation_shape_is_admissible_for_each_journey(self):
        # Positive control: an obligation built from the registry validates, so the
        # negative cases below fail for their stated defect and not for a bad fixture.
        for j, e in load_registry().items():
            if e.get("publication_checks"):
                self.assertEqual(
                    po.validate_obligation(j, obligation_for(e), e, registry_digest.per_journey_digest(e)), [], j)


class ObligationDuplicates(unittest.TestCase):
    def setUp(self):
        self.entry = load_registry()["J53"]
        self.digest = registry_digest.per_journey_digest(self.entry)

    def problems(self, obligation):
        return po.validate_obligation("J53", obligation, self.entry, self.digest)

    def test_duplicate_pending_id_is_inadmissible(self):
        o = obligation_for(self.entry)
        o["pending_checks"].append(copy.deepcopy(o["pending_checks"][0]))
        self.assertTrue(any("duplicate pending check ids" in p for p in self.problems(o)))

    def test_duplicate_candidate_id_is_inadmissible(self):
        o = obligation_for(self.entry)
        o["candidate_checks"].append(copy.deepcopy(o["candidate_checks"][0]))
        self.assertTrue(any("duplicate candidate check ids" in p for p in self.problems(o)))

    def test_id_reused_as_candidate_and_pending_is_inadmissible(self):
        o = obligation_for(self.entry)
        o["candidate_checks"][0]["id"] = o["pending_checks"][0]["id"]
        self.assertTrue(any("both a candidate and a pending" in p for p in self.problems(o)))

    def test_dropping_a_declared_pending_check_is_inadmissible(self):
        o = obligation_for(self.entry)
        o["pending_checks"].pop()
        self.assertTrue(any("do not equal registry publication_checks ids" in p for p in self.problems(o)))

    def test_duplicate_journey_entry_in_obligation_file_is_reported(self):
        o = obligation_for(self.entry)
        _, problems = po.index_obligations({"journeys": [o, copy.deepcopy(o)]})
        self.assertTrue(any("duplicate obligation entry" in p for p in problems))


class RcRulesTests(unittest.TestCase):
    def test_rc_version_is_strict(self):
        for ok in ("0.0.1-rc.8", "10.20.30-rc.0"):
            self.assertTrue(po.is_rc_version(ok), ok)
        for bad in ("0.0.1", "0.0.1-rc.01", "00.0.1-rc.1", "0.0.1-rc.", "0.0.1-rc.1\n",
                    "0.0.1-beta.1", "0.0.1-rc.1-x", "0.0.1-rc.\u0668", "\u0660.0.1-rc.1"):
            self.assertFalse(po.is_rc_version(bad), repr(bad))

    def test_manual_marker_is_never_accepted(self):
        ob = {"pending_checks": [{"id": "j53-ghcr-tag-resolves", "failure_response": "x",
              "automated_procedure": {"manual": True, "justification": "because"}}]}
        problems = po.rc_pending_check_problems("J53", ob, frozenset({"j53-ghcr-tag-resolves"}), set())
        self.assertTrue(any("manual markers are not accepted" in m for m in problems))


if __name__ == "__main__":
    unittest.main(verbosity=2)
