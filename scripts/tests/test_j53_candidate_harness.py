"""Self-tests for scripts/qa/j53-candidate-harness.py (AAASM-6419).

Runs without the final candidate: a fixture repo (real Dockerfile, workflow and policy
sample copied from this checkout, committed in a throwaway git repo) and a stub
`aa-gateway` that answers `--version` and serves a gRPC health Check. Each `*_fails`
test is the negative control for one check: the same harness code path, a known-bad
input, and the check that must go red.

Run: python3 -I scripts/tests/test_j53_candidate_harness.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts/qa/j53-candidate-harness.py"
GIT = "/usr/bin/git"

STUB = r'''#!{python}
import signal, socket, struct, sys
VERSION, SHA, MODE = {version!r}, {sha!r}, {mode!r}
if "--version" in sys.argv:
    print("aa-gateway " + VERSION); print("build-sha: " + SHA); sys.exit(0)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
if MODE == "never_listen":
    signal.pause()
addr = sys.argv[sys.argv.index("--listen") + 1]
host, port = addr.rsplit(":", 1)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host, int(port))); srv.listen(4)
def frame(t, f, s, p): return struct.pack(">I", len(p))[1:] + bytes([t, f]) + struct.pack(">I", s) + p
while True:
    conn, _ = srv.accept()
    buf = b""
    conn.settimeout(3)
    try:
        while b"\x00\x00\x00\x00\x00" not in buf:
            d = conn.recv(65536)
            if not d: break
            buf += d
        status = b"\x08\x02" if MODE == "not_serving" else b"\x08\x01"
        conn.sendall(frame(4, 0, 0, b"") + frame(1, 4, 1, b"\x88")
                     + frame(0, 0, 1, b"\x00" + struct.pack(">I", len(status)) + status)
                     + frame(1, 5, 1, b"\x00\x0bgrpc-status\x010"))
    except OSError:
        pass
    conn.close()
'''


def _sha(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def _git(repo: Path, *a: str) -> str:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(repo), "PATH": "/usr/bin:/bin"}
    return subprocess.run([GIT, "-C", str(repo), *a], env=env, check=True, capture_output=True, text=True).stdout.strip()


class Fixture:
    """A committed fixture repo plus stub gateway; `mutate` edits a file before the commit."""

    def __init__(self, tc: unittest.TestCase, mutate: dict[str, str] | None = None,
                 version="0.0.1-rc.8", sha=None, mode="serving", docs: str | None = None):
        self.dir = Path(tempfile.mkdtemp(prefix="j53-selftest-"))
        tc.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.repo = self.dir / "repo"
        for rel in ("aa-gateway/Dockerfile", ".github/workflows/docker.yml", "policy-examples/balanced.yaml"):
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / rel, self.repo / rel)
        for rel, text in (mutate or {}).items():
            (self.repo / rel).write_text(text)
        _git(self.repo, "init", "-q")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "fixture")
        self.sha = _git(self.repo, "rev-parse", "HEAD")
        self.bin = self.dir / "aa-gateway"
        self.bin.write_text(STUB.format(python=sys.executable, version=version, sha=sha or self.sha, mode=mode))
        self.bin.chmod(self.bin.stat().st_mode | stat.S_IXUSR)
        self.digests = self.dir / "digests.json"
        self.digests.write_text(json.dumps({"aa-gateway": _sha(self.bin)}))
        self.docs = self.dir / "docs"
        self.docs.mkdir()
        (self.docs / "gateway.md").write_text(docs if docs is not None else GOOD_DOCS)
        self.tmpdir = self.dir / "tmp"
        self.tmpdir.mkdir()

    def run(self, expected_version="0.0.1-rc.8", digests=True, docs=True, fragment=False):
        out = self.dir / "report.json"
        frag = self.dir / "fragment.json"
        argv = [sys.executable, "-I", str(HARNESS), "--candidate-sha", self.sha,
                "--expected-version", expected_version, "--repo", str(self.repo),
                "--gateway-bin", str(self.bin), "--out", str(out)]
        if digests:
            argv += ["--expected-digests", str(self.digests)]
        if docs:
            argv += ["--docs-dir", str(self.docs)]
        if fragment:
            argv += ["--obligation-fragment", str(frag)]
        env = {"PATH": "/usr/bin:/bin", "TMPDIR": str(self.tmpdir)}
        p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=120)
        report = json.loads(out.read_text()) if out.exists() else None
        return p.returncode, report, (json.loads(frag.read_text()) if frag.exists() else None)


GOOD_DOCS = """
docker pull ghcr.io/ai-agent-assembly/aa-gateway:v0.0.1-rc.8
docker pull ghcr.io/ai-agent-assembly/aa-gateway@sha256:abc
docker run -v ./policy:/etc/aa/policy -e AA_MODE=remote ghcr.io/ai-agent-assembly/aa-gateway
The gateway serves grpc.health.v1 health checks.
services:
  gw:
    image: ghcr.io/ai-agent-assembly/aa-gateway:v0.0.1-rc.8
"""


def status_of(report, check_id):
    return next(c["status"] for c in report["candidate_checks"] if c["id"] == check_id)


class J53HarnessTests(unittest.TestCase):
    def test_good_fixture_is_candidate_verified_and_fragment_is_admissible(self):
        fx = Fixture(self)
        rc, rep, frag = fx.run(fragment=True)
        self.assertEqual(rep["verdict"], "CANDIDATE_VERIFIED", json.dumps(rep["candidate_checks"], indent=1))
        self.assertEqual(rc, 0)
        self.assertTrue(all(c["status"] == "PASS" for c in rep["candidate_checks"]))
        self.assertIsNotNone(frag)
        mod_path = ROOT / "scripts/qa/publication_obligations.py"
        if mod_path.exists():  # lands with PR #2798; the one-off check in the PR body covers the gap until then
            spec = importlib.util.spec_from_file_location("publication_obligations", mod_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            entry = frag["journeys"][0]
            problems = mod.validate_obligation(
                "J53", entry, {"fidelity": "published_artifact",
                               "publication_checks": [{"id": p["id"]} for p in entry["pending_checks"]]}, "x")
            problems = [p for p in problems if "registry_digest" not in p]
            self.assertEqual(problems, [])

    def test_fragment_has_the_obligation_shape_without_needing_the_validator(self):
        # Mirrors the admissibility rules of scripts/qa/publication_obligations.py (PR #2798)
        # so the shape is enforced even before that module is on main.
        import re
        fx = Fixture(self)
        _, _, frag = fx.run(fragment=True)
        e = frag["journeys"][0]
        self.assertEqual(set(e), {"journey", "candidate_checks", "pending_checks", "depends_on", "failure_response"})
        for chk in e["candidate_checks"]:
            self.assertEqual(chk["status"], "PASS")
            self.assertIn(chk["fidelity"], {"mock", "controlled_fake", "real_local_process", "container"})
            self.assertTrue(chk["evidence_ref"])
            self.assertTrue(chk["artifact_digests"], chk["id"])
            for name, d in chk["artifact_digests"].items():
                self.assertRegex(d, r"sha256:[0-9a-f]{64}")
        for pc in e["pending_checks"]:
            for f in ("id", "channel", "why_publication_only", "command", "expected"):
                self.assertTrue(pc[f].strip(), f)
        self.assertTrue(all({"repo", "event"} <= set(d) for d in e["depends_on"]))
        self.assertEqual(set(e["failure_response"]), {"proposed_actions", "notify", "deadline_hours"})

    def test_artifacts_carry_sha256_of_every_consumed_file(self):
        fx = Fixture(self)
        _, rep, _ = fx.run()
        self.assertEqual(set(rep["artifacts"]), {"aa-gateway", "aa-gateway/Dockerfile", "docker.yml", "policy-sample", "docs-tree"})
        self.assertEqual(rep["artifacts"]["aa-gateway"], _sha(fx.bin))

    def test_publication_dependent_checks_are_never_pass(self):
        fx = Fixture(self)
        _, rep, _ = fx.run()
        pending_ids = {p["id"] for p in rep["pending_checks"]}
        self.assertGreaterEqual(len(pending_ids), 5)
        self.assertTrue(all(p["status"] == "PENDING" for p in rep["pending_checks"]))
        self.assertFalse(pending_ids & {c["id"] for c in rep["candidate_checks"]})
        for p in rep["pending_checks"]:
            for field in ("channel", "why_publication_only", "command", "expected"):
                self.assertTrue(p[field].strip())
        fr = rep["failure_response"]
        self.assertTrue(fr["proposed_actions"] and fr["notify"] and fr["deadline_hours"] > 0)

    def test_scratch_dir_removed_and_no_process_left(self):
        fx = Fixture(self)
        fx.run()
        self.assertEqual(list(fx.tmpdir.iterdir()), [])
        left = subprocess.run(["/bin/ps", "-axo", "command"], capture_output=True, text=True).stdout
        self.assertNotIn(str(fx.bin), left)

    # --- negative controls: every one drives the real harness over known-bad input ---

    def test_tampered_binary_fails(self):
        fx = Fixture(self)
        fx.bin.write_text(fx.bin.read_text() + "\n# tampered after the digest was recorded\n")
        rc, rep, frag = fx.run(fragment=True)
        self.assertEqual(status_of(rep, "j53-artifacts-bound-to-candidate"), "FAIL")
        self.assertEqual(rep["verdict"], "BLOCK")
        self.assertEqual(rc, 1)
        self.assertIsNone(frag)

    def test_tampered_source_vs_committed_blob_fails(self):
        fx = Fixture(self)
        (fx.repo / "aa-gateway/Dockerfile").write_text((fx.repo / "aa-gateway/Dockerfile").read_text() + "\n# edit\n")
        _, rep, _ = fx.run()
        self.assertEqual(status_of(rep, "j53-artifacts-bound-to-candidate"), "FAIL")

    def test_missing_expected_digest_is_not_covered_never_pass(self):
        fx = Fixture(self)
        rc, rep, frag = fx.run(digests=False, fragment=True)
        self.assertEqual(status_of(rep, "j53-artifacts-bound-to-candidate"), "NOT_COVERED")
        self.assertEqual(rep["verdict"], "CANDIDATE_INCOMPLETE")
        self.assertEqual(rc, 3)
        self.assertIsNone(frag)

    def test_wrong_version_fails(self):
        fx = Fixture(self, version="0.0.1-rc.7")
        _, rep, _ = fx.run()
        self.assertEqual(status_of(rep, "j53-gateway-binary-identity"), "FAIL")

    def test_wrong_build_sha_fails(self):
        fx = Fixture(self, sha="d" * 40)
        _, rep, _ = fx.run()
        self.assertEqual(status_of(rep, "j53-gateway-binary-identity"), "FAIL")

    def test_dockerfile_without_entrypoint_fails(self):
        text = (ROOT / "aa-gateway/Dockerfile").read_text().replace('ENTRYPOINT ["/aa-gateway"]', "")
        fx = Fixture(self, mutate={"aa-gateway/Dockerfile": text})
        _, rep, _ = fx.run()
        self.assertEqual(status_of(rep, "j53-dockerfile-contract"), "FAIL")

    def test_workflow_without_sbom_fails(self):
        text = (ROOT / ".github/workflows/docker.yml").read_text()
        head, tail = text.split("  publish-gateway:", 1)
        tail = tail.replace("sbom: true", "sbom: false", 1)
        fx = Fixture(self, mutate={".github/workflows/docker.yml": head + "  publish-gateway:" + tail})
        _, rep, _ = fx.run()
        self.assertEqual(status_of(rep, "j53-publish-workflow-contract"), "FAIL")

    def test_gateway_that_never_listens_fails(self):
        fx = Fixture(self, mode="never_listen")
        _, rep, _ = fx.run()
        self.assertEqual(status_of(rep, "j53-gateway-start-health-stop"), "FAIL")

    def test_gateway_reporting_not_serving_fails(self):
        fx = Fixture(self, mode="not_serving")
        _, rep, _ = fx.run()
        self.assertEqual(status_of(rep, "j53-gateway-start-health-stop"), "FAIL")

    def test_docs_missing_digest_pull_fails(self):
        fx = Fixture(self, docs=GOOD_DOCS.replace("@sha256:abc", ":v1"))
        _, rep, _ = fx.run()
        self.assertEqual(status_of(rep, "j53-docs-container-operation"), "FAIL")

    def test_no_docs_dir_is_not_covered(self):
        fx = Fixture(self)
        _, rep, _ = fx.run(docs=False)
        self.assertEqual(status_of(rep, "j53-docs-container-operation"), "NOT_COVERED")
        self.assertEqual(rep["verdict"], "CANDIDATE_INCOMPLETE")


class GrpcProbeUnitTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("j53h", HARNESS)
        sys.path.insert(0, str(HARNESS.parent))
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)

    def test_decode(self):
        d = self.m._decode_health
        self.assertEqual(d(b"\x00\x00\x00\x00\x02\x08\x01"), "SERVING")
        self.assertEqual(d(b"\x00\x00\x00\x00\x02\x08\x02"), "NOT_SERVING")
        self.assertEqual(d(b"\x00\x00\x00\x00\x00"), "UNKNOWN")
        with self.assertRaises(ValueError):
            d(b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
