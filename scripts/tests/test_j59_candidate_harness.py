"""Self-tests for scripts/qa/j59-candidate-harness.py (AAASM-6419).

No candidate binaries are needed: `STUB` is a single Python file that stands in for
`aasm` (and spawns a tiny loopback HTTP server for `start`). `MODE` selects a
deliberately broken behaviour; each `*_fails` test is the negative control for one
check, driving the real harness CLI over the broken stub and asserting that exact
check goes red. The fixture repo carries the real J59 policy fixtures.

Run: python3 -I scripts/tests/test_j59_candidate_harness.py
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts/qa/j59-candidate-harness.py"
FIXTURES = ["golden-path.v1.yaml", "golden-path.v2-tightened.yaml", "malformed.yaml", "tool-calls.jsonl"]
KEY = "aa_0123456789abcdef0123456789abcdef"

STUB = r'''#!{python}
import hashlib, json, os, re, signal, subprocess, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
VERSION, MODE = {version!r}, {mode!r}
KEY = {key!r}
HOME = os.environ.get("HOME", ".")
ST = os.path.join(HOME, ".stub"); os.makedirs(ST, exist_ok=True)
def rd(n, d=""):
    try: return open(os.path.join(ST, n)).read()
    except OSError: return d
def wr(n, t): open(os.path.join(ST, n), "w").write(t)
def serve(port):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def reply(self, code, ctype, body):
            b = body.encode(); self.send_response(code); self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            if self.path == "/api/v1/health":
                checks = {{"alerts": "ok", "audit": "ok", "policy_engine": "ok", "registry": "ok"}}
                if MODE == "unhealthy": checks["audit"] = "degraded"
                return self.reply(200, "application/json", json.dumps({{"status": "ok", "version": VERSION, "checks": checks}}))
            if self.path.startswith("/api/v1/"):
                if MODE != "open_api" and self.headers.get("Authorization") != "Bearer " + KEY:
                    return self.reply(401, "application/json", "{{}}")
                return self.reply(200, "application/json", "[]")
            if MODE == "dashboard_placeholder":
                return self.reply(200, "text/html", "<html><body>Dashboard not built.</body></html>")
            return self.reply(200, "text/html", '<html><head><script src="/assets/app.js"></script></head></html>')
    HTTPServer(("127.0.0.1", port), H).serve_forever()
def decide(policy_text, tool):
    m = re.search(r"^    " + tool + r":\n((?:      .*\n)+)", policy_text, re.M)
    block = m.group(1) if m else ""
    if "allow: false" in block: return "deny"
    if "requires_approval_if" in block: return "requires_approval"
    return "allow"
a = sys.argv[1:]
if a[:1] == ["__serve"]:
    serve(int(a[1])); sys.exit(0)
if a == ["--version"]:
    print("aasm " + VERSION); sys.exit(0)
if MODE == "cli_fail" and a[:1] in (["audit"], ["logs"]): sys.exit(1)
if a[:1] == ["start"]:
    if MODE == "start_fail": print("error: boom"); sys.exit(1)
    port = a[a.index("--port") + 1]
    p = subprocess.Popen([sys.executable, os.path.abspath(__file__), "__serve", port], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.makedirs(os.path.join(HOME, ".aasm"), exist_ok=True)
    open(os.path.join(HOME, ".aasm", "gateway.pid"), "w").write(str(p.pid))
    wr("port", port); time.sleep(0.4); print("started"); sys.exit(0)
if a[:1] == ["stop"]:
    try: os.kill(int(open(os.path.join(HOME, ".aasm", "gateway.pid")).read()), signal.SIGTERM)
    except (OSError, ValueError): pass
    sys.exit(0)
if a[:1] == ["status"]:
    if "--api-url" in a: print("error: cannot connect to the gateway (connection refused)"); sys.exit(1)
    print("Health:    ok"); sys.exit(0)
if a[:2] == ["topology", "overview"] or a[:2] == ["policy", "list"] or a[:1] in (["audit"], ["logs"]):
    sys.exit(0)
if a[:2] == ["policy", "validate"]:
    t = open(a[2]).read()
    if "[[[" in t: print("error: line 3: YAML parse error"); sys.exit(1)
    print("Policy is valid"); sys.exit(0)
if a[:2] == ["policy", "apply"]:
    t = open(a[2]).read()
    if MODE == "apply_fail": print("error: nope"); sys.exit(1)
    if "[[[" in t:
        if MODE == "bad_apply_mutates": wr("active", t)
        print("error: policy validation failed"); sys.exit(1)
    vid = hashlib.sha256(t.encode()).hexdigest()[:12]
    wr("active", t); wr("v_" + vid, t)
    print("Policy applied successfully.\n  Version:    " + vid); sys.exit(0)
if a[:2] == ["policy", "get"]:
    sys.stdout.write(rd("active")); sys.exit(0)
if a[:2] == ["policy", "rollback"]:
    t = rd("v_" + a[2])
    if not t or MODE == "rollback_broken": print("error: version not found"); sys.exit(1)
    wr("active", t); print("rolled back"); sys.exit(0)
if a[:2] == ["policy", "simulate"]:
    pol = open(a[a.index("--policy") + 1]).read()
    evs = [json.loads(json.loads(l)["payload"])["ToolCall"]["name"] for l in open(a[a.index("--against") + 1]) if l.strip()]
    outs = []
    for i, t in enumerate(evs):
        d = decide(pol, t)
        if MODE == "engine_deny_all": d = "deny"
        if MODE == "engine_ignore_policy": d = decide(open(os.path.join(os.path.dirname(a[a.index("--policy") + 1]), "golden-path.v1.yaml")).read(), t)
        outs.append((i, t, d))
    cnt = lambda k: sum(1 for o in outs if o[2] == k)
    print("Simulation Report\nTotal events:       %d\nAllowed:            %d\nDenied:             %d\nApproval required:  %d\n" % (len(outs), cnt("allow"), cnt("deny"), cnt("requires_approval")))
    for i, t, d in outs:
        if d != "allow": print("%-8d tool:%-14s %-12s reason" % (i, t, d))
    sys.exit(1 if cnt("deny") else 0)
sys.exit(2)
'''


def _sha(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def _git(repo: Path, *a: str) -> str:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(repo), "PATH": "/usr/bin:/bin"}
    return subprocess.run(["/usr/bin/git", "-C", str(repo), *a], env=env, check=True, capture_output=True, text=True).stdout.strip()


class Fixture:
    def __init__(self, tc: unittest.TestCase, mode="good", version="0.0.1-rc.8", mutate: dict[str, str] | None = None):
        self.dir = Path(tempfile.mkdtemp(prefix="j59-selftest-"))
        tc.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.repo = self.dir / "repo"
        fx = self.repo / "scripts/qa/fixtures/j59"
        fx.mkdir(parents=True)
        for n in FIXTURES:
            shutil.copy(ROOT / "scripts/qa/fixtures/j59" / n, fx / n)
        for rel, text in (mutate or {}).items():
            (self.repo / rel).write_text(text)
        _git(self.repo, "init", "-q")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "fixture")
        self.sha = _git(self.repo, "rev-parse", "HEAD")
        self.aasm = self.dir / "aasm"
        self.aasm.write_text(STUB.format(python=sys.executable, version=version, mode=mode, key=KEY))
        self.aasm.chmod(self.aasm.stat().st_mode | stat.S_IXUSR)
        self.api = self.dir / "aa-api-server"
        self.api.write_text("stub api server binary\n")
        self.api.chmod(0o755)
        self.digests = self.dir / "digests.json"
        self.digests.write_text(json.dumps({"aasm": _sha(self.aasm), "aa-api-server": _sha(self.api)}))
        self.tmpdir = self.dir / "tmp"
        self.tmpdir.mkdir()

    def run(self, digests=True, fragment=False):
        out, frag = self.dir / "report.json", self.dir / "fragment.json"
        argv = [sys.executable, "-I", str(HARNESS), "--candidate-sha", self.sha, "--expected-version", "0.0.1-rc.8",
                "--repo", str(self.repo), "--aasm-bin", str(self.aasm), "--api-server-bin", str(self.api), "--out", str(out)]
        if digests:
            argv += ["--expected-digests", str(self.digests)]
        if fragment:
            argv += ["--obligation-fragment", str(frag)]
        p = subprocess.run(argv, env={"PATH": "/usr/bin:/bin", "TMPDIR": str(self.tmpdir)}, capture_output=True, text=True, timeout=180)
        return p.returncode, (json.loads(out.read_text()) if out.exists() else None), (frag.exists())


def st(rep, cid):
    return next(c["status"] for c in rep["candidate_checks"] if c["id"] == cid)


EXECUTED = ["j59-binary-identity", "j59-s2-start-health", "j59-s3-auth-enforced", "j59-s4-policy-load",
            "j59-s5-engine-allow-deny-approval", "j59-s6-s7-cli-operations", "j59-s6-dashboard-asset-served",
            "j59-s8-policy-change-apply", "j59-s9-change-flips-outcome", "j59-s10-diagnose-failures", "j59-s11-rollback",
            "j59-artifacts-bound-to-candidate"]


class J59HarnessTests(unittest.TestCase):
    def test_good_stub_passes_every_executed_check_but_is_never_verified(self):
        fx = Fixture(self)
        rc, rep, frag = fx.run(fragment=True)
        for cid in EXECUTED:
            self.assertEqual(st(rep, cid), "PASS", f"{cid}: {json.dumps(rep['candidate_checks'], indent=1)}")
        uncovered = [c["id"] for c in rep["candidate_checks"] if c["status"] == "NOT_COVERED"]
        self.assertEqual(len(uncovered), 5, uncovered)
        self.assertEqual(rep["verdict"], "CANDIDATE_INCOMPLETE")
        self.assertEqual(rc, 3)
        self.assertFalse(frag, "no obligation fragment while rows are NOT_COVERED")

    def test_all_twelve_steps_are_accounted_for(self):
        fx = Fixture(self)
        _, rep, _ = fx.run()
        ids = " ".join(c["id"] for c in rep["candidate_checks"]) + " " + " ".join(p["id"] for p in rep["pending_checks"])
        for step in range(2, 13):
            self.assertRegex(ids, rf"j59-s(\d+-)*{step}\b|j59-s{step}-", f"step {step} missing")
        self.assertIn("j59-install-release-assets", ids)  # step 1

    def test_publication_dependent_checks_are_never_pass(self):
        fx = Fixture(self)
        _, rep, _ = fx.run()
        self.assertTrue(all(p["status"] == "PENDING" for p in rep["pending_checks"]))
        self.assertFalse({p["id"] for p in rep["pending_checks"]} & {c["id"] for c in rep["candidate_checks"]})
        for p in rep["pending_checks"]:
            for f in ("channel", "why_publication_only", "command", "expected"):
                self.assertTrue(p[f].strip())

    def test_artifact_digests_recorded_for_every_consumed_file(self):
        fx = Fixture(self)
        _, rep, _ = fx.run()
        self.assertEqual(rep["artifacts"]["aasm"], _sha(fx.aasm))
        self.assertEqual(rep["artifacts"]["tool-calls.jsonl"], _sha(fx.repo / "scripts/qa/fixtures/j59/tool-calls.jsonl"))

    def test_scratch_dir_removed_and_no_server_left(self):
        fx = Fixture(self)
        fx.run()
        self.assertEqual(list(fx.tmpdir.iterdir()), [])
        ps = subprocess.run(["/bin/ps", "-axo", "command"], capture_output=True, text=True).stdout
        self.assertNotIn("__serve", ps)

    # --- negative controls ---

    def test_tampered_binary_fails(self):
        fx = Fixture(self)
        fx.aasm.write_text(fx.aasm.read_text() + "\n# tampered\n")
        rc, rep, frag = fx.run()
        self.assertEqual(st(rep, "j59-artifacts-bound-to-candidate"), "FAIL")
        self.assertEqual(rc, 1)

    def test_tampered_fixture_policy_fails(self):
        fx = Fixture(self)
        p = fx.repo / "scripts/qa/fixtures/j59/golden-path.v1.yaml"
        p.write_text(p.read_text() + "# edited after commit\n")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-artifacts-bound-to-candidate"), "FAIL")

    def test_missing_expected_digest_is_not_covered_never_pass(self):
        fx = Fixture(self)
        _, rep, _ = fx.run(digests=False)
        self.assertEqual(st(rep, "j59-artifacts-bound-to-candidate"), "NOT_COVERED")

    def test_wrong_version_fails(self):
        fx = Fixture(self, version="0.0.1-rc.7")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-binary-identity"), "FAIL")

    def test_start_failure_fails(self):
        fx = Fixture(self, mode="start_fail")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s2-start-health"), "FAIL")

    def test_unhealthy_gateway_fails(self):
        fx = Fixture(self, mode="unhealthy")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s2-start-health"), "FAIL")

    def test_unauthenticated_api_fails(self):
        fx = Fixture(self, mode="open_api")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s3-auth-enforced"), "FAIL")

    def test_policy_apply_failure_fails(self):
        fx = Fixture(self, mode="apply_fail")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s4-policy-load"), "FAIL")
        self.assertEqual(st(rep, "j59-s8-policy-change-apply"), "FAIL")

    def test_engine_that_denies_everything_fails(self):
        fx = Fixture(self, mode="engine_deny_all")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s5-engine-allow-deny-approval"), "FAIL")

    def test_engine_that_ignores_policy_fails(self):
        fx = Fixture(self, mode="engine_ignore_policy")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s9-change-flips-outcome"), "FAIL")

    def test_cli_command_failure_fails(self):
        fx = Fixture(self, mode="cli_fail")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s6-s7-cli-operations"), "FAIL")

    def test_dashboard_placeholder_fails(self):
        fx = Fixture(self, mode="dashboard_placeholder")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s6-dashboard-asset-served"), "FAIL")

    def test_rejected_apply_that_changes_state_fails(self):
        fx = Fixture(self, mode="bad_apply_mutates")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s10-diagnose-failures"), "FAIL")

    def test_rollback_not_restoring_fails(self):
        fx = Fixture(self, mode="rollback_broken")
        _, rep, _ = fx.run()
        self.assertEqual(st(rep, "j59-s11-rollback"), "FAIL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
