"""Self-tests for scripts/qa/j08-j56-candidate-harness.py (AAASM-6439).

No SDK and no candidate binaries are needed: `FakeBackend` replaces the harness's exec
seam and simulates the SDK driver, the policy state and the sentinel side effects. `mode`
selects one deliberately broken behaviour; each `*_fails` test is the negative control for
one check, running the real harness logic and asserting that exact check goes red. The
static README check and the digest binding run for real, over a fake wheel and a throwaway
git repo that carries the real J56 fixtures.

Run: python3 -I scripts/tests/test_j08_j56_candidate_harness.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts/qa/j08-j56-candidate-harness.py"
sys.path.insert(0, str(ROOT / "scripts/qa"))
_spec = importlib.util.spec_from_file_location("j08_j56_harness", HARNESS)
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

FIXTURES = ["golden-path.v1.yaml", "golden-path.v2-read-deny.yaml", "sdk_driver.py"]
VERSION = "0.0.1-rc.8"
README_CLAIM = "1. `init_assembly()` registers the agent with the gateway and auto-loads the LangChain adapter.\n"


def _sha(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def _git(repo: Path, *a: str) -> str:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(repo), "PATH": "/usr/bin:/bin"}
    return subprocess.run(["/usr/bin/git", "-C", str(repo), *a], env=env, check=True, capture_output=True, text=True).stdout.strip()


def make_wheel(path: Path, readme: str = README_CLAIM, code: str = "x = 1\n") -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("agent_assembly-0.0.1rc8.dist-info/METADATA", "Name: agent-assembly\n\n" + readme)
        z.writestr("agent_assembly/core/assembly.py", code)


class FakeBackend(H.Backend):
    """Simulates the stack. `mode` breaks exactly one behaviour."""

    def __init__(self, mode: str, ctx, version: str = VERSION):
        self.mode, self.ctx, self.version = mode, ctx, version
        self.agent = "j56-fake"
        self.read_allowed = True
        self.log: list[tuple[str, str]] = []
        self.install_cmds: list[object] = []

    def version_of(self, name):
        return 0, f"{name} {'0.0.1-rc.7' if self.mode == 'wrong_version' else self.version}\n"

    def install(self):
        return (1, "no matching distribution") if self.mode == "install_fail" else (0, "ok")

    def start(self, policy):
        return (False, "aasm start exited 1") if self.mode == "start_fail" else (True, "")

    def apply_policy(self, policy):
        if self.mode == "apply_fail":
            return 1, "nope"
        if "1.1.0" in Path(policy).read_text() and self.mode != "flip_ignored":
            self.read_allowed = False
        return 0, "applied"

    def agent_list(self):
        return 0, self.agent + "\n"

    def audit(self, agent):
        if self.mode == "audit_fail":
            return 1, "boom"
        entries = [{"tool": t, "result": r} for t, r in self.log if not (self.mode == "audit_no_deny" and r == "deny")]
        return 0, json.dumps({"entries": entries})

    def stop(self):
        pass

    def sdk(self, op, **kw):
        if op == "import-core":
            return {"ok": False, "error": "ModuleNotFoundError"} if self.mode == "no_core" else {"ok": True, "sdk_version": "0.0.1rc8"}
        if op == "register":
            good = kw.get("key") == self.good_key
            return {"registered": good or self.mode == "wrong_key_registers", "agent": self.agent}
        tool, s, unwired = kw["tool"], Path(kw["sentinel"]), kw.get("unwired", False)
        if unwired:
            if self.mode == "unwired_still_blocked":
                return {"executed": False, "error": "ToolExecutionBlockedError", "typed": True}
            s.unlink(missing_ok=True)
            return {"executed": True, "error": None, "typed": False}
        deny = (tool == "delete_file" and self.mode != "delete_allowed") or (tool == "read_file" and (not self.read_allowed or self.mode == "read_blocked"))
        if tool == "send_email":
            if self.mode == "email_sent":
                Path(str(s) + ".sent").write_text("sent\n")
                return {"executed": True, "error": None, "typed": False}
            return {"executed": False, "error": "ToolExecutionBlockedError", "typed": True}
        if deny:
            self.log.append((tool, "deny"))
            if self.mode == "delete_untyped" and tool == "delete_file":
                return {"executed": False, "error": "RuntimeError", "typed": False}
            return {"executed": False, "error": "PolicyViolationError", "typed": True}
        self.log.append((tool, "allow"))
        if tool == "delete_file":
            s.unlink(missing_ok=True)
        return {"executed": True, "error": None, "typed": False}


class Fixture:
    def __init__(self, tc: unittest.TestCase, journey="J56", mode="good", wheel_code="register_configure_hook\n", readme=README_CLAIM):
        self.tc, self.journey, self.mode = tc, journey, mode
        self.dir = Path(tempfile.mkdtemp(prefix="j08j56-selftest-"))
        tc.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.repo = self.dir / "repo"
        fx = self.repo / "scripts/qa/fixtures/j56"
        fx.mkdir(parents=True)
        for n in FIXTURES:
            shutil.copy(ROOT / "scripts/qa/fixtures/j56" / n, fx / n)
        _git(self.repo, "init", "-q")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "fixture")
        self.sha = _git(self.repo, "rev-parse", "HEAD")
        self.bins = {}
        for n in ("aasm", "aa-gateway", "aa-runtime", "aa-api-server"):
            self.bins[n] = self.dir / n
            self.bins[n].write_text(f"stub {n}\n")
            self.bins[n].chmod(0o755)
        self.wheel = self.dir / "agent_assembly-0.0.1rc8-py3-none-any.whl"
        make_wheel(self.wheel, readme, wheel_code)
        self.digests = self.dir / "digests.json"
        self.write_digests()
        self.out = self.dir / "report.json"
        self.frag = self.dir / "fragment.json"

    def write_digests(self, **override: str) -> None:
        d = {n: _sha(p) for n, p in self.bins.items()}
        d["python-sdk-wheel"] = _sha(self.wheel)
        d.update(override)
        self.digests.write_text(json.dumps(d))

    def argv(self, digests=True, sdk_sha="b" * 40):
        a = ["--journey", self.journey, "--candidate-sha", self.sha, "--version", VERSION, "--repo", str(self.repo),
             "--gateway", str(self.bins["aa-gateway"]), "--runtime", str(self.bins["aa-runtime"]),
             "--api-server", str(self.bins["aa-api-server"]), "--aasm", str(self.bins["aasm"]),
             "--sdk-wheel", str(self.wheel), "--sdk-sha", sdk_sha, "--out", str(self.out),
             "--obligation-fragment", str(self.frag)]
        return a + (["--expected-digests", str(self.digests)] if digests else [])

    def run(self, digests=True, sdk_sha="b" * 40):
        self.backend = None

        def factory(ctx, bins, wheel, driver):
            self.backend = FakeBackend(self.mode, ctx)
            return self.backend

        rc = H.run_harness(self.argv(digests, sdk_sha), factory)
        return rc, json.loads(self.out.read_text())


def st(rep, cid):
    return next(c["status"] for c in rep["candidate_checks"] if c["id"] == cid)


def registry_ids(journey: str) -> list[str]:
    text = (ROOT / "qa/golden-journeys.yaml").read_text()
    block = re.search(rf"^- id: {journey}\n(.*?)(?=^- id: )", text, re.M | re.S).group(1)
    return re.findall(r"- id: (j\d+-published-[\w-]+)", block)


J56_EXECUTED = ["j56-c-artifacts-bound-to-candidate", "j56-c-binary-identity", "j56-c-install-clean-venv-native-core",
                "j56-c-register-authenticated", "j56-c-allow-read-file", "j56-c-deny-delete-file-typed-no-sideeffect",
                "j56-c-audit-correlation", "j56-c-policy-flip-changes-behavior", "j56-c-unwired-callbacks-control"]


class HarnessShapeTests(unittest.TestCase):
    def test_good_j56_passes_executed_checks_and_is_never_verified(self):
        fx = Fixture(self)
        rc, rep = fx.run()
        for cid in J56_EXECUTED:
            self.assertEqual(st(rep, cid), "PASS", f"{cid}: {json.dumps(rep['candidate_checks'], indent=1)}")
        self.assertEqual(rep["schema"], "b1-candidate-report/1")
        self.assertEqual(rep["verdict"], "CANDIDATE_INCOMPLETE")
        self.assertEqual(rc, 3)
        self.assertFalse(fx.frag.exists(), "no obligation fragment while a row is NOT_COVERED")

    def test_send_email_is_a_classified_gap_never_pass(self):
        _, rep = Fixture(self).run()
        row = next(c for c in rep["candidate_checks"] if c["id"] == "j56-c-send-email-approval-or-gap")
        self.assertEqual(row["status"], "NOT_COVERED")
        self.assertEqual(row["fidelity"], "none")
        self.assertIn("gap:", row["detail"])

    def test_pending_ids_equal_registry_ids_and_are_never_pass(self):
        for journey in ("J08", "J56"):
            _, rep = Fixture(self, journey=journey).run()
            self.assertEqual([p["id"] for p in rep["pending_checks"]], registry_ids(journey))
            self.assertTrue(all(p["status"] == "PENDING" and p["channel"] == "pypi" for p in rep["pending_checks"]))
            self.assertFalse({p["id"] for p in rep["pending_checks"]} & {c["id"] for c in rep["candidate_checks"]})

    def test_record_is_bound_to_candidate_sdk_sha_and_wheel_digest(self):
        fx = Fixture(self)
        _, rep = fx.run(sdk_sha="c" * 40)
        self.assertEqual(rep["candidate_sha"], fx.sha)
        self.assertEqual(rep["sdk_sha"], "c" * 40)
        self.assertEqual(rep["sdk_wheel_sha256"], _sha(fx.wheel))
        self.assertEqual(rep["artifacts"]["python-sdk-wheel"], _sha(fx.wheel))

    def test_good_j08_with_wired_hook_is_verified_and_emits_fragment(self):
        fx = Fixture(self, journey="J08")
        rc, rep = fx.run()
        self.assertEqual({c["id"]: c["status"] for c in rep["candidate_checks"]}.get("j08-c-allow-deny"), "PASS")
        self.assertEqual(rep["verdict"], "CANDIDATE_VERIFIED", json.dumps(rep["candidate_checks"], indent=1))
        self.assertEqual(rc, 0)
        self.assertTrue(fx.frag.exists())

    def test_usage_errors_are_exit_2_without_traceback(self):
        fx = Fixture(self)
        for argv in (fx.argv(sdk_sha="nothex"), [a if a != fx.sha else "xyz" for a in fx.argv()]):
            with self.assertRaises(SystemExit) as e:
                H.run_harness(argv)
            self.assertEqual(e.exception.code, 2)
        fx.wheel.unlink()
        self.assertEqual(H.run_harness(fx.argv()), 2)

    def test_install_uses_offline_find_links_in_a_clean_env(self):
        calls = []
        ctx = H.c.Context("J56", "a" * 40, VERSION)
        self.addCleanup(ctx.cleanup)
        wheel = ctx.tmp / "w" / "agent_assembly-0.0.1rc8-py3-none-any.whl"
        wheel.parent.mkdir()
        make_wheel(wheel)
        bins = {}
        for n in ("aasm", "aa-gateway", "aa-runtime", "aa-api-server"):
            bins[n] = ctx.tmp / f"src-{n}"
            bins[n].write_text("x")
        be = H.LocalBackend(ctx, bins, wheel, ROOT / "scripts/qa/fixtures/j56/sdk_driver.py",
                            exec_fn=lambda argv, env, cwd, timeout=30: (calls.append((argv, env)) or (0, "")))
        be.install()
        pip = calls[-1][0]
        self.assertIn("--no-index", pip)
        self.assertEqual(pip[pip.index("--find-links") + 1], str(wheel.parent))
        self.assertEqual(set(calls[-1][1]) & {"PYTHONPATH", "PIP_INDEX_URL", "VIRTUAL_ENV"}, set())


class StaticReadmeTests(unittest.TestCase):
    def test_claim_without_a_langchain_hook_fails(self):
        _, rep = Fixture(self, journey="J08", wheel_code="_ACTIVE = None\n").run()
        self.assertEqual(st(rep, "j08-c-readme-snippet-matches-wiring"), "FAIL")
        self.assertEqual(rep["verdict"], "BLOCK")

    def test_claim_with_a_hook_passes(self):
        _, rep = Fixture(self, journey="J08").run()
        self.assertEqual(st(rep, "j08-c-readme-snippet-matches-wiring"), "PASS")

    def test_no_claim_is_not_covered_never_pass(self):
        _, rep = Fixture(self, journey="J08", readme="nothing relevant\n").run()
        self.assertEqual(st(rep, "j08-c-readme-snippet-matches-wiring"), "NOT_COVERED")

    def test_unreadable_wheel_is_not_covered(self):
        fx = Fixture(self, journey="J08")
        fx.wheel.write_text("not a zip")
        fx.write_digests()
        _, rep = fx.run()
        self.assertEqual(st(rep, "j08-c-readme-snippet-matches-wiring"), "NOT_COVERED")


class NegativeControlTests(unittest.TestCase):
    def check(self, mode, cid, journey="J56", want="FAIL"):
        _, rep = Fixture(self, journey=journey, mode=mode).run()
        self.assertEqual(st(rep, cid), want, json.dumps(rep["candidate_checks"], indent=1))
        return rep

    def test_tampered_wheel_digest_fails(self):
        fx = Fixture(self)
        fx.write_digests(**{"python-sdk-wheel": "sha256:" + "0" * 64})
        rc, rep = fx.run()
        self.assertEqual(st(rep, "j56-c-artifacts-bound-to-candidate"), "FAIL")
        self.assertEqual(rc, 1)

    def test_missing_expected_digest_is_not_covered_never_pass(self):
        _, rep = Fixture(self).run(digests=False)
        self.assertEqual(st(rep, "j56-c-artifacts-bound-to-candidate"), "NOT_COVERED")

    def test_wrong_version_fails(self):
        self.check("wrong_version", "j56-c-binary-identity")

    def test_install_failure_fails_and_skips_dependents_as_not_covered(self):
        rep = self.check("install_fail", "j56-c-install-clean-venv-native-core")
        self.assertEqual(st(rep, "j56-c-allow-read-file"), "NOT_COVERED")

    def test_missing_native_core_fails(self):
        self.check("no_core", "j56-c-install-clean-venv-native-core")

    def test_stack_start_failure_fails(self):
        rep = self.check("start_fail", "j56-c-register-authenticated")
        self.assertEqual(st(rep, "j56-c-deny-delete-file-typed-no-sideeffect"), "NOT_COVERED")

    def test_wrong_key_registering_fails(self):
        self.check("wrong_key_registers", "j56-c-register-authenticated")
        self.check("wrong_key_registers", "j08-c-register-governed-agent", journey="J08")

    def test_read_file_blocked_fails(self):
        self.check("read_blocked", "j56-c-allow-read-file")

    def test_delete_allowed_leaves_side_effect_fails(self):
        rep = self.check("delete_allowed", "j56-c-deny-delete-file-typed-no-sideeffect")
        self.assertIn("side effect", next(c["detail"] for c in rep["candidate_checks"] if c["id"].endswith("no-sideeffect")))
        self.check("delete_allowed", "j08-c-allow-deny", journey="J08")

    def test_untyped_error_fails_even_though_sentinel_is_intact(self):
        self.check("delete_untyped", "j56-c-deny-delete-file-typed-no-sideeffect")

    def test_send_email_executed_without_approval_fails(self):
        self.check("email_sent", "j56-c-send-email-approval-or-gap")

    def test_audit_without_the_deny_fails(self):
        self.check("audit_no_deny", "j56-c-audit-correlation")
        self.check("audit_fail", "j56-c-audit-correlation")

    def test_policy_flip_ignored_fails(self):
        self.check("flip_ignored", "j56-c-policy-flip-changes-behavior")

    def test_unwired_control_still_blocked_fails(self):
        self.check("unwired_still_blocked", "j56-c-unwired-callbacks-control")


if __name__ == "__main__":
    unittest.main(verbosity=2)
