#!/usr/bin/env python3
"""Self-tests for scripts/qa/b1/candidate_harness.py. Hermetic: build a fixture
release mirror (fake binaries), run the harness as a subprocess, assert on its
real exit code and JSON. Needs no candidate artifacts and no network.

Run: python3 -I scripts/tests/test_b1_candidate_harness.py
"""
from __future__ import annotations

import glob
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts/qa/b1/candidate_harness.py"
CONTROL = ROOT / "scripts/qa/b1/fixtures/install-cli.pre-aaasm-6414.sh"
INSTALLER = ROOT / "scripts/install-cli.sh"
POLICY = ROOT / "policy-examples/low-risk.yaml"
VER = "v0.0.1-rc.8"
SHA = "a" * 40

_spec = importlib.util.spec_from_file_location("candidate_harness", HARNESS)
H = importlib.util.module_from_spec(_spec)
sys.modules["candidate_harness"] = H
_spec.loader.exec_module(H)

PY = sys.executable
FAKE_PLAIN = "#!/bin/sh\necho fake\n"


def fake_aasm(version: str = VER.lstrip("v")) -> str:
    return f"""#!{PY}
import os, subprocess, sys
a = sys.argv[1:]
if a == ["--version"]:
    print("aasm {version}"); sys.exit(0)
dd = os.environ["AA_DATA_DIR"]; pidf = os.path.join(dd, "gateway.pid")
def alive():
    try:
        os.kill(int(open(pidf).read().split()[0]), 0); return True
    except Exception:
        return False
if a[:2] == ["gateway", "start"]:
    pol = a[a.index("--policy") + 1]; listen = a[a.index("--listen") + 1]
    gw = os.path.join(os.path.dirname(os.path.realpath(__file__)), "aa-gateway")
    p = subprocess.Popen([gw, "--policy", pol, "--listen", listen], start_new_session=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.makedirs(dd, exist_ok=True); open(pidf, "w").write(f"{{p.pid}} {{listen}}\\n"); sys.exit(0)
if a[:2] == ["gateway", "status"]:
    sys.exit(0 if alive() else 1)
if a[:2] == ["gateway", "stop"]:
    if alive():
        os.kill(int(open(pidf).read().split()[0]), 15)
    if os.path.exists(pidf):
        os.remove(pidf)
    sys.exit(0)
sys.exit(2)
"""


def fake_gateway(mode: str = "ok", version: str = VER.lstrip("v")) -> str:
    """mode: ok | hang (never listens, records pid) | ignore_policy (listens even without a policy)."""
    return f"""#!{PY}
import os, socket, sys, time
a = sys.argv[1:]
if a == ["--version"]:
    print("aa-gateway {version}"); sys.exit(0)
if "--db-path" in a:
    d = os.path.dirname(a[a.index("--db-path") + 1]); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "pid"), "w").write(str(os.getpid()))
if "{mode}" == "hang":
    time.sleep(600)
pol = a[a.index("--policy") + 1] if "--policy" in a else None
if "{mode}" != "ignore_policy" and (not pol or not os.path.isfile(pol)):
    sys.stderr.write("policy file not found\\n"); sys.exit(2)
host, port = a[a.index("--listen") + 1].rsplit(":", 1)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, int(port))); s.listen(8)
time.sleep(600)
"""


FAKE_API = f"""#!{PY}
import os, socket, sys, time
if "AASM_API_KEY" not in os.environ:
    sys.exit(3)
host, port = os.environ["AA_API_ADDR"].rsplit(":", 1)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, int(port))); s.listen(8)
time.sleep(600)
"""


def make_tar(path: Path, members: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as t:
        for name, body in members.items():
            data = body.encode()
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o755
            t.addfile(ti, io.BytesIO(data))


def write_sums(d: Path) -> None:
    lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}" for f in sorted(d.glob("*.tar.gz"))]
    (d / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def build_mirror(d: Path, plat: "H.Platform", cli_members=None, api_members=None, runtime=True, proxy=True,
                 gateway: str | None = None) -> None:
    d.mkdir(parents=True, exist_ok=True)
    for old in d.glob("*.tar.gz"):
        old.unlink()
    make_tar(d / plat.cli_tarball(), cli_members or {"aasm": fake_aasm(), "aa-gateway": gateway or fake_gateway()})
    make_tar(d / plat.component_tarball("api", VER), api_members or {"aa-api-server": FAKE_API})
    if runtime:
        make_tar(d / plat.component_tarball("runtime", VER), {"aa-runtime": FAKE_PLAIN})
    if proxy:
        make_tar(d / plat.component_tarball("proxy", VER), {"aa-proxy": FAKE_PLAIN})
    write_sums(d)


def run(journey: str, mirror: Path, *extra: str, sha: str | None = SHA) -> tuple[int, dict]:
    cmd = [sys.executable, "-I", str(HARNESS), journey, "--mirror-dir", str(mirror), "--version", VER]
    if sha:
        cmd += ["--candidate-sha", sha]
    p = subprocess.run(cmd + list(extra), capture_output=True, text=True, timeout=900)
    try:
        out = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise AssertionError(f"harness stdout not JSON (rc={p.returncode}): {p.stdout[:300]} {p.stderr[:300]}")
    return p.returncode, out


def status(out: dict, cid: str) -> str:
    for c in out["candidate_checks"]:
        if c["id"] == cid:
            return c["status"]
    raise AssertionError(f"no check {cid}; have {[c['id'] for c in out['candidate_checks']]}")


J04_IDS = {
    "j04.sha256sums_match_artifacts", "j04.installer_default_installs_all_binaries", "j04.installer_version_pin_env",
    "j04.installer_latest_resolution", "j04.installer_refuses_tampered_tarball", "j04.installer_uninstall_removes_binaries",
    "j04.installer_components_cli_runtime", "j04.installer_profile_local_installs_runtime", "j04.installer_profile_full",
    "j04.installed_aasm_version_output", "j04.installed_gateway_version_output", "j04.installed_api_server_starts",
    "j04.negative_control_old_installer_fails",
}
J17_IDS = {
    "j17.installer_places_gateway_beside_aasm", "j17.installed_gateway_version_output", "j17.gateway_serves_sample_policy",
    "j17.aasm_gateway_start_status_stop", "j17.negative_control_old_installer_has_no_gateway",
}


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="b1-selftest-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.plat = H.Platform(None)
        self.mirror = self.tmp / "mirror"
        build_mirror(self.mirror, self.plat)

    # ---- good candidate
    def test_j04_good_candidate_passes_with_all_expected_checks(self) -> None:
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 0, json.dumps(out["candidate_checks"], indent=1))
        self.assertEqual({c["id"] for c in out["candidate_checks"]}, J04_IDS)
        self.assertTrue(all(c["status"] == "PASS" for c in out["candidate_checks"]))
        self.assertEqual(out["not_run"], [])
        self.assertEqual(out["candidate_sha"], SHA)
        self.assertEqual(out["overall"], "CANDIDATE_PASS_PUBLICATION_PENDING")

    def test_j17_good_candidate_passes_with_all_expected_checks(self) -> None:
        rc, out = run("j17", self.mirror)
        self.assertEqual(rc, 0, json.dumps(out["candidate_checks"], indent=1))
        self.assertEqual({c["id"] for c in out["candidate_checks"]}, J17_IDS)
        self.assertTrue(all(c["status"] == "PASS" for c in out["candidate_checks"]))

    # ---- negative controls
    def test_old_installer_fails_the_same_harness(self) -> None:
        for j, cid in (("j04", "j04.installer_default_installs_all_binaries"),
                       ("j17", "j17.installer_places_gateway_beside_aasm")):
            rc, out = run(j, self.mirror, "--installer", str(CONTROL))
            self.assertEqual(rc, 1)
            self.assertEqual(status(out, cid), "FAIL")
            self.assertEqual(out["overall"], "CANDIDATE_FAIL")

    def test_control_that_passes_everything_is_a_failure(self) -> None:
        rc, out = run("j04", self.mirror, "--control-installer", str(INSTALLER), "--allow-unpinned-control")
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.negative_control_old_installer_fails"), "FAIL")

    def test_control_must_match_the_pinned_digest(self) -> None:
        rc, out = run("j04", self.mirror, "--control-installer", str(INSTALLER))
        self.assertEqual(rc, 1)
        c = next(c for c in out["candidate_checks"] if c["id"] == "j04.negative_control_old_installer_fails")
        self.assertEqual(c["status"], "FAIL")
        self.assertIn("pinned", c["detail"])

    def test_unpinned_but_defective_control_is_unpinned_not_pass(self) -> None:
        mod = self.tmp / "control-mod.sh"
        mod.write_bytes(CONTROL.read_bytes() + b"\n# modified\n")
        rc, out = run("j04", self.mirror, "--control-installer", str(mod), "--allow-unpinned-control")
        self.assertEqual(rc, 3)
        self.assertEqual(out["overall"], "UNPINNED_CONTROL")
        self.assertFalse(out["control_pinned"])
        self.assertEqual(status(out, "j04.negative_control_old_installer_fails"), "PASS")

    def test_control_must_show_the_specific_defect_not_just_any_failure(self) -> None:
        broken = self.tmp / "broken.sh"
        broken.write_text("#!/bin/sh\nexit 1\n")
        rc, out = run("j04", self.mirror, "--control-installer", str(broken), "--allow-unpinned-control")
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.negative_control_old_installer_fails"), "FAIL")

    def test_control_fixture_is_byte_identical_to_history_and_pinned(self) -> None:
        self.assertEqual(hashlib.sha256(CONTROL.read_bytes()).hexdigest(), H.CONTROL_SHA256)
        p = subprocess.run(["/usr/bin/git", "-C", str(ROOT), "show", "1f6a2011f^1:scripts/install-cli.sh"],
                           capture_output=True)
        if p.returncode != 0:
            self.skipTest("history not available (shallow clone)")
        self.assertEqual(p.stdout, CONTROL.read_bytes())

    def test_installer_that_skips_checksum_verification_fails_the_tamper_check(self) -> None:
        text = INSTALLER.read_text()
        self.assertIn("sha256_verify() {\n", text)
        patched = self.tmp / "install-noverify.sh"
        patched.write_text(text.replace("sha256_verify() {\n", "sha256_verify() {\n  say 'SHA256 verified.'; return 0\n", 1))
        rc, out = run("j04", self.mirror, "--installer", str(patched))
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.installer_refuses_tampered_tarball"), "FAIL")

    # ---- tamper / defect candidates
    def test_tampered_sha256sums_fails(self) -> None:
        sums = (self.mirror / "SHA256SUMS").read_text().replace(self.plat.cli_tarball(), self.plat.cli_tarball() + ".x", 1)
        (self.mirror / "SHA256SUMS").write_text(sums)
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.sha256sums_match_artifacts"), "FAIL")
        self.assertEqual(status(out, "j04.installer_default_installs_all_binaries"), "FAIL")

    def test_tampered_tarball_fails(self) -> None:
        t = self.mirror / self.plat.cli_tarball()
        b = bytearray(t.read_bytes())
        b[len(b) // 2] ^= 0xFF
        t.write_bytes(bytes(b))
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.sha256sums_match_artifacts"), "FAIL")
        self.assertEqual(status(out, "j04.installer_default_installs_all_binaries"), "FAIL")

    def test_cli_tarball_without_gateway_fails_j17(self) -> None:
        build_mirror(self.mirror, self.plat, cli_members={"aasm": fake_aasm()})
        rc, out = run("j17", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j17.installer_places_gateway_beside_aasm"), "FAIL")

    def test_gateway_that_never_listens_fails_j17(self) -> None:
        build_mirror(self.mirror, self.plat, gateway=fake_gateway("hang"))
        rc, out = run("j17", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j17.gateway_serves_sample_policy"), "FAIL")

    def test_gateway_that_ignores_a_missing_policy_fails_the_inversion(self) -> None:
        build_mirror(self.mirror, self.plat, gateway=fake_gateway("ignore_policy"))
        rc, out = run("j17", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j17.gateway_serves_sample_policy"), "FAIL")

    def test_wrong_version_output_fails(self) -> None:
        build_mirror(self.mirror, self.plat, cli_members={"aasm": fake_aasm("9.9.9"), "aa-gateway": fake_gateway()})
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.installed_aasm_version_output"), "FAIL")

    def test_api_server_that_does_not_start_fails(self) -> None:
        build_mirror(self.mirror, self.plat, api_members={"aa-api-server": "#!/bin/sh\nexit 1\n"})
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.installed_api_server_starts"), "FAIL")

    # ---- INCOMPLETE (not_run) semantics
    def test_missing_runtime_tarball_is_incomplete(self) -> None:
        build_mirror(self.mirror, self.plat, runtime=False)
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 3)
        self.assertEqual(out["overall"], "INCOMPLETE")
        ids = {n["id"] for n in out["not_run"]}
        self.assertIn("j04.installer_components_cli_runtime", ids)
        self.assertIn("j04.installer_profile_full", ids)

    def test_missing_proxy_tarball_is_incomplete(self) -> None:
        build_mirror(self.mirror, self.plat, proxy=False)
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 3)
        self.assertEqual({n["id"] for n in out["not_run"]}, {"j04.installer_profile_full"})

    def _foreign(self) -> "H.Platform":
        spec = "linux/x86_64" if self.plat.host != ("linux", "x86_64") else "darwin/aarch64"
        o, a = spec.split("/")
        return H.Platform(spec)

    def test_foreign_platform_is_incomplete_for_j04_and_j17(self) -> None:
        other = self._foreign()
        mirror = self.tmp / "other"
        build_mirror(mirror, other)
        spec = f"{other.os}/{other.arch}"
        rc, out = run("j04", mirror, "--platform", spec)
        self.assertEqual(rc, 3, json.dumps(out["candidate_checks"], indent=1))
        self.assertEqual(out["overall"], "INCOMPLETE")
        self.assertNotIn("j04.installed_aasm_version_output", [c["id"] for c in out["candidate_checks"]])
        self.assertIn("j04.installed_aasm_version_output", [n["id"] for n in out["not_run"]])
        rc, out = run("j17", mirror, "--platform", spec)
        self.assertEqual(rc, 3)
        self.assertEqual({n["id"] for n in out["not_run"]},
                         {"j17.installed_gateway_version_output", "j17.gateway_serves_sample_policy",
                          "j17.aasm_gateway_start_status_stop"})

    # ---- usage
    def test_candidate_sha_is_required_and_validated(self) -> None:
        for sha in (None, "XYZ"):
            cmd = [sys.executable, "-I", str(HARNESS), "j04", "--mirror-dir", str(self.mirror), "--version", VER]
            if sha:
                cmd += ["--candidate-sha", sha]
            self.assertEqual(subprocess.run(cmd, capture_output=True, text=True).returncode, 2)

    def test_missing_mirror_is_usage_error(self) -> None:
        p = subprocess.run([sys.executable, "-I", str(HARNESS), "j04", "--mirror-dir", str(self.tmp / "nope"),
                            "--version", VER, "--candidate-sha", SHA], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)

    # ---- output contract
    def test_candidate_checks_carry_digests_bound_to_real_files(self) -> None:
        _, out = run("j17", self.mirror)
        cli = self.mirror / self.plat.cli_tarball()
        want = "sha256:" + hashlib.sha256(cli.read_bytes()).hexdigest()
        for c in out["candidate_checks"]:
            self.assertTrue(c["artifact_digests"])
            for k, v in c["artifact_digests"].items():
                self.assertRegex(v, r"^sha256:[0-9a-f]{64}$", k)
            self.assertEqual(c["fidelity"], "real_local_process")
            self.assertEqual(c["candidate_sha"], SHA)
        first = next(c for c in out["candidate_checks"] if c["id"] == "j17.installer_places_gateway_beside_aasm")
        self.assertEqual(first["artifact_digests"][self.plat.cli_tarball()], want)
        gw = next(c for c in out["candidate_checks"] if c["id"] == "j17.gateway_serves_sample_policy")
        self.assertEqual(gw["artifact_digests"]["policy:low-risk.yaml"],
                         "sha256:" + hashlib.sha256(POLICY.read_bytes()).hexdigest())
        ctl = next(c for c in out["candidate_checks"] if c.get("negative_control") and "control" in c["id"])
        self.assertIn("control-installer:install-cli.pre-aaasm-6414.sh", ctl["artifact_digests"])

    def test_not_covered_is_explicit(self) -> None:
        _, j04 = run("j04", self.mirror)
        _, j17 = run("j17", self.mirror)
        self.assertEqual([n["id"] for n in j04["not_covered"]], ["j04.ac.cargo_install_aa_cli_docs_decision"])
        self.assertEqual({n["id"] for n in j17["not_covered"]},
                         {"j17.ac.docs_not_only_cargo_run", "j17.ac.policy_format_unambiguous",
                          "j17.ac.aasm_status_topology_agent_list_healthy"})
        for n in j04["not_covered"] + j17["not_covered"]:
            self.assertTrue(n["reason"].strip() and n["ac"].strip())

    def test_harness_cleans_up(self) -> None:
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "b1-harness-*")))
        run("j04", self.mirror)
        self.assertEqual(before, set(glob.glob(os.path.join(tempfile.gettempdir(), "b1-harness-*"))))

    def test_fragment_validates_against_publication_obligations_module(self) -> None:
        src = ROOT / "scripts/qa/publication_obligations.py"
        text = None
        if src.is_file():
            text = src.read_text()
        else:
            p = subprocess.run(["/usr/bin/git", "-C", str(ROOT), "show",
                                "remote/v0.0.1/AAASM-6419/feat/publication_pending_gate:scripts/qa/publication_obligations.py"],
                               capture_output=True, text=True)
            text = p.stdout if p.returncode == 0 else None
        if not text:
            self.skipTest("publication_obligations.py not available")
        spec = importlib.util.spec_from_file_location("publication_obligations", self.tmp / "po.py")
        (self.tmp / "po.py").write_text(text)
        po = importlib.util.module_from_spec(spec)
        sys.modules["publication_obligations"] = po
        spec.loader.exec_module(po)
        for j, ids in (("j04", J04_IDS), ("j17", J17_IDS)):
            rc, out = run(j, self.mirror)
            frag = dict(out["obligation_fragment"])
            self.assertEqual(frag["_unfilled"], ["registry_digest", "depends_on"])
            self.assertIsNone(frag["registry_digest"])
            self.assertIsNone(frag["depends_on"])
            for p in frag["pending_checks"]:
                self.assertEqual(p["status"], "PUBLICATION_PENDING")
            frag["registry_digest"] = "d"
            frag["depends_on"] = [{"repo": "agent-assembly", "event": "release-published"}]
            catalog = {"fidelity": "published_artifact", "negative_control": True,
                       "publication_checks": [{"id": p["id"]} for p in frag["pending_checks"]]}
            self.assertEqual(po.validate_obligation(j.upper(), frag, catalog, "d"), [])
            self.assertEqual(rc, 0)

    # ---- pending (publication) commands
    def _pending(self, j: str) -> list[dict]:
        _, out = run(j, self.mirror)
        for p in out["pending_checks"]:
            self.assertEqual(p["status"], "PENDING")
            for f in ("id", "channel", "why_publication_only", "command", "expected", "failure_response", "side_effects"):
                self.assertTrue(isinstance(p[f], str) and p[f].strip(), (p["id"], f))
            self.assertNotIn("<TAG>", p["command"])
            self.assertIn(VER, p["command"])
            self.assertNotIn(p["id"], {c["id"] for c in out["candidate_checks"]})
            for bad in ("git push", "git tag", "cargo publish", "npm publish", "twine", "gh release create",
                        "gh release delete", "sudo", "brew uninstall"):
                self.assertNotIn(bad, p["command"])
        return out["pending_checks"]

    def test_pending_commands_are_syntactically_valid_single_sh_c(self) -> None:
        for j in ("j04", "j17"):
            for p in self._pending(j):
                argv = shlex.split(p["command"])
                self.assertEqual(argv[:2], ["sh", "-c"], p["id"])
                self.assertEqual(len(argv), 3)
                f = self.tmp / (p["id"] + ".sh")
                f.write_text(argv[2])
                self.assertEqual(subprocess.run(["sh", "-n", str(f)], capture_output=True).returncode, 0, p["id"])

    def _release_stand_in(self) -> dict:
        rel = self.tmp / "rel"
        (rel / VER).mkdir(parents=True)
        for f in self.mirror.iterdir():
            shutil.copy2(f, rel / VER / f.name)
        (rel / VER / "SHA256SUMS.cosign.bundle").write_text("{}")
        wrap = self.tmp / "wrap"
        wrap.mkdir()
        (wrap / "shim").write_text(H.CURL_SHIM)
        (wrap / "curl").write_text(
            '#!/bin/sh\nfor a in "$@"; do case "$a" in file://*) exec /usr/bin/curl "$@";; esac; done\n'
            f'exec sh {wrap}/shim "$@"\n')
        (wrap / "cosign").write_text('#!/bin/sh\necho "$@" >> "$B1_COSIGN_LOG"\nexit 0\n')
        for n in ("curl", "cosign"):
            (wrap / n).chmod(0o755)
        os.symlink(PY, wrap / "python3")
        return {
            "PATH": f"{wrap}:/usr/bin:/bin", "HOME": str(self.tmp / "realhome"),
            "B1_RELEASE_BASE": f"file://{rel}", "B1_INSTALL_SH_URL": f"file://{INSTALLER}",
            "B1_POLICY_URL": f"file://{POLICY}", "B1_MIRROR": str(rel / VER), "B1_TAG": VER,
            "B1_URL_LOG": str(self.tmp / "urls"), "B1_UNEXPECTED_LOG": str(self.tmp / "bad"),
            "B1_LATEST_MODE": "none", "B1_LATEST_JSON": "/dev/null", "B1_COSIGN_LOG": str(self.tmp / "cosign.log"),
            "AASM_NO_MODIFY_PATH": "1", "TMPDIR": str(self.tmp),
        }

    def _exec_pending(self, p: dict, env: dict) -> subprocess.CompletedProcess:
        return subprocess.run(shlex.split(p["command"]), env=env, capture_output=True, text=True, timeout=300)

    def test_non_network_pending_commands_pass_against_a_stand_in_mirror(self) -> None:
        env = self._release_stand_in()
        by = {p["id"]: p for p in self._pending("j04") + self._pending("j17")}
        for cid in ("j04.published_install_sh_default", "j04.published_release_checksums_and_signature",
                    "j17.published_installer_profile_full_gateway"):
            r = self._exec_pending(by[cid], env)
            self.assertEqual(r.returncode, 0, f"{cid}: {r.stdout[-400:]} {r.stderr[-600:]}")
        self.assertIn("verify-blob", (self.tmp / "cosign.log").read_text())
        self.assertFalse((self.tmp / "realhome").exists(), "pending commands must not touch the caller's HOME")

    def test_pending_commands_fail_when_published_bytes_differ_from_candidate(self) -> None:
        env = self._release_stand_in()
        by = {p["id"]: p for p in self._pending("j04") + self._pending("j17")}
        rel = self.tmp / "rel" / VER
        make_tar(rel / self.plat.cli_tarball(), {"aasm": fake_aasm(), "aa-gateway": fake_gateway() + "# differs\n"})
        write_sums(rel)  # internally consistent, but not the candidate's bytes
        for cid in ("j04.published_install_sh_default", "j04.published_release_checksums_and_signature",
                    "j17.published_installer_profile_full_gateway"):
            r = self._exec_pending(by[cid], env)
            self.assertNotEqual(r.returncode, 0, cid)

    def test_pending_install_fails_on_stale_version_not_a_false_pass(self) -> None:
        env = self._release_stand_in()
        by = {p["id"]: p for p in self._pending("j04")}
        rel = self.tmp / "rel" / VER
        make_tar(rel / self.plat.cli_tarball(), {"aasm": fake_aasm("0.0.0-old"), "aa-gateway": fake_gateway()})
        write_sums(rel)
        self.assertNotEqual(self._exec_pending(by["j04.published_install_sh_default"], env).returncode, 0)

    # ---- shim behaviour
    def _shim(self, *args: str, tag: str = VER) -> subprocess.CompletedProcess:
        shim = self.tmp / "curl-shim"
        shim.write_text(H.CURL_SHIM)
        env = {"PATH": "/usr/bin:/bin", "B1_MIRROR": str(self.mirror), "B1_TAG": tag, "B1_URL_LOG": str(self.tmp / "u"),
               "B1_UNEXPECTED_LOG": str(self.tmp / "b"), "B1_LATEST_MODE": "none", "B1_LATEST_JSON": "/dev/null"}
        return subprocess.run(["sh", str(shim), *args], env=env, capture_output=True)

    def test_shim_head_flag_does_not_copy_and_other_tags_are_refused(self) -> None:
        url = f"{H.REL_BASE}{VER}/SHA256SUMS"
        out = self.tmp / "o"
        self.assertEqual(self._shim("-fsIL", "-o", str(out), url).returncode, 0)
        self.assertFalse(out.exists())
        self.assertEqual(self._shim("-sSfL", "--max-time", "5", "-o", str(out), url).returncode, 0)
        self.assertTrue(out.exists())
        self.assertEqual(self._shim("-sSfL", "-o", str(self.tmp / "o2"), f"{H.REL_BASE}v9.9.9/SHA256SUMS").returncode, 99)
        self.assertEqual(self._shim("-sSfL", "https://example.com/x").returncode, 99)

    # ---- process hygiene (M3)
    def test_killing_the_harness_mid_gateway_start_leaves_no_orphan_or_tempdir(self) -> None:
        build_mirror(self.mirror, self.plat, gateway=fake_gateway("hang"))
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "b1-harness-*")))
        proc = subprocess.Popen([sys.executable, "-I", str(HARNESS), "j17", "--mirror-dir", str(self.mirror),
                                 "--version", VER, "--candidate-sha", SHA],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid_file = None
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and pid_file is None:
            new = set(glob.glob(os.path.join(tempfile.gettempdir(), "b1-harness-*"))) - before
            for d in new:
                hits = glob.glob(os.path.join(d, "*", "home", "gw", "pid"))
                if hits and Path(hits[0]).read_text().strip():
                    pid_file = Path(hits[0])
            time.sleep(0.2)
        self.assertIsNotNone(pid_file, "gateway never started")
        gw_pid = int(pid_file.read_text())
        os.kill(proc.pid, signal.SIGTERM)
        proc.wait(timeout=60)
        time.sleep(0.5)
        with self.assertRaises(ProcessLookupError):
            os.kill(gw_pid, 0)
        self.assertEqual(before, set(glob.glob(os.path.join(tempfile.gettempdir(), "b1-harness-*"))))
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
