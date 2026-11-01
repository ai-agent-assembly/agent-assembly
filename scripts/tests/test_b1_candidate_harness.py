#!/usr/bin/env python3
"""Self-tests for scripts/qa/b1/candidate_harness.py. Hermetic: build a fixture
release mirror (fake binaries), run the harness as a subprocess, assert on its
real exit code and JSON. Needs no candidate artifacts.

Run: python3 -I scripts/tests/test_b1_candidate_harness.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts/qa/b1/candidate_harness.py"
CONTROL = ROOT / "scripts/qa/b1/fixtures/install-cli.pre-aaasm-6414.sh"
INSTALLER = ROOT / "scripts/install-cli.sh"
VER = "v0.0.1-rc.8"

sys.path.insert(0, str(ROOT / "scripts/qa/b1"))  # -I drops the script dir; import for Platform only
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("candidate_harness", HARNESS)
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

FAKE_AASM = f"#!/bin/sh\necho 'aasm {VER.lstrip('v')}'\n"
FAKE_GATEWAY = f"""#!{sys.executable}
import os, socket, sys, time
a = sys.argv[1:]
if a == ["--version"]:
    print("aa-gateway {VER.lstrip('v')}"); sys.exit(0)
pol = a[a.index("--policy") + 1] if "--policy" in a else None
if not pol or not os.path.isfile(pol):
    sys.stderr.write("policy file not found\\n"); sys.exit(2)
host, port = a[a.index("--listen") + 1].rsplit(":", 1)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, int(port))); s.listen(8)
time.sleep(600)
"""
FAKE_PLAIN = "#!/bin/sh\necho fake\n"


def make_tar(path: Path, members: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as t:
        for name, body in members.items():
            data = body.encode()
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o755
            t.addfile(ti, io.BytesIO(data))


def build_mirror(d: Path, plat: "H.Platform", cli_members=None, with_api=True, with_runtime=False) -> None:
    d.mkdir(parents=True, exist_ok=True)
    make_tar(d / plat.cli_tarball(), cli_members or {"aasm": FAKE_AASM, "aa-gateway": FAKE_GATEWAY})
    if with_api:
        make_tar(d / plat.component_tarball("api", VER), {"aa-api-server": FAKE_PLAIN})
    if with_runtime:
        make_tar(d / plat.component_tarball("runtime", VER), {"aa-runtime": FAKE_PLAIN})
    write_sums(d)


def write_sums(d: Path) -> None:
    lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}" for f in sorted(d.glob("*.tar.gz"))]
    (d / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def run(journey: str, mirror: Path, *extra: str) -> tuple[int, dict]:
    p = subprocess.run([sys.executable, "-I", str(HARNESS), journey, "--mirror-dir", str(mirror),
                        "--version", VER, *extra], capture_output=True, text=True, timeout=600)
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


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="b1-selftest-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.plat = H.Platform(None)
        self.mirror = self.tmp / "mirror"
        build_mirror(self.mirror, self.plat)

    # ---- good candidate
    def test_j04_good_candidate_passes_with_control(self) -> None:
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 0, json.dumps(out["candidate_checks"], indent=1))
        self.assertEqual(out["failed"], [])
        self.assertTrue(all(c["status"] == "PASS" for c in out["candidate_checks"]))
        self.assertEqual(status(out, "j04.negative_control_old_installer_fails"), "PASS")
        self.assertEqual(status(out, "j04.installed_aasm_version_output"), "PASS")

    def test_j17_good_candidate_passes_with_controls(self) -> None:
        rc, out = run("j17", self.mirror)
        self.assertEqual(rc, 0, json.dumps(out["candidate_checks"], indent=1))
        for cid in ("j17.installer_places_gateway_beside_aasm", "j17.gateway_serves_sample_policy",
                    "j17.installed_gateway_version_output", "j17.negative_control_old_installer_has_no_gateway"):
            self.assertEqual(status(out, cid), "PASS")

    # ---- negative controls
    def test_old_installer_fails_the_same_harness(self) -> None:
        for j, cid in (("j04", "j04.installer_default_installs_all_binaries"),
                       ("j17", "j17.installer_places_gateway_beside_aasm")):
            rc, out = run(j, self.mirror, "--installer", str(CONTROL))
            self.assertEqual(rc, 1)
            self.assertEqual(status(out, cid), "FAIL")
            self.assertEqual(out["overall"], "CANDIDATE_FAIL")

    def test_control_that_does_not_fail_is_itself_a_failure(self) -> None:
        rc, out = run("j04", self.mirror, "--control-installer", str(INSTALLER))
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.negative_control_old_installer_fails"), "FAIL")

    def test_control_fixture_is_byte_identical_to_history(self) -> None:
        p = subprocess.run(["/usr/bin/git", "-C", str(ROOT), "show", "1f6a2011f^1:scripts/install-cli.sh"],
                           capture_output=True)
        if p.returncode != 0:
            self.skipTest("history not available (shallow clone)")
        self.assertEqual(p.stdout, CONTROL.read_bytes())

    # ---- tamper / defect candidates
    def test_tampered_sha256sums_fails(self) -> None:
        sums = (self.mirror / "SHA256SUMS").read_text().replace(
            self.plat.cli_tarball(), self.plat.cli_tarball() + ".x", 1)
        (self.mirror / "SHA256SUMS").write_text(sums)
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.sha256sums_match_artifacts"), "FAIL")
        self.assertEqual(status(out, "j04.installer_default_installs_all_binaries"), "FAIL")

    def test_tampered_tarball_fails(self) -> None:
        t = self.mirror / self.plat.cli_tarball()
        b = bytearray(t.read_bytes())
        b[len(b) // 2] ^= 0xFF
        t.write_bytes(bytes(b))  # SHA256SUMS now stale
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.sha256sums_match_artifacts"), "FAIL")
        self.assertEqual(status(out, "j04.installer_default_installs_all_binaries"), "FAIL")

    def test_cli_tarball_without_gateway_fails_j17(self) -> None:
        build_mirror(self.mirror, self.plat, cli_members={"aasm": FAKE_AASM})
        rc, out = run("j17", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j17.installer_places_gateway_beside_aasm"), "FAIL")

    def test_gateway_that_never_listens_fails_j17(self) -> None:
        build_mirror(self.mirror, self.plat, cli_members={
            "aasm": FAKE_AASM, "aa-gateway": "#!/bin/sh\n[ \"$1\" = --version ] && echo 'aa-gateway 0.0.1-rc.8' && exit 0\nexit 3\n"})
        rc, out = run("j17", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j17.gateway_serves_sample_policy"), "FAIL")

    def test_wrong_version_output_fails(self) -> None:
        build_mirror(self.mirror, self.plat, cli_members={
            "aasm": "#!/bin/sh\necho 'aasm 9.9.9'\n", "aa-gateway": FAKE_GATEWAY})
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 1)
        self.assertEqual(status(out, "j04.installed_aasm_version_output"), "FAIL")

    # ---- simulated foreign platform: binaries are not executed, checks reported as not_run
    def test_foreign_platform_does_not_execute_binaries(self) -> None:
        other = H.Platform("linux/x86_64" if self.plat.host != ("linux", "x86_64") else "darwin/aarch64")
        mirror = self.tmp / "other"
        build_mirror(mirror, other)
        rc, out = run("j04", mirror, "--platform", f"{other.os}/{other.arch}")
        self.assertEqual(rc, 0, json.dumps(out["candidate_checks"], indent=1))
        ids = [c["id"] for c in out["candidate_checks"]]
        self.assertNotIn("j04.installed_aasm_version_output", ids)
        self.assertIn("j04.installed_aasm_version_output", [n["id"] for n in out["not_run"]])

    def test_optional_runtime_profile_check_runs_when_present(self) -> None:
        build_mirror(self.mirror, self.plat, with_runtime=True)
        rc, out = run("j04", self.mirror)
        self.assertEqual(rc, 0)
        self.assertEqual(status(out, "j04.installer_profile_local_installs_runtime"), "PASS")

    # ---- output contract
    def test_pending_checks_are_never_pass_and_match_obligation_shape(self) -> None:
        for j in ("j04", "j17"):
            _, out = run(j, self.mirror)
            self.assertTrue(out["pending_checks"])
            ids = {c["id"] for c in out["candidate_checks"]} | {n["id"] for n in out["not_run"]}
            for p in out["pending_checks"]:
                self.assertEqual(p["status"], "PENDING")
                for f in ("id", "channel", "why_publication_only", "command", "expected", "failure_response"):
                    self.assertTrue(isinstance(p[f], str) and p[f].strip(), (p["id"], f))
                self.assertNotIn(p["id"], ids)  # an id is candidate XOR pending (publication_obligations.py)
                self.assertIn("published", p["id"])
                for bad in ("git push", "git tag", "cargo publish", "npm publish", "twine", "gh release create",
                            "gh release delete", "brew uninstall", "sudo"):
                    self.assertNotIn(bad, p["command"])
            fr = out["failure_response"]
            self.assertTrue(fr["proposed_actions"] and fr["notify"] and fr["deadline_hours"] > 0)

    def test_candidate_checks_carry_digests_bound_to_real_files(self) -> None:
        _, out = run("j04", self.mirror)
        cli = self.mirror / self.plat.cli_tarball()
        want = "sha256:" + hashlib.sha256(cli.read_bytes()).hexdigest()
        for c in out["candidate_checks"]:
            self.assertTrue(c["artifact_digests"])
            for k, v in c["artifact_digests"].items():
                self.assertRegex(v, r"^sha256:[0-9a-f]{64}$", k)
            self.assertEqual(c["fidelity"], "real_local_process")
            self.assertTrue(c["evidence_ref"])
        self.assertEqual(out["candidate_checks"][0]["artifact_digests"][self.plat.cli_tarball()], want)
        ctl = next(c for c in out["candidate_checks"] if c.get("negative_control"))
        self.assertIn("control-installer:install-cli.pre-aaasm-6414.sh", ctl["artifact_digests"])

    def test_harness_cleans_up_and_writes_nothing_outside_tmp(self) -> None:
        before = {p for p in Path(tempfile.gettempdir()).glob("b1-harness-*")}
        run("j04", self.mirror)
        after = {p for p in Path(tempfile.gettempdir()).glob("b1-harness-*")}
        self.assertEqual(before, after)

    def test_missing_mirror_is_usage_error(self) -> None:
        p = subprocess.run([sys.executable, "-I", str(HARNESS), "j04", "--mirror-dir", str(self.tmp / "nope"),
                            "--version", VER], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
