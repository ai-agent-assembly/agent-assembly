#!/usr/bin/env python3
"""Hermetic pre-publication CANDIDATE harness for journeys J04 and J17 (AAASM-6419, B1).

Run:  python3 -I scripts/qa/b1/candidate_harness.py {j04|j17} --mirror-dir DIR --version vX.Y.Z

`--mirror-dir` is a directory shaped like a GitHub Release asset listing (the
final candidate's artifacts: SHA256SUMS, the cli tarball, the api tarball, ...).
The REAL installer script runs against it through a `curl` shim that serves
only files from that directory; any other URL is refused and recorded. No
network, no credentials, no sudo; everything is written under one mktemp dir
that is removed on exit.

Output (stdout): one JSON object. `candidate_checks[*].status` is PASS or FAIL.
Checks that need a published artifact are NEVER executed or passed here: they
are listed under `pending_checks` (status PENDING) with the exact read-only
post-publication command and the failure response. Field names follow
scripts/qa/publication_obligations.py (PR #2798): candidate_checks entries carry
id/status/fidelity/evidence_ref/negative_control/artifact_digests, pending_checks
entries carry id/channel/why_publication_only/command/expected (+ failure_response
text), failure_response carries proposed_actions/notify/deadline_hours.

Exit: 0 all candidate checks PASS, 1 any FAIL, 2 usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HARNESS_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_INSTALLER = REPO_ROOT / "scripts" / "install-cli.sh"
DEFAULT_CONTROL = REPO_ROOT / "scripts" / "qa" / "b1" / "fixtures" / "install-cli.pre-aaasm-6414.sh"
DEFAULT_POLICY = REPO_ROOT / "policy-examples" / "low-risk.yaml"
FIDELITY = "real_local_process"
RELEASE_URL_PREFIX = "https://github.com/ai-agent-assembly/agent-assembly/releases/download/"

CURL_SHIM = r"""#!/bin/sh
url="" out="" head=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*I*) head=1; shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >> "$B1_URL_LOG"
case "$url" in
  https://github.com/ai-agent-assembly/agent-assembly/releases/download/*/*)
    name="${url##*/}"
    case "$name" in
      SHA256SUMS|aasm-*.tar.gz) ;;
      *) exit 22 ;;
    esac
    f="$B1_MIRROR/$name"
    [ -f "$f" ] || exit 22
    [ "$head" = 1 ] || cp "$f" "$out"
    exit 0 ;;
esac
echo "$url" >> "$B1_UNEXPECTED_LOG"
exit 99
"""

UNAME_SHIM = r"""#!/bin/sh
case "$1" in
  -s) echo "$B1_FAKE_UNAME_S" ;;
  -m) echo "$B1_FAKE_UNAME_M" ;;
  *) exec /usr/bin/uname "$@" ;;
esac
"""

FAILURE_RESPONSE = {
    "proposed_actions": [
        "Treat the failed published-artifact check as a release defect: do not announce the release.",
        "Open a Bug sub-ticket under the journey's Jira Story with the command output attached.",
        "If an artifact is wrong, cut a new candidate and re-run the candidate harness before re-publishing; "
        "never edit or yank a published asset in place without owner approval.",
    ],
    "notify": ["release-owner", "qa-orchestrator"],
    "deadline_hours": 24,
}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest(p: Path) -> str:
    return "sha256:" + sha256_file(p)


class Platform:
    """The OS/arch the installer is told it is running on (via a uname shim)."""

    def __init__(self, spec: str | None):
        host_os = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system(), platform.system().lower())
        host_arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}.get(
            platform.machine().lower(), platform.machine().lower())
        self.host = (host_os, host_arch)
        if spec:
            o, _, a = spec.partition("/")
            if o not in ("linux", "darwin") or a not in ("x86_64", "aarch64"):
                raise SystemExit("--platform must be <linux|darwin>/<x86_64|aarch64>")
            self.os, self.arch = o, a
        else:
            self.os, self.arch = self.host
        self.shimmed = spec is not None

    @property
    def native(self) -> bool:
        return (self.os, self.arch) == self.host

    @property
    def triple(self) -> str:
        return f"{self.arch}-{'apple-darwin' if self.os == 'darwin' else 'unknown-linux-gnu'}"

    @property
    def short(self) -> str:
        return f"{self.os}-{'amd64' if self.arch == 'x86_64' else 'arm64'}"

    def cli_tarball(self) -> str:
        return f"aasm-{self.triple}.tar.gz"

    def component_tarball(self, comp: str, version: str) -> str:
        return f"aasm-{comp}-{version}-{self.short}.tar.gz"

    def uname(self) -> tuple[str, str]:
        return ("Darwin" if self.os == "darwin" else "Linux",
                "arm64" if (self.os == "darwin" and self.arch == "aarch64") else
                ("aarch64" if self.arch == "aarch64" else "x86_64"))


class Sandbox:
    """All scratch state for one harness run; removed on exit."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="b1-harness-"))
        self.n = 0

    def fresh(self, label: str) -> Path:
        self.n += 1
        d = self.root / f"{self.n:02d}-{label}"
        d.mkdir(parents=True)
        return d

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class InstallRun:
    def __init__(self, rc: int, output: str, urls: list[str], unexpected: list[str],
                 dest: Path, home: Path):
        self.rc, self.output, self.urls, self.unexpected, self.dest, self.home = (
            rc, output, urls, unexpected, dest, home)

    def installed(self, name: str) -> bool:
        p = self.dest / name
        return p.is_file() and not p.is_symlink() and os.access(p, os.X_OK)

    @property
    def manifest(self) -> str:
        m = self.home / ".aasm" / "install-manifest"
        return m.read_text() if m.is_file() else ""


def run_installer(sb: Sandbox, plat: Platform, installer: Path, mirror: Path, version: str,
                  extra: list[str], env_version: bool = False, uninstall_of: InstallRun | None = None
                  ) -> InstallRun:
    work = sb.fresh("install" if uninstall_of is None else "uninstall")
    if uninstall_of is not None:
        home, dest = uninstall_of.home, uninstall_of.dest
    else:
        home, dest = work / "home", work / "dest"
        home.mkdir()
    shim = work / "shim"
    shim.mkdir()
    for name, body in (("curl", CURL_SHIM), ("uname", UNAME_SHIM)):
        (shim / name).write_text(body)
        (shim / name).chmod(0o755)
    url_log, bad_log = work / "urls.log", work / "unexpected.log"
    url_log.touch()
    bad_log.touch()
    uname_s, uname_m = plat.uname()
    env = {
        "PATH": f"{shim}:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "AASM_CONFIG_DIR": str(home / ".aa"),
        "AASM_STATE_DIR": str(home / ".aasm"),
        "AASM_NO_MODIFY_PATH": "1",
        "B1_MIRROR": str(mirror),
        "B1_URL_LOG": str(url_log),
        "B1_UNEXPECTED_LOG": str(bad_log),
        "B1_FAKE_UNAME_S": uname_s,
        "B1_FAKE_UNAME_M": uname_m,
        "TMPDIR": str(work),
        "LANG": "C",
    }
    if uninstall_of is not None:
        cmd = ["sh", str(installer), "--uninstall", "--install-dir", str(dest)]
    elif env_version:
        env["AASM_VERSION"] = version
        cmd = ["sh", str(installer), "--install-dir", str(dest)] + extra
    else:
        cmd = ["sh", str(installer), "--version", version, "--install-dir", str(dest)] + extra
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
        rc, out = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        rc, out = 124, "installer timed out after 180s"
    return InstallRun(rc, out, url_log.read_text().split(), bad_log.read_text().split(), dest, home)


def mirror_without_tamper(sb: Sandbox, mirror: Path, name: str) -> Path:
    """Copy of the mirror with one byte of `name` flipped (SHA256SUMS untouched)."""
    d = sb.fresh("tampered-mirror")
    for f in mirror.iterdir():
        if f.is_file():
            shutil.copy2(f, d / f.name)
    data = bytearray((d / name).read_bytes())
    data[len(data) // 2] ^= 0xFF
    (d / name).write_bytes(bytes(data))
    return d


def sums_map(mirror: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    p = mirror / "SHA256SUMS"
    if p.is_file():
        for line in p.read_text().splitlines():
            parts = line.split()
            if len(parts) == 2:
                out[parts[1].lstrip("*")] = parts[0]
    return out


class Ctx:
    def __init__(self, a: argparse.Namespace):
        self.a = a
        self.sb = Sandbox()
        self.plat = Platform(a.platform)
        self.mirror = Path(a.mirror_dir).resolve()
        self.version = a.version
        self.installer = Path(a.installer).resolve()
        self.control = Path(a.control_installer).resolve()
        self.digests_all: dict[str, str] = {}
        self.checks: list[dict] = []
        self.not_run: list[dict] = []

    def art(self, *names: str) -> dict[str, str]:
        out = {}
        for n in names:
            p = self.mirror / n
            if p.is_file():
                out[n] = digest(p)
        out["installer:" + self.installer.name] = digest(self.installer)
        self.digests_all.update(out)
        return out

    def record(self, cid: str, ok: bool, detail: str, names: list[str], negative_control: str = "") -> None:
        c = {
            "id": cid, "status": "PASS" if ok else "FAIL", "fidelity": FIDELITY,
            "evidence_ref": f"{Path(__file__).name} {self.a.journey} --version {self.version}",
            "detail": detail, "artifact_digests": self.art(*names),
        }
        if negative_control:
            c["negative_control"] = negative_control
        self.checks.append(c)

    def skip(self, cid: str, reason: str) -> None:
        self.not_run.append({"id": cid, "reason": reason})


def default_install_problems(r: InstallRun, ctx: Ctx, binaries: list[str]) -> list[str]:
    p: list[str] = []
    if r.rc != 0:
        p.append(f"installer exit {r.rc}: {r.output.strip()[-300:]}")
    for b in binaries:
        if not r.installed(b):
            p.append(f"{b} was not installed as an executable regular file")
        if f"binary={b}" not in r.manifest.splitlines():
            p.append(f"install manifest does not list binary={b}")
    if r.unexpected:
        p.append(f"installer requested non-release URLs: {r.unexpected}")
    return p


def j04_checks(ctx: Ctx) -> None:
    plat, v = ctx.plat, ctx.version
    cli, api = plat.cli_tarball(), plat.component_tarball("api", v)
    base = ["SHA256SUMS", cli, api]
    wanted = ["aasm", "aa-gateway", "aa-api-server"]

    # 1. SHA256SUMS describes the artifacts actually present.
    sums = sums_map(ctx.mirror)
    prob = []
    for n in (cli, api):
        if n not in sums:
            prob.append(f"SHA256SUMS has no entry for {n}")
        elif not (ctx.mirror / n).is_file():
            prob.append(f"{n} listed but absent from mirror")
        elif sha256_file(ctx.mirror / n) != sums[n]:
            prob.append(f"{n} digest differs from SHA256SUMS")
    ctx.record("j04.sha256sums_match_artifacts", not prob, "; ".join(prob) or "cli and api tarballs match SHA256SUMS", base)

    # 2. Default install of the real installer.
    r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [])
    prob = default_install_problems(r, ctx, wanted)
    if f"version={v}" not in r.manifest.splitlines():
        prob.append(f"manifest version is not {v}")
    if any(not u.startswith(RELEASE_URL_PREFIX + v + "/") for u in r.urls):
        prob.append(f"a request escaped the pinned release {v}: {r.urls}")
    ctx.record("j04.installer_default_installs_all_binaries", not prob,
               "; ".join(prob) or "aasm, aa-gateway, aa-api-server installed; manifest lists them", base)
    default_run = r

    # 3. AASM_VERSION env pin (documented form) resolves the same release.
    r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [], env_version=True)
    prob = default_install_problems(r, ctx, wanted)
    if not r.urls or any(not u.startswith(RELEASE_URL_PREFIX + v + "/") for u in r.urls):
        prob.append(f"AASM_VERSION={v} did not pin every download to that release: {r.urls}")
    ctx.record("j04.installer_version_pin_env", not prob, "; ".join(prob) or f"AASM_VERSION={v} pinned", base)

    # 4. Tampered cli tarball is refused and nothing is installed.
    tm = mirror_without_tamper(ctx.sb, ctx.mirror, cli)
    r = run_installer(ctx.sb, plat, ctx.installer, tm, v, [])
    prob = []
    if r.rc == 0:
        prob.append("installer accepted a tampered tarball")
    if "SHA256 mismatch" not in r.output:
        prob.append("no 'SHA256 mismatch' diagnostic")
    for b in wanted:
        if (r.dest / b).exists():
            prob.append(f"{b} present after refused install")
    ctx.record("j04.installer_refuses_tampered_tarball", not prob,
               "; ".join(prob) or "one-byte tamper refused, nothing installed", base)

    # 5. Uninstall removes what install placed.
    u = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [], uninstall_of=default_run)
    left = [b for b in wanted if (default_run.dest / b).exists()]
    prob = ([f"uninstall exit {u.rc}"] if u.rc else []) + ([f"left behind: {left}"] if left else [])
    ctx.record("j04.installer_uninstall_removes_binaries", not prob, "; ".join(prob) or "all binaries removed", base)

    # 6. Installed aasm reports the candidate version (host-native binaries only).
    if plat.native:
        r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [])
        out = ""
        try:
            e = subprocess.run([str(r.dest / "aasm"), "--version"], capture_output=True, text=True, timeout=60,
                               env={"PATH": "/usr/bin:/bin", "HOME": str(r.home)})
            out, rc = e.stdout + e.stderr, e.returncode
        except (OSError, subprocess.TimeoutExpired) as ex:
            rc, out = 1, str(ex)
        want = v.lstrip("v")
        ctx.record("j04.installed_aasm_version_output", rc == 0 and want in out,
                   f"aasm --version rc={rc} output={out.strip()[:200]!r} expected to contain {want!r}", base)
    else:
        ctx.skip("j04.installed_aasm_version_output",
                 f"candidate platform {plat.os}/{plat.arch} is not the host {ctx.plat.host}; run on a matching host")

    # 7. --profile local needs the runtime tarball.
    rt = plat.component_tarball("runtime", v)
    if (ctx.mirror / rt).is_file():
        r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, ["--profile", "local"])
        prob = default_install_problems(r, ctx, wanted + ["aa-runtime"])
        ctx.record("j04.installer_profile_local_installs_runtime", not prob,
                   "; ".join(prob) or "cli+api+runtime installed", base + [rt])
    else:
        ctx.skip("j04.installer_profile_local_installs_runtime", f"{rt} not in mirror")

    negative_control(ctx, "j04.negative_control_old_installer_fails", wanted, base)


def negative_control(ctx: Ctx, cid: str, wanted: list[str], names: list[str]) -> None:
    """The pre-AAASM-6414 installer must FAIL the default-install assertion."""
    r = run_installer(ctx.sb, ctx.plat, ctx.control, ctx.mirror, ctx.version, [])
    prob = default_install_problems(r, ctx, wanted)
    ok = bool(prob)
    c_digest = digest(ctx.control)
    ctx.record(cid, ok,
               ("control failed as required: " + "; ".join(prob)) if ok else
               "CONTROL PASSED - the harness cannot detect the AAASM-6414 defect",
               names,
               negative_control=f"old installer (sha {c_digest}) must fail the default-install assertion")
    ctx.checks[-1]["artifact_digests"]["control-installer:" + ctx.control.name] = c_digest


# ---------------------------------------------------------------- J17

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def gateway_starts(binary: Path, policy: Path, home: Path, timeout: float = 30.0) -> tuple[bool, str]:
    """Start the gateway on a free loopback port; True once it accepts a TCP
    connection while the process is still alive. Always terminates the child."""
    port = free_port()
    state = home / "gw"
    state.mkdir(parents=True, exist_ok=True)
    cmd = [str(binary), "--policy", str(policy), "--listen", f"127.0.0.1:{port}",
           "--audit-dir", str(state / "audit"), "--db-path", str(state / "gw.db")]
    log = open(state / "gateway.log", "wb")
    try:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
                                start_new_session=True)
    except OSError as ex:
        return False, f"could not execute gateway: {ex}"
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                tail = (state / "gateway.log").read_text(errors="replace")[-300:]
                return False, f"gateway exited early rc={proc.returncode}: {tail!r}"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True, f"accepted TCP on 127.0.0.1:{port}"
            except OSError:
                time.sleep(0.2)
        return False, f"no listener on 127.0.0.1:{port} within {timeout}s"
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        log.close()


def j17_checks(ctx: Ctx) -> None:
    plat, v = ctx.plat, ctx.version
    cli, api = plat.cli_tarball(), plat.component_tarball("api", v)
    base = ["SHA256SUMS", cli, api]
    wanted = ["aasm", "aa-gateway"]

    r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [])
    prob = default_install_problems(r, ctx, wanted)
    ctx.record("j17.installer_places_gateway_beside_aasm", not prob,
               "; ".join(prob) or "aa-gateway installed in the same dir as aasm (where `aasm gateway start` looks)", base)

    gw = r.dest / "aa-gateway"
    policy = Path(ctx.a.policy).resolve()
    if plat.native and gw.is_file():
        try:
            e = subprocess.run([str(gw), "--version"], capture_output=True, text=True, timeout=60,
                               env={"PATH": "/usr/bin:/bin", "HOME": str(r.home)})
            out, rc = e.stdout + e.stderr, e.returncode
        except (OSError, subprocess.TimeoutExpired) as ex:
            rc, out = 1, str(ex)
        want = v.lstrip("v")
        ctx.record("j17.installed_gateway_version_output", rc == 0 and want in out,
                   f"aa-gateway --version rc={rc} output={out.strip()[:200]!r} expected to contain {want!r}", base)

        ok, detail = gateway_starts(gw, policy, r.home)
        ok_ctl, detail_ctl = gateway_starts(gw, policy.with_name("does-not-exist.yaml"), r.home, timeout=15.0)
        ctx.record("j17.gateway_serves_sample_policy", ok and not ok_ctl,
                   f"{detail}; control (missing policy): {detail_ctl}", base,
                   negative_control="same start check with a nonexistent --policy path must FAIL"
                   + (" (it did)" if not ok_ctl else " (IT DID NOT)"))
    else:
        for cid in ("j17.installed_gateway_version_output", "j17.gateway_serves_sample_policy"):
            ctx.skip(cid, f"candidate platform {plat.os}/{plat.arch} is not the host {plat.host} (or gateway missing); "
                          "run on a matching host")

    negative_control(ctx, "j17.negative_control_old_installer_has_no_gateway", wanted, base)


# ---------------------------------------------------------------- pending

def pending(journey: str) -> list[dict]:
    fr = ("Do not announce or tag as released. Open a Bug sub-ticket under the journey Story with the command "
          "output; notify the release owner within the deadline; fix forward with a new candidate and re-run "
          "this harness plus this pending check. No yank/delete of published assets without owner approval.")
    tmp_home = 'HOME="$(mktemp -d)" AASM_NO_MODIFY_PATH=1'
    if journey == "J04":
        items = [
            ("j04.published_install_sh_default", "github-release+agent-assembly.com",
             "Fetches the live installer and the public GitHub Release; neither exists before publication.",
             f"{tmp_home} sh -c 'curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --install-dir \"$HOME/bin\" "
             f"--version <TAG>' && \"$HOME/bin/aasm\" --version && \"$HOME/bin/aa-gateway\" --version",
             "exit 0; aasm --version contains <TAG>; aa-gateway and aa-api-server present in $HOME/bin"),
            ("j04.published_release_checksums_and_signature", "github-release",
             "The cosign bundle is produced by release.yml at tag time and the assets are public only after publish.",
             "gh release download <TAG> --repo ai-agent-assembly/agent-assembly --pattern SHA256SUMS "
             "--pattern 'SHA256SUMS.cosign.bundle' --dir \"$(mktemp -d)\" && sha256sum -c SHA256SUMS && "
             "cosign verify-blob --bundle SHA256SUMS.cosign.bundle --certificate-identity-regexp "
             "'^https://github.com/ai-agent-assembly/agent-assembly/\\.github/workflows/release\\.yml@refs/tags/v.*$' "
             "--certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS",
             "sha256sum -c all OK; cosign verify-blob exit 0; published digests equal the candidate artifact_digests"),
            ("j04.published_homebrew_tap_install", "homebrew-tap",
             "The formula is committed to ai-agent-assembly/homebrew-tap by release.yml after publication.",
             "brew install ai-agent-assembly/tap/aasm && aasm --version && command -v aa-gateway",
             "aasm --version contains <TAG>; aa-gateway resolvable (the AAASM-4448/4449 suspect)"),
            ("j04.published_homebrew_runtime", "homebrew-tap",
             "Needs the tap formula for aasm-runtime.",
             "brew install ai-agent-assembly/tap/aasm-runtime && command -v aa-runtime",
             "aa-runtime installed and executable"),
            ("j04.published_crates_io_aa_cli", "crates.io",
             "crates.io state exists only after publication.",
             "curl -fsS https://crates.io/api/v1/crates/aa-cli | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[\"crate\"][\"max_version\"])'",
             "either max_version == candidate version, or documented decision that cargo install aa-cli is intentionally absent"),
        ]
    else:
        items = [
            ("j17.published_installer_profile_full_gateway", "github-release+agent-assembly.com",
             "Installs from the public Release assets.",
             f"{tmp_home} sh -c 'curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --profile full "
             f"--version <TAG> --install-dir \"$HOME/bin\"' && \"$HOME/bin/aa-gateway\" --version",
             "exit 0; aa-gateway reports <TAG>; then start with policy-examples/low-risk.yaml and connect to 127.0.0.1:50051"),
            ("j17.published_homebrew_gateway", "homebrew-tap",
             "Formula lives in the tap after publication.",
             "brew install ai-agent-assembly/tap/aasm && command -v aa-gateway",
             "aa-gateway on PATH (the AAASM-4448/4449 suspect: formula installed only aasm)"),
            ("j17.published_container_image_manifest", "ghcr.io",
             "The image exists in GHCR only after the release workflow pushes it. Inferred: only "
             "ghcr.io/ai-agent-assembly/aa-runtime is referenced in-repo; no gateway image name was found.",
             "docker manifest inspect ghcr.io/ai-agent-assembly/aa-runtime:<TAG>",
             "manifest resolves for linux/amd64 and linux/arm64; if a gateway image is documented, the same for it"),
        ]
    return [{"id": i, "status": "PENDING", "channel": ch, "why_publication_only": why, "command": cmd,
             "expected": exp, "failure_response": fr, "deadline_hours": FAILURE_RESPONSE["deadline_hours"]}
            for i, ch, why, cmd, exp in items]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("journey", choices=["j04", "j17"])
    ap.add_argument("--mirror-dir", required=True)
    ap.add_argument("--version", required=True, help="release tag the candidate carries, e.g. v0.0.1-rc.8")
    ap.add_argument("--installer", default=str(DEFAULT_INSTALLER))
    ap.add_argument("--control-installer", default=str(DEFAULT_CONTROL))
    ap.add_argument("--policy", default=str(DEFAULT_POLICY))
    ap.add_argument("--platform", help="simulate <os>/<arch> via a uname shim (binaries then cannot be executed)")
    a = ap.parse_args(argv)
    a.journey = a.journey
    for label, path in (("mirror-dir", a.mirror_dir), ("installer", a.installer), ("control-installer", a.control_installer)):
        if not Path(path).exists():
            print(f"error: --{label} {path} does not exist", file=sys.stderr)
            return 2
    ctx = Ctx(a)
    try:
        (j04_checks if a.journey == "j04" else j17_checks)(ctx)
    finally:
        ctx.sb.cleanup()
    journey = a.journey.upper()
    failed = [c["id"] for c in ctx.checks if c["status"] != "PASS"]
    result = {
        "harness": "scripts/qa/b1/candidate_harness.py", "harness_version": HARNESS_VERSION,
        "journey": journey, "version": a.version, "platform": f"{ctx.plat.os}/{ctx.plat.arch}",
        "host": f"{ctx.plat.host[0]}/{ctx.plat.host[1]}",
        "artifact_digests": dict(sorted(ctx.digests_all.items())),
        "candidate_checks": ctx.checks, "not_run": ctx.not_run,
        "pending_checks": pending(journey), "failure_response": FAILURE_RESPONSE,
        "failed": failed,
        "overall": "CANDIDATE_FAIL" if failed else "CANDIDATE_PASS_PUBLICATION_PENDING",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
