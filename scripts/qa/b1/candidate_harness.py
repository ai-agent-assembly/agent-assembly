#!/usr/bin/env python3
"""Hermetic pre-publication CANDIDATE harness for journeys J04 and J17 (AAASM-6419, B1).

Run:  python3 -I scripts/qa/b1/candidate_harness.py {j04|j17} \
          --mirror-dir DIR --version vX.Y.Z --candidate-sha <git sha>

`--mirror-dir` is a directory shaped like a GitHub Release asset listing (the
final candidate's artifacts). It is snapshotted into the sandbox first; every
digest reported is of the snapshot bytes the installer actually consumed, and
the source is re-hashed at the end (a change mid-run is a FAIL). The REAL
installer runs against the snapshot through a `curl` shim that serves only that
tag's assets (plus a stand-in latest-release API reply); any other URL is
refused and fails the check. No network, credentials or sudo; everything is
written under one mktemp dir that is removed on exit and on SIGTERM/SIGHUP/SIGINT.

Output (stdout): one JSON object.
- `candidate_checks[*].status` is PASS or FAIL. `evidence_ref` is a command string.
- `not_run`: checks that could not run (foreign platform, missing runtime/proxy
  tarball). Any entry makes the run INCOMPLETE (exit 3), never a pass.
- `not_covered`: acceptance criteria no check covers; not a pass for them.
- `pending_checks` (status PENDING): checks that need a published artifact. They
  are never executed here. Each `command` is one self-contained `sh -c` script
  with the tag and candidate digests substituted.
- `obligation_fragment`: the journey entry in the shape of
  scripts/qa/publication_obligations.py (PR #2798) with `registry_digest` and
  `depends_on` left as explicit null placeholders (listed in `_unfilled`);
  pending status string is PUBLICATION_PENDING there.

Exit: 0 complete and all PASS, 1 any FAIL, 2 usage, 3 INCOMPLETE or UNPINNED control.
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

HARNESS_VERSION = 2
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_INSTALLER = REPO_ROOT / "scripts" / "install-cli.sh"
DEFAULT_CONTROL = REPO_ROOT / "scripts" / "qa" / "b1" / "fixtures" / "install-cli.pre-aaasm-6414.sh"
# sha256 of the byte-identical copy of install-cli.sh at 4b461d4ef (parent of PR #2791 merge 1f6a2011f).
CONTROL_SHA256 = "70c96c54070263ccf01cbe0cffdba16f65730b597d9934ad7132c8ecc4aea1c4"
DEFAULT_POLICY = REPO_ROOT / "policy-examples" / "low-risk.yaml"
FIDELITY = "real_local_process"
REL_BASE = "https://github.com/ai-agent-assembly/agent-assembly/releases/download/"
API_LATEST = "https://api.github.com/repos/ai-agent-assembly/agent-assembly/releases/latest"
API_LIST = "https://api.github.com/repos/ai-agent-assembly/agent-assembly/releases?per_page=1"

CURL_SHIM = r"""#!/bin/sh
url="" out="" head=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -I) head=1; shift ;;
    -[A-HJ-Za-z]*I*) head=1; shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >> "$B1_URL_LOG"
emit() { if [ -n "$out" ]; then cp "$1" "$out"; else cat "$1"; fi; }
case "$url" in
  https://github.com/ai-agent-assembly/agent-assembly/releases/download/"$B1_TAG"/*)
    name="${url##*/}"
    case "$name" in
      SHA256SUMS|aasm-*.tar.gz) ;;
      *) exit 22 ;;
    esac
    f="$B1_MIRROR/$name"
    [ -f "$f" ] || exit 22
    [ "$head" = 1 ] || cp "$f" "$out"
    exit 0 ;;
  "https://api.github.com/repos/ai-agent-assembly/agent-assembly/releases/latest")
    [ "$B1_LATEST_MODE" = latest ] || exit 22
    emit "$B1_LATEST_JSON"; exit 0 ;;
  "https://api.github.com/repos/ai-agent-assembly/agent-assembly/releases?per_page=1")
    [ "$B1_LATEST_MODE" = list ] || exit 22
    emit "$B1_LATEST_JSON"; exit 0 ;;
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

NOT_COVERED = {
    "J04": [
        {"id": "j04.ac.cargo_install_aa_cli_docs_decision",
         "ac": "AAASM-4542: 'cargo install aa-cli' is documented, or its absence is intentional",
         "reason": "A documentation/decision judgement; only crates.io state is probed, and only as a PENDING "
                   "publication check (j04.published_crates_io_aa_cli). No candidate check asserts the decision text."},
    ],
    "J17": [
        {"id": "j17.ac.docs_not_only_cargo_run",
         "ac": "AAASM-4527: docs must not only offer `cargo run -p aa-gateway` / `make dev-setup`",
         "reason": "Documentation judgement; no check reads or judges the docs."},
        {"id": "j17.ac.policy_format_unambiguous",
         "ac": "AAASM-4527: policy format is unambiguous (TOML self-host vs YAML gateway)",
         "reason": "Documentation/product judgement; the gateway start check only proves one YAML sample loads."},
        {"id": "j17.ac.aasm_status_topology_agent_list_healthy",
         "ac": "AAASM-4527: `aasm status` / `aasm agent list` / `aasm topology overview` report healthy",
         "reason": "These read the HTTP API (aa-api-server wired to the gateway), not the gateway's gRPC port; the "
                   "Jira story records them as `unreachable` in OSS gateway-only mode. A candidate check would need a "
                   "full local stack and a decision on what healthy means. Only `aasm gateway start/status/stop` "
                   "(gRPC liveness) is covered (j17.aasm_gateway_start_status_stop)."},
    ],
}

# ---------------------------------------------------------------- process hygiene

_LIVE_PGIDS: set[int] = set()
_SANDBOXES: list["Sandbox"] = []


def _kill_live() -> None:
    for pg in list(_LIVE_PGIDS):
        try:
            os.killpg(pg, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        _LIVE_PGIDS.discard(pg)


def _cleanup_all() -> None:
    _kill_live()
    for sb in list(_SANDBOXES):
        sb.cleanup()


def _on_signal(signum: int, _frame) -> None:
    raise SystemExit(128 + signum)


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
        _SANDBOXES.append(self)

    def fresh(self, label: str) -> Path:
        self.n += 1
        d = self.root / f"{self.n:02d}-{label}"
        d.mkdir(parents=True)
        return d

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        if self in _SANDBOXES:
            _SANDBOXES.remove(self)


class InstallRun:
    def __init__(self, rc, output, urls, unexpected, dest: Path, home: Path):
        self.rc, self.output, self.urls, self.unexpected, self.dest, self.home = (
            rc, output, urls, unexpected, dest, home)

    def installed(self, name: str) -> bool:
        p = self.dest / name
        return p.is_file() and not p.is_symlink() and os.access(p, os.X_OK)

    @property
    def manifest(self) -> str:
        m = self.home / ".aasm" / "install-manifest"
        return m.read_text() if m.is_file() else ""


def run_installer(sb: Sandbox, plat: Platform, installer: Path, mirror: Path, version: str, extra: list[str],
                  mode: str = "flag", uninstall_of: InstallRun | None = None) -> InstallRun:
    """mode: flag (--version), env (AASM_VERSION), latest (API /releases/latest),
    list (API /releases?per_page=1 fallback, /latest 404s)."""
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
    latest_json = work / "latest.json"
    latest_json.write_text('[\n  {\n    "tag_name": "%s"\n  }\n]\n' % version if mode == "list"
                           else '{\n  "tag_name": "%s"\n}\n' % version)
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
        "B1_MIRROR": str(mirror), "B1_TAG": version,
        "B1_URL_LOG": str(url_log), "B1_UNEXPECTED_LOG": str(bad_log),
        "B1_LATEST_MODE": mode if mode in ("latest", "list") else "none", "B1_LATEST_JSON": str(latest_json),
        "B1_FAKE_UNAME_S": uname_s, "B1_FAKE_UNAME_M": uname_m,
        "TMPDIR": str(work), "LANG": "C",
    }
    base = ["sh", str(installer)]
    if uninstall_of is not None:
        cmd = base + ["--uninstall", "--install-dir", str(dest)]
    elif mode == "env":
        env["AASM_VERSION"] = version
        cmd = base + ["--install-dir", str(dest)] + extra
    elif mode in ("latest", "list"):
        cmd = base + ["--install-dir", str(dest)] + extra
    else:
        cmd = base + ["--version", version, "--install-dir", str(dest)] + extra
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
        rc, out = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        rc, out = 124, "installer timed out after 180s"
    return InstallRun(rc, out, url_log.read_text().split(), bad_log.read_text().split(), dest, home)


def tampered_mirror(sb: Sandbox, mirror: Path, name: str) -> Path:
    """Copy of the mirror with `name` altered (one byte appended); SHA256SUMS untouched."""
    d = sb.fresh("tampered-mirror")
    for f in mirror.iterdir():
        if f.is_file():
            shutil.copy2(f, d / f.name)
    with open(d / name, "ab") as fh:
        fh.write(b"\x00")
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


def member_sha(tarball: Path, member: str) -> str | None:
    try:
        with tarfile.open(tarball) as tf:
            f = tf.extractfile(member)
            return hashlib.sha256(f.read()).hexdigest() if f else None
    except (OSError, KeyError, tarfile.TarError):
        return None


class Ctx:
    def __init__(self, a: argparse.Namespace):
        self.a = a
        self.sb = Sandbox()
        self.plat = Platform(a.platform)
        self.src_mirror = Path(a.mirror_dir).resolve()
        # Snapshot: hash and serve the same bytes.
        self.mirror = self.sb.fresh("served")
        self.src_digests: dict[str, str] = {}
        for f in sorted(self.src_mirror.iterdir()):
            if f.is_file():
                shutil.copy2(f, self.mirror / f.name)
                self.src_digests[f.name] = digest(self.mirror / f.name)
        self.version = a.version
        self.installer = Path(a.installer).resolve()
        self.control = Path(a.control_installer).resolve()
        self.control_pinned = True
        pol_dir = self.sb.fresh("policy")
        self.policy = pol_dir / Path(a.policy).name
        shutil.copy2(a.policy, self.policy)
        self.digests_all: dict[str, str] = {}
        self.checks: list[dict] = []
        self.not_run: list[dict] = []

    def tarball_for(self, binary: str) -> str:
        v, p = self.version, self.plat
        return {"aasm": p.cli_tarball(), "aa-gateway": p.cli_tarball(),
                "aa-api-server": p.component_tarball("api", v), "aa-runtime": p.component_tarball("runtime", v),
                "aa-proxy": p.component_tarball("proxy", v)}[binary]

    def art(self, names: list[str], extra: dict[str, str] | None = None) -> dict[str, str]:
        out = {}
        for n in names:
            if n in self.src_digests:
                out[n] = self.src_digests[n]
        out["installer:" + self.installer.name] = digest(self.installer)
        out.update(extra or {})
        self.digests_all.update(out)
        return out

    def record(self, cid: str, ok: bool, detail: str, names: list[str], negative_control: str = "",
               extra: dict[str, str] | None = None) -> None:
        c = {
            "id": cid, "status": "PASS" if ok else "FAIL", "fidelity": FIDELITY,
            "evidence_ref": f"{Path(__file__).name} {self.a.journey} --version {self.version} "
                            f"--candidate-sha {self.a.candidate_sha}",
            "candidate_sha": self.a.candidate_sha,
            "detail": detail, "artifact_digests": self.art(names, extra),
        }
        if negative_control:
            c["negative_control"] = negative_control
        self.checks.append(c)

    def skip(self, cid: str, reason: str) -> None:
        self.not_run.append({"id": cid, "reason": reason})


def install_problems(r: InstallRun, ctx: Ctx, binaries: list[str], absent: list[str] = ()) -> list[str]:
    p: list[str] = []
    if r.rc != 0:
        p.append(f"installer exit {r.rc}: {r.output.strip()[-300:]}")
    for b in binaries:
        if not r.installed(b):
            p.append(f"{b} was not installed as an executable regular file")
            continue
        if f"binary={b}" not in r.manifest.splitlines():
            p.append(f"install manifest does not list binary={b}")
        want = member_sha(ctx.mirror / ctx.tarball_for(b), b)
        if want is None:
            p.append(f"cannot read {b} from {ctx.tarball_for(b)} to compare bytes")
        elif sha256_file(r.dest / b) != want:
            p.append(f"installed {b} differs from the tarball member bytes")
    for b in absent:
        if (r.dest / b).exists():
            p.append(f"{b} installed but was not requested")
    if r.unexpected:
        p.append(f"installer requested non-release URLs: {r.unexpected}")
    if any(not (u.startswith(REL_BASE + ctx.version + "/") or u in (API_LATEST, API_LIST)) for u in r.urls):
        p.append(f"a request left the pinned release {ctx.version}: {r.urls}")
    return p


# ---------------------------------------------------------------- serve probes

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_probe(cmd: list[str], env: dict[str, str], port: int, logfile: Path, timeout: float) -> tuple[bool, str]:
    """Start `cmd` in its own process group; True once 127.0.0.1:port accepts a
    connection while the process is alive. Always terminates the group."""
    log = open(logfile, "wb")
    try:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                env=env, start_new_session=True)
    except OSError as ex:
        log.close()
        return False, f"could not execute {cmd[0]}: {ex}"
    _LIVE_PGIDS.add(proc.pid)
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False, f"exited early rc={proc.returncode}: {logfile.read_text(errors='replace')[-300:]!r}"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True, f"accepted TCP on 127.0.0.1:{port}"
            except OSError:
                time.sleep(0.2)
        return False, f"no listener on 127.0.0.1:{port} within {timeout}s"
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            except ProcessLookupError:
                pass
        _LIVE_PGIDS.discard(proc.pid)
        log.close()


def gateway_starts(binary: Path, policy: Path, home: Path, timeout: float = 30.0) -> tuple[bool, str]:
    port = free_port()
    state = home / "gw"
    state.mkdir(parents=True, exist_ok=True)
    cmd = [str(binary), "--policy", str(policy), "--listen", f"127.0.0.1:{port}",
           "--audit-dir", str(state / "audit"), "--db-path", str(state / "gw.db")]
    return serve_probe(cmd, {"PATH": "/usr/bin:/bin", "HOME": str(home)}, port, state / "gateway.log", timeout)


def api_server_starts(binary: Path, home: Path, timeout: float = 30.0) -> tuple[bool, str]:
    # aa-api-server has no --version: any invocation starts the server, so the
    # probe starts it on a free loopback port with a throwaway key.
    port = free_port()
    d = home / "api"
    d.mkdir(parents=True, exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "AA_API_ADDR": f"127.0.0.1:{port}",
           "AASM_API_KEY": "aa_" + secrets.token_hex(16)}
    return serve_probe([str(binary)], env, port, d / "api.log", timeout)


def aasm_gateway_lifecycle(aasm: Path, policy: Path, home: Path, timeout: float = 45.0) -> tuple[bool, str, bool]:
    """`aasm gateway status` (must be non-zero before start), `start`, `status`
    (zero), `stop`. Returns (ok, detail, pre_start_status_nonzero)."""
    port = free_port()
    data = home / "aasdata"
    data.mkdir(parents=True, exist_ok=True)
    env = {"PATH": f"{aasm.parent}:/usr/bin:/bin", "HOME": str(home), "AA_DATA_DIR": str(data)}

    def sh(*args: str, t: float = 60.0) -> int:
        try:
            return subprocess.run([str(aasm), *args], env=env, capture_output=True, timeout=t,
                                  stdin=subprocess.DEVNULL).returncode
        except (OSError, subprocess.TimeoutExpired):
            return 124

    pre = sh("gateway", "status") != 0
    ok, detail = False, ""
    try:
        rc = sh("gateway", "start", "--policy", str(policy), "--listen", f"127.0.0.1:{port}")
        if rc != 0:
            return False, f"`aasm gateway start` exit {rc}", pre
        deadline = time.monotonic() + timeout
        up = False
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    up = True
                    break
            except OSError:
                time.sleep(0.3)
        st = sh("gateway", "status")
        ok = up and st == 0
        detail = f"listener={'up' if up else 'down'} `aasm gateway status` exit {st}"
    finally:
        sh("gateway", "stop")
        pidf = data / "gateway.pid"
        if pidf.is_file():
            m = re.search(r"\d+", pidf.read_text(errors="replace"))
            if m:
                try:
                    os.kill(int(m.group()), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
    return ok, detail, pre


# ---------------------------------------------------------------- checks

def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/usr/bin/git", "-C", str(REPO_ROOT), *args], capture_output=True, timeout=60,
                          stdin=subprocess.DEVNULL)


def source_matches_candidate_sha(ctx: Ctx) -> None:
    """Tie the harness, installer and policy it hashes to candidate_sha: the
    checkout HEAD must be that commit and each file must equal its blob there
    (a dirty or foreign file is a FAIL). Otherwise candidate_sha is only a label."""
    prob: list[str] = []
    full = ""
    r = _git("rev-parse", "--verify", f"{ctx.a.candidate_sha}^{{commit}}")
    if r.returncode != 0:
        prob.append("candidate_sha is not a commit in this checkout")
    else:
        full = r.stdout.decode().strip()
        head = _git("rev-parse", "HEAD").stdout.decode().strip()
        if head != full:
            prob.append(f"checkout HEAD {head} != candidate commit {full}")
    root = REPO_ROOT.resolve()
    tied = {"installer": ctx.installer, "policy": Path(ctx.a.policy).resolve(), "harness": Path(__file__).resolve()}
    for label, path in tied.items():
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            prob.append(f"{label} {path} is outside the repo checkout, so it cannot be tied to the candidate")
            continue
        if not full:
            continue
        blob = _git("show", f"{full}:{rel}")
        if blob.returncode != 0:
            prob.append(f"{label} {rel} does not exist in the candidate commit")
        elif blob.stdout != path.read_bytes():
            prob.append(f"{label} {rel} differs from the candidate commit (dirty or foreign file)")
    ctx.record(f"{ctx.a.journey}.source_matches_candidate_sha", not prob,
               "; ".join(prob) or f"checkout HEAD is {full}; installer, policy and harness equal their candidate blobs",
               [], extra={"policy:" + Path(ctx.a.policy).name: digest(Path(ctx.a.policy))})


def native_version_output(binary: Path, home: Path, want: str) -> tuple[bool, str]:
    try:
        e = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=60,
                           env={"PATH": "/usr/bin:/bin", "HOME": str(home)}, stdin=subprocess.DEVNULL)
        out, rc = e.stdout + e.stderr, e.returncode
    except (OSError, subprocess.TimeoutExpired) as ex:
        rc, out = 1, str(ex)
    return rc == 0 and want in out, f"{binary.name} --version rc={rc} output={out.strip()[:200]!r} expected to contain {want!r}"


def negative_control(ctx: Ctx, cid: str, base: list[str]) -> None:
    """The pre-AAASM-6414 installer must show its SPECIFIC defect: it exits 0,
    installs aasm, and installs neither aa-gateway nor aa-api-server."""
    c_digest = digest(ctx.control)
    note = f"old installer must exit 0, install aasm only (no aa-gateway, no aa-api-server); pinned sha {CONTROL_SHA256}"
    if c_digest != "sha256:" + CONTROL_SHA256:
        if not ctx.a.allow_unpinned_control:
            ctx.record(cid, False, f"control installer digest {c_digest} differs from the pinned sha256:{CONTROL_SHA256}; "
                       "pass --allow-unpinned-control to override (result is then UNPINNED)", base, negative_control=note)
            return
        ctx.control_pinned = False
    r = run_installer(ctx.sb, ctx.plat, ctx.control, ctx.mirror, ctx.version, [])
    sig = [r.rc == 0, r.installed("aasm"), not (r.dest / "aa-gateway").exists(), not (r.dest / "aa-api-server").exists()]
    ok = all(sig)
    ctx.record(cid, ok,
               "control showed the AAASM-6414 defect signature" if ok else
               f"CONTROL DID NOT SHOW THE DEFECT SIGNATURE (rc0={sig[0]}, aasm={sig[1]}, no-gateway={sig[2]}, "
               f"no-api={sig[3]}): {r.output.strip()[-200:]}",
               base, negative_control=note, extra={"control-installer:" + ctx.control.name: c_digest})


def j04_checks(ctx: Ctx) -> None:
    plat, v = ctx.plat, ctx.version
    cli, api = plat.cli_tarball(), plat.component_tarball("api", v)
    rt, px = plat.component_tarball("runtime", v), plat.component_tarball("proxy", v)
    base = ["SHA256SUMS", cli, api]
    core = ["aasm", "aa-gateway", "aa-api-server"]

    sums = sums_map(ctx.mirror)
    prob = []
    for n in (cli, api, rt, px):
        if not (ctx.mirror / n).is_file():
            if n in (cli, api):
                prob.append(f"{n} absent from mirror")
        elif n not in sums:
            prob.append(f"SHA256SUMS has no entry for {n}")
        elif sha256_file(ctx.mirror / n) != sums[n]:
            prob.append(f"{n} digest differs from SHA256SUMS")
    ctx.record("j04.sha256sums_match_artifacts", not prob, "; ".join(prob) or "every present tarball matches SHA256SUMS",
               base + [rt, px])

    r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [])
    prob = install_problems(r, ctx, core)
    if f"version={v}" not in r.manifest.splitlines():
        prob.append(f"manifest version is not {v}")
    ctx.record("j04.installer_default_installs_all_binaries", not prob,
               "; ".join(prob) or "aasm, aa-gateway, aa-api-server installed (bytes equal tarball members)", base)
    default_run = r

    r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [], mode="env")
    prob = install_problems(r, ctx, core)
    ctx.record("j04.installer_version_pin_env", not prob, "; ".join(prob) or f"AASM_VERSION={v} pinned", base)

    prob = []
    for mode in ("latest", "list"):
        r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [], mode=mode)
        prob += [f"[{mode}] {x}" for x in install_problems(r, ctx, core)]
        want = API_LATEST if mode == "latest" else API_LIST
        if want not in r.urls:
            prob.append(f"[{mode}] installer never asked {want}")
        if f"version={v}" not in r.manifest.splitlines():
            prob.append(f"[{mode}] resolved version is not {v}")
    ctx.record("j04.installer_latest_resolution", not prob,
               "; ".join(prob) or "unpinned install resolved the stand-in latest release via /releases/latest and via the "
               "per_page=1 fallback", base)

    tm = tampered_mirror(ctx.sb, ctx.mirror, cli)
    r = run_installer(ctx.sb, plat, ctx.installer, tm, v, [])
    prob = []
    if r.rc == 0:
        prob.append("installer accepted a tampered tarball")
    if "SHA256 mismatch" not in r.output:
        prob.append("no 'SHA256 mismatch' diagnostic from the installer's own verification")
    for b in core:
        if (r.dest / b).exists():
            prob.append(f"{b} present after refused install")
    ctx.record("j04.installer_refuses_tampered_tarball", not prob,
               "; ".join(prob) or "tampered cli tarball refused by the installer's checksum verification; nothing installed", base)

    u = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [], uninstall_of=default_run)
    left = [b for b in core if (default_run.dest / b).exists()]
    prob = ([f"uninstall exit {u.rc}"] if u.rc else []) + ([f"left behind: {left}"] if left else [])
    ctx.record("j04.installer_uninstall_removes_binaries", not prob, "; ".join(prob) or "all binaries removed", base)

    if (ctx.mirror / rt).is_file():
        r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, ["--components", "cli,runtime"])
        prob = install_problems(r, ctx, ["aasm", "aa-gateway", "aa-runtime"], absent=["aa-api-server"])
        ctx.record("j04.installer_components_cli_runtime", not prob, "; ".join(prob) or "--components cli,runtime installs exactly those",
                   base + [rt])
        r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, ["--profile", "local"])
        prob = install_problems(r, ctx, core + ["aa-runtime"])
        ctx.record("j04.installer_profile_local_installs_runtime", not prob, "; ".join(prob) or "cli+api+runtime installed", base + [rt])
    else:
        for cid in ("j04.installer_components_cli_runtime", "j04.installer_profile_local_installs_runtime"):
            ctx.skip(cid, f"{rt} not in mirror (the runtime AC needs it)")
    if (ctx.mirror / rt).is_file() and (ctx.mirror / px).is_file():
        r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, ["--profile", "full"])
        prob = install_problems(r, ctx, core + ["aa-runtime", "aa-proxy"])
        ctx.record("j04.installer_profile_full", not prob, "; ".join(prob) or "--profile full installed cli+api+runtime+proxy",
                   base + [rt, px])
    else:
        ctx.skip("j04.installer_profile_full", f"{rt} and {px} are both required")

    if plat.native:
        r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [])
        ok, d = native_version_output(r.dest / "aasm", r.home, v.lstrip("v"))
        ctx.record("j04.installed_aasm_version_output", ok, d, base)
        ok, d = native_version_output(r.dest / "aa-gateway", r.home, v.lstrip("v"))
        ctx.record("j04.installed_gateway_version_output", ok, d, base)
        ok, d = api_server_starts(r.dest / "aa-api-server", r.home)
        ctx.record("j04.installed_api_server_starts", ok, d, base)
    else:
        for cid in ("j04.installed_aasm_version_output", "j04.installed_gateway_version_output", "j04.installed_api_server_starts"):
            ctx.skip(cid, f"candidate platform {plat.os}/{plat.arch} is not the host {'/'.join(plat.host)}; run on a matching host")

    negative_control(ctx, "j04.negative_control_old_installer_fails", base)


def j17_checks(ctx: Ctx) -> None:
    plat, v = ctx.plat, ctx.version
    cli, api = plat.cli_tarball(), plat.component_tarball("api", v)
    base = ["SHA256SUMS", cli, api]
    pol = {"policy:" + ctx.policy.name: digest(ctx.policy)}

    r = run_installer(ctx.sb, plat, ctx.installer, ctx.mirror, v, [])
    prob = install_problems(r, ctx, ["aasm", "aa-gateway"])
    ctx.record("j17.installer_places_gateway_beside_aasm", not prob,
               "; ".join(prob) or "aa-gateway installed beside aasm (where `aasm gateway start` looks)", base)

    if plat.native and r.installed("aa-gateway") and r.installed("aasm"):
        ok, d = native_version_output(r.dest / "aa-gateway", r.home, v.lstrip("v"))
        ctx.record("j17.installed_gateway_version_output", ok, d, base)

        ok, detail = gateway_starts(r.dest / "aa-gateway", ctx.policy, r.home)
        ok_ctl, detail_ctl = gateway_starts(r.dest / "aa-gateway", ctx.policy.with_name("does-not-exist.yaml"), r.home, timeout=15.0)
        ctx.record("j17.gateway_serves_sample_policy", ok and not ok_ctl,
                   f"{detail}; control (missing policy): {detail_ctl}", base,
                   negative_control="same start check with a nonexistent --policy path must FAIL"
                   + (" (it did)" if not ok_ctl else " (IT DID NOT)"), extra=pol)

        ok, detail, pre = aasm_gateway_lifecycle(r.dest / "aasm", ctx.policy, r.home)
        ctx.record("j17.aasm_gateway_start_status_stop", ok and pre,
                   f"{detail}; `aasm gateway status` non-zero before start: {pre}", base,
                   negative_control="`aasm gateway status` must be non-zero before start and zero after", extra=pol)
    else:
        for cid in ("j17.installed_gateway_version_output", "j17.gateway_serves_sample_policy", "j17.aasm_gateway_start_status_stop"):
            ctx.skip(cid, f"candidate platform {plat.os}/{plat.arch} is not the host {'/'.join(plat.host)} "
                          "(or aasm/aa-gateway not installed); run on a matching host")

    negative_control(ctx, "j17.negative_control_old_installer_has_no_gateway", base)


# ---------------------------------------------------------------- pending (publication) checks

_PRELUDE = r"""set -eu
TAG=%(tag)s
VER="${TAG#v}"
BASE="${B1_RELEASE_BASE:-https://github.com/ai-agent-assembly/agent-assembly/releases/download}/$TAG"
D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
need_sha() { [ "$(sha "$1")" = "$2" ] || { echo "digest mismatch for $1 (candidate expects $2)" >&2; exit 1; }; }
need_ver() { case "$1" in *"$VER"*) ;; *) echo "version output '$1' lacks $VER" >&2; exit 1 ;; esac; }
"""


def _sh(tag: str, body: str) -> str:
    script = (_PRELUDE % {"tag": shlex.quote(tag)}) + body
    return "sh -c " + shlex.quote(script)


def pending(journey: str, ctx: Ctx) -> list[dict]:
    tag, plat = ctx.version, ctx.plat
    names = {"cli": plat.cli_tarball(), "api": plat.component_tarball("api", tag),
             "runtime": plat.component_tarball("runtime", tag), "proxy": plat.component_tarball("proxy", tag)}
    tdig = {k: ctx.src_digests[n].split(":", 1)[1] for k, n in names.items() if n in ctx.src_digests}
    mem = {}
    for b, k in (("aasm", "cli"), ("aa-gateway", "cli"), ("aa-api-server", "api"), ("aa-runtime", "runtime")):
        if names[k] in ctx.src_digests:
            m = member_sha(ctx.mirror / names[k], b)
            if m:
                mem[b] = m

    def eq(binary: str, path: str) -> str:
        return f'need_sha "{path}" {mem[binary]}\n' if binary in mem else ""

    install = ('export HOME="$D/home"; mkdir -p "$HOME"\n'
               'curl -fsSL "${B1_INSTALL_SH_URL:-https://agent-assembly.com/install.sh}" -o "$D/install.sh"\n')
    fr = ("Do not announce or tag as released. Open a Bug sub-ticket under the journey Story with the command "
          "output; notify the release owner within the deadline; fix forward with a new candidate and re-run "
          "this harness plus this pending check. No yank/delete of published assets without owner approval.")
    iso = "isolated: everything lives in one mktemp dir removed on exit; only reads the public internet"
    brew_iso = ("NOT ISOLATED: installs or UPGRADES in the REAL Homebrew prefix (`brew upgrade || brew install`); "
                "a stale older install cannot false-PASS because the version and candidate digest are asserted")

    sums_loop = "".join(
        f'curl -fsSL "$BASE/{n}" -o "$D/{n}"\n'
        f'want="$(awk -v n="{n}" \'$2==n || $2=="*"n {{print $1; exit}}\' "$D/SHA256SUMS")"\n'
        f'[ -n "$want" ] && [ "$(sha "$D/{n}")" = "$want" ] || {{ echo "{n}: published digest != SHA256SUMS" >&2; exit 1; }}\n'
        + (f'[ "$want" = {tdig[k]} ] || {{ echo "{n}: published digest != candidate digest" >&2; exit 1; }}\n' if k in tdig else "")
        for k, n in names.items())

    if journey == "J04":
        items = [
            ("j04.published_install_sh_default", "github-release+agent-assembly.com",
             "Fetches the live installer and the public GitHub Release; neither exists before publication.",
             _sh(tag, install + 'AASM_NO_MODIFY_PATH=1 sh "$D/install.sh" --version "$TAG" --install-dir "$D/bin"\n'
                 'need_ver "$("$D/bin/aasm" --version)"\n'
                 'for b in aasm aa-gateway aa-api-server; do [ -x "$D/bin/$b" ] || { echo "missing $b" >&2; exit 1; }; done\n'
                 + eq("aasm", "$D/bin/aasm") + eq("aa-gateway", "$D/bin/aa-gateway") + eq("aa-api-server", "$D/bin/aa-api-server")),
             "exit 0; aasm --version contains the tag's version; aasm, aa-gateway and aa-api-server present and byte-equal to the candidate tarball members",
             iso),
            ("j04.published_release_checksums_and_signature", "github-release",
             "The cosign bundle is produced by release.yml at tag time and the assets are public only after publish.",
             _sh(tag, 'curl -fsSL "$BASE/SHA256SUMS" -o "$D/SHA256SUMS"\n'
                 'curl -fsSL "$BASE/SHA256SUMS.cosign.bundle" -o "$D/SHA256SUMS.cosign.bundle"\n'
                 + sums_loop +
                 'command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 1; }\n'
                 '(cd "$D" && cosign verify-blob --bundle SHA256SUMS.cosign.bundle --certificate-identity-regexp '
                 + shlex.quote(r"^https://github.com/ai-agent-assembly/agent-assembly/\.github/workflows/release\.yml@refs/tags/v.*$")
                 + ' --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS)\n'),
             "exit 0: every published tarball digest equals both SHA256SUMS and the candidate digest; cosign verify-blob passes for release.yml at this tag",
             iso),
            ("j04.published_homebrew_tap_install", "homebrew-tap",
             "The formula is committed to ai-agent-assembly/homebrew-tap by release.yml after publication.",
             _sh(tag, 'command -v brew >/dev/null 2>&1 || { echo "brew not found" >&2; exit 1; }\n'
                 'brew upgrade ai-agent-assembly/tap/aasm 2>/dev/null || brew install ai-agent-assembly/tap/aasm\nP="$(brew --prefix)/bin"\n'
                 'need_ver "$("$P/aasm" --version)"\n[ -x "$P/aa-gateway" ] || { echo "aa-gateway not installed by the formula" >&2; exit 1; }\n'
                 + eq("aasm", "$P/aasm") + eq("aa-gateway", "$P/aa-gateway")),
             "aasm --version contains the tag's version; aa-gateway installed (the AAASM-4448/4449 suspect); bytes equal the candidate members",
             brew_iso),
            ("j04.published_homebrew_runtime", "homebrew-tap",
             "Needs the tap formula for aasm-runtime.",
             _sh(tag, 'command -v brew >/dev/null 2>&1 || { echo "brew not found" >&2; exit 1; }\n'
                 'brew upgrade ai-agent-assembly/tap/aasm-runtime 2>/dev/null || brew install ai-agent-assembly/tap/aasm-runtime\nP="$(brew --prefix)/bin"\n'
                 '[ -x "$P/aa-runtime" ] || { echo "aa-runtime not installed" >&2; exit 1; }\n'
                 + eq("aa-runtime", "$P/aa-runtime")),
             "aa-runtime installed and byte-equal to the candidate runtime tarball member", brew_iso),
            ("j04.published_latest_resolves_to_candidate", "github-api",
             "Unpinned `curl | sh` resolves the latest release through the GitHub API; the candidate-time check only "
             "exercises a stand-in reply. rc tags are prereleases and may not appear in /releases/latest.",
             _sh(tag, 'API="${B1_API_BASE:-https://api.github.com/repos/ai-agent-assembly/agent-assembly}"\n'
                 'H1="Accept: application/vnd.github+json"\n'
                 'curl -fsS -H "$H1" -A aa-b1-release-qa "$API/releases?per_page=1" -o "$D/list.json"\n'
                 'top="$(python3 -I -c \'import json,sys; print(json.load(open(sys.argv[1]))[0]["tag_name"])\' "$D/list.json")"\n'
                 '[ "$top" = "$TAG" ] || { echo "newest release is $top, not $TAG" >&2; exit 1; }\n'
                 'code="$(curl -sS -H "$H1" -A aa-b1-release-qa -o "$D/latest.json" -w "%{http_code}" "$API/releases/latest" || true)"\n'
                 'case "$code" in\n'
                 '  404) echo "/releases/latest is 404 (no stable release): the installer falls back to per_page=1 = $TAG" ;;\n'
                 '  200) lt="$(python3 -I -c \'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"])\' "$D/latest.json")"\n'
                 '       [ "$lt" = "$TAG" ] || { echo "unpinned install would resolve to $lt, not the candidate $TAG" >&2; exit 1; } ;;\n'
                 '  *) echo "unexpected HTTP $code from /releases/latest" >&2; exit 1 ;;\n'
                 'esac\n'),
             "exit 0: newest release is the candidate tag and an unpinned install would resolve to it (via /releases/latest when it exists, else the per_page=1 fallback)",
             "read-only GitHub API probe; unauthenticated requests are rate limited"),
            ("j04.published_crates_io_aa_cli", "crates.io",
             "crates.io state exists only after publication.",
             _sh(tag, 'curl -fsS -A "aa-b1-release-qa" https://crates.io/api/v1/crates/aa-cli -o "$D/c.json"\n'
                 'mv="$(python3 -I -c \'import json,sys; print(json.load(open(sys.argv[1]))["crate"]["max_version"])\' "$D/c.json")"\n'
                 '[ "$mv" = "$VER" ] || { echo "crates.io aa-cli max_version=$mv, expected $VER" >&2; exit 1; }\n'),
             "exit 0 when crates.io max_version equals the candidate version; a non-zero exit means either not published or an intentional absence that needs the documented decision",
             iso),
        ]
    else:
        gw_run = (
            'curl -fsSL "${B1_POLICY_URL:-https://raw.githubusercontent.com/ai-agent-assembly/agent-assembly/$TAG/policy-examples/low-risk.yaml}" -o "$D/low-risk.yaml"\n'
            + f'need_sha "$D/low-risk.yaml" {sha256_file(ctx.policy)}\n'
            + 'P="$(python3 -I -c \'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])\')"\n'
            '"$D/bin/aa-gateway" --policy "$D/low-risk.yaml" --listen "127.0.0.1:$P" --audit-dir "$D/audit" --db-path "$D/gw.db" >"$D/gw.log" 2>&1 &\n'
            'G=$!\ntrap \'kill "$G" 2>/dev/null || true; rm -rf "$D"\' EXIT\ni=0\n'
            'until python3 -I -c \'import socket,sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1)\' "$P" 2>/dev/null; do\n'
            '  i=$((i+1))\n  if [ "$i" -ge 60 ] || ! kill -0 "$G" 2>/dev/null; then echo "gateway did not listen on $P" >&2; exit 1; fi\n  sleep 0.5\ndone\n')
        items = [
            ("j17.published_installer_profile_full_gateway", "github-release+agent-assembly.com",
             "Installs from the public Release assets.",
             _sh(tag, install + 'AASM_NO_MODIFY_PATH=1 sh "$D/install.sh" --profile full --version "$TAG" --install-dir "$D/bin"\n'
                 'need_ver "$("$D/bin/aa-gateway" --version)"\n' + eq("aa-gateway", "$D/bin/aa-gateway") + gw_run),
             "exit 0: installed aa-gateway reports the tag's version, equals the candidate member, and serves the sample policy on a loopback port",
             iso),
            ("j17.published_homebrew_gateway", "homebrew-tap",
             "Formula lives in the tap after publication.",
             _sh(tag, 'command -v brew >/dev/null 2>&1 || { echo "brew not found" >&2; exit 1; }\n'
                 'brew upgrade ai-agent-assembly/tap/aasm 2>/dev/null || brew install ai-agent-assembly/tap/aasm\nP="$(brew --prefix)/bin"\n'
                 '[ -x "$P/aa-gateway" ] || { echo "aa-gateway not installed by the formula" >&2; exit 1; }\n'
                 'need_ver "$("$P/aa-gateway" --version)"\n' + eq("aa-gateway", "$P/aa-gateway")),
             "aa-gateway installed by the formula, reports the tag's version and equals the candidate member (AAASM-4448/4449 suspect)",
             brew_iso),
            ("j17.published_container_image_manifest", "ghcr.io",
             "The image exists in GHCR only after the release workflow pushes it. Inferred: only ghcr.io/ai-agent-assembly/aa-runtime "
             "is referenced in-repo; no gateway image name was found.",
             _sh(tag, 'command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }\n'
                 'docker manifest inspect "ghcr.io/ai-agent-assembly/aa-runtime:$TAG" > "$D/m.json"\n'
                 'python3 -I -c \'import json,sys; m=json.load(open(sys.argv[1])); p={(x["platform"]["os"],x["platform"]["architecture"]) for x in m.get("manifests",[])}; sys.exit(0 if {("linux","amd64"),("linux","arm64")}<=p else 1)\' "$D/m.json"\n'),
             "manifest resolves for linux/amd64 and linux/arm64 (read-only registry probe)",
             "read-only registry probe; needs docker and network"),
        ]
    return [{"id": i, "status": "PENDING", "channel": ch, "why_publication_only": why, "command": cmd,
             "expected": exp, "side_effects": se, "failure_response": fr,
             "deadline_hours": FAILURE_RESPONSE["deadline_hours"]}
            for i, ch, why, cmd, exp, se in items]


def build_result(ctx: Ctx, a: argparse.Namespace) -> dict:
    # The source mirror must not have changed under the snapshot we hashed.
    drift = [n for n, d in ctx.src_digests.items()
             if not (ctx.src_mirror / n).is_file() or digest(ctx.src_mirror / n) != d]
    if drift:
        ctx.record("harness.mirror_unchanged_during_run", False, f"mirror files changed during the run: {drift}", [])
    journey = a.journey.upper()
    pend = pending(journey, ctx)
    failed = [c["id"] for c in ctx.checks if c["status"] != "PASS"]
    if failed:
        overall, code = "CANDIDATE_FAIL", 1
    elif ctx.not_run:
        overall, code = "INCOMPLETE", 3
    elif not ctx.control_pinned:
        overall, code = "UNPINNED_CONTROL", 3
    else:
        overall, code = "CANDIDATE_PASS_PUBLICATION_PENDING", 0
    frag_pending = [{**{k: v for k, v in p.items() if k != "status"}, "status": "PUBLICATION_PENDING"} for p in pend]
    result = {
        "harness": "scripts/qa/b1/candidate_harness.py", "harness_version": HARNESS_VERSION,
        "journey": journey, "version": a.version, "candidate_sha": a.candidate_sha,
        "platform": f"{ctx.plat.os}/{ctx.plat.arch}", "host": "/".join(ctx.plat.host),
        "control_pinned": ctx.control_pinned, "control_sha256_pinned": CONTROL_SHA256,
        "artifact_digests": dict(sorted(ctx.digests_all.items())),
        "candidate_checks": ctx.checks, "not_run": ctx.not_run, "not_covered": NOT_COVERED[journey],
        "pending_checks": pend, "failure_response": FAILURE_RESPONSE,
        "failed": failed, "overall": overall,
        "obligation_fragment": {
            "journey": journey, "registry_digest": None, "depends_on": None,
            "_unfilled": ["registry_digest", "depends_on"],
            "_note": "registry_digest and depends_on are placeholders for the obligation builder; "
                     "a fragment with not_run, FAIL or UNPINNED_CONTROL must not be committed as an obligation.",
            "candidate_checks": ctx.checks, "pending_checks": frag_pending, "failure_response": FAILURE_RESPONSE,
        },
    }
    return result, code


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("journey", choices=["j04", "j17"])
    ap.add_argument("--mirror-dir", required=True)
    ap.add_argument("--version", required=True, help="release tag the candidate carries, e.g. v0.0.1-rc.8")
    ap.add_argument("--candidate-sha", required=True, help="git commit sha of the candidate (7-64 hex)")
    ap.add_argument("--installer", default=str(DEFAULT_INSTALLER))
    ap.add_argument("--control-installer", default=str(DEFAULT_CONTROL))
    ap.add_argument("--allow-unpinned-control", action="store_true",
                    help="accept a control installer whose sha256 differs from the pinned one (result is UNPINNED_CONTROL)")
    ap.add_argument("--policy", default=str(DEFAULT_POLICY))
    ap.add_argument("--platform", help="simulate <os>/<arch> via a uname shim (binaries then cannot be executed)")
    a = ap.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{7,64}", a.candidate_sha):
        print("error: --candidate-sha must be 7-64 lowercase hex characters", file=sys.stderr)
        return 2
    for label, path in (("mirror-dir", a.mirror_dir), ("installer", a.installer),
                        ("control-installer", a.control_installer), ("policy", a.policy)):
        if not Path(path).exists():
            print(f"error: --{label} {path} does not exist", file=sys.stderr)
            return 2
    atexit.register(_cleanup_all)
    for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(s, _on_signal)
    ctx = Ctx(a)
    try:
        source_matches_candidate_sha(ctx)
        (j04_checks if a.journey == "j04" else j17_checks)(ctx)
        result, code = build_result(ctx, a)
    finally:
        _cleanup_all()
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
