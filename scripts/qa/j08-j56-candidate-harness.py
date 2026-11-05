#!/usr/bin/env python3
"""J08 (AAASM-4530) and J56 (AAASM-4976) pre-publication candidate harness: governed Python agent.

Both journeys are "install the Python SDK from PyPI, govern an agent against the gateway".
Nothing is published before the tag, so this harness installs a python-sdk wheel built
from a pinned SDK SHA into a clean venv (`pip install --no-index --find-links`, no
network) and drives it against the candidate `aasm`, `aa-gateway`, `aa-runtime` and
`aa-api-server` binaries as real local processes. Record schema, verdict tokens and exit
codes are the shared `b1-candidate-report/1` of `b1_candidate_common.py` (AAASM-6419).

Checks (fidelity real_local_process unless noted), one report per `--journey`:

  J56  install-clean-venv-native-core   wheel installs in a fresh venv and `_core` imports
       register-authenticated           good key registers; a wrong key does not
       allow-read-file                  `golden-path` ALLOW reaches the tool body
       deny-delete-file-typed-no-sideeffect   typed SDK error, sentinel untouched
       send-email-approval-or-gap       never PASS: FAIL if the email was sent, else a classified gap
       audit-correlation                `aasm audit export` shows the allow and the deny for this agent
       policy-flip-changes-behavior     read_file flipped to deny changes the same call
       unwired-callbacks-control        the same delete_file with the SDK hook not invoked DOES run,
                                        so the block above is attributable to the SDK wiring
  J08  register-governed-agent, allow-deny, readme-snippet-matches-wiring (static, over the wheel)

Publication-dependent rows are PENDING and equal the registry ids in
`qa/golden-journeys.yaml`; the registry allows exactly one per journey, so public-docs
discoverability is part of that row's `expected` text rather than a separate id.

The real-run process wiring (how the four binaries are started and which endpoint the SDK
dials) is unproven until the coordinator's first run on real binaries; a stack that does
not come up is reported FAIL/NOT_COVERED, never PASS. Logic is unit-tested through the
`Backend` seam in scripts/tests/test_j08_j56_candidate_harness.py.

Usage:
  python3 -I scripts/qa/j08-j56-candidate-harness.py --journey J56 --candidate-sha <40hex> \
      --version 0.0.1-rc.8 --repo <checkout> --gateway <p> --runtime <p> --api-server <p> --aasm <p> \
      --sdk-wheel <whl> --sdk-sha <40hex> [--expected-digests d.json] [--out r.json]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import uuid
import zipfile
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import b1_candidate_common as c  # noqa: E402

SCRIPT = "scripts/qa/j08-j56-candidate-harness.py"
TEST = "scripts/tests/test_j08_j56_candidate_harness.py"
FIX = "scripts/qa/fixtures/j56"
SOURCES = {
    "golden-path.v1.yaml": f"{FIX}/golden-path.v1.yaml",
    "golden-path.v2-read-deny.yaml": f"{FIX}/golden-path.v2-read-deny.yaml",
    "sdk_driver.py": f"{FIX}/sdk_driver.py",
}
BINARIES = ("aasm", "aa-gateway", "aa-runtime", "aa-api-server")
WHEEL = "python-sdk-wheel"
# A syntactically valid key for a throwaway loopback server; not a credential.
TEST_KEY = "aa_0123456789abcdef0123456789abcdef"
WRONG_KEY = "aa_" + "f" * 32

PENDING_BY_JOURNEY = {
    "J08": c.PendingCheck(
        "j08-published-python-sdk-governed-agent", "pypi",
        "the published SDK only exists on PyPI after the SDK release job runs; the wheel built from the pinned SHA "
        "is not proven byte-identical to it, and docs discoverability needs the live public docs site",
        "pip install --pre agent-assembly==<sdk version> in a clean venv with network, then python3 -I "
        "scripts/qa/j08-j56-candidate-harness.py --journey J08 ... --sdk-wheel <downloaded wheel>",
        "the published wheel installs, its `_core` imports, a governed agent registers against the candidate gateway, "
        "and the public docs quick start for the Python SDK is reachable and names the same install command",
    ),
    "J56": c.PendingCheck(
        "j56-published-python-sdk-canonical-11-step", "pypi",
        "the canonical clean-environment run must use the published SDK and published gateway, which exist only "
        "after release; docs discoverability of the 11 steps needs the live public docs site",
        "pip install --pre agent-assembly==<sdk version> in a clean venv with network, then python3 -I "
        "scripts/qa/j08-j56-candidate-harness.py --journey J56 ... --sdk-wheel <downloaded wheel>",
        "every J56 candidate check is PASS against the published wheel and published binaries, and the public docs "
        "describe the same steps",
    ),
}
JOURNEY_JIRA = {"J08": "AAASM-4530", "J56": "AAASM-4976"}


def failure_response(journey: str) -> dict[str, Any]:
    return {
        "proposed_actions": [
            f"do not announce the release as Python-SDK-ready; record {journey} as failed post-publication",
            f"file a Bug against {JOURNEY_JIRA[journey]} naming the failing check id, the candidate SHA and the wheel digest",
            "if the published wheel differs from the candidate wheel, re-run the SDK publish job on the same SHA before any announcement",
        ],
        "notify": ["release-owner"],
        "deadline_hours": 24,
    }


DEPENDS_ON = [
    {"repo": "python-sdk", "event": "SDK release publishes the wheel to PyPI"},
    {"repo": "agent-assembly", "event": "release.yml publish (GitHub Release assets)"},
]

TYPED_ERRORS = {"ToolExecutionBlockedError", "PolicyViolationError", "MCPToolBlockedError"}
# A LangChain callback only governs a tool when LangChain is told about it; these are the
# hooks through which a handler held in a module global becomes part of a run.
LANGCHAIN_HOOKS = ("register_configure_hook", "add_handler(", "inheritable_handlers", "CallbackManager.configure")
README_CLAIM = re.compile(r"init_assembly\(\)[^\n]{0,200}(auto-load|each tool call|policy gate|allow/deny)", re.I)


class Backend:
    """The exec seam. Everything that starts a process or touches the SDK goes through here,
    so the check logic can be driven by a fake in unit tests with no SDK or binaries."""

    good_key = TEST_KEY

    def version_of(self, name: str) -> tuple[int, str]: raise NotImplementedError
    def install(self) -> tuple[int, str]: raise NotImplementedError
    def start(self, policy: Path) -> tuple[bool, str]: raise NotImplementedError
    def sdk(self, op: str, **kw: Any) -> dict[str, Any]: raise NotImplementedError
    def apply_policy(self, policy: Path) -> tuple[int, str]: raise NotImplementedError
    def audit(self, agent: str) -> tuple[int, str]: raise NotImplementedError
    def agent_list(self) -> tuple[int, str]: raise NotImplementedError
    def stop(self) -> None: raise NotImplementedError


class LocalBackend(Backend):
    """Real local processes: copied binaries, isolated HOME, loopback port, offline venv."""

    def __init__(self, ctx: c.Context, bins: dict[str, Path], wheel: Path, driver: Path,
                 exec_fn: Callable[..., tuple[int, str]] = c.run):
        self.ctx, self.wheel, self.driver, self.exec = ctx, wheel, driver, exec_fn
        self.bindir = ctx.tmp / "bin"
        self.bindir.mkdir()
        for name, src in bins.items():
            shutil.copy(src, self.bindir / name)
        self.home = ctx.tmp / "home"
        self.home.mkdir()
        self.venv = ctx.tmp / "venv"
        self.port = c.free_port()
        self.agent = f"j56-{uuid.uuid4().hex[:8]}"
        self.env = c.clean_env(self.home, {"PATH": f"{self.bindir}:/usr/bin:/bin", "AASM_API_KEY": TEST_KEY})
        self.pidfile = self.home / ".aasm" / "gateway.pid"
        ctx.owned_pidfiles.append(self.pidfile)
        self.started = False

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _cli(self, *args: str, timeout: int = 30) -> tuple[int, str]:
        return self.exec([str(self.bindir / "aasm"), *args], self.env, self.ctx.tmp, timeout)

    def version_of(self, name: str) -> tuple[int, str]:
        return self.exec([str(self.bindir / name), "--version"], self.env, self.ctx.tmp, 30)

    def install(self) -> tuple[int, str]:
        # Without --no-index a missing dependency would be fetched from PyPI and the run
        # would silently stop being offline.
        rc, out = self.exec([sys.executable, "-m", "venv", str(self.venv)], self.env, self.ctx.tmp, 120)
        if rc != 0:
            return rc, out
        env = {**self.env, "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1"}
        return self.exec([str(self.venv / "bin" / "python"), "-m", "pip", "install", "--no-index",
                          "--find-links", str(self.wheel.parent), str(self.wheel)], env, self.ctx.tmp, 300)

    def start(self, policy: Path) -> tuple[bool, str]:
        rc, out = self._cli("start", "--host", "127.0.0.1", "--port", str(self.port), timeout=90)
        self.started = rc == 0
        if rc != 0:
            return False, f"aasm start exited {rc}: {out.strip()[:300]}"
        rc, out = self.apply_policy(policy)
        return rc == 0, f"aasm policy apply exited {rc}: {out.strip()[:200]}"

    def sdk(self, op: str, **kw: Any) -> dict[str, Any]:
        argv = [str(self.venv / "bin" / "python"), "-I", str(self.driver), op, "--gateway-url", self.url,
                "--key", kw.get("key", TEST_KEY), "--agent", self.agent]
        for flag in ("tool", "sentinel"):
            if kw.get(flag):
                argv += [f"--{flag}", str(kw[flag])]
        if kw.get("unwired"):
            argv.append("--unwired")
        rc, out = self.exec(argv, self.env, self.ctx.tmp, 120)
        for line in reversed(out.splitlines()):
            if line.startswith("RESULT "):
                try:
                    return json.loads(line[len("RESULT "):])
                except ValueError:
                    break
        return {"error": "driver-no-result", "detail": f"exit {rc}: {out.strip()[-200:]}"}

    def apply_policy(self, policy: Path) -> tuple[int, str]:
        return self._cli("policy", "apply", str(policy))

    def audit(self, agent: str) -> tuple[int, str]:
        return self._cli("audit", "export", "--format", "json", "--agent", agent)

    def agent_list(self) -> tuple[int, str]:
        return self._cli("agent", "list")

    def stop(self) -> None:
        if self.started:
            self._cli("stop")
            self.started = False
        c.kill_owned_daemon(self.pidfile, self.ctx.tmp)


def _tn(name: str) -> str:
    return f"{TEST}::{name}"


def _res(ctx: c.Context, cid: str, problems: list[str], ok: str, arts: list[str], neg: str,
         fidelity: str = "real_local_process") -> bool:
    ctx.add(cid, c.FAIL if problems else c.PASS, fidelity, "; ".join(problems) or ok, arts, neg)
    return not problems


def _skip(ctx: c.Context, ids: list[str], why: str) -> None:
    for cid in ids:
        ctx.add(cid, c.NOT_COVERED, "real_local_process", why, [])


def _sentinel(ctx: c.Context, name: str) -> Path:
    p = ctx.tmp / "sentinels" / name
    p.parent.mkdir(exist_ok=True)
    p.write_text(f"sentinel {name}\n")
    return p


def _blocked(r: dict[str, Any]) -> bool:
    return not r.get("executed") and bool(r.get("typed") or r.get("error") in TYPED_ERRORS)


def _drive(ctx: c.Context, be: Backend, tool: str, tag: str, unwired: bool = False) -> tuple[dict[str, Any], Path, str]:
    s = _sentinel(ctx, f"{tag}-{tool}")
    before = s.read_text()
    return be.sdk("call", tool=tool, sentinel=s, unwired=unwired), s, before


def check_install(ctx: c.Context, be: Backend, pfx: str) -> bool:
    cid = f"{pfx}-c-install-clean-venv-native-core"
    rc, out = be.install()
    if rc != 0:
        ctx.add(cid, c.FAIL, "real_local_process", f"pip install --no-index exited {rc}: {out.strip()[-300:]}",
                [WHEEL], _tn("test_install_failure_fails"))
        return False
    r = be.sdk("import-core")
    return _res(ctx, cid, [] if r.get("ok") else [f"`import agent_assembly._core` failed: {r.get('error')} {r.get('message', '')}".strip()],
                f"wheel installs offline in a fresh venv and `_core` imports (sdk {r.get('sdk_version')})",
                [WHEEL], _tn("test_missing_native_core_fails"))


def check_register(ctx: c.Context, be: Backend, cid: str, with_agent_list: bool) -> bool:
    p = []
    good = be.sdk("register", key=be.good_key)
    if good.get("registered") is not True:
        p.append(f"registration with the correct key reported registered={good.get('registered')!r} ({good.get('error')})")
    bad = be.sdk("register", key=WRONG_KEY)
    if bad.get("registered") is True:
        p.append("registration with a wrong key reported registered=True")
    if with_agent_list and not p:
        rc, out = be.agent_list()
        if rc != 0 or str(good.get("agent")) not in out:
            p.append(f"`aasm agent list` exit {rc} does not list the registered agent")
    return _res(ctx, cid, p, "correct key registers (and is listed by aasm); a wrong key does not register",
                BINARIES_ART + [WHEEL], _tn("test_wrong_key_registering_fails"))


BINARIES_ART = list(BINARIES)


def check_allow_deny(ctx: c.Context, be: Backend, allow_id: str, deny_id: str | None, combined_id: str | None) -> tuple[bool, bool]:
    r, s, _ = _drive(ctx, be, "read_file", "allow")
    p_allow = [] if r.get("executed") and s.exists() else [f"read_file was not allowed: {r.get('error')} {r.get('message', '')}".strip()]
    d, ds, before = _drive(ctx, be, "delete_file", "deny")
    p_deny = []
    if not _blocked(d):
        p_deny.append(f"delete_file did not raise a typed SDK error (executed={d.get('executed')}, error={d.get('error')!r})")
    if not ds.exists() or ds.read_text() != before:
        p_deny.append("delete_file side effect occurred: the sentinel is missing or changed")
    arts = BINARIES_ART + [WHEEL, "golden-path.v1.yaml"]
    if combined_id:
        _res(ctx, combined_id, p_allow + p_deny, "read_file allowed; delete_file denied with a typed error and the sentinel untouched",
             arts, _tn("test_delete_allowed_leaves_side_effect_fails"))
    else:
        _res(ctx, allow_id, p_allow, "read_file reaches the tool body under the golden-path ALLOW", arts, _tn("test_read_file_blocked_fails"))
        _res(ctx, deny_id or "", p_deny, "delete_file raises a typed SDK error and the sentinel is untouched", arts,
             _tn("test_delete_allowed_leaves_side_effect_fails"))
    return not p_allow, not p_deny


def check_send_email(ctx: c.Context, be: Backend, cid: str) -> None:
    r, s, _ = _drive(ctx, be, "send_email", "email")
    sent = Path(str(s) + ".sent").exists()
    neg = _tn("test_send_email_executed_without_approval_fails")
    arts = BINARIES_ART + [WHEEL, "golden-path.v1.yaml"]
    if sent or r.get("executed"):
        ctx.add(cid, c.FAIL, "real_local_process", "send_email ran although the policy requires approval", arts, neg)
        return
    # The harness drives no approver, so an approved path is never exercised: the best this can
    # be is a classified gap, and PASS would claim an approval flow nobody ran.
    ctx.add(cid, c.NOT_COVERED, "real_local_process",
            f"gap:no-approver-driven: send_email did not execute (SDK outcome: {r.get('error') or 'none'}); the "
            "pending-approval resolution surface of the SDK is not driven by this harness", arts, neg)


def check_audit(ctx: c.Context, be: Backend, cid: str) -> None:
    rc, out = be.audit(getattr(be, "agent", ""))
    neg = _tn("test_audit_without_the_deny_fails")
    arts = BINARIES_ART
    if rc != 0:
        ctx.add(cid, c.FAIL, "real_local_process", f"aasm audit export exit {rc}: {out.strip()[:200]}", arts, neg)
        return
    try:
        data = json.loads(out)
    except ValueError:
        ctx.add(cid, c.FAIL, "real_local_process", "aasm audit export did not print JSON", arts, neg)
        return
    entries = data.get("entries", data) if isinstance(data, dict) else data
    texts = [json.dumps(e, sort_keys=True).lower() for e in entries] if isinstance(entries, list) else []
    allow = any("read_file" in t and re.search(r"\ballow", t) and not re.search(r"den(y|ied)|block", t) for t in texts)
    deny = any("delete_file" in t and re.search(r"den(y|ied)|block", t) for t in texts)
    p = []
    if not allow:
        p.append("no audit entry shows read_file allowed")
    if not deny:
        p.append("no audit entry shows delete_file denied")
    _res(ctx, cid, p, "the audit chain shows the read_file allow and the delete_file deny for this agent", arts, neg)


def check_flip(ctx: c.Context, be: Backend, cid: str, flip: Path, allowed_before: bool) -> None:
    neg = _tn("test_policy_flip_ignored_fails")
    arts = BINARIES_ART + [WHEEL, "golden-path.v1.yaml", "golden-path.v2-read-deny.yaml"]
    if not allowed_before:
        ctx.add(cid, c.NOT_COVERED, "real_local_process", "read_file was not allowed before the flip, so a change cannot be shown", arts, neg)
        return
    rc, out = be.apply_policy(flip)
    if rc != 0:
        ctx.add(cid, c.FAIL, "real_local_process", f"applying the read_file=deny policy exited {rc}: {out.strip()[:200]}", arts, neg)
        return
    r, s, _ = _drive(ctx, be, "read_file", "flip")
    _res(ctx, cid, [] if _blocked(r) else [f"read_file still behaves as allowed after the flip (executed={r.get('executed')}, error={r.get('error')!r})"],
         "the same read_file call is allowed under 1.0.0 and raises a typed error under 1.1.0", arts, neg)


def check_unwired(ctx: c.Context, be: Backend, cid: str, blocked_when_wired: bool) -> None:
    neg = _tn("test_unwired_control_still_blocked_fails")
    arts = BINARIES_ART + [WHEEL]
    if not blocked_when_wired:
        ctx.add(cid, c.NOT_COVERED, "real_local_process", "the wired delete_file was not blocked, so there is no block to attribute", arts, neg)
        return
    r, s, _ = _drive(ctx, be, "delete_file", "unwired", unwired=True)
    ran = r.get("executed") is True and not s.exists()
    _res(ctx, cid, [] if ran else ["with the SDK hook not invoked delete_file did not run: the harness cannot tell SDK blocking from a fixture that refuses"],
         "delete_file runs when the SDK hook is not invoked, so the block seen when wired is caused by the SDK", arts, neg)


def check_readme(ctx: c.Context, wheel: Path, cid: str) -> None:
    neg = _tn("test_readme_claim_without_langchain_hook_fails")
    try:
        with zipfile.ZipFile(wheel) as z:
            meta = next((n for n in z.namelist() if n.endswith(".dist-info/METADATA")), None)
            readme = z.read(meta).decode("utf-8", "replace") if meta else ""
            code = "\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist()
                             if n.startswith("agent_assembly/") and n.endswith(".py"))
    except (OSError, zipfile.BadZipFile) as e:
        ctx.add(cid, c.NOT_COVERED, "static_analysis", f"cannot read the wheel: {e}", [WHEEL], neg)
        return
    if not README_CLAIM.search(readme) or not code:
        ctx.add(cid, c.NOT_COVERED, "static_analysis",
                "the wheel metadata makes no init_assembly() governance claim, or carries no agent_assembly sources", [WHEEL], neg)
        return
    wired = [h for h in LANGCHAIN_HOOKS if h in code]
    ctx.add(cid, c.PASS if wired else c.FAIL, "static_analysis",
            f"README claims init_assembly() governs tool calls; LangChain hook(s) found in the SDK: {wired}" if wired else
            "README claims init_assembly() alone governs LangChain tool calls, but the SDK only stores a callback handler "
            f"and never registers it with LangChain (none of {list(LANGCHAIN_HOOKS)} present)", [WHEEL], neg)


def run_j56(ctx: c.Context, be: Backend, repo: Path) -> None:
    fx = {k: repo / v for k, v in SOURCES.items()}
    ok_id = "j56-c-install-clean-venv-native-core"
    rest = ["j56-c-register-authenticated", "j56-c-allow-read-file", "j56-c-deny-delete-file-typed-no-sideeffect",
            "j56-c-send-email-approval-or-gap", "j56-c-audit-correlation", "j56-c-policy-flip-changes-behavior",
            "j56-c-unwired-callbacks-control"]
    if not check_install(ctx, be, "j56"):
        _skip(ctx, rest, f"{ok_id} did not pass, so the SDK cannot be driven")
        return
    up, why = be.start(fx["golden-path.v1.yaml"])
    if not up:
        ctx.add("j56-c-register-authenticated", c.FAIL, "real_local_process", f"candidate stack did not come up: {why}",
                BINARIES_ART, _tn("test_stack_start_failure_fails"))
        _skip(ctx, rest[1:], "the candidate stack did not start")
        return
    check_register(ctx, be, "j56-c-register-authenticated", with_agent_list=False)
    allowed, denied = check_allow_deny(ctx, be, "j56-c-allow-read-file", "j56-c-deny-delete-file-typed-no-sideeffect", None)
    check_send_email(ctx, be, "j56-c-send-email-approval-or-gap")
    check_audit(ctx, be, "j56-c-audit-correlation")
    check_flip(ctx, be, "j56-c-policy-flip-changes-behavior", fx["golden-path.v2-read-deny.yaml"], allowed)
    check_unwired(ctx, be, "j56-c-unwired-callbacks-control", denied)


def run_j08(ctx: c.Context, be: Backend, repo: Path, wheel: Path) -> None:
    fx = {k: repo / v for k, v in SOURCES.items()}
    check_readme(ctx, wheel, "j08-c-readme-snippet-matches-wiring")
    rest = ["j08-c-register-governed-agent", "j08-c-allow-deny"]
    if not check_install(ctx, be, "j08"):
        _skip(ctx, rest, "the SDK did not install, so it cannot be driven")
        return
    up, why = be.start(fx["golden-path.v1.yaml"])
    if not up:
        ctx.add(rest[0], c.FAIL, "real_local_process", f"candidate stack did not come up: {why}", BINARIES_ART, _tn("test_stack_start_failure_fails"))
        _skip(ctx, rest[1:], "the candidate stack did not start")
        return
    check_register(ctx, be, rest[0], with_agent_list=True)
    check_allow_deny(ctx, be, "", None, rest[1])


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--journey", required=True, choices=["J08", "J56"])
    ap.add_argument("--candidate-sha", required=True, help="40-hex candidate commit")
    ap.add_argument("--version", required=True, help="candidate version, e.g. 0.0.1-rc.8")
    ap.add_argument("--repo", required=True, help="checkout containing the candidate sources")
    for b in ("gateway", "runtime", "api-server", "aasm"):
        ap.add_argument(f"--{b}", required=True)
    ap.add_argument("--sdk-wheel", required=True)
    ap.add_argument("--sdk-sha", required=True, help="40-hex python-sdk commit the wheel was built from")
    ap.add_argument("--expected-digests", help=f"JSON {{name: sha256:<hex>}}; names: {', '.join(BINARIES)}, {WHEEL}")
    ap.add_argument("--out")
    ap.add_argument("--obligation-fragment")
    a = ap.parse_args(argv)
    if a.obligation_fragment:
        Path(a.obligation_fragment).unlink(missing_ok=True)
    for flag in ("candidate_sha", "sdk_sha"):
        if not c.SHA40.fullmatch(getattr(a, flag)):
            ap.error(f"--{flag.replace('_', '-')} must be 40 lowercase hex characters")
    try:
        a.expected = c.load_expected(a.expected_digests)
    except ValueError as e:
        ap.error(f"--expected-digests: {e}")
    return a


def run_harness(argv: list[str], backend_factory: Callable[..., Backend] | None = None) -> int:
    a = parse_args(argv)
    repo = Path(a.repo).resolve()
    ctx = c.Context(a.journey, a.candidate_sha, a.version)
    be: Backend | None = None
    try:
        bins = {"aasm": Path(a.aasm), "aa-gateway": Path(a.gateway), "aa-runtime": Path(a.runtime), "aa-api-server": Path(a.api_server)}
        bins = {k: v.resolve() for k, v in bins.items()}
        wheel = Path(a.sdk_wheel).resolve()
        for name, p in (*bins.items(), (WHEEL, wheel), *[(k, repo / v) for k, v in SOURCES.items()]):
            if not p.is_file():
                print(f"missing artifact {name}: {p}", file=sys.stderr)
                return c.EXIT_USAGE
            ctx.register(name, p)
        pfx = a.journey.lower()
        c.check_artifact_binding(ctx, f"{pfx}-c-artifacts-bound-to-candidate", {**bins, WHEEL: wheel}, SOURCES, repo,
                                 a.expected, _tn("test_tampered_wheel_digest_fails"))
        ident = []
        be = (backend_factory or (lambda *x: LocalBackend(*x)))(ctx, bins, wheel, repo / SOURCES["sdk_driver.py"])
        for name in ("aasm", "aa-gateway"):
            rc, out = be.version_of(name)
            if rc != 0 or a.version not in out:
                ident.append(f"{name} --version {out.strip()[:80]!r} (exit {rc}), want {a.version}")
        _res(ctx, f"{pfx}-c-binary-identity", ident, f"aasm and aa-gateway both report {a.version}", ["aasm", "aa-gateway"],
             _tn("test_wrong_version_fails"))
        (run_j56 if a.journey == "J56" else lambda x, y, z: run_j08(x, y, z, wheel))(ctx, be, repo)
        report = c.build_report(ctx, SCRIPT, [PENDING_BY_JOURNEY[a.journey]], failure_response(a.journey), DEPENDS_ON)
        report["sdk_sha"] = a.sdk_sha
        report["sdk_wheel_sha256"] = ctx.artifacts[WHEEL]
        report["observations"] = [
            "The record is bound to candidate_sha, sdk_sha and sdk_wheel_sha256; a wheel whose sha256 differs from the expected digest FAILS the artifacts-bound check.",
            "send-email-approval-or-gap is never PASS: no approver is driven, so it stays a classified NOT_COVERED gap unless the email ran (FAIL).",
            "The wheel is built from sdk_sha, not downloaded from PyPI; the published install stays PENDING.",
        ]
        return c.finish(ctx, report, a.out, a.obligation_fragment)
    finally:
        if be is not None:
            be.stop()
        ctx.cleanup()


if __name__ == "__main__":
    c.main_guard(run_harness)
