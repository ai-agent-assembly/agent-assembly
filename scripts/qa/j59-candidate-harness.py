#!/usr/bin/env python3
"""J59 (AAASM-4979) pre-publication candidate harness: operator deploy, observe, govern, recover.

AAASM-4979 lists twelve steps written against rc.6 published artifacts. This harness
runs the steps an operator can do against the *candidate* `aasm` and `aa-api-server`
binaries as real local processes (isolated HOME, ephemeral loopback port, no network
beyond that port) and classifies the rest. Per step:

  1  install the recommended distribution      PENDING   needs published release assets / images
  2  start + health                            candidate (aasm start, /api/v1/health, aasm status)
  3  authentication                            candidate (401 without/with wrong key, ok with key)
     tenancy / team model                      NOT_COVERED (no hermetic surface identified)
  4  load the golden-path policy               candidate (validate, apply, get)
  5  allow / deny / approval                   candidate as an ENGINE decision: `aasm policy simulate`
                                               replays three synthetic tool-call events through the
                                               real policy engine. NOT a governed live agent action:
                                               that stays NOT_COVERED (needs SDK/runtime; D5, AAASM-6415)
  6  CLI and Dashboard operations              CLI candidate; dashboard asset served is a candidate check;
                                               operating the dashboard is NOT_COVERED (browser)
  7  audit, logs, observability                candidate for the surfaces; audit events from a governed
                                               action are NOT_COVERED (no agent produced any)
  8  change and apply a policy                 candidate
  9  change affects behaviour                  candidate, again as an engine decision flip, not a live agent
  10 diagnose a bad policy / wrong endpoint    candidate
  11 roll back to known-good                   candidate
  12 core-value moment                         NOT_COVERED (composite; needs the live-agent leg of 5 and 7)

NOT_COVERED rows keep the verdict at CANDIDATE_INCOMPLETE and withhold the obligation
fragment: the obligation schema has no slot for "neither executed nor publication-
dependent", so those rows would otherwise vanish silently. That is a decision for the
release owner, not something this script can paper over.

Usage:
  python3 -I scripts/qa/j59-candidate-harness.py --candidate-sha <40hex> --expected-version 0.0.1-rc.8 \
      --repo <checkout> --aasm-bin <path> --api-server-bin <path> [--expected-digests d.json] [--out r.json]
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import b1_candidate_common as c  # noqa: E402

SCRIPT = "scripts/qa/j59-candidate-harness.py"
TEST = "scripts/tests/test_j59_candidate_harness.py"
FIX = "scripts/qa/fixtures/j59"
SOURCES = {
    "golden-path.v1.yaml": f"{FIX}/golden-path.v1.yaml",
    "golden-path.v2-tightened.yaml": f"{FIX}/golden-path.v2-tightened.yaml",
    "malformed.yaml": f"{FIX}/malformed.yaml",
    "tool-calls.jsonl": f"{FIX}/tool-calls.jsonl",
}
# A syntactically valid key for a throwaway loopback server; not a credential.
TEST_KEY = "aa_0123456789abcdef0123456789abcdef"

_GH = "gh-release-tag"


def _img(name: str) -> str:
    return (f"python3 -I scripts/qa/post-publish-verify.py --tag <tag> --obligations <file> --only {name}")


PENDING = [
    c.PendingCheck(
        "j59-install-release-assets", "github-release",
        "step 1 installs the recommended distribution from published release tarballs (and the Homebrew tap and "
        "install.sh that resolve them, whose evidence J04 owns); the assets exist only after release.yml publishes",
        _img("j59-install-release-assets"),
        "the GitHub Release for <tag> lists SHA256SUMS and a tarball for each documented platform, and every "
        "tarball named in SHA256SUMS exists as a release asset",
    ),
    c.PendingCheck(
        "j59-ghcr-gateway-image", "ghcr",
        "step 1/2 deploy the recommended OSS distribution, which names ghcr.io/ai-agent-assembly/aa-gateway:<tag>",
        _img("j59-ghcr-gateway-image"),
        "aa-gateway:<tag> resolves anonymously to an index with linux/amd64 and linux/arm64 whose body hashes to its digest",
    ),
    c.PendingCheck(
        "j59-ghcr-runtime-image", "ghcr",
        "step 1/2 deploy also names ghcr.io/ai-agent-assembly/aa-runtime:<tag>",
        _img("j59-ghcr-runtime-image"),
        "aa-runtime:<tag> resolves anonymously to an index with linux/amd64 and linux/arm64 whose body hashes to its digest",
    ),
    c.PendingCheck(
        "j59-published-binaries-golden-path", "github-release",
        "steps 2 to 11 must be re-run against the published binaries: release.yml rebuilds them, so the candidate "
        "binaries verified here are not proven identical to what users download. Operator step (it downloads and "
        "extracts tarballs), so post-publish-verify.py reports it INCONCLUSIVE until an operator records it",
        "download aasm-cli-<ver>-<os>-<arch>.tar.gz and aasm-api-<ver>-<os>-<arch>.tar.gz, verify against SHA256SUMS, extract, then: "
        "python3 -I scripts/qa/j59-candidate-harness.py --candidate-sha <tag commit> --expected-version <ver> --repo <checkout> "
        "--aasm-bin <extracted aasm> --api-server-bin <extracted aa-api-server>",
        "every candidate check of this harness is PASS against the extracted published binaries",
    ),
]

FAILURE_RESPONSE = {
    "proposed_actions": [
        "do not announce the release as operator-ready; record J59 as failed post-publication",
        "file a Bug against AAASM-4979 naming the failing check id and the published asset digest",
        "if a published binary or image is wrong, re-run the publish job on the same tag; if the defect is in the product, "
        "decide yank or hold with the release owner before any announcement",
    ],
    "notify": ["release-owner"],
    "deadline_hours": 24,
}
DEPENDS_ON = [
    {"repo": "agent-assembly", "event": "release.yml publish (GitHub Release assets)"},
    {"repo": "agent-assembly", "event": "docker.yml publish-gateway and publish-runtime on the release tag"},
]


class Stack:
    """One isolated `aasm start` deployment."""

    def __init__(self, ctx: c.Context, aasm: Path, api: Path):
        self.ctx = ctx
        self.bindir = ctx.tmp / "bin"
        self.bindir.mkdir()
        self.aasm = self.bindir / "aasm"
        shutil.copy(aasm, self.aasm)
        shutil.copy(api, self.bindir / "aa-api-server")
        self.home = ctx.tmp / "home"
        self.home.mkdir()
        self.env = c.clean_env(self.home, {"PATH": f"{self.bindir}:/usr/bin:/bin", "AASM_API_KEY": TEST_KEY})
        self.port = c.free_port()
        self.started = False

    def cli(self, *args: str, timeout: int = 30, env: dict[str, str] | None = None) -> tuple[int, str]:
        return c.run([str(self.aasm), *args], env or self.env, self.ctx.tmp, timeout)

    def start(self) -> tuple[int, str]:
        rc, out = self.cli("start", "--host", "127.0.0.1", "--port", str(self.port), timeout=90)
        self.started = rc == 0
        return rc, out

    def stop(self) -> None:
        if self.started:
            self.cli("stop", timeout=30)
            self.started = False
        pidfile = self.home / ".aasm" / "gateway.pid"
        if pidfile.exists():  # recorded by our own isolated HOME, so ownership is proven by path
            try:
                import os
                import signal
                os.kill(int(pidfile.read_text().strip()), signal.SIGKILL)
            except (OSError, ValueError):
                pass

    def http(self, path: str, key: str | None = None) -> tuple[int, str, str]:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        if key is not None:
            req.add_header("Authorization", f"Bearer {key}")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.headers.get("content-type", ""), r.read(1 << 20).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("content-type", ""), e.read(1 << 16).decode("utf-8", "replace")
        except OSError as e:
            return 0, "", str(e)


def parse_sim(out: str) -> dict[str, object]:
    def num(label: str) -> int:
        m = re.search(rf"^{label}:\s+(\d+)", out, re.M)
        return int(m.group(1)) if m else -1
    flagged = {m.group(1): m.group(2) for m in re.finditer(r"^\d+\s+tool:(\S+)\s+(\S+)", out, re.M)}
    return {"total": num("Total events"), "allowed": num("Allowed"), "denied": num("Denied"),
            "approval": num("Approval required"), "flagged": flagged}


def _res(ctx: c.Context, cid: str, problems: list[str], ok: str, fidelity: str, arts: list[str], neg: str) -> None:
    ctx.add(cid, c.FAIL if problems else c.PASS, fidelity, "; ".join(problems) or ok, arts, neg)


def run_steps(ctx: c.Context, st: Stack, repo: Path) -> None:
    fx = {k: repo / v for k, v in SOURCES.items()}
    bins = ["aasm", "aa-api-server"]

    # identity
    rc, out = st.cli("--version")
    p = [] if (rc == 0 and out.strip() == f"aasm {ctx.expected_version}") else [f"aasm --version {out.strip()!r} (exit {rc}), want 'aasm {ctx.expected_version}'"]
    rc, out = st.start()
    if rc != 0:
        ctx.add("j59-s2-start-health", c.FAIL, "real_local_process", f"aasm start exited {rc}: {out.strip()[:300]}", bins, f"{TEST}::test_start_failure_fails")
        ctx.add("j59-binary-identity", c.FAIL, "real_local_process", "; ".join(p) or "aasm version ok; server not started", bins, f"{TEST}::test_wrong_version_fails")
        return
    code, _, body = st.http("/api/v1/health")
    health = {}
    try:
        health = json.loads(body)
    except ValueError:
        pass
    if health.get("version") != ctx.expected_version:
        p.append(f"aa-api-server reports version {health.get('version')!r}, want {ctx.expected_version!r}")
    ctx.add("j59-binary-identity", c.FAIL if p else c.PASS, "real_local_process",
            "; ".join(p) or f"aasm and aa-api-server both report {ctx.expected_version}", bins, f"{TEST}::test_wrong_version_fails")

    # step 2
    p = []
    if code != 200 or health.get("status") != "ok":
        p.append(f"/api/v1/health -> {code} status={health.get('status')!r}")
    bad = {k: v for k, v in (health.get("checks") or {}).items() if v != "ok"}
    if bad or not health.get("checks"):
        p.append(f"health checks not all ok: {bad or 'none reported'}")
    rc, out = st.cli("status")
    if rc != 0 or "Health:" not in out:
        p.append(f"aasm status exit {rc}")
    _res(ctx, "j59-s2-start-health", p, "aasm start, /api/v1/health ok with every check ok, aasm status exit 0",
         "real_local_process", bins, f"{TEST}::test_start_failure_fails")

    # step 3
    p = []
    s1, _, _ = st.http("/api/v1/policies")
    s2, _, _ = st.http("/api/v1/policies", key="aa_" + "f" * 32)
    s3, _, _ = st.http("/api/v1/policies", key=TEST_KEY)
    if s1 != 401:
        p.append(f"no Authorization header -> {s1}, want 401")
    if s2 != 401:
        p.append(f"wrong key -> {s2}, want 401")
    if s3 != 200:
        p.append(f"correct key -> {s3}, want 200")
    _res(ctx, "j59-s3-auth-enforced", p, "401 without a key and with a wrong key, 200 with the key",
         "real_local_process", bins, f"{TEST}::test_unauthenticated_api_fails")

    # step 4
    p = []
    rc, out = st.cli("policy", "validate", str(fx["golden-path.v1.yaml"]))
    if rc != 0 or re.search(r"^warning", out, re.M):
        p.append(f"validate exit {rc}: {out.strip()[:200]}")
    rc, out = st.cli("policy", "apply", str(fx["golden-path.v1.yaml"]))
    v1 = (re.search(r"Version:\s+(\S+)", out) or [None, None])[1]
    if rc != 0 or not v1:
        p.append(f"apply exit {rc}, no version id in output")
    rc, got1 = st.cli("policy", "get")
    if rc != 0 or "name: golden-path" not in got1 or 'version: "1.0.0"' not in got1:
        p.append("policy get does not return golden-path 1.0.0 after apply")
    _res(ctx, "j59-s4-policy-load", p, "golden-path 1.0.0 validates warning-free, applies and reads back",
         "real_local_process", bins + ["golden-path.v1.yaml"], f"{TEST}::test_policy_apply_failure_fails")

    # step 5 (engine decision, not a live agent action)
    rc, out = st.cli("policy", "simulate", "--policy", str(fx["golden-path.v1.yaml"]), "--against", str(fx["tool-calls.jsonl"]))
    sim1 = parse_sim(out)
    want = {"total": 3, "allowed": 1, "denied": 1, "approval": 1}
    p = [f"{k}={sim1[k]}, want {v}" for k, v in want.items() if sim1[k] != v]
    if sim1["flagged"] != {"delete_file": "deny", "send_email": "requires_approval"}:
        p.append(f"flagged outcomes {sim1['flagged']}")
    _res(ctx, "j59-s5-engine-allow-deny-approval", p,
         "policy engine allows read_file, denies delete_file, requires approval for send_email (replayed synthetic events)",
         "controlled_fake", bins + ["golden-path.v1.yaml", "tool-calls.jsonl"], f"{TEST}::test_engine_that_denies_everything_fails")

    # step 6 / 7 CLI + dashboard asset + signals
    p = []
    for args in (("status",), ("topology", "overview"), ("policy", "list"), ("audit", "list"), ("logs",)):
        rc, out = st.cli(*args)
        if rc != 0:
            p.append(f"aasm {' '.join(args)} exit {rc}: {out.strip()[:120]}")
    _res(ctx, "j59-s6-s7-cli-operations", p, "status, topology overview, policy list, audit list and logs all exit 0",
         "real_local_process", bins, f"{TEST}::test_cli_command_failure_fails")
    code, ctype, body = st.http("/")
    p = []
    if code != 200 or "html" not in ctype:
        p.append(f"GET / -> {code} {ctype}")
    elif "Dashboard not built" in body or "<script" not in body:
        p.append("GET / is the 'Dashboard not built' placeholder or has no script tag")
    ctx.add("j59-s6-dashboard-asset-served", c.FAIL if p else c.PASS, "real_local_process",
            "; ".join(p) or "GET / serves the built dashboard shell", bins, f"{TEST}::test_dashboard_placeholder_fails")

    # step 8 / 9
    p = []
    rc, out = st.cli("policy", "apply", str(fx["golden-path.v2-tightened.yaml"]))
    v2 = (re.search(r"Version:\s+(\S+)", out) or [None, None])[1]
    if rc != 0 or not v2:
        p.append(f"apply v2 exit {rc}")
    rc, got2 = st.cli("policy", "get")
    if 'version: "1.1.0"' not in got2:
        p.append("policy get does not return 1.1.0 after apply")
    _res(ctx, "j59-s8-policy-change-apply", p, "tightened policy 1.1.0 applies and reads back",
         "real_local_process", bins + ["golden-path.v2-tightened.yaml"], f"{TEST}::test_policy_apply_failure_fails")
    rc, out = st.cli("policy", "simulate", "--policy", str(fx["golden-path.v2-tightened.yaml"]), "--against", str(fx["tool-calls.jsonl"]))
    sim2 = parse_sim(out)
    flipped = sim1["flagged"].get("read_file") is None and sim2["flagged"].get("read_file") == "deny"
    p = [] if flipped and sim2["denied"] == 2 else [f"read_file did not flip allow->deny: v1={sim1['flagged']} v2={sim2['flagged']}"]
    _res(ctx, "j59-s9-change-flips-outcome", p, "the same event is allowed under 1.0.0 and denied under 1.1.0 (engine replay, not a live agent)",
         "controlled_fake", bins + ["golden-path.v1.yaml", "golden-path.v2-tightened.yaml", "tool-calls.jsonl"],
         f"{TEST}::test_engine_that_ignores_policy_fails")

    # step 10
    p = []
    rc, out = st.cli("policy", "validate", str(fx["malformed.yaml"]))
    if rc == 0 or "line" not in out:
        p.append(f"validate of a malformed policy exit {rc}, output lacks a line number")
    rc, out = st.cli("policy", "apply", str(fx["malformed.yaml"]))
    if rc == 0:
        p.append("apply of a malformed policy exited 0")
    rc, after = st.cli("policy", "get")
    if after != got2:
        p.append("the active policy changed after a rejected apply")
    dead = c.free_port()
    rc, out = st.cli("status", "--api-url", f"http://127.0.0.1:{dead}")
    if rc == 0 or not re.search(r"connect|unreachable|refused|error", out, re.I):
        p.append(f"status against a dead endpoint exit {rc} without a diagnostic")
    _res(ctx, "j59-s10-diagnose-failures", p, "malformed policy rejected with a line number and left the active policy intact; dead endpoint diagnosed",
         "real_local_process", bins + ["malformed.yaml"], f"{TEST}::test_rejected_apply_that_changes_state_fails")

    # step 11
    p = []
    if not v1:
        p.append("no version id captured from the first apply")
    else:
        rc, out = st.cli("policy", "rollback", v1)
        if rc != 0:
            p.append(f"policy rollback {v1} exit {rc}: {out.strip()[:160]}")
        rc, back = st.cli("policy", "get")
        if 'version: "1.0.0"' not in back:
            p.append("policy get is not golden-path 1.0.0 after rollback")
    _res(ctx, "j59-s11-rollback", p, "rollback to the first applied version restores golden-path 1.0.0",
         "real_local_process", bins, f"{TEST}::test_rollback_not_restoring_fails")


def not_covered(ctx: c.Context) -> None:
    rows = [
        ("j59-s3-tenancy-team-model", "step 3: no hermetic surface for the minimum tenancy/team model was identified; needs an owner decision on what to assert"),
        ("j59-s5-live-agent-action-governed", "step 5: allow/deny/approval on a live governed agent action needs the SDK or runtime in the loop (python-sdk, D5 AAASM-6415 unmerged); the engine decision above is not this"),
        ("j59-s6-dashboard-operations", "step 6: operating the dashboard needs a real browser"),
        ("j59-s7-audit-events-of-governed-action", "step 7: no agent produced audit events, so audit content and trace were not inspected"),
        ("j59-s12-core-value-no-agent-change", "step 12: composite of the live-agent legs of steps 5, 7 and 9; not executable without an agent"),
    ]
    for cid, why in rows:
        ctx.add(cid, c.NOT_COVERED, "real_local_process", why, [])


def run_harness(argv: list[str]) -> int:
    def extra(ap):
        ap.add_argument("--aasm-bin", required=True)
        ap.add_argument("--api-server-bin", required=True)
    a = c.parse_common_args(argv, extra)
    repo = Path(a.repo).resolve()
    ctx = c.Context("J59", a.candidate_sha, a.expected_version)
    stack = None
    try:
        aasm, api = Path(a.aasm_bin).resolve(), Path(a.api_server_bin).resolve()
        for name, p in (("aasm", aasm), ("aa-api-server", api), *[(k, repo / v) for k, v in SOURCES.items()]):
            if not p.is_file():
                print(f"missing artifact {name}: {p}", file=sys.stderr)
                return c.EXIT_USAGE
            ctx.register(name, p)
        c.check_artifact_binding(ctx, "j59-artifacts-bound-to-candidate", {"aasm": aasm, "aa-api-server": api},
                                 SOURCES, repo, c.load_expected(a.expected_digests), f"{TEST}::test_tampered_binary_fails")
        stack = Stack(ctx, aasm, api)
        run_steps(ctx, stack, repo)
        not_covered(ctx)
        report = c.build_report(ctx, SCRIPT, PENDING, FAILURE_RESPONSE, DEPENDS_ON)
        report["observations"] = [
            "Steps 5 and 9 are engine decisions over replayed synthetic events (aasm policy simulate), not governed live agent actions.",
            "Candidate binaries are identified by version and by sha256 against the expected-digests record; aasm exposes no build-sha, so there is no build-sha check for J59.",
            "J59 can only reach CANDIDATE_VERIFIED once the NOT_COVERED rows are executed or the release owner records them as accepted gaps; the obligation schema has no field for them.",
        ]
        return c.finish(ctx, report, a.out, a.obligation_fragment)
    finally:
        if stack:
            stack.stop()
        ctx.cleanup()


if __name__ == "__main__":
    c.main_guard(run_harness)
