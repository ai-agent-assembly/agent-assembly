#!/usr/bin/env python3
"""J59 (AAASM-4979) pre-publication candidate harness: operator deploy, observe, govern, recover.

AAASM-4979 lists twelve steps written against rc.6 published artifacts. This harness
runs the steps an operator can do against the *candidate* `aasm` and `aa-api-server`
binaries as real local processes (isolated HOME, ephemeral loopback port, no network
beyond that port) and classifies the rest. Per step:

  1  install the recommended distribution      PENDING   needs published release assets / images
  2  start + health                            candidate (aasm start, /api/v1/health, aasm status)
  3  authentication                            candidate (401 without/with wrong key, ok with key)
     tenancy / team model                      live (j59-s3-tenancy-team-model: two SDK agents under two teams;
                                               j59-s3-org-scoped-audit-filter: the documented org tier)
  4  load the golden-path policy               candidate (validate, apply, get)
  5  allow / deny / approval                   engine decision via `aasm policy simulate` (replayed synthetic
                                               events) AND, with the live inputs, a governed live agent action
                                               (j59-s5-live-agent-action-governed: real SDK -> runtime -> gateway)
  6  CLI and Dashboard operations              CLI candidate; dashboard asset served is a candidate check;
                                               j59-s6-dashboard-operations drives the dashboard with Playwright
  7  audit, logs, observability                candidate for the surfaces; j59-s7-audit-events-of-governed-action
                                               inspects the audit content of the governed actions
  8  change and apply a policy                 candidate
  9  change affects behaviour                  candidate, as an engine decision flip (see 12 for the live one)
  10 diagnose a bad policy / wrong endpoint    candidate
  11 roll back to known-good                   candidate
  12 core-value moment                         j59-s12-core-value-no-agent-change: the same unchanged agent is
                                               allowed under policy 1.0.0 and denied under 1.1.0; audit records both

The five live rows (s3 tenancy, s5, s6 dashboard, s7, s12) need the live inputs: --gateway-bin, --runtime-bin and
--sdk-wheel (all three, built from the candidate; run this script with the interpreter whose ABI tag matches the
wheel), plus --node-bin, --dashboard-dir (a dashboard checkout with node_modules holding @playwright/test) and
--playwright-browsers for the browser row. Without them the rows stay NOT_COVERED with the missing input named,
which keeps the verdict at CANDIDATE_INCOMPLETE and withholds the obligation fragment. The live stack binds the
gateway's fixed gRPC port 127.0.0.1:50051, so only one such run can be active on a host; it starts only after the
`aasm start` steps above have stopped their own server. The live logic lives in scripts/qa/j59_live_agent.py and
reuses the J08/J56 harness's LocalBackend and allow/deny/approval helpers.

Usage:
  python3 -I scripts/qa/j59-candidate-harness.py --candidate-sha <40hex> --expected-version 0.0.1-rc.8 \
      --repo <checkout> --aasm-bin <path> --api-server-bin <path> [--expected-digests d.json] [--out r.json] \
      [--gateway-bin <path> --runtime-bin <path> --sdk-wheel <whl> [--node-bin <node> --dashboard-dir <dir> --playwright-browsers <dir>]]
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
import j59_live_agent as live  # noqa: E402

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


def _img(name: str) -> str:
    return (f"python3 -I scripts/qa/post-publish-verify.py --tag <tag> --obligations <file> --only {name}")


PENDING = [
    c.PendingCheck(
        "j59-install-release-assets", "github-release",
        "step 1 installs the recommended distribution from published release tarballs (and the Homebrew tap and "
        "install.sh that resolve them, whose evidence J04 owns); the assets exist only after release.yml publishes",
        _img("j59-install-release-assets"),
        "the release is not a draft; SHA256SUMS parses; every file it names is an uploaded release asset; and the "
        "legacy aasm-<target>, aasm-cli-<tag>-<os-arch> and aasm-api-<tag>-<os-arch> tarballs (aa-api-server ships only "
        "in aasm-api-*) exist for linux and darwin on amd64 and arm64 and are named in SHA256SUMS. Tarball contents "
        "are not downloaded or hashed",
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
        ("if a published binary or image is wrong, re-run the publish job on the same tag; if the defect is in the product, "
         "decide yank or hold with the release owner before any announcement"),
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
        self.bindir = ctx.tmp / "j59-bin"  # the live stack of the J08/J56 backend owns tmp/bin and tmp/home
        self.bindir.mkdir()
        self.aasm = self.bindir / "aasm"
        shutil.copy(aasm, self.aasm)
        shutil.copy(api, self.bindir / "aa-api-server")
        self.home = ctx.tmp / "j59-home"
        self.home.mkdir()
        self.env = c.clean_env(self.home, {"PATH": f"{self.bindir}:/usr/bin:/bin", "AASM_API_KEY": TEST_KEY})
        self.port = c.free_port()
        self.started = False
        # Registered immediately: if the harness is signalled mid-run (even inside `aasm start`),
        # Context.cleanup finds and kills the daemonized server through this file.
        self.pidfile = self.home / ".aasm" / "gateway.pid"
        ctx.owned_pidfiles.append(self.pidfile)

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
        c.kill_owned_daemon(self.pidfile, self.ctx.tmp)

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
        # Non-JSON health body: `health` stays {}, so the version comparison below reports a
        # FAIL (None != expected). Swallowing here cannot turn a bad response into a PASS.
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


def not_covered(ctx: c.Context, why: str) -> None:
    for cid in live.ROW_IDS:
        ctx.add(cid, c.NOT_COVERED, "real_local_process", why, [])


def run_harness(argv: list[str]) -> int:
    def extra(ap):
        ap.add_argument("--aasm-bin", required=True)
        ap.add_argument("--api-server-bin", required=True)
        ap.add_argument("--gateway-bin", help="live rows: candidate aa-gateway")
        ap.add_argument("--runtime-bin", help="live rows: candidate aa-runtime")
        ap.add_argument("--keygen-bin", help="live rows: aa-keygen (cargo example of aa-auth) used to issue the org-bound operator keys")
        ap.add_argument("--sdk-wheel", help="live rows: candidate python-sdk wheel (its cp tag must match this interpreter)")
        ap.add_argument("--node-bin", help="dashboard row: node executable")
        ap.add_argument("--dashboard-dir", help="dashboard row: dashboard checkout whose node_modules has @playwright/test")
        ap.add_argument("--playwright-browsers", help="dashboard row: Playwright browser cache directory")
    a = c.parse_common_args(argv, extra)
    repo = Path(a.repo).resolve()
    live_args = {"--gateway-bin": a.gateway_bin, "--runtime-bin": a.runtime_bin, "--sdk-wheel": a.sdk_wheel}
    if any(live_args.values()) and not all(live_args.values()):
        print(f"the live rows need all of {', '.join(live_args)}; missing: {', '.join(k for k, v in live_args.items() if not v)}", file=sys.stderr)
        return c.EXIT_USAGE
    is_live = all(live_args.values())
    ctx = c.Context("J59", a.candidate_sha, a.expected_version)
    stack = None
    be = None
    try:
        aasm, api = Path(a.aasm_bin).resolve(), Path(a.api_server_bin).resolve()
        binaries = {"aasm": aasm, "aa-api-server": api}
        sources = dict(SOURCES)
        if is_live:
            binaries.update({"aa-gateway": Path(a.gateway_bin).resolve(), "aa-runtime": Path(a.runtime_bin).resolve(),
                             live.WHEEL: Path(a.sdk_wheel).resolve()})
            sources.update(live.LIVE_SOURCES)
        for name, p in (*binaries.items(), *[(k, repo / v) for k, v in sources.items()]):
            if not p.is_file():
                print(f"missing artifact {name}: {p}", file=sys.stderr)
                return c.EXIT_USAGE
            ctx.register(name, p)
        c.check_artifact_binding(ctx, "j59-artifacts-bound-to-candidate", binaries,
                                 sources, repo, a.expected, f"{TEST}::test_tampered_binary_fails")
        stack = Stack(ctx, aasm, api)
        run_steps(ctx, stack, repo)
        if is_live:
            stack.stop()  # the live stack binds the same fixed gRPC port
            be = live.make_backend_class()(ctx, {k: binaries[k] for k in ("aasm", "aa-gateway", "aa-runtime", "aa-api-server")},
                                           binaries[live.WHEEL], repo / live.LIVE_SOURCES["sdk_agent.py"],
                                           keygen=Path(a.keygen_bin).resolve() if a.keygen_bin else None)
            live.run_live(ctx, be, repo, {"node": Path(a.node_bin).resolve() if a.node_bin else None,
                                          "dash_dir": Path(a.dashboard_dir).resolve() if a.dashboard_dir else None,
                                          "browsers": Path(a.playwright_browsers).resolve() if a.playwright_browsers else None})
        else:
            not_covered(ctx, "live-agent inputs (--gateway-bin, --runtime-bin, --sdk-wheel) were not supplied, so no agent was driven")
        report = c.build_report(ctx, SCRIPT, PENDING, FAILURE_RESPONSE, DEPENDS_ON)
        report["observations"] = [
            "j59-s5-engine-allow-deny-approval and j59-s9-change-flips-outcome are engine decisions over replayed synthetic events (aasm policy simulate); the live-agent rows (s3, s5, s6, s7, s12) are the governed-agent legs.",
            "FINDING (j59-s9-applied-policy-stays-enforced): a policy installed with `aasm policy apply` / POST /api/v1/policies is enforced for at most 5s and is then swapped back to the gateway's policy file (the bootstrap budget-only policy when $AA_POLICY is unset, which allows every tool) by aa-gateway/src/engine/watcher.rs reconcile_file_tick, while `aasm policy get` keeps reporting the applied policy. The live rows therefore run with $AA_POLICY pointing at the golden-path file and change policy through that file.",
            "RESOLVED (j59-s3-org-scoped-audit-filter, AAASM-6444): init_assembly() takes org_id and registration_key. The org is bound to an operator API key (x-aa-registration-key), a client org_id is only a claim the gateway checks against the key, and the row asserts two-org isolation, cross-org read denial with an admin control, spoof refusal and the org-less policy on the live stack. Before this change the SDK could not carry an org and docs/src/operations/org-isolation.md's init_assembly(agent_id={org_id, ...}) call raised TypeError.",
            "RESOLVED (audit identity, AAASM-6447): a later SDK process of an already-registered agent used to get AlreadyExists, run asserted and write entries with the agent name and no team_id, so one agent appeared under several agent_id values. It now re-binds to the existing agent and credential in two ways, neither of which an identifier alone can use: (1) with an operator key bound to the agent's organization; (2) for an org-less agent, by possession of the agent's own random durable key, which its first registration declared (durable_identity_key) and the gateway recorded. A key-less process restarted from the same state directory keeps one registry id; another holder of the same label (another key) becomes a separate agent and never reaches the first record. After a gateway restart (AAASM-6451) both kinds re-register with the same agent id and receive a NEW credential (the gateway stores the org and public key, never the credential); a running process must be restarted to pick it up. LIMITS: records created before this change or by clients that do not declare the key, and rows written by a gateway older than AAASM-6451 (no stored key), are not re-bound, still get AlreadyExists, and keep their registry slot until removed; the durable-key declaration is the creating client's own claim; the shared credential means one process's Deregister ends all of them; a copied key file is a takeover of that identity.",
            "RESOLVED (audit filter, AAASM-6446): GET /api/v1/logs?agent_id=<x> used to filter only on a 32-hex audit id and return every agent for any other value. It now matches the 32-hex id, the claimed name or did:key, and the registry-resolved agent; an unmatched value returns an empty page and a blank one is a 400. `aasm audit export --agent` goes through the same endpoint.",
            "The live rows run one SDK program (fixtures/j59/sdk_agent.py, bound to the candidate commit) as two agents under two teams; audit attribution to an agent is done by this harness because `aasm audit export --agent` did not filter on the candidate.",
            "Candidate binaries are identified by version and by sha256 against the expected-digests record; aasm exposes no build-sha, so there is no build-sha check for J59.",
            "j59-published-binaries-golden-path is an operator step with no recording mechanism yet (tracked follow-up); post-publish-verify.py reports it INCONCLUSIVE, never PASS.",
            "Rows are NOT_COVERED only when their inputs were not supplied (or the live stack did not come up); the obligation schema has no field for them, so J59 reaches CANDIDATE_VERIFIED only when every row is executed and PASS.",
        ]
        return c.finish(ctx, report, a.out, a.obligation_fragment)
    finally:
        if be is not None:
            be.stop()
        if stack:
            stack.stop()
        ctx.cleanup()


if __name__ == "__main__":
    c.main_guard(run_harness)
