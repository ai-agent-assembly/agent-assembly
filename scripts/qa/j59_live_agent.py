"""J59 (AAASM-4979) live-agent rows: a governed SDK agent against the candidate stack (AAASM-6439).

The five rows below used to be NOT_COVERED because nothing drove a real agent. They now run on the
real stack the J08/J56 harness already knows how to start (gateway + aa-runtime + isolated HOME + a
clean venv with the candidate SDK wheel), reusing its `LocalBackend` and its allow/deny/approval check
helpers rather than a second copy of the stack-start logic:

  j59-s5-live-agent-action-governed       allow, deny (typed error, sentinel untouched) and approval, live
  j59-s7-audit-events-of-governed-action  audit content for this agent over `aasm audit export` AND /api/v1/logs
  j59-s3-tenancy-team-model               team model carried by the SDK path (topology teams, audit team_id)
  j59-s3-org-scoped-audit-filter          the documented org tier: ?org_id= isolates one org's events
  j59-s12-core-value-no-agent-change      same unchanged agent: allowed under v1, denied under v2, audit records both
  j59-s9-applied-policy-stays-enforced    a policy applied with `aasm policy apply` is still enforced 12s later
  j59-s6-dashboard-operations             Playwright drives the real dashboard (login, agents, audit, approvals)

Two agents run as the same unchanged program (`fixtures/j59/sdk_agent.py`) under different agent ids and
teams so "a different agent's events are absent" is a real assertion, not a vacuous one.

The module is import-safe (no side effects) and every process/HTTP touch goes through the backend seam, so
`scripts/tests/test_j59_live_agent.py` drives the check logic with a fake stack and proves each check fails
when the behaviour it names breaks.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import b1_candidate_common as c  # noqa: E402

TEST = "scripts/tests/test_j59_live_agent.py"
FIX = "scripts/qa/fixtures/j59"
LIVE_SOURCES = {
    "sdk_agent.py": f"{FIX}/sdk_agent.py",
    "dashboard_ops.mjs": f"{FIX}/dashboard_ops.mjs",
}
WHEEL = "python-sdk-wheel"
LIVE_BINARIES = ("aa-gateway", "aa-runtime")
TEAM_A, TEAM_B = "alpha", "beta"
ORGS = ("acme", "globex")
ROW_IDS = (
    "j59-s3-tenancy-team-model",
    "j59-s5-live-agent-action-governed",
    "j59-s6-dashboard-operations",
    "j59-s7-audit-events-of-governed-action",
    "j59-s12-core-value-no-agent-change",
)


def load_j56() -> Any:
    """The J08/J56 harness (hyphenated file name, so not importable by name). Loaded once."""
    name = "j08_j56_candidate_harness"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / "j08-j56-candidate-harness.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _tn(name: str) -> str:
    return f"{TEST}::{name}"


class Recorder:
    """Stands in for a Context so J56's check helpers can be folded into one J59 row."""

    def __init__(self, ctx: Any):
        self.tmp = ctx.tmp
        self.checks: list[c.Check] = []

    def add(self, check_id: str, status: str, fidelity: str, detail: str,
            artifacts: list[str] | None = None, negative_control: str | None = None) -> c.Check:
        ck = c.Check(check_id, status, fidelity, detail, list(artifacts or []), negative_control)
        self.checks.append(ck)
        return ck


def _row(ctx: Any, cid: str, problems: list[str], ok: str, arts: list[str], neg: str,
         fidelity: str = "real_local_process") -> bool:
    ctx.add(cid, c.FAIL if problems else c.PASS, fidelity, "; ".join(problems) or ok, arts, neg)
    return not problems


# ---------------------------------------------------------------- the stack

def make_backend_class() -> type:
    H = load_j56()

    class LiveBackend(H.LocalBackend):
        """J56's LocalBackend plus a second agent, team tags, HTTP and an un-filtered audit export.

        `aasm audit export --agent <x>` did not filter by agent on the candidate (two agents' exports were
        identical), so `audit()` returns the whole export and attribution to an agent is done by this
        harness from the entries themselves (see `belongs`)."""

        def __init__(self, ctx: Any, bins: dict[str, Path], wheel: Path, driver: Path, keygen: Path | None = None, **kw: Any):
            super().__init__(ctx, bins, wheel, driver, **kw)
            self.driver = driver
            self.keygen = keygen
            self.org_key_files: dict[str, Path] = {}
            self.team_of: dict[str, str] = {self.agent: TEAM_A}
            self.agent_b = f"j59b-{uuid.uuid4().hex[:8]}"
            self.extra: list[tuple[subprocess.Popen[bytes], Path]] = []

        def sdk(self, op: str, **kw: Any) -> dict[str, Any]:
            agent = kw.get("agent", self.agent)
            argv = [str(self.venv / "bin" / "python"), "-I", str(self.driver), op, "--gateway-url", self.url,
                    "--key", kw.get("key", H.TEST_KEY), "--agent", agent]
            if self.team_of.get(agent):
                argv += ["--team", self.team_of[agent]]
            for flag in ("tool", "sentinel", "org"):
                if kw.get(flag):
                    argv += [f"--{flag}", str(kw[flag])]
            # `key_org` names which organization's operator key the agent presents at registration (it defaults to the
            # org it claims); `no_key` presents none. The key is passed as a file path, never as an argument value.
            key_org = None if kw.get("no_key") else kw.get("key_org", kw.get("org"))
            if key_org and key_org in self.org_key_files:
                argv += ["--registration-key-file", str(self.org_key_files[key_org])]
            rc, out = self.exec(argv, self.env, self.ctx.tmp, 120)
            for line in reversed(out.splitlines()):
                if line.startswith("RESULT "):
                    try:
                        return json.loads(line[len("RESULT "):])
                    except ValueError:
                        break
            return {"error": "driver-no-result", "detail": f"exit {rc}: {out.strip()[-200:]}"}

        def _start_runtime(self) -> tuple[bool, str]:
            """J56 reports the runtime up as soon as its IPC socket file exists, but the runtime logs binding that
            socket before it has connected its gateway client. No run was seen to depend on the gap (the ungoverned
            calls investigated while building this were the policy revert, see check_policy_durability), so this is a
            cheap guard, not a fix for an observed failure: wait for the health listener, which is bound after the
            gateway client and the pipeline."""
            ports: list[int] = []
            real = c.free_port

            def spy() -> int:
                ports.append(real())
                return ports[-1]

            c.free_port = spy
            try:
                ok, why = super()._start_runtime()
            finally:
                c.free_port = real
            if ok and ports and not c.wait_port(ports[-1], 30):
                return False, "aa-runtime bound its IPC socket but its health listener never came up"
            return ok, why

        def audit(self, agent: str) -> tuple[int, str]:  # noqa: ARG002  # see class docstring
            return self._cli("audit", "export", "--format", "json")

        def add_agent(self, name: str, team: str | None, org: str | None = None) -> tuple[bool, str]:
            """A second per-agent runtime (the SDK dials /tmp/aa-runtime-<agent>.sock) on the same gateway."""
            sock = Path(f"/tmp/aa-runtime-{name}.sock")
            health = c.free_port()
            env = {**self.env, "AA_AGENT_ID": name, "AA_POLICY_PATH": "", "RUST_LOG": "warn",
                   "AA_GATEWAY_ENDPOINT": f"http://127.0.0.1:{H.GRPC_PORT}", "AA_METRICS_ADDR": f"127.0.0.1:{health}",
                   "AA_AUDIT_BUFFER_PATH": str(self.home / f"audit-{name}.db")}
            if team:
                env["AA_AGENT_TEAM_ID"] = team
            if org:
                env["AA_AGENT_ORG_ID"] = org
            log = (self.ctx.tmp / f"aa-runtime-{name}.log").open("wb")  # never a pipe: an undrained pipe stalls the runtime
            p = subprocess.Popen([str(self.bindir / "aa-runtime")], env=env, cwd=self.ctx.tmp, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            self.ctx._children.append(p)
            self.extra.append((p, sock))
            if team:
                self.team_of[name] = team
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if sock.exists():
                    # ready only once the health listener is up (after the gateway client); see _start_runtime
                    if c.wait_port(health, 30):
                        return True, "aa-runtime is listening"
                    return False, f"aa-runtime for {name} bound {sock} but its health listener never came up"
                if p.poll() is not None:
                    return False, f"aa-runtime for {name} exited {p.returncode} before binding {sock}"
                time.sleep(0.2)
            return False, f"aa-runtime for {name} did not bind {sock} within 20s"

        def provision_org_keys(self, orgs: tuple[str, ...]) -> tuple[bool, str]:
            """Issue one read-scoped operator key per org with `aa-keygen`, into the key file the gateway reads at boot
            (`AA_API_KEYS_PATH`), which the REST side merges too. The raw keys land only in owner-only files."""
            if self.keygen is None:
                return False, "no aa-keygen binary was supplied (--keygen-bin), so no org-bound operator key can be issued"
            keys_json = self.home / "org-keys.json"
            for org in orgs:
                out = self.home / f"org-{org}.key"
                rc, text = self.exec([str(self.keygen), "--keys-file", str(keys_json), "--key-out", str(out), "--org", org,
                                      "--scope", "read"], self.env, self.ctx.tmp, 60)
                if rc != 0 or not out.is_file():
                    return False, f"aa-keygen for {org} exited {rc}: {text.strip()[-200:]}"
                self.org_key_files[org] = out
            self.env["AA_API_KEYS_PATH"] = str(keys_json)
            return True, ""

        def http(self, path: str, key_org: str | None = None) -> tuple[int, str]:
            req = urllib.request.Request(self.url + path)
            bearer = self.org_key_files[key_org].read_text().strip() if key_org else H.TEST_KEY
            req.add_header("Authorization", f"Bearer {bearer}")
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    return r.status, r.read(4 << 20).decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                return e.code, e.read(1 << 16).decode("utf-8", "replace")
            except OSError as e:
                return 0, str(e)

        def policy_get(self) -> tuple[int, str]:
            return self._cli("policy", "get")

        def start(self, policy: Path) -> tuple[bool, str]:
            """The gateway re-reads its policy *file* every 5s and swaps it over whatever `aasm policy apply` installed
            (see check_policy_durability), so a run that relies on an applied policy is governed only by timing luck.
            The live rows therefore start the gateway with `$AA_POLICY` pointing at the golden-path file (the operator's
            durable route) and still apply the same policy through the CLI, as the J59 contract says."""
            ok, why = self.provision_org_keys(ORGS)
            if not ok:
                self.org_keys_error = why  # reported by check_org_filter; the rest of the stack still runs
            self.policy_file = self.ctx.tmp / "policy-source" / "golden-path.yaml"
            self.policy_file.parent.mkdir(exist_ok=True)
            self.policy_file.write_text(policy.read_text())
            self.env["AA_POLICY"] = str(self.policy_file)
            return super().start(policy)

        def set_policy_source(self, policy: Path) -> None:
            """Change the policy through the file the gateway watches: the route that stays enforced."""
            self.policy_file.write_text(policy.read_text())

        def wait(self, seconds: float) -> None:
            time.sleep(seconds)

        def stop(self) -> None:
            super().stop()
            for p, sock in self.extra:
                c.terminate_group(p)
                sock.unlink(missing_ok=True)
                Path(str(sock)[: -len(".sock")] + ".lock").unlink(missing_ok=True)

    return LiveBackend


# ---------------------------------------------------------------- audit model

def parse_entries(raw: Any) -> list[dict[str, Any]] | None:
    """Normalised audit entries from either `aasm audit export --format json` or /api/v1/logs `items`."""
    items = raw.get("entries", raw.get("items", raw)) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return None
    out = []
    for e in items:
        if not isinstance(e, dict):
            return None
        p = e.get("payload")
        if isinstance(p, str):
            try:
                p = json.loads(p)
            except ValueError:
                p = {}
        out.append({"seq": e.get("seq"), "event_type": e.get("event_type"), "agent_id": e.get("agent_id") or "",
                    "payload": p if isinstance(p, dict) else {}})
    return out


def belongs(e: dict[str, Any], name: str, reg_id: str | None) -> bool:
    """An entry is this agent's when it names the agent (deny/approval entries carry the registered name as the
    claimed id), or when it is bound to its registration (allow entries carry a did:key as the claimed id and the
    registered id as `root_agent_id`). A did:key alone says nothing about who the agent is, so it is not trusted."""
    p = e["payload"]
    if p.get("agent_id_claimed") == name:
        return True
    return bool(reg_id) and reg_id in (p.get("root_agent_id"), e["agent_id"])


EXPECTED_EVENTS = (
    # (event_type, action, verdict, decision enum)
    ("ToolCallIntercepted", "read_file", "allow", 1),
    ("PolicyViolation", "delete_file", "deny", 2),
    ("ApprovalRequested", "send_email", "pending", 3),
)


def find_event(entries: list[dict[str, Any]], etype: str, action: str, verdict: str, decision: int) -> list[dict[str, Any]]:
    return [e for e in entries if e["event_type"] == etype and e["payload"].get("action") == action
            and e["payload"].get("verdict") == verdict and e["payload"].get("decision") == decision]


def registered_ids(be: Any) -> tuple[dict[str, str], str]:
    st, body = be.http("/api/v1/agents?per_page=100")
    try:
        items = json.loads(body).get("items", []) if st == 200 else None
    except ValueError:
        items = None
    if items is None:
        return {}, f"/api/v1/agents -> {st}"
    return {a.get("name"): a.get("id") for a in items if isinstance(a, dict)}, ""


def _fetch_both(be: Any) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """The audit chain as the CLI exports it and as the REST API serves it."""
    problems: list[str] = []
    views: dict[str, list[dict[str, Any]]] = {}
    rc, out = be.audit("")
    try:
        cli = parse_entries(json.loads(out)) if rc == 0 else None
    except ValueError:
        cli = None
    if cli is None:
        problems.append(f"`aasm audit export --format json` exit {rc} did not print an entry list")
    else:
        views["aasm audit export"] = cli
    st, body = be.http("/api/v1/logs?per_page=100")
    try:
        rest = parse_entries(json.loads(body)) if st == 200 else None
    except ValueError:
        rest = None
    if rest is None:
        problems.append(f"GET /api/v1/logs -> {st} did not return an entry list")
    else:
        views["/api/v1/logs"] = rest
    return views, problems


# ---------------------------------------------------------------- rows

def check_live_action(ctx: Any, be: Any, cid: str) -> tuple[bool, bool]:
    """Step 5: allow, deny and approval on a live SDK agent. J56's helpers do the driving and judging; this folds
    them into the single J59 row. Returns (read_file allowed, delete_file denied)."""
    H = load_j56()
    r1, r2 = Recorder(ctx), Recorder(ctx)
    allowed, denied = H.check_allow_deny(r1, be, "", None, "allow-deny")
    H.check_send_email(r2, be, "approval")
    bad = [f"{x.id}: {x.detail}" for x in r1.checks + r2.checks if x.status != c.PASS]
    arts = list(H.BINARIES_ART) + [WHEEL, "golden-path.v1.yaml", "sdk_agent.py"]
    _row(ctx, cid, bad,
         "live SDK agent through the real runtime and gateway: read_file allowed; delete_file raised a typed error with "
         "the sentinel untouched; send_email did not run unapproved, queued a pending approval that `aasm approvals "
         "approve` resolved, and the audit chain recorded ApprovalRequested",
         arts, _tn("test_s5_delete_executing_fails"))
    return allowed, denied


def drive_second_agent(ctx: Any, be: Any) -> list[str]:
    """Agent B: the same three calls. Two send_email calls leave two pending requests for the dashboard to resolve."""
    H = load_j56()
    problems: list[str] = []
    ok, why = be.add_agent(be.agent_b, TEAM_B)
    if not ok:
        return [f"second agent runtime did not start: {why}"]
    for tool, tag in (("read_file", "b-read"), ("delete_file", "b-del"), ("send_email", "b-mail1"), ("send_email", "b-mail2")):
        s = H._sentinel(ctx, f"{tag}-{tool}")
        r = be.sdk("call", agent=be.agent_b, tool=tool, sentinel=s)
        if tool == "read_file" and not r.get("executed"):
            problems.append(f"agent B read_file was not allowed: {r.get('error')}")
        if tool != "read_file" and not H._blocked(r):
            problems.append(f"agent B {tool} was not blocked: driver result {json.dumps(r, sort_keys=True)[:240]}")
    return problems


def check_audit_content(ctx: Any, be: Any, cid: str) -> dict[str, Any]:
    """Step 7: inspect the audit chain of the governed actions, attributed per agent, over two surfaces."""
    neg = _tn("test_s7_missing_deny_fails")
    arts = list(load_j56().BINARIES_ART)
    ids, why = registered_ids(be)
    problems = [why] if why else []
    views, vp = _fetch_both(be)
    problems += vp
    names = {"A": be.agent, "B": be.agent_b}
    for n in names.values():
        if n not in ids:
            problems.append(f"{n} is not in /api/v1/agents")
    notes: list[str] = []
    state: dict[str, Any] = {"entries": {}, "ids": ids}
    for view, entries in views.items():
        own = {k: [e for e in entries if belongs(e, n, ids.get(n))] for k, n in names.items()}
        state["entries"][view] = own
        for k, n in names.items():
            for etype, action, verdict, decision in EXPECTED_EVENTS:
                hit = find_event(own[k], etype, action, verdict, decision)
                if not hit:
                    problems.append(f"{view}: no {etype} for {n} naming {action} with verdict {verdict}")
                elif etype == "PolicyViolation" and not hit[0]["payload"].get("reason"):
                    problems.append(f"{view}: the {action} deny for {n} carries no reason")
            for e in own[k]:
                if not e["agent_id"]:
                    problems.append(f"{view}: an entry for {n} has no agent id")
        leak = {e["seq"] for e in own["A"]} & {e["seq"] for e in own["B"]}
        if leak:
            problems.append(f"{view}: entries {sorted(leak)} are attributed to both agents")
        for e in own["A"]:
            if e["payload"].get("agent_id_claimed") == names["B"]:
                problems.append(f"{view}: agent A's set contains an entry that names agent B")
        for e in own["B"]:
            if e["payload"].get("agent_id_claimed") == names["A"]:
                problems.append(f"{view}: agent B's set contains an entry that names agent A")
        foreign = len(entries) - len(own["A"]) - len(own["B"])
        notes.append(f"{view}: {len(own['A'])} entries for A, {len(own['B'])} for B, {foreign} for neither")
    # the REST agent_id filter must separate the agents' deny entries by their audit id
    rest_a = state["entries"].get("/api/v1/logs", {}).get("A", [])
    deny_a = find_event(rest_a, "PolicyViolation", "delete_file", "deny", 2)
    if deny_a:
        aid = deny_a[0]["agent_id"]
        st, body = be.http(f"/api/v1/logs?agent_id={aid}&per_page=100")
        try:
            got = parse_entries(json.loads(body)) if st == 200 else None
        except ValueError:
            got = None
        if not got:
            problems.append(f"/api/v1/logs?agent_id={aid[:12]}… returned nothing for agent A's deny entry")
        elif any(e["agent_id"] != aid for e in got):
            problems.append("/api/v1/logs?agent_id= returned entries of other agent ids")
        elif any(belongs(e, names["B"], ids.get(names["B"])) for e in got):
            problems.append("/api/v1/logs?agent_id= for agent A returned agent B's events")
        else:
            notes.append(f"agent_id filter returns only that id ({len(got)} entries)")
    sample = (state["entries"].get("aasm audit export", {}).get("A") or [{}])
    traces = [e["payload"].get("trace_id") for e in sample if e]
    spans = [e["payload"].get("span_id") for e in sample if e]
    notes.append("trace_id " + ("present" if any(traces) else "null on every entry") + ", span_id "
                 + ("present" if any(spans) else "null on every entry"))
    _row(ctx, cid, problems,
         "allow (ToolCallIntercepted/allow), deny (PolicyViolation/deny with a reason) and ApprovalRequested/pending are in "
         "both `aasm audit export` and /api/v1/logs for each of two agents, no entry is attributed to both, and the "
         f"agent_id filter separates them; {'; '.join(notes)}", arts, neg)
    state["notes"] = notes
    return state


def check_team_model(ctx: Any, be: Any, cid: str) -> None:
    """Step 3, the part the SDK path can carry: team_id. Two agents under two teams must show up as two teams in the
    topology an operator looks at, and the audit entries must carry each agent's team."""
    neg = _tn("test_s3_single_team_topology_fails")
    arts = list(load_j56().BINARIES_ART)
    problems: list[str] = []
    st, body = be.http("/api/v1/topology/overview")
    try:
        topo = json.loads(body) if st == 200 else {}
    except ValueError:
        topo = {}
    teams = {t.get("team_id"): t.get("agent_count") for t in topo.get("teams", []) if isinstance(t, dict)}
    if teams.get(TEAM_A) != 1 or teams.get(TEAM_B) != 1:
        problems.append(f"topology overview teams {teams} (status {st}), want {{{TEAM_A!r}: 1, {TEAM_B!r}: 1}}")
    views, vp = _fetch_both(be)
    problems += vp
    ids, why = registered_ids(be)
    if why:
        problems.append(why)
    for view, entries in views.items():
        for agent, team in ((be.agent, TEAM_A), (be.agent_b, TEAM_B)):
            allow = find_event([e for e in entries if belongs(e, agent, ids.get(agent))],
                               "ToolCallIntercepted", "read_file", "allow", 1)
            got = {e["payload"].get("team_id") for e in allow}
            if got != {team}:
                problems.append(f"{view}: agent {agent}'s allow entry carries team_id {sorted(map(str, got))}, want {team!r}")
    _row(ctx, cid, problems,
         f"two agents registered by the SDK with team_id {TEAM_A!r} and {TEAM_B!r} appear as two one-agent teams in "
         "/api/v1/topology/overview and their allow entries carry the matching team_id (entries from an agent's "
         "later SDK processes carry none; see the report observations)", arts, neg)


def check_org_filter(ctx: Any, be: Any, cid: str) -> None:
    """Step 3, the documented org tier (docs/src/operations/org-isolation.md): agents registered with an org_id, then
    `/api/v1/logs?org_id=X` returns only X's events. Runs the full two-org assertion when the SDK can carry an org;
    otherwise FAILS with the evidence, because the documented way to set it up does not work."""
    neg = _tn("test_s3_org_filter_without_org_support_fails")
    arts = list(load_j56().BINARIES_ART) + [WHEEL]
    probe = be.sdk("org-probe", agent=f"{be.agent}-probe")
    if probe.get("error") or "has_org_param" not in probe:
        ctx.add(cid, c.FAIL, "real_local_process", f"the org probe did not run: {probe.get('error')} {probe.get('detail', '')}".strip(), arts, neg)
        return
    views, vp = _fetch_both(be)
    ids, _ = registered_ids(be)
    sdk_org_ids: set[Any] = set()
    for entries in views.values():
        for agent in (be.agent, be.agent_b):
            sdk_org_ids |= {e["payload"].get("org_id") for e in entries if belongs(e, agent, ids.get(agent))}
    if not probe["has_org_param"]:
        st, body = be.http("/api/v1/logs?org_id=acme&per_page=100")
        try:
            n = len(json.loads(body).get("items", [])) if st == 200 else -1
        except ValueError:
            n = -1
        ctx.add(cid, c.FAIL, "real_local_process",
                "the SDK cannot register an agent under an org: init_assembly() parameters are "
                f"{probe.get('params')}, and the documented org call raised {probe.get('org_attempt', {}).get('error')}: "
                f"{probe.get('org_attempt', {}).get('message')}. Every audit entry of the two governed agents carries "
                f"org_id {sorted(map(str, sdk_org_ids))}, and GET /api/v1/logs?org_id=acme returns {n} entries. The org tier "
                "documented in org-isolation.md cannot be set up through the SDK on this build, so org-scoped audit isolation "
                "was not demonstrable. Decision needed: fix the SDK (or the docs example), or record org isolation as out of "
                "scope for the SDK path", arts, neg)
        return
    if getattr(be, "org_keys_error", None):
        ctx.add(cid, c.FAIL, "real_local_process", f"the org tier needs org-bound operator keys and none could be issued: {be.org_keys_error}", arts, neg)
        return
    problems = list(vp)
    H = load_j56()
    orgs = {"acme": f"j59o-{uuid.uuid4().hex[:6]}", "globex": f"j59o-{uuid.uuid4().hex[:6]}"}

    def items_of(path: str, key_org: str | None = None) -> tuple[int, list[dict[str, Any]] | None]:
        st, body = be.http(path, key_org) if key_org else be.http(path)
        try:
            return st, parse_entries(json.loads(body)) if st == 200 else None
        except ValueError:
            return st, None

    def entry_orgs(entries: list[dict[str, Any]]) -> set[Any]:
        return {e["payload"].get("org_id") for e in entries}

    # 1. Isolation: each org's agent, registered under that org's key, lands in that org and nowhere else.
    for org, name in orgs.items():
        ok, why = be.add_agent(name, None, org)
        if not ok:
            problems.append(why)
            continue
        s = H._sentinel(ctx, f"org-{org}")
        r = be.sdk("call", agent=name, org=org, tool="read_file", sentinel=s)
        if not r.get("executed"):
            problems.append(f"{org} agent read_file did not run: {r.get('error')} {r.get('message', '')}".strip())
    for org, name in orgs.items():
        other = orgs["globex" if org == "acme" else "acme"]
        st, got = items_of(f"/api/v1/logs?org_id={org}&per_page=100")
        if not got:
            problems.append(f"?org_id={org} returned no entries (status {st})")
            continue
        if entry_orgs(got) != {org}:
            problems.append(f"?org_id={org} returned entries carrying org_id {sorted(map(str, entry_orgs(got)))}, want only {org!r}")
        if any(e["payload"].get("agent_id_claimed") == other for e in got):
            problems.append(f"?org_id={org} contains the other org's agent")

    # 2. Cross-org read: a key bound to acme cannot read globex's audit, by filter or by omission. The admin read of
    # globex is the negative control: it proves the acme caller's empty answer is the authorization, not missing data.
    st_x, cross = items_of("/api/v1/logs?org_id=globex&per_page=100", "acme")
    leaked = entry_orgs(cross or []) - {"acme"}
    if st_x not in (200, 403) or leaked:
        problems.append(f"an acme-bound key reading ?org_id=globex got status {st_x} and entries of org_id {sorted(map(str, leaked))}; "
                        "want a denial or only its own org's entries")
    st_a, own = items_of("/api/v1/logs?per_page=100", "acme")
    if not own:
        problems.append(f"an acme-bound key reading its own audit got status {st_a} and no entries")
    elif entry_orgs(own) != {"acme"}:
        problems.append(f"an acme-bound key with no org filter saw entries of org_id {sorted(map(str, entry_orgs(own)))}, want only 'acme'")
    st_g, admin_view = items_of(f"/api/v1/logs?org_id=globex&per_page=100")
    if not admin_view:
        problems.append("negative control failed: the admin read of ?org_id=globex is empty, so the acme caller's empty answer proves nothing")

    # 3. Spoofed identity: acme's key claiming globex is refused and registers nothing; the matching claim registers
    # (negative control: the refusal is about the mismatch, not about this agent or its key).
    spoofer, honest = f"j59s-{uuid.uuid4().hex[:6]}", f"j59h-{uuid.uuid4().hex[:6]}"
    for name, claim in ((spoofer, "globex"), (honest, "acme")):
        ok, why = be.add_agent(name, None, claim)
        if not ok:
            problems.append(why)
    bad = be.sdk("register", agent=spoofer, org="globex", key_org="acme")
    if bad.get("registered"):
        problems.append("an agent presenting acme's key and claiming org globex was registered")
    good = be.sdk("register", agent=honest, org="acme", key_org="acme")
    if not good.get("registered"):
        problems.append(f"negative control failed: an agent presenting acme's key and claiming acme did not register ({good.get('error')} {good.get('message', '')})".strip())
    ids, _ = registered_ids(be)
    if spoofer in ids:
        problems.append("the spoofing agent appears in /api/v1/agents")

    # 4. Missing org: no org and no key registers org-less (legacy behaviour) and never matches an org filter; an org
    # claim with no key is refused.
    legacy, claimant = f"j59l-{uuid.uuid4().hex[:6]}", f"j59c-{uuid.uuid4().hex[:6]}"
    for name in (legacy, claimant):
        ok, why = be.add_agent(name, None, None)
        if not ok:
            problems.append(why)
    s = H._sentinel(ctx, "org-legacy")
    r = be.sdk("call", agent=legacy, tool="read_file", sentinel=s)
    if not r.get("executed"):
        problems.append(f"the org-less agent read_file did not run: {r.get('error')}")
    nokey = be.sdk("register", agent=claimant, org="acme", no_key=True)
    if nokey.get("registered"):
        problems.append("an agent claiming org acme with no registration key was registered")
    ids, _ = registered_ids(be)
    legacy_id = ids.get(legacy)
    _, everything = items_of("/api/v1/logs?per_page=500")
    mine = [e for e in (everything or []) if belongs(e, legacy, legacy_id)]
    if not mine:
        problems.append("the org-less agent's audit entries are missing")
    elif entry_orgs(mine) != {None}:
        problems.append(f"the org-less agent's entries carry org_id {sorted(map(str, entry_orgs(mine)))}, want none")
    for org in ("acme", "globex"):
        _, filtered = items_of(f"/api/v1/logs?org_id={org}&per_page=500")
        if any(belongs(e, legacy, legacy_id) for e in (filtered or [])):
            problems.append(f"the org-less agent's entries matched ?org_id={org}")
    _row(ctx, cid, problems,
         "two orgs registered with org-bound operator keys: ?org_id= returns only each org's events; an acme-bound key cannot "
         "read globex (admin control sees it); acme's key claiming globex is refused and registers nothing; no key plus an org "
         "claim is refused; an org-less agent registers with org_id null and never matches an org filter", arts, neg)


def _blocked_now(be: Any, ctx: Any, tag: str) -> tuple[bool, dict[str, Any]]:
    H = load_j56()
    r, _, _ = H._drive(ctx, be, "read_file", tag)
    return H._blocked(r), r


def check_core_value(ctx: Any, be: Any, cid: str, v2: Path, driver_digest: Callable[[], str], bound_digest: str | None,
                     settle_seconds: float = 20.0) -> None:
    """Step 12: the same unmodified agent, the same call; allowed under policy v1, denied under v2; the audit chain
    records both decisions, and the denial is explained (typed error text and an audit reason). The change is made
    through the policy file the gateway watches, because that is the only route that stays enforced (see
    check_policy_durability); the harness polls until the gateway has picked it up (<= 5s reconcile interval)."""
    H = load_j56()
    neg = _tn("test_s12_policy_change_ignored_fails")
    arts = list(H.BINARIES_ART) + [WHEEL, "golden-path.v1.yaml", "golden-path.v2-tightened.yaml", "sdk_agent.py"]
    problems: list[str] = []
    before_digest = driver_digest()
    if bound_digest is not None and before_digest != bound_digest:
        problems.append("the agent program differs from the bound source before the run")
    r1, _, _ = H._drive(ctx, be, "read_file", "s12-v1")
    if not r1.get("executed"):
        ctx.add(cid, c.FAIL, "real_local_process", f"read_file was not allowed under the first policy, so no change can be shown ({r1.get('error')})", arts, neg)
        return
    be.set_policy_source(v2)
    waited, last = 0.0, {}
    blocked = False
    while True:
        blocked, last = _blocked_now(be, ctx, f"s12-v2-{int(waited)}")
        if blocked or waited >= settle_seconds:
            break
        be.wait(1.0)
        waited += 1.0
    if not blocked:
        problems.append(f"the same read_file call was still allowed {int(waited)}s after the policy file changed to the tightened policy "
                        f"(executed={last.get('executed')}, error={last.get('error')!r})")
    elif not last.get("message"):
        problems.append("the typed error carries no explanation")
    ids, _ = registered_ids(be)
    views, vp = _fetch_both(be)
    problems += vp
    for view, entries in views.items():
        own = [e for e in entries if belongs(e, be.agent, ids.get(be.agent))]
        allows = find_event(own, "ToolCallIntercepted", "read_file", "allow", 1)
        denies = find_event(own, "PolicyViolation", "read_file", "deny", 2)
        if not allows:
            problems.append(f"{view}: no read_file allow entry for the agent before the policy change")
        if not denies:
            problems.append(f"{view}: no read_file deny entry for the agent after the policy change")
        else:
            if not denies[0]["payload"].get("reason"):
                problems.append(f"{view}: the read_file deny entry carries no reason, so the change is not explained")
            if allows and not max(a["seq"] for a in allows) < min(d["seq"] for d in denies):
                problems.append(f"{view}: a read_file allow entry follows the first deny, so the change did not hold")
    if driver_digest() != before_digest:
        problems.append("the agent program changed during the run")
    _row(ctx, cid, problems,
         f"the same unchanged agent program (sha256 {before_digest[7:19]}) ran read_file: allowed under policy 1.0.0, then, "
         f"once the watched policy file carried 1.1.0 ({int(waited)}s later), denied with a typed error and an explained "
         "PolicyViolation entry; the audit chain holds the allows before the deny, and nothing but the policy changed", arts, neg)


def check_policy_durability(ctx: Any, be: Any, cid: str, other: Path, hold_seconds: float = 12.0,
                             watched: Path | None = None, settle_seconds: float = 20.0) -> None:
    """Step 8/9: a policy applied with `aasm policy apply` must stay enforced. On the candidate the gateway swaps the
    watched policy file back over it within 5s while `aasm policy get` keeps reporting the applied version, so this
    check is expected to FAIL there. `other` must change the agent's read_file outcome relative to the watched file."""
    H = load_j56()
    neg = _tn("test_s9_applied_policy_reverting_fails")
    arts = list(H.BINARIES_ART) + [WHEEL, "golden-path.v1.yaml", "sdk_agent.py"]
    if watched is not None:
        # Put the watched file in the state this row needs instead of inheriting whatever an earlier row left behind;
        # otherwise a failure in that row would turn the expected revert FAIL into a NOT_COVERED here.
        be.set_policy_source(watched)
        waited = 0.0
        while not _blocked_now(be, ctx, f"dur-w{int(waited)}")[0]:
            if waited >= settle_seconds:
                ctx.add(cid, c.FAIL, "real_local_process", f"the watched policy file did not block read_file within {int(settle_seconds)}s, so the starting state of this row could not be established", arts, neg)
                return
            be.wait(1.0)
            waited += 1.0
    if not _blocked_now(be, ctx, "dur-0")[0]:
        ctx.add(cid, c.NOT_COVERED, "real_local_process", "read_file is not blocked under the watched policy, so an applied policy that allows it cannot be told apart", arts, neg)
        return
    effective = False
    for attempt in range(3):  # a reconcile tick can land between the apply and the call; retry rather than blame the product
        rc, out = be.apply_policy(other)
        if rc != 0:
            ctx.add(cid, c.FAIL, "real_local_process", f"`aasm policy apply` exited {rc}: {out.strip()[:160]}", arts, neg)
            return
        if not _blocked_now(be, ctx, f"dur-a{attempt}")[0]:
            effective = True
            break
        be.wait(1.0)
    if not effective:
        ctx.add(cid, c.FAIL, "real_local_process", "the applied policy never changed read_file's outcome, even immediately after `aasm policy apply` (3 attempts)", arts, neg)
        return
    be.wait(hold_seconds)
    blocked_after, last = _blocked_now(be, ctx, "dur-hold")
    rc, got = be.policy_get()
    still_reported = "golden-path" in got
    problems = []
    if blocked_after:
        problems.append(f"the applied policy took effect and then stopped being enforced: {int(hold_seconds)}s after `aasm policy apply` read_file "
                        f"was blocked again by the previous policy while `aasm policy get` "
                        f"{'still reports golden-path' if still_reported else 'output changed'} (silent revert; the gateway re-reads its policy file every 5s "
                        "and swaps it over the applied policy, aa-gateway/src/engine/watcher.rs reconcile_file_tick). Decision needed: make `policy apply` "
                        "durable (write the file source or suspend the reconciler) or document apply as non-durable")
    _row(ctx, cid, problems,
         f"a policy applied with `aasm policy apply` was still enforced {int(hold_seconds)}s later", arts, neg)


def check_dashboard_operations(ctx: Any, be: Any, cid: str, state: dict[str, Any], node: Path | None,
                               dash_dir: Path | None, browsers: Path | None, script: Path) -> None:
    """Step 6: a real browser operates the real dashboard against this stack. The browser's own verdict is only
    half the check: the approval actions must also show in the approval store read back through the API."""
    neg = _tn("test_s6_ui_claims_without_server_effect_fails")
    arts = list(load_j56().BINARIES_ART) + ["dashboard_ops.mjs"]
    missing = [n for n, v in (("--node-bin", node), ("--dashboard-dir", dash_dir), ("--playwright-browsers", browsers)) if not v]
    if missing:
        ctx.add(cid, c.NOT_COVERED, "real_local_process",
                f"browser inputs not supplied ({', '.join(missing)}): node, a dashboard checkout with node_modules (for @playwright/test) "
                "and an installed Playwright browser cache are needed", arts, neg)
        return
    assert node and dash_dir and browsers
    if not (dash_dir / "node_modules" / "@playwright" / "test").exists():
        ctx.add(cid, c.NOT_COVERED, "real_local_process", f"{dash_dir}/node_modules has no @playwright/test (run pnpm install there)", arts, neg)
        return
    work = ctx.tmp / "dash"
    work.mkdir(exist_ok=True)
    shutil.copy(script, work / "dashboard_ops.mjs")
    link = work / "node_modules"
    if not link.exists():
        link.symlink_to(dash_dir / "node_modules")
    own = state["entries"].get("/api/v1/logs", {}).get("A", [])
    rows: list[dict[str, str]] = []
    for etype, action, verdict, decision in EXPECTED_EVENTS:
        hit = find_event(own, etype, action, verdict, decision)
        if hit:
            label = {"ToolCallIntercepted": "TOOL CALL", "PolicyViolation": "POLICY VIOLATION", "ApprovalRequested": "APPROVAL REQUESTED"}[etype]
            row = {"digest": hit[0]["agent_id"][:14], "label": label, "decision": verdict.upper()}
            if etype == "PolicyViolation":
                row["summary"] = str(hit[0]["payload"].get("reason") or "")
            rows.append(row)
    if len(rows) != len(EXPECTED_EVENTS):
        ctx.add(cid, c.FAIL, "real_local_process", "the audit API holds no allow/deny/approval entries for the agent, so there is nothing for the dashboard to show", arts, neg)
        return
    spec = work / "spec.json"
    spec.write_text(json.dumps({"url": be.url, "apiKey": load_j56().TEST_KEY, "agents": [be.agent, be.agent_b],
                                "auditRows": rows, "approveAgent": be.agent_b}))
    env = c.clean_env(ctx.tmp / "dash-home", {"PATH": f"{node.parent}:/usr/bin:/bin", "PLAYWRIGHT_BROWSERS_PATH": str(browsers)})
    (ctx.tmp / "dash-home").mkdir(exist_ok=True)
    rc, out = be.exec([str(node), str(work / "dashboard_ops.mjs"), str(spec)], env, work, 300)
    result: dict[str, Any] | None = None
    for line in reversed(out.splitlines()):
        if line.startswith("RESULT "):
            try:
                result = json.loads(line[len("RESULT "):])
            except ValueError:
                pass  # an unparsable RESULT line leaves result None, which the row reports as a failure below
            break
    problems: list[str] = []
    if result is None:
        problems.append(f"the browser script printed no RESULT (exit {rc}): {out.strip()[-300:]}")
    else:
        for s in result.get("steps", []):
            if not s.get("ok"):
                problems.append(f"UI step {s.get('name')} failed: {s.get('detail')}")
        if not result.get("steps"):
            problems.append("the browser script ran no steps")
        if rc != 0 and not problems:
            problems.append(f"the browser script exited {rc} although every step reported ok")
    if not problems:
        for status, want in (("approved", 1), ("rejected", 1)):
            st, body = be.http(f"/api/v1/approvals?status={status}&per_page=100")
            try:
                items = json.loads(body).get("items", []) if st == 200 else None
            except ValueError:
                items = None
            n = sum(1 for i in (items or []) if i.get("agent_id") == be.agent_b and i.get("status") == status)
            if items is None or n != want:
                problems.append(f"the UI reported a {status} request but the API holds {n} {status} request(s) for {be.agent_b} (want {want})")
        st, body = be.http("/api/v1/approvals?status=pending&per_page=100")
        try:
            pend = [i for i in json.loads(body).get("items", []) if i.get("agent_id") == be.agent_b] if st == 200 else None
        except ValueError:
            pend = None
        if pend is None or pend:
            problems.append(f"pending requests for {be.agent_b} remain after the UI resolved both")
    names = ", ".join(s["name"] for s in (result or {}).get("steps", []))
    _row(ctx, cid, problems,
         f"Playwright drove the dashboard served by the candidate stack: {names}; the approve and reject it performed are "
         f"in the approval store (API read-back); console errors seen: {len((result or {}).get('consoleErrors', []))}",
         arts, neg)


# ---------------------------------------------------------------- orchestration

def run_live(ctx: Any, be: Any, repo: Path, inputs: dict[str, Any]) -> None:
    """Runs the five rows (plus the org-filter check) against a started stack. `be` is a LiveBackend or a fake."""
    H = load_j56()
    v2 = repo / FIX / "golden-path.v2-tightened.yaml"
    rest = [*ROW_IDS, "j59-s3-org-scoped-audit-filter"]

    def skip(why: str) -> None:
        for cid in rest:
            ctx.add(cid, c.NOT_COVERED, "real_local_process", why, [])

    inst = Recorder(ctx)
    if not H.check_install(inst, be, "j59"):
        ctx.add("j59-live-stack-up", c.FAIL, "real_local_process", f"SDK install: {inst.checks[-1].detail}", [WHEEL], _tn("test_install_failure_fails"))
        skip("j59-live-stack-up did not pass, so no agent can be driven")
        return
    up, why = be.start(repo / FIX / "golden-path.v1.yaml")
    if not up:
        ctx.add("j59-live-stack-up", c.FAIL, "real_local_process", f"candidate stack did not come up: {why}", list(H.BINARIES_ART), _tn("test_stack_start_failure_fails"))
        skip("j59-live-stack-up did not pass, so no agent can be driven")
        return
    ctx.add("j59-live-stack-up", c.PASS, "real_local_process",
            "SDK wheel installed offline into a clean venv; gateway and aa-runtime started under an isolated HOME with golden-path 1.0.0",
            list(H.BINARIES_ART) + [WHEEL], _tn("test_stack_start_failure_fails"))
    check_live_action(ctx, be, "j59-s5-live-agent-action-governed")
    b_problems = drive_second_agent(ctx, be)
    if b_problems:
        ctx.add("j59-s7-audit-events-of-governed-action", c.FAIL, "real_local_process", "; ".join(b_problems), list(H.BINARIES_ART), _tn("test_s7_second_agent_failure_fails"))
        state: dict[str, Any] = {"entries": {}}
    else:
        state = check_audit_content(ctx, be, "j59-s7-audit-events-of-governed-action")
    check_team_model(ctx, be, "j59-s3-tenancy-team-model")
    check_org_filter(ctx, be, "j59-s3-org-scoped-audit-filter")
    if state["entries"]:
        check_dashboard_operations(ctx, be, "j59-s6-dashboard-operations", state, inputs.get("node"), inputs.get("dash_dir"),
                                   inputs.get("browsers"), repo / LIVE_SOURCES["dashboard_ops.mjs"])
    else:
        ctx.add("j59-s6-dashboard-operations", c.NOT_COVERED, "real_local_process", "no audit state was captured, so the dashboard has nothing to be compared with", [], _tn("test_s6_ui_claims_without_server_effect_fails"))
    driver = be.driver
    check_core_value(ctx, be, "j59-s12-core-value-no-agent-change", v2, lambda: c.sha256_file(driver), ctx.artifacts.get("sdk_agent.py"),
                     inputs.get("settle_seconds", 20.0))
    check_policy_durability(ctx, be, "j59-s9-applied-policy-stays-enforced", repo / FIX / "golden-path.v1.yaml", inputs.get("hold_seconds", 12.0),
                            watched=v2, settle_seconds=inputs.get("settle_seconds", 20.0))
