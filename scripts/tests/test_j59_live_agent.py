"""Self-tests for scripts/qa/j59_live_agent.py (AAASM-6439), the J59 live-agent rows.

No SDK, binary, browser or network is needed: `FakeLive` stands in for the stack (the same seam the J08/J56
tests use) and simulates what the candidate really does, including its audit payload shape, the identity
quirks (only the first process of an agent is bound and carries team_id; later ones are asserted), the
approval store and the dashboard script's RESULT line. `mode` breaks exactly one behaviour; each `*_fails`
test is the negative control for one row and asserts that exact row goes red while the good fake passes it.

Run: python3 -I scripts/tests/test_j59_live_agent.py
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/qa"))
import j59_live_agent as L  # noqa: E402

H = L.load_j56()
c = L.c
SCRIPT = ROOT / "scripts/qa/fixtures/j59/dashboard_ops.mjs"
ALPHA, BETA = "alpha", "beta"


def hexid(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:32]


class FakeLive:
    """A deterministic stand-in for the live stack. `mode` selects the one broken behaviour."""

    good_key = H.TEST_KEY

    def __init__(self, mode: str, ctx: c.Context):
        self.mode, self.ctx = mode, ctx
        self.agent, self.agent_b = "j56-fake", "j59b-fake"
        self.url = "http://127.0.0.1:1"
        self.team_of = {self.agent: ALPHA}
        self.version = "1.0.0"  # the policy in force
        self.file_version = "1.0.0"  # the watched policy file
        self.entries: list[dict] = []
        self.seen: dict[str, int] = {}
        self.pending: list[dict] = []
        self.decided: list[dict] = []
        self.org_of: dict[str, str] = {}
        self.org_key_files = {"acme": Path("acme.key"), "globex": Path("globex.key")}
        self.org_keys_error = "no aa-keygen" if mode == "no_keygen" else None
        self.refused: set[str] = set()
        self.key_bound: set[str] = set()  # agents registered under an org-bound operator key (AAASM-6447)
        self.registered_once: set[str] = set()
        self.rebound: set[str] = set()
        self.driver = ctx.tmp / "sdk_agent.py"
        self.driver.write_text("# the unchanged agent program\n")
        self.dash_calls = 0

    # -- stack lifecycle
    def install(self):
        return (1, "no matching distribution") if self.mode == "install_fail" else (0, "ok")

    def start(self, policy):
        return (False, "aasm start exited 1") if self.mode == "start_fail" else (True, "")

    def stop(self):
        pass

    def add_agent(self, name, team, org=None):
        if self.mode == "b_runtime_fail" and name == self.agent_b:
            return False, "aa-runtime did not bind"
        if team:
            self.team_of[name] = team
        if org:
            self.org_of[name] = org
        return True, ""

    def _bind(self, agent, claim, key_org, no_key):
        """The gateway's org binding as the real one decides it (aa-gateway org_binding.rs); `mode` breaks one row."""
        if no_key or not key_org:
            if claim and self.mode != "claim_without_key_accepted":
                return False, "org claim without a registration key"
            self.org_of.pop(agent, None)
            if claim:
                self.org_of[agent] = claim
            return True, ""
        if claim and claim != key_org and self.mode != "spoof_accepted":
            return False, "claimed org does not match the key's organization"
        self.org_of[agent] = claim or key_org
        self.key_bound.add(agent)
        return True, ""

    # -- policy
    def apply_policy(self, path):
        if self.mode == "apply_fail":
            return 1, "nope"
        if self.mode != "apply_ineffective":
            self.version = "1.1.0" if "1.1.0" in Path(path).read_text() else "1.0.0"
        self.applied = Path(path).read_text()
        return 0, "applied"

    def set_policy_source(self, path):
        self.file_version = "1.1.0" if "1.1.0" in Path(path).read_text() else "1.0.0"
        self.reload_in = 2 if self.mode == "slow_reload" else 0
        if self.mode != "policy_ignored" and not self.reload_in:
            self.version = self.file_version

    reload_in = 0

    def wait(self, seconds):
        if self.reload_in:
            self.reload_in -= 1
            if not self.reload_in and self.mode != "policy_ignored":
                self.version = self.file_version
        if self.mode == "policy_reverts" and seconds >= 5:
            self.version = self.file_version  # the gateway's file reconciler swapped the watched file back in

    def policy_get(self):
        return 0, f'name: golden-path\nversion: "{self.file_version if self.mode == "policy_reverts" else self.version}"\n'

    # -- the agent
    def sdk(self, op, **kw):
        if op == "import-core":
            return {"ok": True, "sdk_version": "0.0.1rc8"}
        agent = kw.get("agent", self.agent)
        if op == "org-probe":
            if self.mode == "org_unsupported":
                return {"has_org_param": False, "has_team_param": True, "params": ["gateway_url", "team_id"],
                        "org_attempt": {"accepted": False, "error": "TypeError", "message": "unexpected keyword argument 'org_id'"}}
            return {"has_org_param": True, "has_team_param": True, "params": ["gateway_url", "team_id", "org_id"], "org_attempt": {"accepted": True}}
        if op in ("register", "call") and agent not in self.seen and agent not in self.refused:
            ok, why = self._bind(agent, kw.get("org"), kw.get("key_org", kw.get("org")), bool(kw.get("no_key")))
            if not ok:
                self.refused.add(agent)
                if op == "register":
                    return {"registered": False, "agent": agent, "error": "PermissionDenied", "message": why}
        if agent in self.refused:
            return {"executed": False, "error": "RegisterFailed", "typed": False, "message": "registration refused"}
        if op == "register":
            self.seen.setdefault(agent, 0)
            if agent in self.registered_once:
                # A later process of an agent that is already registered (AAASM-6447): the gateway re-binds it only
                # for an agent registered under an org-bound operator key presented again; otherwise AlreadyExists.
                rebindable = agent in self.key_bound and kw.get("key_org", kw.get("org")) and not kw.get("no_key")
                if self.mode == "orgless_rebound":
                    rebindable = True
                if self.mode == "bound_no_rebind":
                    rebindable = False
                if not rebindable:
                    return {"registered": False, "agent": agent, "error": "AlreadyExists", "message": "agent already registered"}
                self.rebound.add(agent)
            self.registered_once.add(agent)
            return {"registered": True, "agent": agent}
        tool, s = kw["tool"], Path(kw["sentinel"])
        first = self.seen.get(agent, 0) == 0 or agent in self.rebound
        self.seen[agent] = self.seen.get(agent, 0) + 1
        if self.mode == "driver_mutated" and tool == "read_file" and self.file_version == "1.1.0":
            self.driver.write_text("# the program was edited to make the call pass\n")
        deny_read = self.version == "1.1.0"
        if tool == "send_email":
            if self.mode == "email_executes":
                Path(str(s) + ".sent").write_text("sent\n")
                return {"executed": True, "error": None, "typed": False}
            self._approval(agent)
            return {"executed": False, "error": "ToolExecutionBlockedError", "typed": True, "message": "Tool execution was not approved by governance."}
        if tool == "delete_file" and self.mode != "delete_executes" or tool == "read_file" and (deny_read or self.mode == "read_blocked"):
            self._violation(agent, tool)
            msg = "" if (self.mode == "empty_message" and tool == "read_file") else "tool denied by policy"
            return {"executed": False, "error": "ToolExecutionBlockedError", "typed": True, "message": msg}
        self._allow(agent, tool, first)
        if tool == "delete_file":
            s.unlink(missing_ok=True)
        return {"executed": True, "error": None, "typed": False}

    # -- audit model (shapes copied from the candidate's real entries)
    def _entry(self, agent, etype, tool, verdict, decision, bound, reason=""):
        reg = hexid("reg-" + agent)
        claimed = agent
        if self.mode == "leak_b_as_a" and agent == self.agent_b:
            claimed = self.agent
        team = self.team_of.get(agent) if bound and self.mode != "team_not_on_entries" else None
        payload = {"action": tool, "action_type": 2, "agent_id_claimed": "did:key:z6Mkfake" if bound else claimed,
                   "agent_id_hex": hexid("bound-" + agent) if bound else hexid("name-" + agent), "decision": decision,
                   "org_id": self.org_of.get(agent), "policy_rule": "tool:" + tool, "reason": reason, "span_id": None,
                   "team_id": team, "trace_id": None, "verdict": verdict, "root_agent_id": reg if bound else None,
                   "agent_identity_assurance": "bound" if bound else "asserted"}
        if self.mode == "leak_b_as_a" and agent == self.agent_b:
            payload["root_agent_id"] = hexid("reg-" + agent)
        self.entries.append({"seq": len(self.entries), "timestamp": "2026-11-05T00:00:00+00:00", "agent_id": payload["agent_id_hex"],
                             "session_id": "0" * 32, "event_type": etype, "payload": json.dumps(payload)})

    def _allow(self, agent, tool, first):
        if self.mode == "b_not_audited" and agent == self.agent_b:
            return
        self._entry(agent, "ToolCallIntercepted", tool, "allow", 1, first)

    def _violation(self, agent, tool):
        if self.mode == "no_deny_audit" or (self.mode == "flip_no_deny_audit" and tool == "read_file") or (self.mode == "b_not_audited" and agent == self.agent_b):
            return
        reason = "" if (self.mode == "deny_without_reason" or (self.mode == "flip_deny_without_reason" and tool == "read_file")) else "tool denied by policy"
        self._entry(agent, "PolicyViolation", tool, "deny", 2, False, reason)

    def _approval(self, agent):
        if self.mode != "no_pending_approval":
            self.pending.append({"id": f"ap-{len(self.pending) + len(self.decided)}", "agent_id": agent, "status": "pending", "reason": "requires_approval"})
        if self.mode == "b_not_audited" and agent == self.agent_b:
            return
        self._entry(agent, "ApprovalRequested", "send_email", "pending", 3, False)

    def audit(self, agent):
        if self.mode == "audit_cli_fails":
            return 1, "boom"
        return 0, json.dumps(self.entries)

    def approvals(self, *args):
        if args[0] == "list":
            return 0, json.dumps([p for p in self.pending])
        self.pending, hit = [p for p in self.pending if p["id"] != args[1]], [p for p in self.pending if p["id"] == args[1]]
        self.decided += [{**h, "status": "approved"} for h in hit]
        return 0, f"Approved: {args[1]} (status: approved)\n"

    # -- REST
    def http(self, path, key_org=None):
        u = urlparse(path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if key_org and u.path == "/api/v1/logs" and self.mode != "cross_org_read_allowed":
            q["org_id"] = key_org  # a tenant-bound caller is pinned to its own org
        if u.path == "/api/v1/agents":
            return 200, json.dumps({"items": [{"id": hexid("reg-" + n), "name": n} for n in self.seen]})
        if u.path == "/api/v1/logs":
            items = list(self.entries)
            if "agent_id" in q and self.mode != "agent_filter_ignored":
                items = [e for e in items if e["agent_id"] == q["agent_id"]]
            if "org_id" in q and self.mode != "org_leaks":
                keep_none = self.mode == "org_less_matches_org_filter"
                items = [e for e in items if json.loads(e["payload"]).get("org_id") == q["org_id"]
                         or (keep_none and json.loads(e["payload"]).get("org_id") is None)]
            if self.mode == "logs_api_down":
                return 500, "{}"
            return 200, json.dumps({"items": items, "page": 1, "per_page": 100, "total": len(items)})
        if u.path == "/api/v1/topology/overview":
            teams: dict[str, int] = {}
            for n in self.seen:
                t = self.team_of.get(n) if self.mode != "single_team" else ALPHA
                if t:
                    teams[t] = teams.get(t, 0) + 1
            return 200, json.dumps({"teams": [{"team_id": t, "agent_count": n} for t, n in teams.items()]})
        if u.path == "/api/v1/approvals":
            st = q.get("status", "pending")
            src = self.pending if st == "pending" else [d for d in self.decided if d["status"] == st]
            return 200, json.dumps({"items": src})
        return 404, "{}"

    # -- the dashboard script, as `be.exec`
    def exec(self, argv, env, cwd, timeout):
        self.dash_calls += 1
        spec = json.loads(Path(argv[2]).read_text())
        assert spec["approveAgent"] == self.agent_b and len(spec["auditRows"]) == 3 and spec["agents"] == [self.agent, self.agent_b]
        if self.mode == "ui_no_result":
            return 1, "Error: browser launch failed\n"
        mine = [p for p in self.pending if p["agent_id"] == self.agent_b]
        if self.mode != "ui_no_server_effect" and len(mine) >= 2:
            first, second = mine[0], mine[1]
            self.pending = [p for p in self.pending if p["id"] not in (first["id"], second["id"])]
            self.decided.append({**first, "status": "approved"})
            if self.mode != "ui_reject_not_applied":
                self.decided.append({**second, "status": "rejected"})
        steps = [{"name": n, "ok": True, "detail": ""} for n in ("login-with-api-key", "agent-list-shows-harness-agents", "audit-log-shows-allow-deny-approval", "approvals-page-lists-pending-and-resolves-from-ui")]
        if self.mode == "ui_step_fails":
            steps[2] = {"name": steps[2]["name"], "ok": False, "detail": "no audit row for agent abc… with TOOL CALL / ALLOW"}
        ok = all(s["ok"] for s in steps)
        return (1 if (not ok or self.mode == "ui_exit_nonzero") else 0), "RESULT " + json.dumps({"ok": ok, "steps": steps, "consoleErrors": [], "apiFailures": []}) + "\n"


class Env:
    def __init__(self, tc: unittest.TestCase, mode: str = "good", browser_inputs: bool = True):
        self.ctx = c.Context("J59", "a" * 40, "0.0.1-rc.8")
        tc.addCleanup(self.ctx.cleanup)
        self.be = FakeLive(mode, self.ctx)
        self.repo = Path(tempfile.mkdtemp(prefix="j59live-selftest-"))
        tc.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        fx = self.repo / "scripts/qa/fixtures/j59"
        fx.mkdir(parents=True)
        for n in ("golden-path.v1.yaml", "golden-path.v2-tightened.yaml"):
            shutil.copy(ROOT / "scripts/qa/fixtures/j59" / n, fx / n)
        shutil.copy(SCRIPT, fx / "dashboard_ops.mjs")
        self.ctx.artifacts["sdk_agent.py"] = c.sha256_file(self.be.driver)
        nm = self.repo / "dash/node_modules/@playwright/test"
        nm.mkdir(parents=True)
        (self.repo / "browsers").mkdir()
        node = self.repo / "bin/node"
        node.parent.mkdir()
        node.write_text("")
        self.inputs = {"node": node, "dash_dir": self.repo / "dash", "browsers": self.repo / "browsers"} if browser_inputs else {}

    def run(self) -> dict[str, c.Check]:
        L.run_live(self.ctx, self.be, self.repo, {**self.inputs, "settle_seconds": 4, "hold_seconds": 12})
        return {x.id: x for x in self.ctx.checks}


def stat(tc: unittest.TestCase, mode: str, **kw) -> dict[str, c.Check]:
    return Env(tc, mode, **kw).run()


GOOD_IDS = ["j59-live-stack-up", *L.ROW_IDS, "j59-s3-org-scoped-audit-filter", "j59-s9-applied-policy-stays-enforced"]


class LiveRowTests(unittest.TestCase):
    def test_good_stack_passes_every_live_row(self):
        res = stat(self, "good")
        for cid in GOOD_IDS:
            self.assertEqual(res[cid].status, "PASS", f"{cid}: {res[cid].detail}")

    def test_every_check_names_a_negative_control_in_this_file(self):
        res = stat(self, "good")
        src = Path(__file__).read_text()
        for cid, ck in res.items():
            self.assertTrue(ck.negative_control, cid)
            name = ck.negative_control.split("::")[-1]
            self.assertIn(f"def {name}(", src, f"{cid} points at a missing test {name}")

    def test_rows_fail_independently(self):
        res = stat(self, "delete_executes")
        self.assertEqual(res["j59-s5-live-agent-action-governed"].status, "FAIL")
        self.assertEqual(res["j59-s3-tenancy-team-model"].status, "PASS")

    # --- s5
    def test_s5_delete_executing_fails(self):
        res = stat(self, "delete_executes")
        self.assertEqual(res["j59-s5-live-agent-action-governed"].status, "FAIL")
        self.assertIn("delete_file", res["j59-s5-live-agent-action-governed"].detail)

    def test_s5_send_email_executing_unapproved_fails(self):
        self.assertEqual(stat(self, "email_executes")["j59-s5-live-agent-action-governed"].status, "FAIL")

    def test_s5_read_blocked_fails(self):
        self.assertEqual(stat(self, "read_blocked")["j59-s5-live-agent-action-governed"].status, "FAIL")

    def test_s5_no_pending_approval_fails(self):
        self.assertEqual(stat(self, "no_pending_approval")["j59-s5-live-agent-action-governed"].status, "FAIL")

    # --- s7
    def test_s7_missing_deny_fails(self):
        res = stat(self, "no_deny_audit")
        self.assertEqual(res["j59-s7-audit-events-of-governed-action"].status, "FAIL")
        self.assertIn("PolicyViolation", res["j59-s7-audit-events-of-governed-action"].detail)

    def test_s7_deny_without_reason_fails(self):
        self.assertEqual(stat(self, "deny_without_reason")["j59-s7-audit-events-of-governed-action"].status, "FAIL")

    def test_s7_other_agents_events_in_this_agents_set_fails(self):
        res = stat(self, "leak_b_as_a")
        self.assertEqual(res["j59-s7-audit-events-of-governed-action"].status, "FAIL")
        self.assertRegex(res["j59-s7-audit-events-of-governed-action"].detail, r"both agents|names agent")

    def test_s7_second_agent_unaudited_fails_so_isolation_is_not_vacuous(self):
        res = stat(self, "b_not_audited")
        self.assertEqual(res["j59-s7-audit-events-of-governed-action"].status, "FAIL")
        self.assertIn(self_name_b(), res["j59-s7-audit-events-of-governed-action"].detail)

    def test_s7_agent_id_filter_ignored_fails(self):
        res = stat(self, "agent_filter_ignored")
        self.assertEqual(res["j59-s7-audit-events-of-governed-action"].status, "FAIL")
        self.assertIn("agent_id", res["j59-s7-audit-events-of-governed-action"].detail)

    def test_s7_cli_export_failing_fails(self):
        self.assertEqual(stat(self, "audit_cli_fails")["j59-s7-audit-events-of-governed-action"].status, "FAIL")

    def test_s7_rest_logs_down_fails(self):
        self.assertEqual(stat(self, "logs_api_down")["j59-s7-audit-events-of-governed-action"].status, "FAIL")

    def test_s7_second_agent_failure_fails(self):
        self.assertEqual(stat(self, "b_runtime_fail")["j59-s7-audit-events-of-governed-action"].status, "FAIL")

    # --- s3
    def test_s3_single_team_topology_fails(self):
        res = stat(self, "single_team")
        self.assertEqual(res["j59-s3-tenancy-team-model"].status, "FAIL")
        self.assertIn("topology", res["j59-s3-tenancy-team-model"].detail)

    def test_s3_team_missing_on_entries_fails(self):
        res = stat(self, "team_not_on_entries")
        self.assertEqual(res["j59-s3-tenancy-team-model"].status, "FAIL")
        self.assertIn("team_id", res["j59-s3-tenancy-team-model"].detail)

    def test_s3_org_filter_without_org_support_fails(self):
        res = stat(self, "org_unsupported")
        row = res["j59-s3-org-scoped-audit-filter"]
        self.assertEqual(row.status, "FAIL")
        self.assertIn("TypeError", row.detail)
        self.assertIn("Decision needed", row.detail)
        self.assertEqual(res["j59-s3-tenancy-team-model"].status, "PASS")

    def test_s3_org_filter_returning_other_orgs_events_fails(self):
        self.assertEqual(stat(self, "org_leaks")["j59-s3-org-scoped-audit-filter"].status, "FAIL")

    # --- s3 org tier (AAASM-6444): each broken behaviour fails the row with its own message
    def _org_row(self, mode):
        return stat(self, mode)["j59-s3-org-scoped-audit-filter"]

    def test_s3_org_row_passes_when_every_org_behaviour_holds(self):
        row = self._org_row("good")
        self.assertEqual(row.status, "PASS", row.detail)

    def test_s3_cross_org_read_allowed_fails(self):
        row = self._org_row("cross_org_read_allowed")
        self.assertEqual(row.status, "FAIL")
        self.assertIn("acme-bound key", row.detail)

    def test_s3_org_less_agent_rebound_fails(self):
        """The org-less negative control: the row fails if an org-less agent's later process is ever re-bound."""
        row = self._org_row("orgless_rebound")
        self.assertEqual(row.status, "FAIL")
        self.assertIn("org-less agent's later process was re-bound", row.detail)

    def test_s3_org_bound_agent_not_rebound_with_its_key_fails(self):
        row = self._org_row("bound_no_rebind")
        self.assertEqual(row.status, "FAIL")
        self.assertIn("did not re-bind", row.detail)

    def test_s3_org_row_states_the_rebind_limitation(self):
        row = self._org_row("good")
        self.assertIn("NOT resolved for org-less agents", row.detail)

    def test_s3_spoofed_org_registered_fails(self):
        row = self._org_row("spoof_accepted")
        self.assertEqual(row.status, "FAIL")
        self.assertIn("claiming org globex was registered", row.detail)

    def test_s3_org_claim_without_key_registered_fails(self):
        row = self._org_row("claim_without_key_accepted")
        self.assertEqual(row.status, "FAIL")
        self.assertIn("no registration key was registered", row.detail)

    def test_s3_org_less_agent_matching_an_org_filter_fails(self):
        row = self._org_row("org_less_matches_org_filter")
        self.assertEqual(row.status, "FAIL")
        self.assertIn("org-less agent", row.detail)

    def test_s3_org_row_fails_when_no_org_keys_can_be_issued(self):
        row = self._org_row("no_keygen")
        self.assertEqual(row.status, "FAIL")
        self.assertIn("operator keys", row.detail)

    # --- s12
    def test_s12_policy_change_ignored_fails(self):
        res = stat(self, "policy_ignored")
        self.assertEqual(res["j59-s12-core-value-no-agent-change"].status, "FAIL")

    def test_s12_agent_program_edited_fails(self):
        res = stat(self, "driver_mutated")
        self.assertEqual(res["j59-s12-core-value-no-agent-change"].status, "FAIL")
        self.assertIn("agent program", res["j59-s12-core-value-no-agent-change"].detail)

    def test_s12_denial_not_in_audit_fails(self):
        self.assertEqual(stat(self, "flip_no_deny_audit")["j59-s12-core-value-no-agent-change"].status, "FAIL")

    def test_s12_denial_without_explanation_fails(self):
        self.assertEqual(stat(self, "flip_deny_without_reason")["j59-s12-core-value-no-agent-change"].status, "FAIL")
        self.assertEqual(stat(self, "empty_message")["j59-s12-core-value-no-agent-change"].status, "FAIL")

    def test_s12_waits_for_the_gateway_to_pick_up_the_policy_file(self):
        res = stat(self, "slow_reload")
        self.assertEqual(res["j59-s12-core-value-no-agent-change"].status, "PASS", res["j59-s12-core-value-no-agent-change"].detail)

    # --- s9 durability
    def test_s9_applied_policy_reverting_fails(self):
        res = stat(self, "policy_reverts")
        row = res["j59-s9-applied-policy-stays-enforced"]
        self.assertEqual(row.status, "FAIL")
        self.assertIn("silent revert", row.detail)
        self.assertIn("Decision needed", row.detail)
        self.assertEqual(res["j59-s12-core-value-no-agent-change"].status, "PASS")

    def test_s9_is_not_masked_when_the_watched_file_never_blocks(self):
        # policy_ignored makes s12 fail; s9 must still say FAIL (starting state not established), not NOT_COVERED.
        row = stat(self, "policy_ignored")["j59-s9-applied-policy-stays-enforced"]
        self.assertEqual(row.status, "FAIL")
        self.assertIn("starting state", row.detail)

    def test_s9_apply_that_never_takes_effect_fails(self):
        self.assertEqual(stat(self, "apply_ineffective")["j59-s9-applied-policy-stays-enforced"].status, "FAIL")

    def test_s9_apply_command_failing_fails(self):
        self.assertEqual(stat(self, "apply_fail")["j59-s9-applied-policy-stays-enforced"].status, "FAIL")

    # --- s6
    def test_s6_ui_step_failure_fails(self):
        res = stat(self, "ui_step_fails")
        self.assertEqual(res["j59-s6-dashboard-operations"].status, "FAIL")
        self.assertIn("audit-log-shows-allow-deny-approval", res["j59-s6-dashboard-operations"].detail)

    def test_s6_ui_claims_without_server_effect_fails(self):
        res = stat(self, "ui_no_server_effect")
        self.assertEqual(res["j59-s6-dashboard-operations"].status, "FAIL")
        self.assertIn("API holds", res["j59-s6-dashboard-operations"].detail)

    def test_s6_reject_not_applied_fails(self):
        self.assertEqual(stat(self, "ui_reject_not_applied")["j59-s6-dashboard-operations"].status, "FAIL")

    def test_s6_script_without_result_fails(self):
        self.assertEqual(stat(self, "ui_no_result")["j59-s6-dashboard-operations"].status, "FAIL")

    def test_s6_nonzero_exit_with_green_steps_fails(self):
        self.assertEqual(stat(self, "ui_exit_nonzero")["j59-s6-dashboard-operations"].status, "FAIL")

    def test_s6_missing_browser_inputs_is_not_covered_never_pass(self):
        res = stat(self, "good", browser_inputs=False)
        row = res["j59-s6-dashboard-operations"]
        self.assertEqual(row.status, "NOT_COVERED")
        self.assertEqual(row.fidelity, "none")
        self.assertIn("--node-bin", row.detail)

    def test_s6_dashboard_dir_without_playwright_is_not_covered(self):
        env = Env(self)
        shutil.rmtree(env.repo / "dash/node_modules")
        (env.repo / "dash/node_modules").mkdir()
        self.assertEqual(env.run()["j59-s6-dashboard-operations"].status, "NOT_COVERED")
        self.assertEqual(env.be.dash_calls, 0)

    # --- stack
    def test_install_failure_fails(self):
        res = stat(self, "install_fail")
        self.assertEqual(res["j59-live-stack-up"].status, "FAIL")
        for cid in L.ROW_IDS:
            self.assertEqual(res[cid].status, "NOT_COVERED", cid)

    def test_stack_start_failure_fails(self):
        res = stat(self, "start_fail")
        self.assertEqual(res["j59-live-stack-up"].status, "FAIL")
        for cid in L.ROW_IDS:
            self.assertEqual(res[cid].status, "NOT_COVERED", cid)


def self_name_a() -> str:
    return "j56-fake"


def self_name_b() -> str:
    return "j59b-fake"


class AttributionTests(unittest.TestCase):
    def test_a_did_key_alone_does_not_attribute_an_entry(self):
        e = {"seq": 1, "agent_id": "x", "event_type": "ToolCallIntercepted",
             "payload": {"agent_id_claimed": "did:key:z6Mkother", "root_agent_id": "reg-of-someone-else"}}
        self.assertFalse(L.belongs(e, "agent-a", "reg-a"))

    def test_registered_id_attributes_a_bound_entry(self):
        e = {"seq": 1, "agent_id": "x", "event_type": "ToolCallIntercepted",
             "payload": {"agent_id_claimed": "did:key:z6Mk", "root_agent_id": "reg-a"}}
        self.assertTrue(L.belongs(e, "agent-a", "reg-a"))

    def test_claimed_name_attributes_an_asserted_entry(self):
        e = {"seq": 1, "agent_id": "y", "event_type": "PolicyViolation", "payload": {"agent_id_claimed": "agent-a"}}
        self.assertTrue(L.belongs(e, "agent-a", None))
        self.assertFalse(L.belongs(e, "agent-b", "reg-b"))

    def test_parse_entries_rejects_non_lists_and_reads_string_payloads(self):
        self.assertIsNone(L.parse_entries({"items": "nope"}))
        got = L.parse_entries({"items": [{"seq": 1, "event_type": "X", "agent_id": "a", "payload": "{\"action\": \"read_file\"}"}]})
        self.assertEqual(got[0]["payload"]["action"], "read_file")

    def test_org_probe_that_cannot_run_fails_the_org_check(self):
        env = Env(self)
        env.be.sdk = lambda op, **kw: {"error": "driver-no-result", "detail": "exit 1"}  # type: ignore[method-assign]
        L.check_org_filter(env.ctx, env.be, "j59-s3-org-scoped-audit-filter")
        self.assertEqual(env.ctx.checks[-1].status, "FAIL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
