//! CLI integration test fixture (AAASM-1449 / F121 Phase A ST-0).
//!
//! Wraps [`TopologyTestEnv`] (the AAASM-1066 in-process gateway harness) with
//! helpers for invoking the `aasm` CLI against the live HTTP gateway: a
//! pre-wired [`std::process::Command`] builder, agent seeding via direct
//! registry insertion, and a static-fixture path resolver.
//!
//! ## Design notes
//!
//! * The underlying harness already mounts the full `aa-api` router via
//!   `aa_api::server::build_app(state)` — no router extension was needed
//!   to support CLI tests beyond topology coverage.
//! * Agent seeding uses **direct registry insertion** (the harness exposes
//!   `Arc<AgentRegistry>` as a public field). The codebase exposes agent
//!   registration via gRPC only; the in-process HTTP harness deliberately
//!   stays HTTP-only, so direct insertion is the pragmatic equivalent that
//!   matches the in-memory `AgentRegistry` shape the REST endpoints + CLI
//!   read from. Same divergence pattern documented in `scenario.rs`.
//! * Policy / alert / audit / cost seeding is **NOT included here** — each
//!   downstream Phase A sub-task (ST-3 policy, Phase B audit/alerts/cost)
//!   adds the specific seed helpers it needs against the resources its
//!   tests actually touch. Keeps ST-0 focused on what Phase A definitely
//!   needs (agents + CLI invocation + format helpers).
//! * Per-test gateway boot is the established pattern (see the divergence
//!   note in `topology_roundtrip.rs` — sharing a `TopologyTestEnv` across
//!   `#[tokio::test]` runtimes is unsound because each `#[tokio::test]`
//!   spawns an independent runtime that gets dropped between tests).

use std::collections::{BTreeMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aa_api::models::trace::TraceSpan;
use aa_core::audit::AuditEventType;
use aa_core::{AgentId, AuditEntry, SessionId};
use aa_gateway::registry::{AgentRecord, AgentStatus};
use aa_runtime::approval::{ApprovalRequest, ApprovalRequestId};
use chrono::{Duration as ChronoDuration, Utc};
use rust_decimal::Decimal;
use tempfile::TempDir;
use uuid::Uuid;

use super::TopologyTestEnv;

/// Per-process counter feeding the second + third bytes of seeded agent IDs.
/// Combined with `std::process::id()` in the first byte and the test-binary
/// hash in the fourth, this produces collision-free 16-byte IDs across
/// parallel cargo nextest test binaries.
static AGENT_SEED_COUNTER: AtomicU16 = AtomicU16::new(0);

/// CLI integration test fixture.
///
/// Holds the in-process gateway (`env`) and provides helpers for invoking
/// `aasm` against it. Per-test instances are the norm — drop tears down
/// the gateway via [`TopologyTestEnv::Drop`].
pub struct CliFixture {
    /// Underlying topology / HTTP test environment from AAASM-1066.
    pub env: TopologyTestEnv,
    /// Per-fixture `AA_DATA_DIR` for filesystem-only CLI leaves
    /// (`policy get` / `policy history` / `policy simulate`). Tests
    /// can pre-populate `data_dir().join("policy-history")` before
    /// invoking the CLI to exercise non-empty paths.
    pub _data_dir: TempDir,
}

impl CliFixture {
    /// Boot a fresh in-process gateway. Wraps [`TopologyTestEnv::start`].
    pub async fn start() -> anyhow::Result<Self> {
        Ok(Self {
            env: TopologyTestEnv::start().await?,
            _data_dir: tempfile::tempdir()?,
        })
    }

    /// Path the CLI sees as `AA_DATA_DIR` for filesystem-only leaves.
    pub fn data_dir(&self) -> &Path {
        self._data_dir.path()
    }

    /// Base URL of the in-process gateway (e.g. `http://127.0.0.1:PORT`).
    pub fn base_url(&self) -> String {
        self.env.base_url()
    }

    /// Returns a [`std::process::Command`] pre-wired with `--api-url
    /// <fixture URL>`. Caller adds the subcommand + flags.
    ///
    /// The binary is built via `cargo run -p aa-cli --bin aasm` because
    /// `assert_cmd::Command::cargo_bin` only works for the bin's own crate
    /// (it relies on `CARGO_BIN_EXE_<name>`, which Cargo only sets for the
    /// owning crate's integration tests). The first invocation per test
    /// binary triggers a build; subsequent invocations hit the cache.
    pub fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO"));
        cmd.args(["run", "--quiet", "-p", "aa-cli", "--bin", "aasm", "--", "--api-url"])
            .arg(self.env.base_url())
            .env("AA_DATA_DIR", self.data_dir());
        cmd
    }

    /// Resolve a path under `tests/common/fixtures/<rel>` to its on-disk
    /// location. Uses `CARGO_MANIFEST_DIR` so it works regardless of
    /// where `cargo nextest` is invoked from.
    pub fn fixture_path(rel: impl AsRef<Path>) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/common/fixtures")
            .join(rel)
    }

    /// Render a 16-byte agent ID as the 32-char lowercase hex string used
    /// by `aa-api`'s REST endpoints and the `aasm` CLI.
    pub fn hex_id(id: &[u8; 16]) -> String {
        id.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Seed `n` independent agents into the in-process registry with
    /// default attributes. Returns the 16-byte agent IDs in registration
    /// order.
    pub fn seed_agents(&self, n: usize) -> Vec<[u8; 16]> {
        (0..n).map(|_| self.seed_agent_with(AgentSpec::default())).collect()
    }

    /// Seed one agent with caller-supplied attributes. Returns its 16-byte
    /// agent ID.
    ///
    /// The ID is derived from a process-local counter so concurrent
    /// `CliFixture::start()` calls (e.g. parallel nextest tests within a
    /// binary) produce non-colliding IDs.
    pub fn seed_agent_with(&self, spec: AgentSpec) -> [u8; 16] {
        let counter = AGENT_SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid_bytes = std::process::id().to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let mut id = [0u8; 16];
        id[0..4].copy_from_slice(&pid_bytes);
        id[4..6].copy_from_slice(&counter_bytes);
        // Remaining 10 bytes left zero — uniqueness comes from pid + counter.

        let name = spec
            .name
            .unwrap_or_else(|| format!("cli-it-{:04x}{:04x}", pid_bytes[0] as u16, counter));
        let framework = spec.framework.unwrap_or_else(|| "cli-it".into());
        let status = spec.status.unwrap_or(AgentStatus::Active);
        let team_id = spec.team_id.or_else(|| Some("cli-it".to_string()));

        let record = AgentRecord {
            agent_id: id,
            name,
            framework,
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "deadbeef".into(),
            credential_token: "cli-it-token".into(),
            metadata: BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: VecDeque::new(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key: None,
        };

        self.env
            .agent_registry
            .register(record)
            .expect("seed_agent_with: register should succeed");
        id
    }
}

/// Attributes for [`CliFixture::seed_agent_with`]. `None` fields fall back
/// to test-friendly defaults (active status, `cli-it` framework + team,
/// auto-generated name).
#[derive(Default)]
pub struct AgentSpec {
    pub name: Option<String>,
    pub framework: Option<String>,
    pub status: Option<AgentStatus>,
    pub team_id: Option<String>,
}

impl CliFixture {
    /// POST a policy YAML to `/api/v1/policies` and return the response
    /// body's `name` (SHA-256 prefix used by `policy get --version`).
    ///
    /// Used by `cli_policy.rs` (ST-3) to populate the gateway's policy
    /// state before testing `aasm policy list` / `policy show`. The
    /// harness boots with `AuthMode::Off`, which gives the request a
    /// synthetic OrgAdmin caller — no auth header needed.
    pub async fn seed_policy(&self, yaml: &str) -> anyhow::Result<String> {
        let url = format!("{}/api/v1/policies", self.env.base_url());
        let body = serde_json::json!({ "policy_yaml": yaml });
        let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("seed_policy POST returned {status}: {text}");
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("seed_policy: response not JSON ({e}): {text}"))?;
        parsed
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("seed_policy: response missing 'name' field: {text}"))
    }

    /// Submit a pending approval request directly into the in-process
    /// `ApprovalQueue`. Returns the assigned request id.
    ///
    /// Used by `cli_status.rs` (ST-10) and any future `cli_approvals.rs`
    /// (ST-13). Direct submission is the pragmatic equivalent of the
    /// production "policy engine triggers an approval requirement" path —
    /// `aa-api` exposes only `/approve` and `/reject` endpoints, not a
    /// `POST /approvals` write, so HTTP-based seeding would require
    /// stand-up of the policy engine + runtime, which is well beyond the
    /// scope of these CLI tests.
    ///
    /// The request is submitted with a 1-hour timeout so the background
    /// auto-resolve task does not race in-test assertions; the returned
    /// `ApprovalFuture` is dropped (the queue retains the pending entry
    /// regardless).
    #[allow(dead_code)]
    pub fn seed_approval(&self, agent_id: &str, action: &str) -> ApprovalRequestId {
        let request = ApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: agent_id.to_string(),
            action: action.to_string(),
            condition_triggered: "cli-it-seed".to_string(),
            submitted_at: chrono::Utc::now().timestamp() as u64,
            timeout_secs: 3600,
            fallback: aa_core::PolicyResult::Deny {
                reason: "cli-it timeout".to_string(),
            },
            team_id: None,
            timeout_override_secs: None,
            escalation_role_override: None,
        };
        let (id, _future) = self.env.approval_queue.submit(request);
        id
    }
}

impl CliFixture {
    /// Seed `n` agents into the given team. Returns their 16-byte ids in
    /// registration order. Used by `topology team` tests that need a
    /// specific team populated.
    pub fn seed_team_members(&self, team_id: &str, n: usize) -> Vec<[u8; 16]> {
        (0..n)
            .map(|_| {
                self.seed_agent_with(AgentSpec {
                    team_id: Some(team_id.to_string()),
                    ..AgentSpec::default()
                })
            })
            .collect()
    }

    /// Seed a parent + child pair under the given team. Returns
    /// `(parent_id, child_id)`. The parent has depth 0 and no parent;
    /// the child has depth 1 and references the parent. Used by
    /// `topology tree` and `topology lineage` tests.
    pub fn seed_parent_child(&self, team_id: &str) -> ([u8; 16], [u8; 16]) {
        let parent_id = self.seed_agent_with(AgentSpec {
            team_id: Some(team_id.to_string()),
            name: Some(format!("parent-{}", &Self::hex_id(&[0; 16])[..4])),
            ..AgentSpec::default()
        });
        let counter = AGENT_SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid_bytes = std::process::id().to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let mut child_id = [0u8; 16];
        child_id[0..4].copy_from_slice(&pid_bytes);
        child_id[4..6].copy_from_slice(&counter_bytes);

        let parent_hex = Self::hex_id(&parent_id);
        let record = AgentRecord {
            agent_id: child_id,
            name: format!("child-{:04x}", counter),
            framework: "cli-it".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "deadbeef".into(),
            credential_token: "cli-it-token".into(),
            metadata: BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: VecDeque::new(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: Some(parent_hex),
            team_id: Some(team_id.to_string()),
            depth: 1,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some(parent_id),
            children: vec![],
            parent_key: Some(parent_id),
        };
        self.env
            .agent_registry
            .register(record)
            .expect("seed_parent_child: register child should succeed");
        (parent_id, child_id)
    }

    /// Seed a session's trace store with `n_spans` flat spans (no
    /// parent-child links). Span IDs are `span-0`, `span-1`, … and
    /// timestamps are spaced one second apart starting at `now() - n_spans s`
    /// so the resulting trace has a strictly ascending `start_time` order
    /// regardless of insertion order.
    ///
    /// Used by `cli_trace.rs` (AAASM-1468 / F121 ST-12) to populate trace
    /// state before invoking `aasm trace <session-id>`. Inserts directly
    /// into the in-memory trace store via [`TopologyTestEnv::trace_store`]
    /// — the gateway exposes no HTTP route for span ingestion.
    pub fn seed_trace_session(&self, session_id: &str, agent_id: &str, n_spans: usize) {
        let now = Utc::now();
        for i in 0..n_spans {
            let offset = ChronoDuration::seconds((i as i64) - (n_spans as i64));
            let start = now + offset;
            let span = TraceSpan {
                span_id: format!("span-{i}"),
                parent_span_id: None,
                operation: format!("op-{i}"),
                decision: Some("allow".to_string()),
                start_time: start,
                end_time: Some(start + ChronoDuration::milliseconds(100)),
            };
            self.env
                .trace_store
                .record_span(session_id, agent_id, span)
                .expect("seed_trace_session: record_span should succeed");
        }
    }

    /// Seed one cost sample for the given agent (and optionally its team)
    /// into the shared `BudgetTracker`. The amount is parsed as a decimal
    /// USD string (e.g. `"8.10"`) so callers can express precise figures
    /// without floating-point round-tripping.
    ///
    /// Used by `cli_cost.rs` (AAASM-1470 / F121 ST-14) to populate spend
    /// state before invoking `aasm cost summary` / `cost forecast`. The
    /// gateway exposes no HTTP route for recording cost samples, so direct
    /// insertion is the test-only equivalent — same pattern as
    /// `seed_agent_with` (registry) and `seed_trace_session` (trace store).
    pub fn seed_cost_sample(&self, agent_id: [u8; 16], team_id: Option<&str>, usd: &str) {
        let amount = Decimal::from_str(usd).expect("seed_cost_sample: invalid USD amount");
        let agent_id = AgentId::from_bytes(agent_id);
        self.env.budget_tracker.record_raw_spend(agent_id, team_id, amount);
    }
}

impl CliFixture {
    /// Append one audit entry to the per-fixture JSONL file in
    /// [`TopologyTestEnv::audit_dir`]. Lets per-leaf tests control timestamp,
    /// agent, and event type independently — used by `cli_logs.rs` filter
    /// tests where `seed_audit_events` (bulk-stride helper below) is too
    /// coarse.
    pub fn seed_audit_event(
        &self,
        timestamp_ns: u64,
        agent_id: [u8; 16],
        event_type: AuditEventType,
        payload: &str,
    ) -> anyhow::Result<()> {
        let entry = AuditEntry::new(
            0,
            timestamp_ns,
            event_type,
            AgentId::from_bytes(agent_id),
            SessionId::from_bytes([0u8; 16]),
            payload.to_string(),
            [0u8; 32],
        );
        let line = serde_json::to_string(&entry)?;
        let path = self.env.audit_dir.join("seed.jsonl");
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }

    /// Seed `n` audit entries for `agent_id` with `event_type`, timestamps
    /// spaced one second apart ending at "now". Returns the nanosecond
    /// timestamp of the oldest entry so the caller can build `--since`
    /// boundaries relative to it.
    pub fn seed_audit_events(&self, n: usize, agent_id: [u8; 16], event_type: AuditEventType) -> anyhow::Result<u64> {
        // Pin "now" against UNIX_EPOCH so all entries share a stable base;
        // back off by `n` seconds so the newest entry lands within the last
        // second (keeps `--since 1h` happy without needing system clock games).
        let now_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
        let stride_ns: u64 = Duration::from_secs(1).as_nanos() as u64;
        let oldest_ns = now_ns - stride_ns * n as u64;
        for i in 0..n {
            let ts = oldest_ns + stride_ns * i as u64;
            self.seed_audit_event(ts, agent_id, event_type, &format!("seed-{i}"))?;
        }
        Ok(oldest_ns)
    }
}
