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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};

use aa_gateway::registry::{AgentRecord, AgentStatus};

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
}

impl CliFixture {
    /// Boot a fresh in-process gateway. Wraps [`TopologyTestEnv::start`].
    pub async fn start() -> anyhow::Result<Self> {
        Ok(Self {
            env: TopologyTestEnv::start().await?,
        })
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
            .arg(self.env.base_url());
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
