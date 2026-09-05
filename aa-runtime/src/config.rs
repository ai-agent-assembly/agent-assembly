//! Runtime configuration loaded from environment variables.

use std::path::PathBuf;

use crate::pipeline::enforcement::DEFAULT_MAX_FIELD_BYTES;

/// Default per-RPC deadline for a gateway policy query, in milliseconds.
///
/// A few seconds is generous for a healthy in-cluster gateway hop yet short
/// enough that a hung gateway cannot stall the runtime's policy checks for long
/// (AAASM-3987).
pub const DEFAULT_GATEWAY_TIMEOUT_MS: u64 = 5_000;

/// A gateway credential token, held only long enough to attach it to outbound
/// requests.
///
/// The sole reason this isn't a plain `String`: [`RuntimeConfig`] derives
/// `Debug` (logged/printed via `{:?}` in error paths and tests), and a bare
/// `String` field would put the live credential in any such output. `Debug`
/// is overridden to print a fixed placeholder instead.
#[derive(Clone)]
pub struct CredentialToken(String);

impl CredentialToken {
    /// Wrap a token value. Exposed for test fixtures that construct a
    /// [`RuntimeConfig`] directly rather than through [`RuntimeConfig::from_env`].
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// Borrow the token value, e.g. to attach as gRPC request metadata.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CredentialToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialToken(<redacted>)")
    }
}

/// Configuration for the `aa-runtime` sidecar process.
///
/// All fields are populated by [`RuntimeConfig::from_env`].
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Stable identity of this agent instance.
    ///
    /// Read from `AA_AGENT_ID`. Required — startup fails if unset.
    /// Used to name the Unix socket: `/tmp/aa-runtime-<agent_id>.sock`.
    pub agent_id: String,

    /// Team component of this agent's composite identity.
    ///
    /// Read from `AA_AGENT_TEAM_ID` (default empty). Combined with
    /// [`agent_org_id`](Self::agent_org_id) and [`agent_id`](Self::agent_id) to
    /// build the `AgentId` triple the runtime uses to subscribe to the
    /// gateway's `OpControlStream`, which the gateway routes by the full
    /// `(org_id, team_id, agent_id)` triple (AAASM-3491).
    pub agent_team_id: String,

    /// Org component of this agent's composite identity.
    ///
    /// Read from `AA_AGENT_ORG_ID` (default empty). See
    /// [`agent_team_id`](Self::agent_team_id).
    pub agent_org_id: String,

    /// Number of Tokio worker threads.
    ///
    /// Read from `AA_RUNTIME_WORKER_THREADS`. Defaults to `0`, which tells
    /// Tokio to use one thread per logical CPU.
    pub worker_threads: usize,

    /// Maximum seconds to wait for in-flight tasks to complete during shutdown.
    ///
    /// Read from `AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS`. Defaults to `30`.
    pub shutdown_timeout_secs: u64,

    /// Maximum number of concurrent SDK connections to the IPC socket.
    ///
    /// Read from `AA_IPC_MAX_CONNECTIONS`. Defaults to `64`.
    pub ipc_max_connections: usize,

    /// Depth of the mpsc channel that feeds the event pipeline.
    ///
    /// Read from `AA_PIPELINE_INPUT_BUFFER`. Defaults to `10_000`.
    /// Zero falls back to the default.
    pub pipeline_input_buffer: usize,

    /// Maximum events in a batch before an early flush is triggered.
    ///
    /// Read from `AA_PIPELINE_BATCH_SIZE`. Defaults to `100`.
    /// Zero falls back to the default.
    pub pipeline_batch_size: usize,

    /// Interval in milliseconds between scheduled batch flushes.
    ///
    /// Read from `AA_PIPELINE_FLUSH_INTERVAL_MS`. Defaults to `100`.
    /// Zero falls back to the default.
    pub pipeline_flush_interval_ms: u64,

    /// Capacity of the broadcast ring buffer for fan-out subscribers.
    ///
    /// Read from `AA_PIPELINE_BROADCAST_CAPACITY`. Defaults to `1_024`.
    /// Zero falls back to the default.
    pub pipeline_broadcast_capacity: usize,

    /// Bind address for the health/metrics HTTP server.
    ///
    /// Read from `AA_METRICS_ADDR`. Defaults to `"0.0.0.0:8080"`. A
    /// non-loopback value is refused at bind time
    /// (`runtime::check_metrics_bind_addr`) unless `AA_METRICS_ALLOW_REMOTE=1`
    /// (AAASM-5985) — this field carries the configured value, not the
    /// value actually bound.
    pub metrics_addr: String,

    /// Path to the policy file used for request enforcement.
    ///
    /// Read from `AA_POLICY_PATH`.
    /// - Not set → `Some("/etc/aa/policy.toml")` (default path)
    /// - Non-empty string → `Some(<value>)`
    /// - Empty string → `None` (policy enforcement disabled)
    pub policy_path: Option<PathBuf>,

    /// Optional gRPC endpoint for the governance gateway.
    ///
    /// Read from `AA_GATEWAY_ENDPOINT`.
    /// - Not set or empty → `None` (local policy evaluation)
    /// - Non-empty string → `Some(<value>)` (forward policy checks to gateway)
    ///
    /// When set, `handle_policy_query` forwards `CheckActionRequest` to the
    /// gateway via [`crate::gateway_client::GatewayClient`] instead of
    /// evaluating locally with [`crate::policy::PolicyRules`].
    pub gateway_endpoint: Option<String>,

    /// Credential token authenticating the `OpControlStream` subscription
    /// (AAASM-5009) to a gateway that enforces per-RPC credential auth
    /// (`aa-gateway/src/iam/grpc_auth.rs`).
    ///
    /// Read from `AA_GATEWAY_CREDENTIAL_TOKEN`. `None` when unset or empty —
    /// the subscription is then sent without a credential, which a
    /// credential-enforcing gateway rejects (every shipped gateway does; see
    /// `aa-gateway/src/main.rs`). Requires [`gateway_agent_id`](Self::gateway_agent_id)
    /// to also be set — `from_env` fails at boot rather than silently retrying
    /// forever if only one of the pair is provided.
    pub gateway_credential_token: Option<CredentialToken>,

    /// The registered agent identity (a `did:key`, minted by
    /// `AgentLifecycleService.Register`) that
    /// [`gateway_credential_token`](Self::gateway_credential_token) was issued
    /// for.
    ///
    /// Read from `AA_GATEWAY_AGENT_ID`. Deliberately distinct from
    /// [`agent_id`](Self::agent_id): the gateway keys its credential registry
    /// by `SHA256("{org_id}/{team_id}/{registered_agent_id}")`
    /// (`aa-gateway/src/registry/convert.rs`), and the human-readable
    /// `AA_AGENT_ID` this runtime instance uses to name its IPC socket is
    /// never itself registered. The org component of that key is always
    /// empty — every SDK registration hardcodes `org_id: ""`
    /// (`aa-sdk-client/src/gateway.rs`) — so there is no corresponding
    /// `AA_GATEWAY_ORG_ID`; [`agent_team_id`](Self::agent_team_id) is reused
    /// as the team component since it already serves the identical purpose
    /// for the unauthenticated subscription path this replaces.
    pub gateway_agent_id: Option<String>,

    /// Sliding window duration in milliseconds for the correlation engine.
    ///
    /// Read from `AA_CORRELATION_WINDOW_MS`. Defaults to `5_000`.
    /// Zero falls back to the default.
    pub correlation_window_ms: u64,

    /// Interval in milliseconds between correlation and eviction runs.
    ///
    /// Read from `AA_CORRELATION_INTERVAL_MS`. Defaults to `1_000`.
    /// Zero falls back to the default.
    pub correlation_interval_ms: u64,

    /// Path to the `agent-assembly.toml` whose `[gateway.nats]` table configures
    /// the audit publisher.
    ///
    /// Read from `AA_NATS_CONFIG_PATH`.
    /// - Not set or empty → `None` (audit publisher disabled; agent still runs)
    /// - Non-empty string → `Some(<value>)`
    pub nats_config_path: Option<PathBuf>,

    /// Path to the local SQLite fallback buffer that holds audit events which
    /// cannot be published while NATS is unreachable.
    ///
    /// Read from `AA_AUDIT_BUFFER_PATH`; defaults to
    /// `<temp-dir>/aa-audit-buffer-<agent_id>.db`. Only used when the audit
    /// publisher is enabled.
    pub audit_buffer_path: PathBuf,

    /// Upper bound, in bytes, on any single secret-bearing field handed to the
    /// runtime credential scanner. Fields larger than this are redacted whole
    /// (fail-closed) rather than partially scanned.
    ///
    /// Read from `AA_ENFORCEMENT_MAX_FIELD_BYTES`. Defaults to
    /// [`DEFAULT_MAX_FIELD_BYTES`] (64 KiB). Zero falls back to the default.
    pub enforcement_max_field_bytes: usize,

    /// Whether a policy check **denies** when the gateway is configured but
    /// unreachable (fail-closed), instead of falling back to permissive local
    /// evaluation (fail-open).
    ///
    /// Read from `AA_GATEWAY_FAIL_CLOSED`. Defaults to `true` — the enforce
    /// posture. The gateway is the authoritative policy decision point; when it
    /// cannot be reached we must not silently default to Allow (AAASM-3110), so
    /// the safe default is to deny. Set to `false` only for an observe /
    /// disabled posture where the runtime should fall back to local rules and
    /// allow on no match. Accepts `false`/`0`/`no`/`off` (case-insensitive) to
    /// disable; any other value (or unset) keeps fail-closed.
    pub gateway_fail_closed: bool,

    /// Per-RPC deadline, in milliseconds, applied to each gateway policy query
    /// (`check_action`).
    ///
    /// Read from `AA_GATEWAY_TIMEOUT_MS`; defaults to [`DEFAULT_GATEWAY_TIMEOUT_MS`].
    /// A gateway that accepts a connection but then stops responding would
    /// otherwise block the policy check forever, stalling every agent's checks
    /// behind the shared client — a runtime-wide head-of-line DoS (AAASM-3987).
    /// The deadline bounds that: on elapse the query is treated as a failure and
    /// routed into the same fail-closed path as a transport error. Zero falls
    /// back to the default so the deadline can never be disabled (that would
    /// reintroduce the hang).
    pub gateway_timeout_ms: u64,

    /// Whether to serve the Developer Integration API (ADR 0030 Decision 5).
    ///
    /// Read from `AA_DEVINT_ENABLED`; **off by default**. The DI-API is a
    /// developer-workstation lifecycle surface, not part of the enforcement
    /// path, so a container runtime enforcing policy for one agent has no use
    /// for it and must not open a socket it will never serve. `aasm` sets this
    /// when it auto-starts a runtime for `aasm integrations …` (AAASM-5280).
    ///
    /// Accepts `1`/`true`/`yes` (case-insensitive); anything else is off, so a
    /// typo fails closed rather than opening the surface.
    pub devint_enabled: bool,
}

impl RuntimeConfig {
    /// Build configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if `AA_AGENT_ID` is not set.
    ///
    /// # Env vars
    ///
    /// | Variable | Type | Default |
    /// |---|---|---|
    /// | `AA_AGENT_ID` | `String` | **required** |
    /// | `AA_RUNTIME_WORKER_THREADS` | `usize` | `0` (Tokio picks per-CPU) |
    /// | `AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS` | `u64` | `30` |
    /// | `AA_IPC_MAX_CONNECTIONS` | `usize` | `64` |
    /// | `AA_PIPELINE_INPUT_BUFFER` | `usize` | `10_000` |
    /// | `AA_PIPELINE_BATCH_SIZE` | `usize` | `100` |
    /// | `AA_PIPELINE_FLUSH_INTERVAL_MS` | `u64` | `100` |
    /// | `AA_PIPELINE_BROADCAST_CAPACITY` | `usize` | `1_024` |
    /// | `AA_METRICS_ADDR` | `String` | `"0.0.0.0:8080"` (non-loopback refused without `AA_METRICS_ALLOW_REMOTE=1`, AAASM-5985) |
    /// | `AA_POLICY_PATH` | `Option<PathBuf>` | `Some("/etc/aa/policy.toml")` |
    /// | `AA_GATEWAY_ENDPOINT` | `Option<String>` | `None` |
    /// | `AA_CORRELATION_WINDOW_MS` | `u64` | `5_000` |
    /// | `AA_CORRELATION_INTERVAL_MS` | `u64` | `1_000` |
    /// | `AA_NATS_CONFIG_PATH` | `Option<PathBuf>` | `None` (publisher disabled) |
    /// | `AA_AUDIT_BUFFER_PATH` | `PathBuf` | `<temp>/aa-audit-buffer-<agent_id>.db` |
    /// | `AA_ENFORCEMENT_MAX_FIELD_BYTES` | `usize` | `65536` (64 KiB) |
    /// | `AA_GATEWAY_FAIL_CLOSED` | `bool` | `true` (deny on gateway unreachable) |
    /// | `AA_GATEWAY_TIMEOUT_MS` | `u64` | `5000` (per-RPC gateway deadline) |
    /// | `AA_AGENT_TEAM_ID` | `String` | `""` (op-control subscription identity) |
    /// | `AA_AGENT_ORG_ID` | `String` | `""` (op-control subscription identity) |
    /// | `AA_GATEWAY_CREDENTIAL_TOKEN` | `Option<CredentialToken>` | `None` (op-control subscription is sent unauthenticated) |
    /// | `AA_GATEWAY_AGENT_ID` | `Option<String>` | `None`; **required** when `AA_GATEWAY_CREDENTIAL_TOKEN` is set |
    pub fn from_env() -> Result<Self, String> {
        let agent_id = std::env::var("AA_AGENT_ID").map_err(|_| "AA_AGENT_ID is required but not set".to_string())?;

        if agent_id.trim().is_empty() {
            return Err("AA_AGENT_ID must not be blank or empty".to_string());
        }

        if agent_id.contains('/') || agent_id.contains("..") {
            return Err("AA_AGENT_ID must not contain path separators ('/' or '..')".to_string());
        }

        // Optional composite-identity components — empty when the agent is not
        // scoped to a team/org. Used only to address the OpControlStream
        // subscription (AAASM-3491).
        let agent_team_id = std::env::var("AA_AGENT_TEAM_ID").unwrap_or_default();
        let agent_org_id = std::env::var("AA_AGENT_ORG_ID").unwrap_or_default();

        let worker_threads = std::env::var("AA_RUNTIME_WORKER_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let shutdown_timeout_secs = std::env::var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        let ipc_max_connections = std::env::var("AA_IPC_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(64);

        let pipeline_input_buffer = std::env::var("AA_PIPELINE_INPUT_BUFFER")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(10_000);

        let pipeline_batch_size = std::env::var("AA_PIPELINE_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(100);

        let pipeline_flush_interval_ms = std::env::var("AA_PIPELINE_FLUSH_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(100);

        let pipeline_broadcast_capacity = std::env::var("AA_PIPELINE_BROADCAST_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(1_024);

        let metrics_addr = std::env::var("AA_METRICS_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

        let policy_path = match std::env::var("AA_POLICY_PATH") {
            Err(_) => Some(PathBuf::from("/etc/aa/policy.toml")),
            Ok(v) if v.is_empty() => None,
            Ok(v) => Some(PathBuf::from(v)),
        };

        let gateway_endpoint = std::env::var("AA_GATEWAY_ENDPOINT").ok().filter(|v| !v.is_empty());

        let gateway_credential_token = std::env::var("AA_GATEWAY_CREDENTIAL_TOKEN")
            .ok()
            .filter(|v| !v.is_empty())
            .map(CredentialToken);
        let gateway_agent_id = std::env::var("AA_GATEWAY_AGENT_ID").ok().filter(|v| !v.is_empty());

        // Fail loud at boot rather than leave the op-control subscriber to
        // retry forever against a gateway that will keep rejecting it for a
        // reason the operator can't see from the reconnect-loop logs alone
        // (AAASM-5009).
        if gateway_credential_token.is_some() && gateway_agent_id.is_none() {
            return Err(
                "AA_GATEWAY_CREDENTIAL_TOKEN is set but AA_GATEWAY_AGENT_ID is not — both are \
                 required to authenticate the op-control subscription"
                    .to_string(),
            );
        }

        let correlation_window_ms = std::env::var("AA_CORRELATION_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(5_000);

        let correlation_interval_ms = std::env::var("AA_CORRELATION_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(1_000);

        let nats_config_path = std::env::var("AA_NATS_CONFIG_PATH")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);

        let audit_buffer_path = std::env::var("AA_AUDIT_BUFFER_PATH")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join(format!("aa-audit-buffer-{agent_id}.db")));

        let enforcement_max_field_bytes = std::env::var("AA_ENFORCEMENT_MAX_FIELD_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_MAX_FIELD_BYTES);

        // Fail-closed by default; only an explicit falsey value opts out.
        let gateway_fail_closed = std::env::var("AA_GATEWAY_FAIL_CLOSED")
            .ok()
            .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no" | "off"))
            .unwrap_or(true);

        // Zero (or unparseable) falls back to the default: the deadline must not
        // be disable-able, or the head-of-line DoS it guards against returns.
        let gateway_timeout_ms = std::env::var("AA_GATEWAY_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_GATEWAY_TIMEOUT_MS);

        let devint_enabled = std::env::var("AA_DEVINT_ENABLED")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        Ok(Self {
            agent_id,
            agent_team_id,
            agent_org_id,
            worker_threads,
            shutdown_timeout_secs,
            ipc_max_connections,
            pipeline_input_buffer,
            pipeline_batch_size,
            pipeline_flush_interval_ms,
            pipeline_broadcast_capacity,
            metrics_addr,
            policy_path,
            gateway_endpoint,
            gateway_credential_token,
            gateway_agent_id,
            correlation_window_ms,
            correlation_interval_ms,
            nats_config_path,
            audit_buffer_path,
            enforcement_max_field_bytes,
            gateway_fail_closed,
            gateway_timeout_ms,
            devint_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    //! # Test isolation
    //!
    //! These tests mutate process environment variables. `AA_AGENT_ID` and
    //! `AA_DEVINT_ENABLED` are also mutated by `runtime.rs`'s DI-API wiring
    //! tests, so isolation cannot be a lock scoped to this module alone — it
    //! goes through `crate::test_env::EnvGuard`, the one crate-wide,
    //! panic-safe env lock (AAASM-5970), which serializes against every
    //! env-mutating test in the crate and restores on drop even if a test
    //! panics mid-body.

    use super::*;
    use crate::test_env::EnvGuard;

    #[test]
    fn reads_agent_id_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "test-agent-42");
        env.unset("AA_RUNTIME_WORKER_THREADS");
        env.unset("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
        env.unset("AA_IPC_MAX_CONNECTIONS");

        let config = RuntimeConfig::from_env().expect("should succeed with AA_AGENT_ID set");

        assert_eq!(config.agent_id, "test-agent-42");
        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 30);
        assert_eq!(config.ipc_max_connections, 64);

        env.unset("AA_AGENT_ID");
    }

    /// The DI-API is off unless it was asked for, and a value that is not a
    /// recognisable yes leaves it off — a typo must not open a local surface.
    #[test]
    fn the_developer_integration_api_is_opt_in_and_fails_closed() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "devint-config-test");

        env.unset("AA_DEVINT_ENABLED");
        assert!(!RuntimeConfig::from_env().expect("config").devint_enabled);

        for on in ["1", "true", "TRUE", "yes", " Yes "] {
            env.set("AA_DEVINT_ENABLED", on);
            assert!(
                RuntimeConfig::from_env().expect("config").devint_enabled,
                "{on:?} should enable the DI-API"
            );
        }

        for off in ["0", "false", "no", "", "ture", "on"] {
            env.set("AA_DEVINT_ENABLED", off);
            assert!(
                !RuntimeConfig::from_env().expect("config").devint_enabled,
                "{off:?} must not enable the DI-API"
            );
        }

        env.unset("AA_DEVINT_ENABLED");
        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn fails_fast_when_agent_id_missing() {
        let mut env = EnvGuard::new();
        env.unset("AA_AGENT_ID");

        let result = RuntimeConfig::from_env();

        assert!(result.is_err(), "expected error when AA_AGENT_ID is not set");
        assert!(result.unwrap_err().contains("AA_AGENT_ID"));
    }

    #[test]
    fn fails_fast_when_agent_id_empty() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "   ");

        let result = RuntimeConfig::from_env();

        assert!(result.is_err());

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn defaults_when_env_vars_absent() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "default-test-agent");
        env.unset("AA_RUNTIME_WORKER_THREADS");
        env.unset("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
        env.unset("AA_IPC_MAX_CONNECTIONS");
        env.unset("AA_PIPELINE_INPUT_BUFFER");
        env.unset("AA_PIPELINE_BATCH_SIZE");
        env.unset("AA_PIPELINE_FLUSH_INTERVAL_MS");
        env.unset("AA_PIPELINE_BROADCAST_CAPACITY");
        env.unset("AA_METRICS_ADDR");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 30);
        assert_eq!(config.ipc_max_connections, 64);
        assert_eq!(config.pipeline_input_buffer, 10_000);
        assert_eq!(config.pipeline_batch_size, 100);
        assert_eq!(config.pipeline_flush_interval_ms, 100);
        assert_eq!(config.pipeline_broadcast_capacity, 1_024);
        assert_eq!(config.metrics_addr, "0.0.0.0:8080");

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn reads_worker_threads_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-wt");
        env.set("AA_RUNTIME_WORKER_THREADS", "4");
        env.unset("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.worker_threads, 4);
        assert_eq!(config.shutdown_timeout_secs, 30);

        env.unset("AA_AGENT_ID");
        env.unset("AA_RUNTIME_WORKER_THREADS");
    }

    #[test]
    fn reads_shutdown_timeout_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-st");
        env.unset("AA_RUNTIME_WORKER_THREADS");
        env.set("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "60");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 60);

        env.unset("AA_AGENT_ID");
        env.unset("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
    }

    #[test]
    fn reads_ipc_max_connections_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-mc");
        env.set("AA_IPC_MAX_CONNECTIONS", "128");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.ipc_max_connections, 128);

        env.unset("AA_AGENT_ID");
        env.unset("AA_IPC_MAX_CONNECTIONS");
    }

    #[test]
    fn rejects_zero_ipc_max_connections() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-zero");
        env.set("AA_IPC_MAX_CONNECTIONS", "0");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.ipc_max_connections, 64, "0 should fall back to default");

        env.unset("AA_AGENT_ID");
        env.unset("AA_IPC_MAX_CONNECTIONS");
    }

    #[test]
    fn rejects_agent_id_with_path_separator() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "../../etc/passwd");

        let result = RuntimeConfig::from_env();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("path separator"));

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn falls_back_to_default_on_invalid_value() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-inv");
        env.set("AA_RUNTIME_WORKER_THREADS", "not-a-number");
        env.set("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "abc");
        env.unset("AA_IPC_MAX_CONNECTIONS");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 30);
        assert_eq!(config.ipc_max_connections, 64);

        env.unset("AA_AGENT_ID");
        env.unset("AA_RUNTIME_WORKER_THREADS");
        env.unset("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
        env.unset("AA_IPC_MAX_CONNECTIONS");
    }

    #[test]
    fn reads_pipeline_input_buffer_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-pib");
        env.set("AA_PIPELINE_INPUT_BUFFER", "5000"); // arbitrary non-default, non-zero value

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_input_buffer, 5000);

        env.unset("AA_AGENT_ID");
        env.unset("AA_PIPELINE_INPUT_BUFFER");
    }

    #[test]
    fn reads_pipeline_batch_size_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-pbs");
        env.set("AA_PIPELINE_BATCH_SIZE", "50"); // arbitrary non-default, non-zero value

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_batch_size, 50);

        env.unset("AA_AGENT_ID");
        env.unset("AA_PIPELINE_BATCH_SIZE");
    }

    #[test]
    fn reads_pipeline_flush_interval_ms_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-pfi");
        env.set("AA_PIPELINE_FLUSH_INTERVAL_MS", "200"); // arbitrary non-default, non-zero value

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_flush_interval_ms, 200);

        env.unset("AA_AGENT_ID");
        env.unset("AA_PIPELINE_FLUSH_INTERVAL_MS");
    }

    #[test]
    fn reads_pipeline_broadcast_capacity_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-pbc");
        env.set("AA_PIPELINE_BROADCAST_CAPACITY", "2048"); // arbitrary non-default, non-zero value

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_broadcast_capacity, 2048);

        env.unset("AA_AGENT_ID");
        env.unset("AA_PIPELINE_BROADCAST_CAPACITY");
    }

    #[test]
    fn pipeline_defaults_when_env_vars_absent() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-pipe-defaults");
        env.unset("AA_PIPELINE_INPUT_BUFFER");
        env.unset("AA_PIPELINE_BATCH_SIZE");
        env.unset("AA_PIPELINE_FLUSH_INTERVAL_MS");
        env.unset("AA_PIPELINE_BROADCAST_CAPACITY");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_input_buffer, 10_000);
        assert_eq!(config.pipeline_batch_size, 100);
        assert_eq!(config.pipeline_flush_interval_ms, 100);
        assert_eq!(config.pipeline_broadcast_capacity, 1_024);

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn pipeline_rejects_zero_values() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-pipe-zero");
        env.set("AA_PIPELINE_INPUT_BUFFER", "0");
        env.set("AA_PIPELINE_BATCH_SIZE", "0");
        env.set("AA_PIPELINE_FLUSH_INTERVAL_MS", "0");
        env.set("AA_PIPELINE_BROADCAST_CAPACITY", "0");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_input_buffer, 10_000, "0 should fall back to default");
        assert_eq!(config.pipeline_batch_size, 100, "0 should fall back to default");
        assert_eq!(config.pipeline_flush_interval_ms, 100, "0 should fall back to default");
        assert_eq!(
            config.pipeline_broadcast_capacity, 1_024,
            "0 should fall back to default"
        );

        env.unset("AA_AGENT_ID");
        env.unset("AA_PIPELINE_INPUT_BUFFER");
        env.unset("AA_PIPELINE_BATCH_SIZE");
        env.unset("AA_PIPELINE_FLUSH_INTERVAL_MS");
        env.unset("AA_PIPELINE_BROADCAST_CAPACITY");
    }

    #[test]
    fn metrics_addr_reads_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-metrics");
        env.set("AA_METRICS_ADDR", "127.0.0.1:9090");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.metrics_addr, "127.0.0.1:9090");

        env.unset("AA_AGENT_ID");
        env.unset("AA_METRICS_ADDR");
    }

    #[test]
    fn metrics_addr_defaults_when_unset() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-metrics-default");
        env.unset("AA_METRICS_ADDR");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.metrics_addr, "0.0.0.0:8080");

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn policy_path_defaults_when_unset() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-policy-default");
        env.unset("AA_POLICY_PATH");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.policy_path, Some(PathBuf::from("/etc/aa/policy.toml")));

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn policy_path_reads_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-policy-custom");
        env.set("AA_POLICY_PATH", "/custom/policy.toml");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.policy_path, Some(PathBuf::from("/custom/policy.toml")));

        env.unset("AA_AGENT_ID");
        env.unset("AA_POLICY_PATH");
    }

    #[test]
    fn policy_path_none_when_empty_string() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-policy-disabled");
        env.set("AA_POLICY_PATH", "");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.policy_path, None);

        env.unset("AA_AGENT_ID");
        env.unset("AA_POLICY_PATH");
    }

    #[test]
    fn gateway_endpoint_none_when_unset() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-gw-default");
        env.unset("AA_GATEWAY_ENDPOINT");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.gateway_endpoint, None);

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn gateway_endpoint_none_when_empty() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-gw-empty");
        env.set("AA_GATEWAY_ENDPOINT", "");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.gateway_endpoint, None);

        env.unset("AA_AGENT_ID");
        env.unset("AA_GATEWAY_ENDPOINT");
    }

    #[test]
    fn gateway_endpoint_reads_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-gw-custom");
        env.set("AA_GATEWAY_ENDPOINT", "http://127.0.0.1:50051");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.gateway_endpoint, Some("http://127.0.0.1:50051".to_string()));

        env.unset("AA_AGENT_ID");
        env.unset("AA_GATEWAY_ENDPOINT");
    }

    #[test]
    fn gateway_credential_and_agent_id_default_to_none() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-cred-default");
        env.unset("AA_GATEWAY_CREDENTIAL_TOKEN");
        env.unset("AA_GATEWAY_AGENT_ID");

        let config = RuntimeConfig::from_env().unwrap();

        assert!(config.gateway_credential_token.is_none());
        assert!(config.gateway_agent_id.is_none());

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn gateway_credential_and_agent_id_read_from_env_when_both_set() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-cred-both");
        env.set("AA_GATEWAY_CREDENTIAL_TOKEN", "tok-abc123");
        env.set("AA_GATEWAY_AGENT_ID", "did:key:z6MkExample");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.gateway_credential_token.unwrap().as_str(), "tok-abc123");
        assert_eq!(config.gateway_agent_id, Some("did:key:z6MkExample".to_string()));

        env.unset("AA_AGENT_ID");
        env.unset("AA_GATEWAY_CREDENTIAL_TOKEN");
        env.unset("AA_GATEWAY_AGENT_ID");
    }

    /// AAASM-5009: a token with no registered identity for it to belong to
    /// would leave the op-control subscriber retrying forever against
    /// `permission_denied` with nothing in the logs pointing at the missing
    /// var — fail at boot instead.
    #[test]
    fn boot_fails_when_credential_token_set_without_gateway_agent_id() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-cred-missing-id");
        env.set("AA_GATEWAY_CREDENTIAL_TOKEN", "tok-abc123");
        env.unset("AA_GATEWAY_AGENT_ID");

        let result = RuntimeConfig::from_env();

        assert!(
            result.is_err(),
            "must fail closed rather than start with an unusable credential"
        );
        let message = result.unwrap_err();
        assert!(message.contains("AA_GATEWAY_CREDENTIAL_TOKEN"));
        assert!(message.contains("AA_GATEWAY_AGENT_ID"));

        env.unset("AA_AGENT_ID");
        env.unset("AA_GATEWAY_CREDENTIAL_TOKEN");
    }

    /// `AA_GATEWAY_AGENT_ID` alone (no token) is accepted — it's meaningless
    /// without a token to authenticate, but there's no ambiguity to fail
    /// closed against the way there is for the reverse case.
    #[test]
    fn gateway_agent_id_alone_without_token_is_accepted() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-cred-id-only");
        env.unset("AA_GATEWAY_CREDENTIAL_TOKEN");
        env.set("AA_GATEWAY_AGENT_ID", "did:key:z6MkExample");

        let config = RuntimeConfig::from_env().unwrap();

        assert!(config.gateway_credential_token.is_none());
        assert_eq!(config.gateway_agent_id, Some("did:key:z6MkExample".to_string()));

        env.unset("AA_AGENT_ID");
        env.unset("AA_GATEWAY_AGENT_ID");
    }

    /// The credential must never appear in `{:?}` output — `RuntimeConfig`
    /// derives `Debug` and is logged/printed in several error paths.
    #[test]
    fn credential_token_debug_output_never_contains_the_value() {
        let token = CredentialToken("super-secret-value".to_string());
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("super-secret-value"));
        assert_eq!(rendered, "CredentialToken(<redacted>)");
    }

    #[test]
    fn correlation_defaults_when_env_vars_absent() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-corr-defaults");
        env.unset("AA_CORRELATION_WINDOW_MS");
        env.unset("AA_CORRELATION_INTERVAL_MS");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.correlation_window_ms, 5_000);
        assert_eq!(config.correlation_interval_ms, 1_000);

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn reads_correlation_window_ms_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-corr-win");
        env.set("AA_CORRELATION_WINDOW_MS", "10000");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.correlation_window_ms, 10_000);

        env.unset("AA_AGENT_ID");
        env.unset("AA_CORRELATION_WINDOW_MS");
    }

    #[test]
    fn reads_correlation_interval_ms_from_env() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-corr-int");
        env.set("AA_CORRELATION_INTERVAL_MS", "2000");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.correlation_interval_ms, 2_000);

        env.unset("AA_AGENT_ID");
        env.unset("AA_CORRELATION_INTERVAL_MS");
    }

    #[test]
    fn correlation_rejects_zero_values() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-corr-zero");
        env.set("AA_CORRELATION_WINDOW_MS", "0");
        env.set("AA_CORRELATION_INTERVAL_MS", "0");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.correlation_window_ms, 5_000, "0 should fall back to default");
        assert_eq!(config.correlation_interval_ms, 1_000, "0 should fall back to default");

        env.unset("AA_AGENT_ID");
        env.unset("AA_CORRELATION_WINDOW_MS");
        env.unset("AA_CORRELATION_INTERVAL_MS");
    }

    #[test]
    fn nats_config_path_set_yields_some_unset_yields_none() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-nats");

        env.set("AA_NATS_CONFIG_PATH", "/etc/aa/agent-assembly.toml");
        let configured = RuntimeConfig::from_env().unwrap();
        assert_eq!(
            configured.nats_config_path,
            Some(PathBuf::from("/etc/aa/agent-assembly.toml"))
        );

        // Empty value ⇒ publisher disabled.
        env.set("AA_NATS_CONFIG_PATH", "");
        assert!(RuntimeConfig::from_env().unwrap().nats_config_path.is_none());

        env.unset("AA_NATS_CONFIG_PATH");
        assert!(RuntimeConfig::from_env().unwrap().nats_config_path.is_none());

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn audit_buffer_path_defaults_per_agent_and_honors_override() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-buf");
        env.unset("AA_AUDIT_BUFFER_PATH");

        let default_cfg = RuntimeConfig::from_env().unwrap();
        assert_eq!(
            default_cfg.audit_buffer_path,
            std::env::temp_dir().join("aa-audit-buffer-agent-buf.db")
        );

        env.set("AA_AUDIT_BUFFER_PATH", "/var/lib/aa/buf.db");
        assert_eq!(
            RuntimeConfig::from_env().unwrap().audit_buffer_path,
            PathBuf::from("/var/lib/aa/buf.db")
        );

        env.unset("AA_AGENT_ID");
        env.unset("AA_AUDIT_BUFFER_PATH");
    }

    #[test]
    fn enforcement_max_field_bytes_reads_defaults_and_rejects_zero() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-enf");

        // Explicit non-default value is honoured.
        env.set("AA_ENFORCEMENT_MAX_FIELD_BYTES", "4096");
        assert_eq!(RuntimeConfig::from_env().unwrap().enforcement_max_field_bytes, 4096);

        // Zero falls back to the default (a 0-byte cap would redact everything).
        env.set("AA_ENFORCEMENT_MAX_FIELD_BYTES", "0");
        assert_eq!(
            RuntimeConfig::from_env().unwrap().enforcement_max_field_bytes,
            DEFAULT_MAX_FIELD_BYTES,
            "0 should fall back to default"
        );

        // Unset falls back to the default.
        env.unset("AA_ENFORCEMENT_MAX_FIELD_BYTES");
        assert_eq!(
            RuntimeConfig::from_env().unwrap().enforcement_max_field_bytes,
            DEFAULT_MAX_FIELD_BYTES
        );

        env.unset("AA_AGENT_ID");
    }

    #[test]
    fn gateway_fail_closed_defaults_true_and_honors_falsey_opt_out() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-fc");

        // Unset → fail-closed (the safe enforce default, AAASM-3110).
        env.unset("AA_GATEWAY_FAIL_CLOSED");
        assert!(RuntimeConfig::from_env().unwrap().gateway_fail_closed);

        // Explicit falsey values opt out (observe/disabled posture).
        for falsey in ["false", "0", "no", "off", "OFF", "False"] {
            env.set("AA_GATEWAY_FAIL_CLOSED", falsey);
            assert!(
                !RuntimeConfig::from_env().unwrap().gateway_fail_closed,
                "{falsey} should disable fail-closed"
            );
        }

        // Any other value keeps fail-closed.
        env.set("AA_GATEWAY_FAIL_CLOSED", "true");
        assert!(RuntimeConfig::from_env().unwrap().gateway_fail_closed);

        env.unset("AA_AGENT_ID");
        env.unset("AA_GATEWAY_FAIL_CLOSED");
    }

    #[test]
    fn gateway_timeout_defaults_and_rejects_zero() {
        let mut env = EnvGuard::new();
        env.set("AA_AGENT_ID", "agent-to");

        // Unset → the default deadline.
        env.unset("AA_GATEWAY_TIMEOUT_MS");
        assert_eq!(
            RuntimeConfig::from_env().unwrap().gateway_timeout_ms,
            DEFAULT_GATEWAY_TIMEOUT_MS
        );

        // A positive value is honoured verbatim.
        env.set("AA_GATEWAY_TIMEOUT_MS", "1500");
        assert_eq!(RuntimeConfig::from_env().unwrap().gateway_timeout_ms, 1_500);

        // Zero must NOT disable the deadline — fall back to the default so the
        // head-of-line DoS guard (AAASM-3987) cannot be turned off.
        env.set("AA_GATEWAY_TIMEOUT_MS", "0");
        assert_eq!(
            RuntimeConfig::from_env().unwrap().gateway_timeout_ms,
            DEFAULT_GATEWAY_TIMEOUT_MS
        );

        env.unset("AA_AGENT_ID");
        env.unset("AA_GATEWAY_TIMEOUT_MS");
    }
}
