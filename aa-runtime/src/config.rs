//! Runtime configuration loaded from environment variables.

use std::path::PathBuf;

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
    /// Read from `AA_METRICS_ADDR`. Defaults to `"0.0.0.0:8080"`.
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
    /// | `AA_METRICS_ADDR` | `String` | `"0.0.0.0:8080"` |
    /// | `AA_POLICY_PATH` | `Option<PathBuf>` | `Some("/etc/aa/policy.toml")` |
    /// | `AA_GATEWAY_ENDPOINT` | `Option<String>` | `None` |
    /// | `AA_CORRELATION_WINDOW_MS` | `u64` | `5_000` |
    /// | `AA_CORRELATION_INTERVAL_MS` | `u64` | `1_000` |
    /// | `AA_NATS_CONFIG_PATH` | `Option<PathBuf>` | `None` (publisher disabled) |
    /// | `AA_AUDIT_BUFFER_PATH` | `PathBuf` | `<temp>/aa-audit-buffer-<agent_id>.db` |
    pub fn from_env() -> Result<Self, String> {
        let agent_id = std::env::var("AA_AGENT_ID").map_err(|_| "AA_AGENT_ID is required but not set".to_string())?;

        if agent_id.trim().is_empty() {
            return Err("AA_AGENT_ID must not be blank or empty".to_string());
        }

        if agent_id.contains('/') || agent_id.contains("..") {
            return Err("AA_AGENT_ID must not contain path separators ('/' or '..')".to_string());
        }

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

        Ok(Self {
            agent_id,
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
            correlation_window_ms,
            correlation_interval_ms,
            nats_config_path,
            audit_buffer_path,
        })
    }
}

#[cfg(test)]
mod tests {
    //! # Test isolation requirement
    //!
    //! These tests mutate process environment variables and must be run sequentially:
    //! ```text
    //! cargo test -p aa-runtime -- --test-threads=1
    //! ```
    //! Running with the default thread pool causes env var races between tests.

    use super::*;
    use std::sync::Mutex;

    // Env vars are process-global; this mutex serializes all tests that
    // read or write them so they cannot race under multi-threaded test runners
    // (e.g. `cargo llvm-cov` which uses `cargo test` with parallel threads).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn reads_agent_id_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "test-agent-42");
        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
        std::env::remove_var("AA_IPC_MAX_CONNECTIONS");

        let config = RuntimeConfig::from_env().expect("should succeed with AA_AGENT_ID set");

        assert_eq!(config.agent_id, "test-agent-42");
        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 30);
        assert_eq!(config.ipc_max_connections, 64);

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn fails_fast_when_agent_id_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("AA_AGENT_ID");

        let result = RuntimeConfig::from_env();

        assert!(result.is_err(), "expected error when AA_AGENT_ID is not set");
        assert!(result.unwrap_err().contains("AA_AGENT_ID"));
    }

    #[test]
    fn fails_fast_when_agent_id_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "   ");

        let result = RuntimeConfig::from_env();

        assert!(result.is_err());

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn defaults_when_env_vars_absent() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "default-test-agent");
        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
        std::env::remove_var("AA_IPC_MAX_CONNECTIONS");
        std::env::remove_var("AA_PIPELINE_INPUT_BUFFER");
        std::env::remove_var("AA_PIPELINE_BATCH_SIZE");
        std::env::remove_var("AA_PIPELINE_FLUSH_INTERVAL_MS");
        std::env::remove_var("AA_PIPELINE_BROADCAST_CAPACITY");
        std::env::remove_var("AA_METRICS_ADDR");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 30);
        assert_eq!(config.ipc_max_connections, 64);
        assert_eq!(config.pipeline_input_buffer, 10_000);
        assert_eq!(config.pipeline_batch_size, 100);
        assert_eq!(config.pipeline_flush_interval_ms, 100);
        assert_eq!(config.pipeline_broadcast_capacity, 1_024);
        assert_eq!(config.metrics_addr, "0.0.0.0:8080");

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn reads_worker_threads_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-wt");
        std::env::set_var("AA_RUNTIME_WORKER_THREADS", "4");
        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.worker_threads, 4);
        assert_eq!(config.shutdown_timeout_secs, 30);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
    }

    #[test]
    fn reads_shutdown_timeout_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-st");
        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
        std::env::set_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "60");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 60);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
    }

    #[test]
    fn reads_ipc_max_connections_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-mc");
        std::env::set_var("AA_IPC_MAX_CONNECTIONS", "128");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.ipc_max_connections, 128);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_IPC_MAX_CONNECTIONS");
    }

    #[test]
    fn rejects_zero_ipc_max_connections() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-zero");
        std::env::set_var("AA_IPC_MAX_CONNECTIONS", "0");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.ipc_max_connections, 64, "0 should fall back to default");

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_IPC_MAX_CONNECTIONS");
    }

    #[test]
    fn rejects_agent_id_with_path_separator() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "../../etc/passwd");

        let result = RuntimeConfig::from_env();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("path separator"));

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn falls_back_to_default_on_invalid_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-inv");
        std::env::set_var("AA_RUNTIME_WORKER_THREADS", "not-a-number");
        std::env::set_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "abc");
        std::env::remove_var("AA_IPC_MAX_CONNECTIONS");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.worker_threads, 0);
        assert_eq!(config.shutdown_timeout_secs, 30);
        assert_eq!(config.ipc_max_connections, 64);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_RUNTIME_WORKER_THREADS");
        std::env::remove_var("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS");
        std::env::remove_var("AA_IPC_MAX_CONNECTIONS");
    }

    #[test]
    fn reads_pipeline_input_buffer_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-pib");
        std::env::set_var("AA_PIPELINE_INPUT_BUFFER", "5000"); // arbitrary non-default, non-zero value

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_input_buffer, 5000);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_PIPELINE_INPUT_BUFFER");
    }

    #[test]
    fn reads_pipeline_batch_size_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-pbs");
        std::env::set_var("AA_PIPELINE_BATCH_SIZE", "50"); // arbitrary non-default, non-zero value

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_batch_size, 50);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_PIPELINE_BATCH_SIZE");
    }

    #[test]
    fn reads_pipeline_flush_interval_ms_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-pfi");
        std::env::set_var("AA_PIPELINE_FLUSH_INTERVAL_MS", "200"); // arbitrary non-default, non-zero value

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_flush_interval_ms, 200);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_PIPELINE_FLUSH_INTERVAL_MS");
    }

    #[test]
    fn reads_pipeline_broadcast_capacity_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-pbc");
        std::env::set_var("AA_PIPELINE_BROADCAST_CAPACITY", "2048"); // arbitrary non-default, non-zero value

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_broadcast_capacity, 2048);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_PIPELINE_BROADCAST_CAPACITY");
    }

    #[test]
    fn pipeline_defaults_when_env_vars_absent() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-pipe-defaults");
        std::env::remove_var("AA_PIPELINE_INPUT_BUFFER");
        std::env::remove_var("AA_PIPELINE_BATCH_SIZE");
        std::env::remove_var("AA_PIPELINE_FLUSH_INTERVAL_MS");
        std::env::remove_var("AA_PIPELINE_BROADCAST_CAPACITY");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_input_buffer, 10_000);
        assert_eq!(config.pipeline_batch_size, 100);
        assert_eq!(config.pipeline_flush_interval_ms, 100);
        assert_eq!(config.pipeline_broadcast_capacity, 1_024);

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn pipeline_rejects_zero_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-pipe-zero");
        std::env::set_var("AA_PIPELINE_INPUT_BUFFER", "0");
        std::env::set_var("AA_PIPELINE_BATCH_SIZE", "0");
        std::env::set_var("AA_PIPELINE_FLUSH_INTERVAL_MS", "0");
        std::env::set_var("AA_PIPELINE_BROADCAST_CAPACITY", "0");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.pipeline_input_buffer, 10_000, "0 should fall back to default");
        assert_eq!(config.pipeline_batch_size, 100, "0 should fall back to default");
        assert_eq!(config.pipeline_flush_interval_ms, 100, "0 should fall back to default");
        assert_eq!(
            config.pipeline_broadcast_capacity, 1_024,
            "0 should fall back to default"
        );

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_PIPELINE_INPUT_BUFFER");
        std::env::remove_var("AA_PIPELINE_BATCH_SIZE");
        std::env::remove_var("AA_PIPELINE_FLUSH_INTERVAL_MS");
        std::env::remove_var("AA_PIPELINE_BROADCAST_CAPACITY");
    }

    #[test]
    fn metrics_addr_reads_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-metrics");
        std::env::set_var("AA_METRICS_ADDR", "127.0.0.1:9090");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.metrics_addr, "127.0.0.1:9090");

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_METRICS_ADDR");
    }

    #[test]
    fn metrics_addr_defaults_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-metrics-default");
        std::env::remove_var("AA_METRICS_ADDR");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.metrics_addr, "0.0.0.0:8080");

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn policy_path_defaults_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-policy-default");
        std::env::remove_var("AA_POLICY_PATH");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.policy_path, Some(PathBuf::from("/etc/aa/policy.toml")));

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn policy_path_reads_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-policy-custom");
        std::env::set_var("AA_POLICY_PATH", "/custom/policy.toml");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.policy_path, Some(PathBuf::from("/custom/policy.toml")));

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_POLICY_PATH");
    }

    #[test]
    fn policy_path_none_when_empty_string() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-policy-disabled");
        std::env::set_var("AA_POLICY_PATH", "");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.policy_path, None);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_POLICY_PATH");
    }

    #[test]
    fn gateway_endpoint_none_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-gw-default");
        std::env::remove_var("AA_GATEWAY_ENDPOINT");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.gateway_endpoint, None);

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn gateway_endpoint_none_when_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-gw-empty");
        std::env::set_var("AA_GATEWAY_ENDPOINT", "");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.gateway_endpoint, None);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_GATEWAY_ENDPOINT");
    }

    #[test]
    fn gateway_endpoint_reads_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-gw-custom");
        std::env::set_var("AA_GATEWAY_ENDPOINT", "http://127.0.0.1:50051");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.gateway_endpoint, Some("http://127.0.0.1:50051".to_string()));

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_GATEWAY_ENDPOINT");
    }

    #[test]
    fn correlation_defaults_when_env_vars_absent() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-corr-defaults");
        std::env::remove_var("AA_CORRELATION_WINDOW_MS");
        std::env::remove_var("AA_CORRELATION_INTERVAL_MS");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.correlation_window_ms, 5_000);
        assert_eq!(config.correlation_interval_ms, 1_000);

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn reads_correlation_window_ms_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-corr-win");
        std::env::set_var("AA_CORRELATION_WINDOW_MS", "10000");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.correlation_window_ms, 10_000);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_CORRELATION_WINDOW_MS");
    }

    #[test]
    fn reads_correlation_interval_ms_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-corr-int");
        std::env::set_var("AA_CORRELATION_INTERVAL_MS", "2000");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.correlation_interval_ms, 2_000);

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_CORRELATION_INTERVAL_MS");
    }

    #[test]
    fn correlation_rejects_zero_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-corr-zero");
        std::env::set_var("AA_CORRELATION_WINDOW_MS", "0");
        std::env::set_var("AA_CORRELATION_INTERVAL_MS", "0");

        let config = RuntimeConfig::from_env().unwrap();

        assert_eq!(config.correlation_window_ms, 5_000, "0 should fall back to default");
        assert_eq!(config.correlation_interval_ms, 1_000, "0 should fall back to default");

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_CORRELATION_WINDOW_MS");
        std::env::remove_var("AA_CORRELATION_INTERVAL_MS");
    }

    #[test]
    fn nats_config_path_set_yields_some_unset_yields_none() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-nats");

        std::env::set_var("AA_NATS_CONFIG_PATH", "/etc/aa/agent-assembly.toml");
        let configured = RuntimeConfig::from_env().unwrap();
        assert_eq!(
            configured.nats_config_path,
            Some(PathBuf::from("/etc/aa/agent-assembly.toml"))
        );

        // Empty value ⇒ publisher disabled.
        std::env::set_var("AA_NATS_CONFIG_PATH", "");
        assert!(RuntimeConfig::from_env().unwrap().nats_config_path.is_none());

        std::env::remove_var("AA_NATS_CONFIG_PATH");
        assert!(RuntimeConfig::from_env().unwrap().nats_config_path.is_none());

        std::env::remove_var("AA_AGENT_ID");
    }

    #[test]
    fn audit_buffer_path_defaults_per_agent_and_honors_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_AGENT_ID", "agent-buf");
        std::env::remove_var("AA_AUDIT_BUFFER_PATH");

        let default_cfg = RuntimeConfig::from_env().unwrap();
        assert_eq!(
            default_cfg.audit_buffer_path,
            std::env::temp_dir().join("aa-audit-buffer-agent-buf.db")
        );

        std::env::set_var("AA_AUDIT_BUFFER_PATH", "/var/lib/aa/buf.db");
        assert_eq!(
            RuntimeConfig::from_env().unwrap().audit_buffer_path,
            PathBuf::from("/var/lib/aa/buf.db")
        );

        std::env::remove_var("AA_AGENT_ID");
        std::env::remove_var("AA_AUDIT_BUFFER_PATH");
    }
}
