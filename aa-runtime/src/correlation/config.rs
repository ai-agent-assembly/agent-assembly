//! Configuration for the causal correlation engine.

/// Configuration parameters for the [`super::CorrelationEngine`].
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Maximum time window (in milliseconds) within which an intent and an
    /// action must occur to be considered causally correlated.
    ///
    /// Default: 5000 ms.
    pub window_ms: u64,
    /// Maximum number of events held in the sliding window before the oldest
    /// events are force-evicted regardless of age.
    pub max_window_size: usize,
    /// How often (in milliseconds) the engine runs TTL eviction on the sliding
    /// window to discard events older than `window_ms`.
    pub eviction_interval_ms: u64,
}

impl CorrelationConfig {
    /// Build a [`CorrelationConfig`] from the runtime-level configuration.
    ///
    /// Maps `RuntimeConfig::correlation_window_ms` → `window_ms` and
    /// `RuntimeConfig::correlation_interval_ms` → `eviction_interval_ms`.
    /// `max_window_size` keeps the compile-time default (`10_000`).
    pub fn from_runtime_config(rc: &crate::config::RuntimeConfig) -> Self {
        let defaults = Self::default();
        Self {
            window_ms: rc.correlation_window_ms,
            max_window_size: defaults.max_window_size,
            eviction_interval_ms: rc.correlation_interval_ms,
        }
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            window_ms: 5_000,
            max_window_size: 10_000,
            eviction_interval_ms: 1_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = CorrelationConfig::default();
        assert_eq!(config.window_ms, 5_000);
        assert_eq!(config.max_window_size, 10_000);
        assert_eq!(config.eviction_interval_ms, 1_000);
    }

    #[test]
    fn config_is_clone() {
        let config = CorrelationConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.window_ms, config.window_ms);
    }

    #[test]
    fn from_runtime_config_maps_fields() {
        let rc = crate::config::RuntimeConfig {
            agent_id: "test".to_string(),
            worker_threads: 0,
            shutdown_timeout_secs: 30,
            ipc_max_connections: 64,
            pipeline_input_buffer: 10_000,
            pipeline_batch_size: 100,
            pipeline_flush_interval_ms: 100,
            pipeline_broadcast_capacity: 1_024,
            metrics_addr: "0.0.0.0:8080".to_string(),
            policy_path: None,
            gateway_endpoint: None,
            correlation_window_ms: 8_000,
            correlation_interval_ms: 2_000,
            nats_config_path: None,
            audit_buffer_path: std::path::PathBuf::from("/tmp/aa-audit-buffer-test.db"),
            enforcement_max_field_bytes: crate::pipeline::enforcement::DEFAULT_MAX_FIELD_BYTES,
        };

        let config = CorrelationConfig::from_runtime_config(&rc);

        assert_eq!(config.window_ms, 8_000);
        assert_eq!(config.eviction_interval_ms, 2_000);
        assert_eq!(config.max_window_size, 10_000, "max_window_size keeps default");
    }
}
