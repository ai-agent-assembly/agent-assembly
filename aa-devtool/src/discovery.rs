//! [`DiscoveryService`] — runs all registered [`DevToolAdapter`]s concurrently
//! and returns detected tools.

use std::sync::Arc;

use futures::future;
use aa_core::{DevToolAdapter, DevToolInfo};

/// Runs all registered [`DevToolAdapter`]s concurrently and collects detected tools.
///
/// Each adapter's [`DevToolAdapter::detect`] method is executed in a
/// `spawn_blocking` task so that synchronous filesystem / subprocess probing
/// does not block the async executor. Adapters that return `None` (tool not
/// installed) or that panic are silently skipped.
pub struct DiscoveryService {
    adapters: Vec<Arc<dyn DevToolAdapter>>,
}

impl Default for DiscoveryService {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryService {
    /// Create a [`DiscoveryService`] pre-loaded with the four built-in adapters:
    /// Claude Code, Codex, GitHub Copilot, and Windsurf.
    pub fn new() -> Self {
        use crate::adapters::{ClaudeCodeAdapter, CodexAdapter, CopilotAdapter, WindsurfAdapter};
        Self::with_adapters(vec![
            Box::new(ClaudeCodeAdapter::default()),
            Box::new(CodexAdapter::default()),
            Box::new(CopilotAdapter::default()),
            Box::new(WindsurfAdapter::default()),
        ])
    }

    /// Create a [`DiscoveryService`] with a custom adapter list.
    ///
    /// Intended for testing and for callers that want to extend or replace
    /// the built-in adapter set.
    pub fn with_adapters(adapters: Vec<Box<dyn DevToolAdapter>>) -> Self {
        Self {
            adapters: adapters.into_iter().map(Arc::from).collect(),
        }
    }

    /// Run all adapters concurrently and return the list of detected tools.
    ///
    /// Adapters returning `None` (tool not installed) are excluded from the
    /// result. Adapters that panic are caught by `spawn_blocking` and silently
    /// dropped — they do not crash the service.
    pub async fn discover_all(&self) -> Vec<DevToolInfo> {
        let handles: Vec<_> = self
            .adapters
            .iter()
            .map(|a| {
                let a = Arc::clone(a);
                tokio::task::spawn_blocking(move || a.detect())
            })
            .collect();

        let outcomes = future::join_all(handles).await;
        outcomes
            .into_iter()
            .filter_map(|r| match r {
                Ok(Some(info)) => Some(info),
                _ => None, // tool not installed, or adapter panicked
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use async_trait::async_trait;
    use aa_core::{
        AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo,
    };
    use aa_core::policy::PolicyDocument;

    use super::DiscoveryService;

    // ---- stub helpers -------------------------------------------------------

    struct AlwaysDetected;

    #[async_trait]
    impl DevToolAdapter for AlwaysDetected {
        fn detect(&self) -> Option<DevToolInfo> {
            Some(DevToolInfo {
                kind: DevToolKind::ClaudeCode,
                version: Some("1.0.0".into()),
                install_path: PathBuf::from("/usr/bin/claude"),
                governance_level: GovernanceLevel::L3Native,
                supports_mcp: true,
                supports_managed_settings: true,
            })
        }

        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            Err(AdapterError::SettingsGenerationFailed("stub".into()))
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            Err(AdapterError::SettingsApplyFailed(std::io::Error::other("stub")))
        }
        fn build_launch_command(&self, _a: &[String], _b: &str, _c: Option<&str>, _d: Option<&str>) -> Result<std::process::Command, AdapterError> {
            Err(AdapterError::LaunchFailed("stub".into()))
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> { Ok(vec![]) }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> { Ok(()) }
        fn governance_level(&self) -> GovernanceLevel { GovernanceLevel::L3Native }
    }

    struct NeverDetected;

    #[async_trait]
    impl DevToolAdapter for NeverDetected {
        fn detect(&self) -> Option<DevToolInfo> { None }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            Err(AdapterError::SettingsGenerationFailed("stub".into()))
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            Err(AdapterError::SettingsApplyFailed(std::io::Error::other("stub")))
        }
        fn build_launch_command(&self, _a: &[String], _b: &str, _c: Option<&str>, _d: Option<&str>) -> Result<std::process::Command, AdapterError> {
            Err(AdapterError::LaunchFailed("stub".into()))
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> { Ok(vec![]) }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> { Ok(()) }
        fn governance_level(&self) -> GovernanceLevel { GovernanceLevel::L0Discover }
    }

    struct PanicAdapter;

    #[async_trait]
    impl DevToolAdapter for PanicAdapter {
        fn detect(&self) -> Option<DevToolInfo> { panic!("intentional panic for test") }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            Err(AdapterError::SettingsGenerationFailed("stub".into()))
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            Err(AdapterError::SettingsApplyFailed(std::io::Error::other("stub")))
        }
        fn build_launch_command(&self, _a: &[String], _b: &str, _c: Option<&str>, _d: Option<&str>) -> Result<std::process::Command, AdapterError> {
            Err(AdapterError::LaunchFailed("stub".into()))
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> { Ok(vec![]) }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> { Ok(()) }
        fn governance_level(&self) -> GovernanceLevel { GovernanceLevel::L0Discover }
    }

    // ---- tests --------------------------------------------------------------

    #[tokio::test]
    async fn discover_returns_only_detected_tools() {
        let svc = DiscoveryService::with_adapters(vec![
            Box::new(AlwaysDetected),
            Box::new(NeverDetected),
        ]);
        let tools = svc.discover_all().await;
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].kind, DevToolKind::ClaudeCode);
    }

    #[tokio::test]
    async fn discover_handles_panicking_adapter() {
        let svc = DiscoveryService::with_adapters(vec![
            Box::new(PanicAdapter),
            Box::new(AlwaysDetected),
        ]);
        // The panic must not propagate; the surviving adapter's result is returned.
        let tools = svc.discover_all().await;
        assert_eq!(tools.len(), 1);
    }

    #[tokio::test]
    async fn discover_empty_when_no_tools_found() {
        let svc = DiscoveryService::with_adapters(vec![
            Box::new(NeverDetected),
            Box::new(NeverDetected),
        ]);
        let tools = svc.discover_all().await;
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn discover_runs_concurrently() {
        use std::time::{Duration, Instant};

        // Build three adapters each sleeping 10 ms in detect().
        // If run serially the total would be ~30 ms; concurrently it should be ~10 ms.
        struct SleepyAdapter;

        #[async_trait]
        impl DevToolAdapter for SleepyAdapter {
            fn detect(&self) -> Option<DevToolInfo> {
                std::thread::sleep(Duration::from_millis(10));
                Some(DevToolInfo {
                    kind: DevToolKind::Codex,
                    version: None,
                    install_path: PathBuf::from("/usr/bin/codex"),
                    governance_level: GovernanceLevel::L2Enforce,
                    supports_mcp: false,
                    supports_managed_settings: false,
                })
            }
            async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
                Err(AdapterError::SettingsGenerationFailed("stub".into()))
            }
            async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
                Err(AdapterError::SettingsApplyFailed(std::io::Error::other("stub")))
            }
            fn build_launch_command(&self, _a: &[String], _b: &str, _c: Option<&str>, _d: Option<&str>) -> Result<std::process::Command, AdapterError> {
                Err(AdapterError::LaunchFailed("stub".into()))
            }
            async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> { Ok(vec![]) }
            async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> { Ok(()) }
            fn governance_level(&self) -> GovernanceLevel { GovernanceLevel::L2Enforce }
        }

        let svc = DiscoveryService::with_adapters(vec![
            Box::new(SleepyAdapter),
            Box::new(SleepyAdapter),
            Box::new(SleepyAdapter),
        ]);

        let start = Instant::now();
        let tools = svc.discover_all().await;
        let elapsed = start.elapsed();

        assert_eq!(tools.len(), 3);
        // Concurrent run: wall time must be less than 2× the individual sleep time.
        assert!(
            elapsed < Duration::from_millis(20),
            "expected concurrent execution (~10 ms), got {elapsed:?}"
        );
    }
}
