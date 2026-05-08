use aa_core::{AdapterError, Capability, CapabilitySet, DevToolAdapter};

/// Translate a [`CapabilitySet`] into an `apply_mcp_governance` call on `adapter`.
///
/// Only [`Capability::McpTool`] variants are relevant — all other capability
/// kinds (file, network, process) are enforced at the gateway/proxy/eBPF layers
/// and have no corresponding MCP configuration surface.
pub async fn apply_capability_policy(adapter: &dyn DevToolAdapter, caps: &CapabilitySet) -> Result<(), AdapterError> {
    let allowed: Vec<String> = caps
        .allow
        .iter()
        .filter_map(|c| {
            if let Capability::McpTool(name) = c {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();

    let denied: Vec<String> = caps
        .deny
        .iter()
        .filter_map(|c| {
            if let Capability::McpTool(name) = c {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();

    adapter.apply_mcp_governance(&allowed, &denied).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::{Capability, CapabilitySet};
    use std::sync::Mutex;

    struct MockAdapter {
        calls: Mutex<Vec<(Vec<String>, Vec<String>)>>,
    }

    impl MockAdapter {
        fn new() -> Self {
            Self {
                calls: Mutex::new(vec![]),
            }
        }

        fn recorded_calls(&self) -> Vec<(Vec<String>, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl DevToolAdapter for MockAdapter {
        fn detect(&self) -> Option<aa_core::DevToolInfo> {
            None
        }

        async fn generate_managed_settings(&self, _: &aa_core::PolicyDocument) -> Result<String, AdapterError> {
            Err(AdapterError::SettingsGenerationFailed("mock".into()))
        }

        async fn apply_settings(&self, _: &str) -> Result<(), AdapterError> {
            Ok(())
        }

        fn build_launch_command(
            &self,
            _: &[String],
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            Err(AdapterError::LaunchFailed("mock".into()))
        }

        async fn list_mcp_servers(&self) -> Result<Vec<aa_core::McpServerInfo>, AdapterError> {
            Ok(vec![])
        }

        async fn apply_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<(), AdapterError> {
            self.calls.lock().unwrap().push((allowed.to_vec(), denied.to_vec()));
            Ok(())
        }

        fn governance_level(&self) -> aa_core::GovernanceLevel {
            aa_core::GovernanceLevel::L2Enforce
        }
    }

    #[tokio::test]
    async fn apply_empty_capability_set_calls_apply_with_empty_lists() {
        let adapter = MockAdapter::new();
        let caps = CapabilitySet::default();

        apply_capability_policy(&adapter, &caps).await.unwrap();

        let calls = adapter.recorded_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (vec![] as Vec<String>, vec![] as Vec<String>));
    }

    #[tokio::test]
    async fn apply_denied_mcp_tool_passes_to_denied_list() {
        let adapter = MockAdapter::new();
        let mut caps = CapabilitySet::default();
        caps.deny.insert(Capability::McpTool("bash".into()));

        apply_capability_policy(&adapter, &caps).await.unwrap();

        let calls = adapter.recorded_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Vec::<String>::new());
        assert_eq!(calls[0].1, vec!["bash"]);
    }

    #[tokio::test]
    async fn apply_allowed_mcp_tools_pass_to_allowed_list() {
        let adapter = MockAdapter::new();
        let mut caps = CapabilitySet::default();
        caps.allow.insert(Capability::McpTool("bash".into()));
        caps.allow.insert(Capability::McpTool("git".into()));

        apply_capability_policy(&adapter, &caps).await.unwrap();

        let calls = adapter.recorded_calls();
        assert_eq!(calls.len(), 1);
        let mut allowed = calls[0].0.clone();
        allowed.sort();
        assert_eq!(allowed, vec!["bash", "git"]);
        assert_eq!(calls[0].1, Vec::<String>::new());
    }

    #[tokio::test]
    async fn apply_non_mcp_capabilities_not_in_lists() {
        let adapter = MockAdapter::new();
        let mut caps = CapabilitySet::default();
        caps.deny.insert(Capability::FileWrite);
        caps.deny.insert(Capability::TerminalExec);

        apply_capability_policy(&adapter, &caps).await.unwrap();

        let calls = adapter.recorded_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (vec![] as Vec<String>, vec![] as Vec<String>));
    }

    #[tokio::test]
    async fn apply_both_allow_and_deny_mcp_tools() {
        let adapter = MockAdapter::new();
        let mut caps = CapabilitySet::default();
        caps.allow.insert(Capability::McpTool("git".into()));
        caps.deny.insert(Capability::McpTool("bash".into()));

        apply_capability_policy(&adapter, &caps).await.unwrap();

        let calls = adapter.recorded_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, vec!["git"]);
        assert_eq!(calls[0].1, vec!["bash"]);
    }
}
