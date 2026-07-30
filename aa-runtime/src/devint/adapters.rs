//! Linking the built-in adapters into the lifecycle service (ADR 0030 §6.1).
//!
//! # Why the registry, and why a shim
//!
//! ADR 0030 §6.1 makes adapter registration "an explicit construction into an
//! in-memory registry at startup — no `inventory::submit!`, no `dlopen`". This
//! module is that construction for `aa-runtime`, and it resolves every adapter
//! through [`aa_devtool::registry`] rather than naming the per-tool crates, so
//! there is still exactly one place that decides which implementation backs a
//! tool (AAASM-5274).
//!
//! None of those adapters implements
//! [`DevToolIntegration`](aa_core::integration::DevToolIntegration) yet — the
//! first native implementor is AAASM-5281. Until then
//! [`LegacyAdapterShim`](aa_core::integration::LegacyAdapterShim) makes each of
//! them satisfy the lifecycle contract, declaring honestly that it cannot
//! substantiate the mechanisms it was never designed to expose (§7).
//!
//! # What a shimmed adapter can and cannot do
//!
//! It can be **discovered**, **planned** and **reported on**: `list`, `plan`
//! and `status` are real for every built-in tool from this commit. It cannot be
//! **applied**, because the shim's plan carries
//! `StepAction::ApplyLegacyManagedSettings` — the legacy trait renders and
//! writes in two calls and never discloses the destination path, so there is no
//! file for
//! [`FilesystemExecutor`](aa_core::integration::FilesystemExecutor) to write and
//! no prior state for a receipt to record. The executor refuses that step with
//! a reason rather than reporting a success nothing performed, which is the
//! behaviour AAASM-5281 replaces by shipping a native adapter whose plan names
//! its file.
//!
//! # This module is stripped before publishing
//!
//! `aa-devtool*` are `publish = false` (AAASM-2340), so the dependency and this
//! module are removed by `.ci/strip-for-publish.sh` before
//! `cargo workspaces publish`, exactly as `aa-cli`'s `run`/`tools` commands and
//! `aa-gateway`'s NATS audit consumer already are. A published `aa-runtime`
//! therefore starts with an empty integration registry — the DI-API still
//! binds, and `list_tools` honestly returns nothing.

use std::sync::Arc;

use async_trait::async_trait;

use aa_core::dev_tool::{AdapterError, DevToolAdapter, DevToolInfo, GovernanceLevel, McpServerInfo};
use aa_core::integration::LegacyAdapterShim;
use aa_core::policy::PolicyDocument;

use super::service::RegisteredIntegration;

/// Every built-in tool, wrapped so the lifecycle service can drive it.
///
/// `policy` is the document the shim renders managed settings from. Resolving a
/// *policy profile* into a document belongs to the trusted layers and never
/// crosses the DI-API (ADR 0030 matrix row 6); until that resolution exists the
/// runtime passes the document it was started with.
pub fn built_in_integrations(policy: PolicyDocument) -> Vec<RegisteredIntegration> {
    aa_devtool::registry::SUPPORTED_TOOLS
        .iter()
        .filter_map(|token| {
            let kind = aa_devtool::registry::kind_for(token)?;
            let adapter = aa_devtool::registry::adapter_for(token)?;
            let shim = LegacyAdapterShim::new(kind.clone(), BoxedAdapter(adapter), policy.clone());
            Some(RegisteredIntegration::new(kind, Arc::new(shim)))
        })
        .collect()
}

/// A `Box<dyn DevToolAdapter>` that is itself a `DevToolAdapter`.
///
/// [`LegacyAdapterShim`] is generic over a *sized* adapter, and the registry
/// hands out trait objects. Delegating here keeps the registry the single
/// source of truth for which implementation backs a tool; the alternative —
/// naming each `aa-devtool-*` crate in this module — is precisely the
/// second resolution path AAASM-5274 removed.
struct BoxedAdapter(Box<dyn DevToolAdapter>);

#[async_trait]
impl DevToolAdapter for BoxedAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        self.0.detect()
    }

    async fn generate_managed_settings(&self, policy: &PolicyDocument) -> Result<String, AdapterError> {
        self.0.generate_managed_settings(policy).await
    }

    async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError> {
        self.0.apply_settings(settings).await
    }

    fn build_launch_command(
        &self,
        tool_args: &[String],
        agent_id: &str,
        team_id: Option<&str>,
        proxy_addr: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        self.0.build_launch_command(tool_args, agent_id, team_id, proxy_addr)
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        self.0.list_mcp_servers().await
    }

    async fn apply_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<(), AdapterError> {
        self.0.apply_mcp_governance(allowed, denied).await
    }

    fn governance_level(&self) -> GovernanceLevel {
        self.0.governance_level()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::dev_tool::DevToolKind;

    use crate::devint::lifecycle::IntegrationLifecycle;
    use crate::devint::service::EngineLifecycle;
    use aa_core::integration::ReceiptStore;

    fn policy() -> PolicyDocument {
        PolicyDocument {
            version: 1,
            name: "test".to_string(),
            rules: Vec::new(),
            enforcement_mode: aa_core::policy::EnforcementMode::Enforce,
        }
    }

    #[test]
    fn every_registered_tool_becomes_one_integration() {
        let integrations = built_in_integrations(policy());
        assert_eq!(integrations.len(), aa_devtool::registry::SUPPORTED_TOOLS.len());
    }

    #[test]
    fn no_two_registrations_answer_for_the_same_tool() {
        let integrations = built_in_integrations(policy());
        for (i, a) in integrations.iter().enumerate() {
            for b in integrations.iter().skip(i + 1) {
                assert_ne!(a.tool, b.tool, "two registrations claim the same tool");
            }
        }
    }

    /// The registry's whole point: `list_tools` reaches every built-in tool,
    /// detected or not, so a user sees "Codex — not installed" rather than
    /// nothing at all.
    #[tokio::test]
    async fn the_service_lists_every_built_in_tool() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = EngineLifecycle::new(built_in_integrations(policy()), ReceiptStore::at(dir.path()));
        let tools = service.list_tools().await.expect("list");
        let ids: Vec<String> = tools
            .iter()
            .map(|t| crate::devint::projection::tool_id(&t.tool))
            .collect();
        assert!(ids.contains(&"claude-code".to_string()), "{ids:?}");
        assert!(ids.contains(&"codex".to_string()), "{ids:?}");
    }

    /// The shim declares what it cannot substantiate rather than claiming it.
    /// A capability set full of `Supported` from an adapter that was never
    /// designed to expose them is the over-claim §3.3 exists to prevent.
    #[tokio::test]
    async fn a_shimmed_adapter_declares_its_unsupported_mechanisms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = EngineLifecycle::new(built_in_integrations(policy()), ReceiptStore::at(dir.path()));
        let tools = service.list_tools().await.expect("list");
        let claude = tools
            .iter()
            .find(|t| t.tool == DevToolKind::ClaudeCode)
            .expect("claude-code is registered");
        assert!(
            claude
                .capabilities
                .declared()
                .values()
                .any(|s| matches!(s, aa_core::integration::CapabilitySupport::Unsupported { .. })),
            "the legacy shim claimed every mechanism"
        );
    }
}
