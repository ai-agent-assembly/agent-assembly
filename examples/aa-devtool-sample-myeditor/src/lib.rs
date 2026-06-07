//! Sample [`DevToolAdapter`] implementation for a fictional `MyEditor` IDE.
//!
//! This crate exists as a **reference for plugin authors** (see
//! [`docs/devtools/plugins.md`]). It is intentionally hand-rolled — no
//! real `myeditor` binary exists. Detection succeeds when an env var
//! pointing at a stub binary is set; MCP-server discovery reads a
//! fixture JSON shipped under `fixtures/mcp_servers.json`. Concrete
//! per-tool adapters (Claude Code, Codex, Copilot, Windsurf, SaaS) are
//! tracked separately in AAASM-201..205 and AAASM-918.
//!
//! [`DevToolAdapter`]: aa_core::DevToolAdapter
//! [`docs/devtools/plugins.md`]: https://github.com/ai-agent-assembly/agent-assembly/blob/master/docs/devtools/plugins.md

#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Environment variable consulted by [`MyEditorAdapter::detect`] to locate
/// the (fictional) `myeditor` binary on the host.
pub const MYEDITOR_BIN_ENV: &str = "MYEDITOR_BIN";

/// Stable identifier this sample adapter registers itself under in the
/// [`DevToolKind::Custom`] discriminator. Plugin authors publishing a
/// real adapter should pick a stable, namespaced string of their own
/// (e.g. `acme.myeditor`).
pub const MYEDITOR_KIND_ID: &str = "myeditor";

/// Reference [`DevToolAdapter`] implementation for the fictional
/// `MyEditor` IDE.
///
/// Constructor takes an explicit fixture path so tests can point at the
/// in-repo `fixtures/mcp_servers.json` and adapter authors can see how a
/// real adapter would consult its own tool's native config file.
#[derive(Debug, Clone)]
pub struct MyEditorAdapter {
    /// Filesystem path to the MCP-servers fixture (or, in a real
    /// adapter, the tool's native config file).
    mcp_config_path: PathBuf,
}

impl MyEditorAdapter {
    /// Construct an adapter that reads its MCP server list from
    /// `mcp_config_path`.
    pub fn new(mcp_config_path: impl Into<PathBuf>) -> Self {
        Self {
            mcp_config_path: mcp_config_path.into(),
        }
    }

    /// Path the adapter will read for MCP-server discovery. Exposed for
    /// tests so they can assert the adapter's wiring without
    /// roundtripping through the filesystem.
    pub fn mcp_config_path(&self) -> &Path {
        &self.mcp_config_path
    }
}

/// Native MCP-config shape for `MyEditor`. Mirrors the JSON layout
/// shipped in `fixtures/mcp_servers.json`.
#[derive(Debug, Deserialize)]
struct MyEditorMcpConfig {
    #[serde(rename = "mcpServers")]
    mcp_servers: std::collections::BTreeMap<String, MyEditorMcpEntry>,
}

#[derive(Debug, Deserialize)]
struct MyEditorMcpEntry {
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

/// Managed-settings document the sample adapter would write into a real
/// MyEditor config. Defined as a typed struct so
/// [`MyEditorAdapter::generate_managed_settings`] can serialize a
/// reproducible JSON document without ad-hoc string formatting.
#[derive(Debug, Serialize)]
struct ManagedSettings<'a> {
    /// Stamp identifying which Agent Assembly policy generated this
    /// settings document. Real adapters may include the policy hash;
    /// this sample uses the policy's tenant scope.
    generated_by: &'static str,
    /// Permitted MCP server names (placeholder list — production
    /// adapters consult `policy.mcp_allowlist()`).
    mcp_allow: &'a [&'a str],
}

#[async_trait]
impl DevToolAdapter for MyEditorAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        // Real adapter would `which myeditor` or read a known install
        // marker. Sample uses an env-var probe so the test suite can
        // toggle detection without filesystem mocking.
        let install_path = std::env::var_os(MYEDITOR_BIN_ENV).map(PathBuf::from)?;
        Some(DevToolInfo {
            kind: DevToolKind::Custom(MYEDITOR_KIND_ID.to_string()),
            version: Some("0.0.0-sample".to_string()),
            install_path,
            governance_level: GovernanceLevel::L1Observe,
            supports_mcp: true,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
        // Production adapters translate `policy` into the tool's native
        // config schema. The sample emits a tiny placeholder document
        // so plugin authors see the shape and the serialization
        // boundary without drowning in domain detail.
        let settings = ManagedSettings {
            generated_by: "aa-devtool-sample-myeditor",
            mcp_allow: &["filesystem", "github", "internal-search"],
        };
        serde_json::to_string_pretty(&settings).map_err(|e| AdapterError::Serde(e.to_string()))
    }

    async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError> {
        // Real adapter would write to MyEditor's managed-settings file
        // (e.g. `~/.config/myeditor/managed.json`). The sample writes
        // beside the MCP fixture so tests can assert the write
        // happened without leaking outside `tempfile`-managed scope.
        let target = self
            .mcp_config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("managed.json");
        std::fs::write(&target, settings).map_err(AdapterError::SettingsApplyFailed)?;
        Ok(())
    }

    fn build_launch_command(
        &self,
        tool_args: &[String],
        agent_id: &str,
        team_id: Option<&str>,
        proxy_addr: Option<&str>,
    ) -> Result<Command, AdapterError> {
        // The launcher invokes this to start MyEditor with governance
        // wiring. Sample injects identity via env vars (idiomatic for
        // most CLIs) and HTTPS_PROXY when a proxy address is set.
        let bin = std::env::var(MYEDITOR_BIN_ENV)
            .map_err(|_| AdapterError::LaunchFailed(format!("{MYEDITOR_BIN_ENV} unset")))?;
        let mut cmd = Command::new(bin);
        cmd.args(tool_args);
        cmd.env("AA_AGENT_ID", agent_id);
        if let Some(team) = team_id {
            cmd.env("AA_TEAM_ID", team);
        }
        if let Some(proxy) = proxy_addr {
            cmd.env("HTTPS_PROXY", proxy);
        }
        Ok(cmd)
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        let raw = std::fs::read_to_string(&self.mcp_config_path)?;
        let parsed: MyEditorMcpConfig =
            serde_json::from_str(&raw).map_err(|e| AdapterError::McpConfigFailed(format!("parse failed: {e}")))?;
        Ok(parsed
            .mcp_servers
            .into_iter()
            .map(|(name, entry)| McpServerInfo {
                name,
                command: entry.command,
                args: entry.args,
            })
            .collect())
    }

    async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
        // Real adapter rewrites MyEditor's MCP config to drop denied
        // servers and trim non-allowed entries. Sample is a no-op so
        // adapter authors see the call site without test fixtures
        // making assertions about a side effect that varies by tool.
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        // IDE-host adapters cap at L1 (Observe) per Epic 14's
        // capability matrix — the IDE sandbox prevents MyEditor from
        // surfacing the hooks needed for L2 (Enforce) without
        // launcher-side process control.
        GovernanceLevel::L1Observe
    }
}
