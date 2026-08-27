//! Foundational types for the AI dev tool governance framework.
//!
//! These types are referenced by the `DevToolAdapter` trait and by every
//! per-tool adapter (Claude Code, Codex, GitHub Copilot, Windsurf Cascade).
//! They are intentionally light and free of runtime dependencies so that
//! adapters can be implemented in `no_std` contexts where applicable.

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Governance level applied to a managed AI dev tool or agent.
///
/// Variants are ordered such that
/// `L0Discover < L1Observe < L2Enforce < L3Native`. The derived `Ord`
/// implementation enables policies to express "at-least-this-level" rules,
/// for example `governance_level >= L2Enforce`.
///
/// | Level | Capability |
/// | --- | --- |
/// | [`L0Discover`][Self::L0Discover] | eBPF / proxy detects unknown agents and their external behavior. |
/// | [`L1Observe`][Self::L1Observe] | Network, file, process, and MCP observability without enforcement. |
/// | [`L2Enforce`][Self::L2Enforce] | Allow / deny, approval, redaction, and budget enforcement. |
/// | [`L3Native`][Self::L3Native] | Full SDK-integrated governance with identity, lineage, and semantic context. |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GovernanceLevel {
    /// L0 — Discover. eBPF / proxy detects unknown agents and their
    /// external behavior; no policy enforcement is applied.
    ///
    /// This is also the [`Default`] for [`GovernanceLevel`]: any agent or
    /// rule that does not declare a level is treated as L0 (discover-only).
    #[default]
    L0Discover,
    /// L1 — Observe. Network, file, process, and MCP observability
    /// without enforcement.
    L1Observe,
    /// L2 — Enforce. Allow / deny, approval, redaction, and budget
    /// enforcement applied to the governed tool.
    L2Enforce,
    /// L3 — Native. Full SDK-integrated governance with identity,
    /// lineage, and semantic context awareness.
    L3Native,
}

impl core::fmt::Display for GovernanceLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GovernanceLevel::L0Discover => write!(f, "L0Discover"),
            GovernanceLevel::L1Observe => write!(f, "L1Observe"),
            GovernanceLevel::L2Enforce => write!(f, "L2Enforce"),
            GovernanceLevel::L3Native => write!(f, "L3Native"),
        }
    }
}

impl core::str::FromStr for GovernanceLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "L0" | "L0Discover" => Ok(GovernanceLevel::L0Discover),
            "L1" | "L1Observe" => Ok(GovernanceLevel::L1Observe),
            "L2" | "L2Enforce" => Ok(GovernanceLevel::L2Enforce),
            "L3" | "L3Native" => Ok(GovernanceLevel::L3Native),
            _ => Err("unknown governance level; expected L0, L1, L2, or L3"),
        }
    }
}

/// Concrete kind of AI dev tool being governed.
///
/// Concrete variants are matched against built-in `DevToolAdapter`
/// implementations. The [`Custom`][Self::Custom] variant lets out-of-tree
/// adapters identify themselves by name without requiring a code change
/// to this enum.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DevToolKind {
    /// Anthropic Claude Code (CLI).
    ClaudeCode,
    /// OpenAI Codex CLI.
    Codex,
    /// GitHub Copilot operating in agent mode.
    GitHubCopilot,
    /// Codeium Windsurf Cascade IDE agent.
    WindsurfCascade,
    /// Adapter-defined custom tool identified by an opaque name string.
    Custom(String),
}

/// Lightweight description of an MCP server an adapter is aware of.
///
/// Returned by [`DevToolAdapter::list_mcp_servers`] and consumed by
/// [`DevToolAdapter::apply_mcp_governance`]. This is a minimal placeholder;
/// when `aa-core` grows a richer MCP type (e.g. transport-aware
/// description), this struct will be replaced or wrapped without any
/// trait-method signature change.
///
/// [`DevToolAdapter::list_mcp_servers`]: <not yet defined; introduced in this same Subtask>
/// [`DevToolAdapter::apply_mcp_governance`]: <not yet defined; introduced in this same Subtask>
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct McpServerInfo {
    /// Stable identifier the tool uses for this MCP server (matches the
    /// key under which the server appears in the tool's native
    /// configuration file).
    pub name: String,
    /// Executable invoked to start the MCP server process.
    pub command: String,
    /// Arguments passed to `command` when the MCP server is started.
    pub args: Vec<String>,
}

/// Error type returned from [`DevToolAdapter`] method failures.
///
/// Variants are kept narrow so the gateway and the `aa run` launcher can
/// match on them and respond differently (e.g. `ToolNotFound` is
/// surfaced as a friendly CLI error, while `Io` is logged and
/// retried). The `#[from]` attribute on `Io` lets adapter implementations
/// use the `?` operator with `std::io::Error` without manual
/// `.map_err(...)` plumbing.
///
/// Gated on `feature = "std"` because [`AdapterError::SettingsApplyFailed`]
/// and [`AdapterError::Io`] wrap [`std::io::Error`].
///
/// `#[non_exhaustive]` is kept so future variants can be added without
/// breaking downstream callers that match on this enum.
#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdapterError {
    /// The tool's binary or installation marker could not be located on
    /// the host.
    #[error("dev tool not found on this host")]
    ToolNotFound,

    /// Detection failed for a reason other than the tool simply not being
    /// installed (e.g. permission denied reading the install directory,
    /// version probe failed).
    #[error("dev tool detection failed: {0}")]
    DetectionFailed(String),

    /// The policy contained constructs the tool's native managed-settings
    /// format cannot express. Returned by
    /// [`DevToolAdapter::generate_managed_settings`].
    #[error("managed-settings generation failed: {0}")]
    SettingsGenerationFailed(String),

    /// Writing rendered managed settings to the tool's configuration
    /// surface failed. Returned by [`DevToolAdapter::apply_settings`].
    #[error("managed-settings apply failed: {0}")]
    SettingsApplyFailed(std::io::Error),

    /// The tool's binary could not be located, or its argument format
    /// cannot accommodate the launcher's governance wiring. Returned by
    /// [`DevToolAdapter::build_launch_command`].
    #[error("launch command construction failed: {0}")]
    LaunchFailed(String),

    /// The tool's MCP configuration surface could not be read or written
    /// (malformed file, permission denied, schema mismatch). Returned
    /// by [`DevToolAdapter::list_mcp_servers`] and
    /// [`DevToolAdapter::apply_mcp_governance`].
    #[error("MCP configuration failed: {0}")]
    McpConfigFailed(String),

    /// Generic I/O failure not covered by a more specific variant. The
    /// `#[from]` attribute lets adapter implementations use `?` to
    /// propagate `std::io::Error` directly.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization or deserialization failure during managed-settings
    /// or MCP-config rendering. Adapter implementations stringify their
    /// underlying serde error (e.g. `serde_json::Error::to_string()`)
    /// and pass the message in. Keeps `aa-core` free of a runtime
    /// `serde_json` dependency.
    #[error("serialization error: {0}")]
    Serde(String),
}

/// Static metadata describing a detected AI dev tool installation.
///
/// Returned by `DevToolAdapter::detect` and used to drive registry
/// decisions, managed-settings generation, and per-tool launch wiring.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DevToolInfo {
    /// Concrete tool variant.
    pub kind: DevToolKind,
    /// Tool version string, if reported by the binary.
    pub version: Option<String>,
    /// Absolute path to the installed tool binary.
    pub install_path: PathBuf,
    /// Highest governance level this installation can operate at.
    pub governance_level: GovernanceLevel,
    /// Whether the tool exposes MCP server configuration we can govern.
    pub supports_mcp: bool,
    /// Whether the tool reads governance config from a managed-settings file.
    pub supports_managed_settings: bool,
}

/// Per-tool integration contract for the dev tool governance framework.
///
/// Every per-tool adapter (Claude Code, Codex, GitHub Copilot, Windsurf
/// Cascade, third-party SaaS coding agents) implements this trait. The
/// gateway and the `aa run` launcher consume adapters via `dyn
/// DevToolAdapter`, so the trait must be object-safe — that property is
/// locked in by an explicit compile-time check added in AAASM-925.
///
/// Implementations live in their own crates / Stories and are out of
/// scope for this Subtask (see AAASM-201 through AAASM-205, AAASM-918).
///
/// ## Async dispatch
///
/// The `async fn` methods are macro-desugared by `async_trait::async_trait`
/// into boxed-future return types so that `dyn DevToolAdapter` is
/// dyn-safe on stable Rust. The boxing cost is negligible compared to
/// the I/O these methods perform (filesystem reads, subprocess writes,
/// MCP discovery).
#[cfg(feature = "std")]
#[async_trait::async_trait]
pub trait DevToolAdapter: Send + Sync {
    /// Detect whether the tool this adapter targets is installed on the
    /// current host.
    ///
    /// ### Contract
    /// * Returns `Some(DevToolInfo)` when the tool's binary or
    ///   well-known installation marker is present and readable.
    /// * Returns `None` when the tool is not installed, is unreadable,
    ///   or cannot be confirmed (e.g. the user lacks filesystem
    ///   permission).
    /// * Must not perform network I/O — detection runs at every CLI
    ///   invocation and is on the hot path.
    fn detect(&self) -> Option<DevToolInfo>;

    /// Translate an Agent Assembly [`PolicyDocument`] into the tool's
    /// native managed-settings format (e.g. JSON for Claude Code,
    /// `.codex/config.toml` for Codex).
    ///
    /// ### Contract
    /// * On success, returns the rendered settings document as a UTF-8
    ///   string ready to be written by [`apply_settings`].
    /// * Returns [`AdapterError::SettingsGenerationFailed`] when the
    ///   policy contains constructs the tool's native config cannot
    ///   express.
    /// * Pure: must not touch the filesystem.
    ///
    /// [`PolicyDocument`]: crate::policy::PolicyDocument
    /// [`apply_settings`]: Self::apply_settings
    async fn generate_managed_settings(&self, policy: &crate::policy::PolicyDocument) -> Result<String, AdapterError>;

    /// Write the rendered managed settings into the tool's
    /// configuration surface, replacing any prior managed block.
    ///
    /// ### Contract
    /// * On success, the tool will pick up the new policy on its next
    ///   launch (some tools require a restart; the adapter is expected
    ///   to document that in its own crate-level docs).
    /// * Returns [`AdapterError::SettingsApplyFailed`] on filesystem error.
    /// * Idempotent: applying the same `settings` twice is a no-op.
    async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError>;

    /// Build the [`std::process::Command`] used by the `aa run` launcher
    /// to start the tool with governance wiring (proxy, env vars,
    /// agent identity, optional team identity).
    ///
    /// ### Contract
    /// * Caller passes raw `tool_args` plus the agent and (optional)
    ///   team identity that the gateway issued for this run.
    /// * `proxy_addr`, when set, is the `host:port` of the local MitM
    ///   proxy; the adapter must inject the appropriate
    ///   `HTTPS_PROXY` / `OPENAI_BASE_URL` / similar env var so the
    ///   tool routes traffic through it.
    /// * Returns [`AdapterError::LaunchFailed`] when the tool's binary
    ///   cannot be located or its argument format cannot accommodate
    ///   the wiring.
    /// * Sync (no I/O performed) — the returned `Command` is *built*,
    ///   not spawned. Spawning is the launcher's job.
    ///
    /// ### The environment on the returned command is part of the contract
    ///
    /// The launcher **must** apply [`Command::get_envs`] to the child it
    /// spawns. The environment is not advisory decoration on top of a
    /// program and its arguments: `NODE_EXTRA_CA_CERTS` is the only
    /// mechanism by which an Electron/Node tool's runtime trusts the
    /// intercepting proxy's CA, so a launcher that rebuilds the child from
    /// [`Command::get_program`] and [`Command::get_args`] alone starts a
    /// tool the proxy cannot terminate TLS for and reports it as governed.
    /// That is AAASM-5327, and it violated nothing that had been written
    /// down — which is why it is written down here.
    ///
    /// A `None` value from [`Command::get_envs`] means **remove that
    /// variable from the child**, never "set it to the empty string": an
    /// adapter unsets a variable to switch a tool behaviour off, and an
    /// empty-but-present variable is one the tool may still honour.
    ///
    /// The child's environment is the union of the launcher's own
    /// environment and this one, and on a collision **the adapter's value
    /// wins** — it is the layer that knows the tool's requirements and the
    /// layer that normalises values (the gateway's bare `host:port` proxy
    /// address is not a proxy URL an HTTP client accepts). An adapter may
    /// rely on that, but must not assume it is the sole source of the
    /// child's variables.
    ///
    /// The same obligation is stated at length on the lifecycle successor,
    /// [`LaunchableTool::build_launch_command`](crate::integration::LaunchableTool::build_launch_command).
    ///
    /// [`Command::get_envs`]: std::process::Command::get_envs
    /// [`Command::get_program`]: std::process::Command::get_program
    /// [`Command::get_args`]: std::process::Command::get_args
    fn build_launch_command(
        &self,
        tool_args: &[String],
        agent_id: &str,
        team_id: Option<&str>,
        proxy_addr: Option<&str>,
    ) -> Result<std::process::Command, AdapterError>;

    /// Enumerate the MCP servers the tool is currently configured to
    /// connect to.
    ///
    /// ### Contract
    /// * Returns the parsed list from the tool's native MCP config
    ///   surface (e.g. `~/.claude/mcp_servers.json`).
    /// * Returns an empty `Vec` (not an error) when the tool supports
    ///   MCP but has no servers configured.
    /// * Returns [`AdapterError::McpConfigFailed`] when the config
    ///   exists but is malformed.
    /// * Tools whose `DevToolInfo::supports_mcp == false` should
    ///   instead return an empty `Vec`.
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError>;

    /// Apply an MCP allow / deny list to the tool's configuration.
    ///
    /// ### Contract
    /// * `allowed` lists MCP server names that are permitted; any
    ///   server not in `allowed` and present in `denied` (or in the
    ///   currently-configured set) must be removed from the tool's
    ///   active config.
    /// * `denied` is an explicit blocklist applied even if a server
    ///   appears in `allowed` — `denied` wins on conflict (matches
    ///   policy-engine evaluation order).
    /// * Returns [`AdapterError::McpConfigFailed`] on filesystem write
    ///   failure.
    /// * Tools without MCP support should return `Ok(())` without
    ///   performing any work.
    async fn apply_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<(), AdapterError>;

    /// Highest governance level this adapter can achieve for the tool
    /// it targets.
    ///
    /// ### Contract
    /// * Returns the static, build-time-known cap for this adapter
    ///   (e.g. an SDK-integrated adapter returns `L3Native`; a SaaS
    ///   coding agent's observability-only adapter returns
    ///   `L1Observe`).
    /// * Must agree with `detect()`'s `DevToolInfo::governance_level`
    ///   for any successful detection — gateway uses this to
    ///   short-circuit policy decisions when an action would require
    ///   a level the adapter cannot enforce.
    fn governance_level(&self) -> GovernanceLevel;

    /// Environment variable name this adapter's [`build_launch_command`] will
    /// set, on this host, to give the launched tool its own process-scoped
    /// trust in the proxy's MitM CA — or `None` if this launch has no such
    /// mechanism (AAASM-5978).
    ///
    /// ### Contract
    /// * Return `Some(var)` only if `build_launch_command` will, **for this
    ///   specific launch**, actually set `var` to a value the tool's runtime
    ///   consults for CA trust (e.g. `NODE_EXTRA_CA_CERTS` for a Node-based
    ///   tool that has the trust material installed). This is install state,
    ///   not a static per-adapter property — an adapter whose managed
    ///   integration hasn't been installed on this host must return `None`
    ///   even if it supports the mechanism in general.
    /// * The default `None` is correct for any adapter that hasn't verified
    ///   this against its tool's real runtime: a wrong `Some` here means the
    ///   caller skips the macOS System Keychain CA install believing the tool
    ///   trusts the CA some other way, when it does not.
    /// * Must not perform I/O beyond what `build_launch_command` already
    ///   does — this is consulted on the same hot launch path.
    ///
    /// [`build_launch_command`]: Self::build_launch_command
    fn process_scoped_ca_trust_var(&self) -> Option<&'static str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_level_orders_l0_through_l3() {
        assert!(GovernanceLevel::L0Discover < GovernanceLevel::L1Observe);
        assert!(GovernanceLevel::L1Observe < GovernanceLevel::L2Enforce);
        assert!(GovernanceLevel::L2Enforce < GovernanceLevel::L3Native);
        assert!(GovernanceLevel::L0Discover < GovernanceLevel::L3Native);
    }

    #[cfg(all(feature = "serde", feature = "alloc"))]
    #[test]
    fn dev_tool_kind_round_trips_via_serde_json() {
        let cases = [
            DevToolKind::ClaudeCode,
            DevToolKind::Codex,
            DevToolKind::GitHubCopilot,
            DevToolKind::WindsurfCascade,
            DevToolKind::Custom(String::from("MyEditor")),
        ];
        for original in cases {
            let json = serde_json::to_string(&original).expect("serialize");
            let restored: DevToolKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, original);
        }
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn dev_tool_info_round_trips_via_serde_json() {
        let original = DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version: Some(String::from("1.2.3")),
            install_path: PathBuf::from("/usr/local/bin/claude"),
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: true,
            supports_managed_settings: false,
        };
        let json1 = serde_json::to_string(&original).expect("serialize");
        let restored: DevToolInfo = serde_json::from_str(&json1).expect("deserialize");
        let json2 = serde_json::to_string(&restored).expect("re-serialize");
        assert_eq!(json1, json2);
    }

    // ---- Trait conformance (locks DevToolAdapter's shape) -----------------
    //
    // These helpers are compile-time checks. The fact that they reference
    // `&dyn DevToolAdapter` and `Box<dyn DevToolAdapter>` (which require
    // `Send + Sync` because the trait inherits those bounds) is what
    // exercises the assertions — if any future change makes the trait
    // un-object-safe or drops `Send + Sync`, this module fails to compile.

    #[cfg(feature = "std")]
    fn _assert_object_safe(_: &dyn DevToolAdapter) {}

    #[cfg(feature = "std")]
    fn _assert_send_sync<T: Send + Sync>() {}

    /// Compile-time conformance check for `DevToolAdapter`.
    ///
    /// Locks two invariants every implementor must satisfy:
    /// 1. The trait is **object-safe** — `&dyn DevToolAdapter` and
    ///    `Box<dyn DevToolAdapter>` both compile.
    /// 2. Trait objects are `Send + Sync` — required so adapters can be
    ///    stored in a global registry and called from the gateway's
    ///    Tokio task pool.
    ///
    /// If either invariant breaks (someone adds a non-dyn-compatible
    /// method, removes the `Send + Sync` bound on the trait, etc.) this
    /// test will fail to compile — which is exactly what AAASM-925
    /// requires it to do.
    #[cfg(feature = "std")]
    #[test]
    fn trait_is_object_safe() {
        let _: fn(&dyn DevToolAdapter) = _assert_object_safe;
        _assert_send_sync::<Box<dyn DevToolAdapter>>();
    }
}
