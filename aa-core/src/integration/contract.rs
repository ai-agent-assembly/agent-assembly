//! The lifecycle trait every integration implements, and the optional mechanism
//! sub-traits it opts into.
//!
//! # Why the split, and where the line is
//!
//! The old [`DevToolAdapter`](crate::DevToolAdapter) makes every mechanism
//! mandatory, so `aa-devtool-codex` implements `apply_mcp_governance` as `Ok(())`
//! with the comment *"Codex does not expose MCP governance"* — a tool that
//! cannot do a thing is forced to claim it can and then lie quietly. Composition
//! removes the lie: [`DevToolIntegration`] carries only what **every** tool can
//! answer, and each mechanism lives behind an accessor whose default body
//! returns `None`. Codex simply does not declare
//! [`McpGovernance`](IntegrationCapability::McpGovernance) and inherits
//! `as_mcp_governed() -> None`; Copilot does not implement
//! [`LaunchableTool`] and says why in its capability declaration instead of
//! failing at run time.
//!
//! # Why there is no `apply_integration`
//!
//! The adapter *authors* a plan; the service *executes* it (ADR 0030 matrix rows
//! 2 and 3). Putting apply on the adapter trait would re-create the
//! shared-ownership problem the matrix exists to prevent, and would put rollback
//! correctness and crash recovery in N places instead of one.
//!
//! # Declared must match implemented
//!
//! Declaring a capability `Supported` while its accessor returns `None` is a
//! contract violation, not a style issue: everything downstream reads the
//! declaration. [`capability_conformance`] is the check, and it is meant to be
//! called from every adapter's own test suite.

use std::collections::BTreeMap;

use crate::dev_tool::{AdapterError, DevToolInfo, McpServerInfo};

use super::capability::{DevToolCapabilities, IntegrationCapability};
use super::plan::{IntegrationPlan, IntegrationRequest, RemovalPlan};
use super::receipt::IntegrationReceipt;
use super::status::{IntegrationStatus, VerificationResult};
use super::step::IntegrationStep;
use super::version::VersionSupport;

/// Everything a launch needs, gathered so [`LaunchableTool`] takes one argument
/// rather than five positional ones.
///
/// `env` exists because a proxy address alone is not enough to make an
/// Electron/Node tool trust the intercepting proxy — `NODE_EXTRA_CA_CERTS` has
/// to point at the CA an earlier plan step materialised. A launch surface with
/// no way to carry that variable cannot express the highest-value fix the
/// AAASM-5276 spike identified.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct LaunchSpec {
    /// Arguments to pass through to the tool untouched.
    pub tool_args: Vec<String>,
    /// The agent identity the gateway issued for this run.
    pub agent_id: String,
    /// The team identity, when the run has one.
    pub team_id: Option<String>,
    /// `host:port` of the local intercepting proxy, when one is running.
    pub proxy_addr: Option<String>,
    /// Extra environment variables to inject, name to value.
    pub env: BTreeMap<String, String>,
}

/// Hand-written because [`LaunchSpec::env`] may hold credential values — the
/// crate documentation above states exactly why the field exists
/// (`NODE_EXTRA_CA_CERTS`, and any other variable a launch step decided the
/// tool needs). AAASM-5942: no `Debug` print of a `LaunchSpec` exists in this
/// workspace today, but a type whose only sensitive field a derived `Debug`
/// would expose is fixed pre-emptively, matching every other backend struct
/// carrying a child environment, rather than left correct only by the
/// accident of no caller having printed it yet.
impl core::fmt::Debug for LaunchSpec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LaunchSpec")
            .field("tool_args", &self.tool_args)
            .field("agent_id", &self.agent_id)
            .field("team_id", &self.team_id)
            .field("proxy_addr", &self.proxy_addr)
            .field("env", &format!("<{} var(s)>", self.env.len()))
            .finish()
    }
}

impl LaunchSpec {
    /// A spec for `agent_id` with no arguments, no proxy and no extra
    /// environment.
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            ..Self::default()
        }
    }

    /// Pass arguments through to the tool.
    #[must_use]
    pub fn with_args(mut self, tool_args: Vec<String>) -> Self {
        self.tool_args = tool_args;
        self
    }

    /// Route the tool through a local proxy.
    #[must_use]
    pub fn through_proxy(mut self, proxy_addr: impl Into<String>) -> Self {
        self.proxy_addr = Some(proxy_addr.into());
        self
    }

    /// Inject an environment variable into the launch.
    #[must_use]
    pub fn with_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(name.into(), value.into());
        self
    }
}

/// The lifecycle contract every dev-tool integration implements.
///
/// Object-safe and `Send + Sync`, so integrations can live in a registry and be
/// called from the runtime's task pool.
#[async_trait::async_trait]
pub trait DevToolIntegration: Send + Sync {
    /// What integration mechanisms this adapter exposes for its tool.
    ///
    /// A static declaration except for
    /// [`RequiresVersion`](super::CapabilitySupport::RequiresVersion), whose
    /// `detected` field the adapter fills from its own detection. Anything not
    /// named here is **absent**, which is never read as supported.
    fn capabilities(&self) -> DevToolCapabilities;

    /// Detect whether the tool is installed on this host.
    ///
    /// Same contract as [`DevToolAdapter::detect`](crate::DevToolAdapter::detect):
    /// `None` when the tool is absent, unreadable or unconfirmable, and no
    /// network I/O.
    fn detect(&self) -> Option<DevToolInfo>;

    /// Which tool versions this adapter understands, plus its own version and
    /// the lifecycle schema it was compiled against.
    ///
    /// Owned by the adapter because only it knows what a version *means* for its
    /// tool (ADR 0030 matrix row 1).
    fn version_support(&self) -> VersionSupport;

    /// Author the steps needed to take this tool to the requested level.
    ///
    /// ### Contract
    /// * Pure with respect to the host: planning describes mutations, it does
    ///   not perform them. Reading the host to *decide* the steps is expected;
    ///   writing to it is not.
    /// * The returned plan must satisfy
    ///   [`IntegrationPlan::validate`] — in particular every settings-touching
    ///   step must name the scope the request asked for.
    /// * Mechanisms the tool cannot use are reported in
    ///   [`IntegrationPlan::unsupported`] with the reason from
    ///   [`capabilities`](Self::capabilities), rather than failing.
    /// * The plan's level may be **below** the requested one; it may never be
    ///   silently above it.
    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError>;

    /// Report what is currently true for this tool, with the evidence.
    ///
    /// ### Contract
    /// * Derived on every call. Never cached — protection that has stopped
    ///   holding must stop being reported.
    /// * `receipt` is `None` when nothing has been applied; the answer is then
    ///   at most
    ///   [`DetectedNotIntegrated`](super::ProtectionLevel::DetectedNotIntegrated),
    ///   however complete the tool's configuration happens to look.
    /// * Missing evidence lowers the reported state; it never raises it.
    async fn integration_status(&self, receipt: Option<&IntegrationReceipt>)
        -> Result<IntegrationStatus, AdapterError>;

    /// Check that what the receipt claims is still true.
    ///
    /// ### Contract
    /// * Every observation is returned as
    ///   [`ProtectionEvidence`](super::ProtectionEvidence) tagged with how it was
    ///   obtained, so read-back and exercised evidence stay distinguishable.
    /// * An adapter with no verification mechanism returns
    ///   [`VerificationOutcome::Unverifiable`](super::VerificationOutcome::Unverifiable)
    ///   — not [`Passed`](super::VerificationOutcome::Passed), and not an error.
    async fn verify_integration(&self, receipt: &IntegrationReceipt) -> Result<VerificationResult, AdapterError>;

    /// Author the steps that undo what the receipt records.
    ///
    /// ### Contract
    /// * Derived from the receipt, not re-derived from the current host state:
    ///   removal must undo what was done, not what would be done now.
    /// * Anything that cannot be undone automatically is declared in
    ///   [`RemovalPlan::residual`] rather than silently left behind.
    async fn plan_removal(&self, receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError>;

    /// The MCP surface, when this tool has one.
    ///
    /// `None` is the honest answer for a tool without MCP, and it is the default
    /// — MCP is one optional capability among twelve, never the architecture.
    fn as_mcp_governed(&self) -> Option<&dyn McpGovernedTool> {
        None
    }

    /// The launch surface, when this tool has one.
    ///
    /// `None` for IDE-hosted tools, which have no launch command at all. Their
    /// capability declaration carries the sentence explaining why, at plan time,
    /// where the user can still choose a different mechanism.
    fn as_launchable(&self) -> Option<&dyn LaunchableTool> {
        None
    }

    /// The hook surface, when this tool has one.
    fn as_hookable(&self) -> Option<&dyn HookableTool> {
        None
    }
}

/// Optional surface for tools that expose their MCP configuration.
#[async_trait::async_trait]
pub trait McpGovernedTool: Send + Sync {
    /// Enumerate the MCP servers the tool is currently configured to use.
    ///
    /// Returns an empty `Vec` — not an error — when the tool supports MCP but
    /// has none configured.
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError>;

    /// Author the step that applies an MCP allow/deny list.
    ///
    /// Authoring, not applying: `denied` wins on conflict, matching the policy
    /// engine's evaluation order.
    fn plan_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<IntegrationStep, AdapterError>;
}

/// Optional surface for tools that can be started through a governed launcher.
pub trait LaunchableTool: Send + Sync {
    /// Build the command that starts the tool with governance wiring.
    ///
    /// The returned command is *built*, not spawned. Returns
    /// [`AdapterError::LaunchFailed`] only for genuine run-time failures (the
    /// binary has moved, an argument cannot be encoded) — "this tool has no
    /// launch command" is a capability declaration, not an error.
    ///
    /// # The environment on the returned command is part of the contract
    ///
    /// A caller **must** apply [`Command::get_envs`] to the child it spawns.
    /// What comes back is not "a program and some arguments, plus some advisory
    /// variables": for an Electron/Node tool `NODE_EXTRA_CA_CERTS` is the *only*
    /// mechanism by which the tool's runtime trusts the intercepting proxy's CA,
    /// so a caller that drops the environment launches a tool the proxy cannot
    /// terminate TLS for — and reports it as governed. AAASM-5327 was exactly
    /// that: a caller that rebuilt the child from [`Command::get_program`] and
    /// [`Command::get_args`] alone, violating no contract on paper because none
    /// was written down. The obligation is stated here so the next occurrence is
    /// a contract violation rather than an oversight.
    ///
    /// A `None` value from [`Command::get_envs`] means **remove that variable
    /// from the child**, never "set it to the empty string". The two are not
    /// interchangeable, and flattening them is itself a security bug: an adapter
    /// unsets a variable to switch a tool behaviour *off*, and an
    /// empty-but-present variable is one the tool may still read and honour.
    ///
    /// # When the adapter's variables collide with the caller's
    ///
    /// The child's environment is the union of both sources, and on a collision
    /// **the adapter's value wins** (the behaviour AAASM-5327 established). The
    /// adapter is the layer that knows what the tool actually requires, and the
    /// layer that normalises values — the gateway hands out a bare `host:port`
    /// proxy address, which is not a proxy URL an HTTP client accepts, and only
    /// the adapter knows which form its own tool needs. An implementer may
    /// therefore rely on its values surviving the merge and need not defend
    /// against a caller overwriting them. It may **not** assume it is the sole
    /// source of the child's environment: the caller's variables are delivered
    /// too, and a variable the adapter never mentions is passed through.
    ///
    /// That rule is about the caller's *ambient* environment at spawn time, and
    /// it is the opposite of the rule for [`LaunchSpec::env`], where the caller
    /// **wins**. The two are not in tension: `LaunchSpec::env` is an argument to
    /// this method rather than a competing source, and it is how a caller asks
    /// for one run to differ — pinning a CA for a test, or overriding a variable
    /// without editing what the install recorded. An adapter should therefore
    /// apply `spec.env` last, after its own values.
    ///
    /// [`Command::get_envs`]: std::process::Command::get_envs
    /// [`Command::get_program`]: std::process::Command::get_program
    /// [`Command::get_args`]: std::process::Command::get_args
    fn build_launch_command(&self, spec: &LaunchSpec) -> Result<std::process::Command, AdapterError>;
}

/// Optional surface for tools that expose installable hooks.
pub trait HookableTool: Send + Sync {
    /// Author the steps that install this integration's hooks.
    fn plan_hooks(&self, request: &IntegrationRequest) -> Result<Vec<IntegrationStep>, AdapterError>;
}

/// A mismatch between what an adapter declares and what it implements.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConformanceViolation {
    /// A capability resolves to effective but the surface that implements it is
    /// not there.
    #[error("{capability:?} is declared as supported but {accessor}() returns None")]
    DeclaredWithoutSurface {
        /// The over-claimed capability.
        capability: IntegrationCapability,
        /// The accessor that should have returned `Some`.
        accessor: &'static str,
    },
    /// A surface is implemented but nothing declares it, so no caller will ever
    /// find it. Under-declaring is not a security problem, but it is still a
    /// bug: an unadvertised mechanism is an unused one.
    #[error("{accessor}() returns Some but no corresponding capability is declared")]
    SurfaceWithoutDeclaration {
        /// The accessor that returned `Some`.
        accessor: &'static str,
    },
}

/// Check that every declared capability has the surface that implements it, and
/// vice versa.
///
/// Intended to be called from each adapter's own test suite, which is why it
/// takes `&dyn` and returns every violation rather than short-circuiting on the
/// first.
pub fn capability_conformance(integration: &dyn DevToolIntegration) -> Vec<ConformanceViolation> {
    let caps = integration.capabilities();
    let mut violations = Vec::new();

    let mcp_declared = IntegrationCapability::ALL
        .iter()
        .filter(|cap| cap.is_mcp())
        .any(|cap| caps.is_effective(*cap));
    match (mcp_declared, integration.as_mcp_governed().is_some()) {
        (true, false) => violations.push(ConformanceViolation::DeclaredWithoutSurface {
            capability: IntegrationCapability::McpGovernance,
            accessor: "as_mcp_governed",
        }),
        (false, true) => violations.push(ConformanceViolation::SurfaceWithoutDeclaration {
            accessor: "as_mcp_governed",
        }),
        _ => {}
    }

    let launch_declared = caps.is_effective(IntegrationCapability::ManagedLaunch);
    match (launch_declared, integration.as_launchable().is_some()) {
        (true, false) => violations.push(ConformanceViolation::DeclaredWithoutSurface {
            capability: IntegrationCapability::ManagedLaunch,
            accessor: "as_launchable",
        }),
        (false, true) => violations.push(ConformanceViolation::SurfaceWithoutDeclaration {
            accessor: "as_launchable",
        }),
        _ => {}
    }

    let hooks_declared = caps.is_effective(IntegrationCapability::Hooks);
    match (hooks_declared, integration.as_hookable().is_some()) {
        (true, false) => violations.push(ConformanceViolation::DeclaredWithoutSurface {
            capability: IntegrationCapability::Hooks,
            accessor: "as_hookable",
        }),
        (false, true) => violations.push(ConformanceViolation::SurfaceWithoutDeclaration {
            accessor: "as_hookable",
        }),
        _ => {}
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_tool::DevToolKind;
    use crate::integration::plan::{ProtectionProfile, RemovalPlan};
    use crate::integration::state::ProtectionLevel;
    use crate::integration::step::SettingsScope;
    use crate::integration::version::{SupportedToolVersions, ToolVersion, LIFECYCLE_SCHEMA_VERSION};
    use crate::integration::{LifecyclePhase, ProtectionState, VerificationResult, VersionCompatibility};
    use crate::GovernanceLevel;

    /// **AAASM-5942, falsifiability-critical.** `{:?}` on a `LaunchSpec`
    /// carrying a resolved `env` must not recover the sentinel value —
    /// absence, not a mask token, per this ticket's own warning that a test
    /// grepping for a mask string "passes against the vulnerable code and
    /// proves nothing".
    ///
    /// The negative control is documented rather than left committed: with
    /// `#[derive(Debug)]` restored on `LaunchSpec` in place of its
    /// hand-written impl, this exact assertion reddened with the sentinel
    /// visible in the formatted output, confirming the test can fail. See
    /// this ticket's implementation report for the before/after transcript.
    #[test]
    fn debug_formatting_of_a_launch_spec_env_never_recovers_its_value() {
        const SENTINEL: &str = "aaasm-5942-sentinel-not-a-real-secret-9f3c9e2b";
        let spec = LaunchSpec::new("agent-under-test").with_env("AASM_TEST_CREDENTIAL", SENTINEL);
        let rendered = format!("{spec:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "Debug output recovered the sentinel value: {rendered}"
        );
    }

    /// Minimal integration whose capability declaration the tests vary.
    struct Stub {
        caps: DevToolCapabilities,
        mcp: bool,
    }

    #[async_trait::async_trait]
    impl DevToolIntegration for Stub {
        fn capabilities(&self) -> DevToolCapabilities {
            self.caps.clone()
        }

        fn detect(&self) -> Option<DevToolInfo> {
            None
        }

        fn version_support(&self) -> VersionSupport {
            VersionSupport {
                adapter_version: ToolVersion::new(0, 1, 0),
                lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION,
                supported_tool_versions: SupportedToolVersions::at_least(ToolVersion::new(1, 0, 0)),
            }
        }

        async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
            Ok(IntegrationPlan::new(
                "plan",
                request,
                ProtectionLevel::DetectedNotIntegrated,
                GovernanceLevel::L0Discover,
            ))
        }

        async fn integration_status(
            &self,
            _receipt: Option<&IntegrationReceipt>,
        ) -> Result<IntegrationStatus, AdapterError> {
            Ok(IntegrationStatus {
                tool: DevToolKind::Custom("stub".to_string()),
                phase: LifecyclePhase::NotInstalled,
                state: ProtectionState::Ladder(ProtectionLevel::NotInstalled),
                evidence: Vec::new(),
                planned_level: ProtectionLevel::NotInstalled,
                adapter_ceiling: GovernanceLevel::L0Discover,
                compatibility: VersionCompatibility::Unknown {
                    reason: "stub".to_string(),
                },
                next_level: None,
                observed_at_unix_secs: 0,
                policy: crate::integration::policy_posture::PolicyPosture::Unknown {
                    reason: "stub adapter".to_string(),
                },
            })
        }

        async fn verify_integration(&self, _receipt: &IntegrationReceipt) -> Result<VerificationResult, AdapterError> {
            Ok(VerificationResult::unverifiable(0, "stub"))
        }

        async fn plan_removal(&self, _receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError> {
            Ok(RemovalPlan::new("removal", DevToolKind::Custom("stub".to_string())))
        }

        fn as_mcp_governed(&self) -> Option<&dyn McpGovernedTool> {
            if self.mcp {
                Some(self)
            } else {
                None
            }
        }
    }

    #[async_trait::async_trait]
    impl McpGovernedTool for Stub {
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            Ok(Vec::new())
        }

        fn plan_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<IntegrationStep, AdapterError> {
            Ok(IntegrationStep::new(
                "mcp",
                crate::integration::step::StepAction::ConfigureMcpServers {
                    allowed: allowed.to_vec(),
                    denied: denied.to_vec(),
                },
                "apply the MCP allow/deny list",
            ))
        }
    }

    fn _assert_object_safe(_: &dyn DevToolIntegration) {}
    fn _assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn the_lifecycle_trait_is_object_safe_and_send_sync() {
        let stub = Stub {
            caps: DevToolCapabilities::new(),
            mcp: false,
        };
        let as_dyn: &dyn DevToolIntegration = &stub;
        _assert_object_safe(as_dyn);
        _assert_send_sync::<Box<dyn DevToolIntegration>>();
    }

    #[test]
    fn a_tool_without_mcp_needs_no_no_op_implementation() {
        // The Codex shape: no MCP declaration, no MCP surface, nothing to stub.
        let codex_like = Stub {
            caps: DevToolCapabilities::new()
                .supported(IntegrationCapability::Discovery)
                .supported(IntegrationCapability::ManagedSettings),
            mcp: false,
        };
        assert!(codex_like.as_mcp_governed().is_none());
        assert!(capability_conformance(&codex_like).is_empty());
    }

    #[test]
    fn declaring_mcp_without_the_surface_is_a_conformance_violation() {
        let liar = Stub {
            caps: DevToolCapabilities::new().supported(IntegrationCapability::McpGovernance),
            mcp: false,
        };
        assert_eq!(
            capability_conformance(&liar),
            vec![ConformanceViolation::DeclaredWithoutSurface {
                capability: IntegrationCapability::McpGovernance,
                accessor: "as_mcp_governed",
            }]
        );
    }

    #[test]
    fn implementing_a_surface_nobody_declared_is_also_reported() {
        let hidden = Stub {
            caps: DevToolCapabilities::new(),
            mcp: true,
        };
        assert_eq!(
            capability_conformance(&hidden),
            vec![ConformanceViolation::SurfaceWithoutDeclaration {
                accessor: "as_mcp_governed",
            }]
        );
    }

    #[test]
    fn an_undeclared_capability_does_not_demand_a_surface() {
        // Absent is not Unsupported and is not Supported — it demands nothing.
        let minimal = Stub {
            caps: DevToolCapabilities::new().unsupported(
                IntegrationCapability::ManagedLaunch,
                "this tool is a VS Code extension and has no launch command",
            ),
            mcp: false,
        };
        assert!(capability_conformance(&minimal).is_empty());
    }

    #[test]
    fn a_launch_spec_can_carry_the_ca_variable_the_spike_needed() {
        let spec = LaunchSpec::new("agent-1")
            .with_args(vec!["--help".to_string()])
            .through_proxy("127.0.0.1:8080")
            .with_env("NODE_EXTRA_CA_CERTS", "/home/dev/.aa/ca/aasm-ca.pem");
        assert_eq!(
            spec.env.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some("/home/dev/.aa/ca/aasm-ca.pem")
        );
        assert_eq!(spec.proxy_addr.as_deref(), Some("127.0.0.1:8080"));

        // A request built for the same tool validates as an empty plan, so the
        // async surface is exercised end to end in the `aa-devtool-contract`
        // integration tests (aa-core has no async test runtime by design).
        let request = IntegrationRequest::new(
            DevToolKind::Custom("stub".to_string()),
            ProtectionProfile::Recommended,
            SettingsScope::User,
        );
        assert_eq!(request.settings_scope, SettingsScope::User);
    }
}
