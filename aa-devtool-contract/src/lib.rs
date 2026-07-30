//! Capability-restricted facade over [`aa-core`] for `aa-devtool-*` plugins.
//!
//! # Why this crate exists (AAASM-3565)
//!
//! `aa-devtool-*` plugins (claude-code, codex, copilot, windsurf, saas, the
//! sample editor) run inside the developer's trusted environment. Each one used
//! to carry a direct `aa-core` path dependency, which meant a *single*
//! under-reviewed plugin PR could reach the **entire** `aa-core` public API —
//! identity, storage, gateway tokens, the LLM/agent/approval subsystems — even
//! though a devtool adapter only ever needs the [`DevToolAdapter`] surface and
//! a handful of policy/audit value types.
//!
//! This crate is the **compile-time analogue of a restricted IPC interface**:
//! it depends on the full `aa-core` internally but re-exports *only* the audited
//! symbol set below. Plugins depend on this crate, never on `aa-core` directly.
//! A smuggled call to an unrelated `aa-core` subsystem (e.g.
//! `aa_core::storage::…` or a gateway token type) is therefore a **compile
//! error** in a plugin crate, not a silent capability.
//!
//! # The contract surface
//!
//! The re-export list below is the trusted boundary. It was audited from
//! `git grep aa_core` across every `aa-devtool*/src` tree. Adding a symbol here
//! widens the surface a plugin can reach and **must** go through a security
//! reviewer (see `.github/CODEOWNERS` and `deny.toml`). Do not re-export whole
//! `aa-core` modules (`policy::`, `identity`, `storage`, `config`, …) — only the
//! flat value types and the adapter trait the plugins consume.
//!
//! The list is in two groups. The first is the original `DevToolAdapter`
//! surface (AAASM-3565). The second is the Developer Integration lifecycle
//! contract (AAASM-5277, ADR 0030 §7.1) — the capability, plan, receipt, status
//! and evidence types plus the lifecycle traits. The second group is additive:
//! `DevToolAdapter` and everything around it is retained unchanged, and
//! [`LegacyAdapterShim`] bridges any adapter that has not migrated.
//!
//! [`aa-core`]: aa_core

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// --- DevToolAdapter capability surface (aa_core::dev_tool) ---------------
pub use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};

// --- Policy value types the adapters read at apply()/settings time -------
pub use aa_core::{EnforcementMode, PolicyDecision, PolicyDocument, PolicyRule};

// --- Capability bridge value types (aa_core::capability) -----------------
pub use aa_core::{Capability, CapabilitySet};

// --- Audit pipeline entry the SaaS overlay emits (aa_core::audit) --------
pub use aa_core::AuditEntry;

// --- Developer Integration lifecycle contract (aa_core::integration) ------
//
// AAASM-5277 / ADR 0030 §7.1. This is the second re-export group, and it is
// the largest widening this crate has taken. Three properties keep it
// reviewable, and a reviewer should check all three on any future addition:
//
//   1. Every symbol below is either a **flat value type** (a struct or enum of
//      owned primitives, paths and other symbols in this list) or one of the
//      five lifecycle traits. No `aa_core` module is re-exported.
//   2. Nothing here transitively reaches `aa_core::storage`, `identity`,
//      `config`, the gateway credential types or the LLM/approval subsystems —
//      the prohibition in the module docs above is unchanged and still binding.
//   3. No lifecycle type has a field that can hold a `PolicyDocument`, a raw
//      payload or a credential. A policy is named by `PolicyProfileRef`
//      (id + display name + digest) — enough to display and compare, never
//      enough to read (ADR 0030 §5.5).
//
// `PolicyDocument` itself remains reachable only through the pre-existing
// policy group above, which the legacy `DevToolAdapter` surface requires.

// The lifecycle trait plus the optional mechanism surfaces an adapter opts
// into. Composition is what lets a tool without MCP or without a launch
// command implement nothing rather than a misleading no-op.
pub use aa_core::integration::{DevToolIntegration, HookableTool, LaunchSpec, LaunchableTool, McpGovernedTool};

// The conformance check every adapter's own test suite is expected to call:
// declaring a capability whose accessor returns `None` is a contract
// violation, and adapters can only see it through this crate.
pub use aa_core::integration::{capability_conformance, ConformanceViolation};

// The capability axis (ADR 0030 Decision 3). Deliberately NOT
// `aa_core::Capability` — that is the agent-action axis re-exported above and
// governed by ADR 0029; §3.1 makes the distinct names mandatory.
pub use aa_core::integration::{CapabilityResolution, CapabilitySupport, DevToolCapabilities, IntegrationCapability};

// Request and plan authoring. `ProtectionProfile` and `PolicyProfileRef` are
// what an adapter reads instead of a policy document.
pub use aa_core::integration::{
    IntegrationPlan, IntegrationRequest, PlanError, PolicyProfileRef, ProtectionProfile, RemovalPlan,
    UnsupportedMechanism,
};

// Step vocabulary. Every variant of `StepAction` is constructible only from
// these, so an adapter cannot describe a mutation the plan model cannot render
// for review or record for removal.
pub use aa_core::integration::{
    ArtifactOperation, EnvValue, IntegrationStep, ProbeDescriptor, SettingsMerge, SettingsScope, StepAction,
    StepPrivilege, StepRequirement, TrustMaterialKind,
};

// Receipts are read by adapters (status, verify, plan_removal) and written
// only by the service — the type is shared, the authority is not.
pub use aa_core::integration::{IntegrationReceipt, ReceiptError, StepReceipt};

// Status and verification results, including the exercised-vs-read-back
// distinction that keeps `GatewayProtected` honest.
pub use aa_core::integration::{IntegrationStatus, LifecyclePhase, NextLevel, VerificationOutcome, VerificationResult};

// Protection state and the evidence it is derived from. `StateDerivation` is
// re-exported because an adapter's `integration_status` must derive the state
// through it rather than inventing a second derivation.
pub use aa_core::integration::{
    EvidenceKind, ExerciseOutcome, ProtectionEvidence, ProtectionLevel, ProtectionState, StateDerivation,
    DEFAULT_FRESHNESS_WINDOW_SECS,
};

// Version representation and compatibility classification, owned by the
// adapter (ADR 0030 matrix row 1).
pub use aa_core::integration::{
    ComponentVersions, SupportedToolVersions, ToolVersion, VersionCompatibility, VersionParseError, VersionSupport,
    LIFECYCLE_SCHEMA_VERSION,
};

// The migration bridge, so an unmigrated adapter — including any out-of-tree
// one — satisfies the lifecycle contract without being rewritten (ADR 0030 §7).
pub use aa_core::integration::{LegacyAdapterShim, LEGACY_UNSUPPORTED_REASON};

// Timestamp helper. Every lifecycle timestamp is plain Unix seconds, and an
// adapter that stamps evidence needs the same clock the service reads it with.
pub use aa_core::integration::now_unix_secs;
