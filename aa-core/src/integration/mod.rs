//! The Developer Integration lifecycle contract — ADR 0030 Decisions 3 and 4.
//!
//! # What this module is for
//!
//! [`DevToolAdapter`](crate::DevToolAdapter) can detect a tool, render settings,
//! build a launch command and push an MCP list. It cannot answer *"is this
//! developer actually protected right now, and how do you know?"* — there is no
//! plan, no receipt, no verification, no drift, no removal, and every mechanism
//! is mandatory whether or not the tool has it. This module adds the lifecycle
//! vocabulary that does answer it, as **types and traits only**: plan authoring
//! lives here, plan *execution*, receipt storage and drift comparison belong to
//! the service (AAASM-5278), and the local API that carries them belongs to
//! AAASM-5279.
//!
//! # The three ideas worth knowing before reading the types
//!
//! 1. **Capabilities are declared, three-valued and fail-absent.** An adapter
//!    says which mechanisms it exposes; anything it did not mention is *absent*,
//!    which is never read as supported. MCP is one capability among twelve, and
//!    a tool that does not have it declares nothing rather than implementing a
//!    no-op. See [`capability`].
//! 2. **A protection state is a measurement, not a setting.** It is derived from
//!    evidence on every read, it carries that evidence, and missing evidence
//!    always lowers it. Configuration read back from a file can justify
//!    [`ProtectionLevel::Integrated`] and never more; only traffic that was
//!    exercised and adjudicated by the core can justify
//!    [`ProtectionLevel::GatewayProtected`]. See [`state`].
//! 3. **Authoring and executing are different jobs.** An adapter authors an
//!    [`IntegrationPlan`]; the service executes it and owns the
//!    [`IntegrationReceipt`]. That is why there is no `apply` method on
//!    [`DevToolIntegration`].
//!
//! # Migration
//!
//! Nothing here replaces [`DevToolAdapter`], which is retained unchanged.
//! [`LegacyAdapterShim`] makes any existing adapter — in-tree, out-of-tree, or
//! the public sample — satisfy the new contract on day one, declaring honestly
//! that it cannot substantiate the mechanisms it was never designed to expose.

pub mod capability;
pub mod version;

pub use capability::{CapabilityResolution, CapabilitySupport, DevToolCapabilities, IntegrationCapability};
pub use version::{
    core_version, ComponentVersions, SupportedToolVersions, ToolVersion, VersionCompatibility, VersionParseError,
    VersionSupport, LIFECYCLE_SCHEMA_VERSION,
};

/// Seconds since the Unix epoch, saturating at zero for clocks set before it.
///
/// Every timestamp in this module is plain `u64` Unix seconds rather than a
/// richer time type: these values are serialized into receipts and status
/// responses that must survive a schema round trip through any client, and they
/// are only ever compared against a freshness window.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
