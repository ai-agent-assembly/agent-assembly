//! What integration mechanisms a dev tool exposes — ADR 0030 Decision 3.
//!
//! # This is a different axis from [`crate::capability::Capability`]
//!
//! `aa_core::Capability` / `CapabilitySet` model **agent action** capabilities
//! (`FileWrite`, `TerminalExec`, `NetworkOutbound`, …) and are the subject of
//! ADR 0029. The types here model **which levers exist for wiring a developer
//! tool into governance**. ADR 0030 §3.1 makes the distinct naming mandatory:
//! conflating them would make ADR 0029's over-permission rule read as if it
//! applied to integration mechanisms.
//!
//! # Fail-absent (ADR 0030 §3.4, transferred from ADR 0029)
//!
//! A capability that is **not declared** is [`CapabilityResolution::Absent`] —
//! not `Unsupported`, and never supported. An adapter that has not been updated
//! for a new capability has not answered the question, and a missing answer is
//! never read as a yes. The same applies to
//! [`CapabilitySupport::RequiresVersion`] whose `detected` is `None`: a missing
//! version is a missing comparison.
//!
//! # Why `ModelPathInterception` and `ModelGatewayBaseUrl` are separate
//!
//! They look alike and are opposites. The AAASM-5276 spike measured, against
//! Claude Code 2.1.220, that redirecting `ANTHROPIC_BASE_URL` delivered the raw
//! synthetic secret to the provider with **no AASM component anywhere in the
//! path**. Base-URL redirection is *routing*; only interception is *protection*.
//! [`IntegrationCapability::justifies_gateway_protection`] is where that
//! distinction is made unforgeable.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::version::ToolVersion;

/// One integration mechanism a dev tool may expose.
///
/// Deliberately **not** named `Capability` — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum IntegrationCapability {
    /// The adapter can detect the tool's presence and version on this host.
    Discovery,
    /// The adapter can render and merge a managed settings block into the
    /// tool's native configuration.
    ManagedSettings,
    /// The adapter can build a governed launch command for the tool. IDE-hosted
    /// tools (Copilot, Windsurf) declare this `Unsupported` with a reason
    /// instead of failing at run time.
    ManagedLaunch,
    /// An AASM component sits **in** the tool's model-bound path and inspects
    /// what crosses it (the MitM proxy with its CA trusted by the tool, or the
    /// gateway on the wire). This is the only mechanism that can justify
    /// [`ProtectionLevel::GatewayProtected`](super::ProtectionLevel::GatewayProtected).
    ModelPathInterception,
    /// The tool honours a configurable model base URL. This is **routing, not
    /// protection**: pointing the tool at another endpoint changes where its
    /// traffic goes, not whether anything inspects it.
    ModelGatewayBaseUrl,
    /// The tool honours `HTTP_PROXY` / `HTTPS_PROXY` or an equivalent. A
    /// transport lever — it is how interception is often *achieved*, but on its
    /// own it says nothing about what is on the other end of the proxy.
    HttpProxy,
    /// The tool exposes pre/post hooks AASM can install.
    Hooks,
    /// The tool exposes the MCP servers it is configured to use.
    McpDiscovery,
    /// The tool honours an MCP allow/deny list.
    McpGovernance,
    /// The tool can gate individual tool invocations on an approval decision.
    ToolActionApproval,
    /// A first-class in-IDE surface exists for status and approval prompts.
    NativeIdeUi,
    /// The integration can be backed by host controls (proxy CA in the system
    /// trust store, eBPF probes).
    HostEnforcement,
}

impl IntegrationCapability {
    /// Every variant, in declaration order. Kept in step with the enum by a unit
    /// test in this module.
    pub const ALL: [IntegrationCapability; 12] = [
        Self::Discovery,
        Self::ManagedSettings,
        Self::ManagedLaunch,
        Self::ModelPathInterception,
        Self::ModelGatewayBaseUrl,
        Self::HttpProxy,
        Self::Hooks,
        Self::McpDiscovery,
        Self::McpGovernance,
        Self::ToolActionApproval,
        Self::NativeIdeUi,
        Self::HostEnforcement,
    ];

    /// Whether exercised evidence about this mechanism can justify
    /// [`GatewayProtected`](super::ProtectionLevel::GatewayProtected).
    ///
    /// True for [`ModelPathInterception`](Self::ModelPathInterception) alone.
    /// [`ModelGatewayBaseUrl`](Self::ModelGatewayBaseUrl) and
    /// [`HttpProxy`](Self::HttpProxy) are routing levers: they determine where
    /// traffic goes, not that an AASM component inspected it. The AAASM-5276
    /// spike measured a base-URL redirection delivering a raw secret to the
    /// provider, so treating the two as interchangeable would report protection
    /// that had demonstrably not happened.
    pub fn justifies_gateway_protection(self) -> bool {
        matches!(self, Self::ModelPathInterception)
    }

    /// Whether attested evidence about this mechanism can justify
    /// [`HostEnforced`](super::ProtectionLevel::HostEnforced).
    pub fn justifies_host_enforcement(self) -> bool {
        matches!(self, Self::HostEnforcement)
    }

    /// Whether MCP is involved. Used by the conformance check that pairs a
    /// declaration with its optional accessor.
    pub fn is_mcp(self) -> bool {
        matches!(self, Self::McpDiscovery | Self::McpGovernance)
    }
}

/// How one [`IntegrationCapability`] is supported by an adapter.
///
/// Absence of a key from [`DevToolCapabilities`] means *not declared*, which is
/// **not** the same as [`Unsupported`](Self::Unsupported) — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum CapabilitySupport {
    /// The adapter can do this for this tool.
    Supported,
    /// The adapter cannot do this, and `reason` says why in words a user can
    /// read. This is what replaces a run-time `LaunchFailed` for a fact that was
    /// knowable at plan time (ADR 0030 §3.2).
    Unsupported {
        /// User-facing explanation, surfaced in the plan's dry-run output.
        reason: Cow<'static, str>,
    },
    /// The mechanism exists from `min` onwards. `detected` carries the version
    /// actually found; `None` resolves to [`CapabilityResolution::Absent`].
    RequiresVersion {
        /// Lowest tool version at which this mechanism exists.
        min: ToolVersion,
        /// The version detected on this host, when one was.
        detected: Option<ToolVersion>,
    },
}

impl CapabilitySupport {
    /// Convenience constructor for [`Unsupported`](Self::Unsupported).
    pub fn unsupported(reason: impl Into<Cow<'static, str>>) -> Self {
        Self::Unsupported { reason: reason.into() }
    }
}

/// Three-valued reading of a capability declaration — the *effective* answer.
///
/// Only [`Effective`](Self::Effective) may raise a protection state or be shown
/// to a user as something the product can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CapabilityResolution {
    /// Declared, and substantiated on this host at this version.
    Effective,
    /// Declared and explicitly unavailable, with a stated reason.
    Unsupported,
    /// Not declared at all, or declared with a version constraint that could not
    /// be evaluated. Never read as supported.
    Absent,
}

/// The full set of integration mechanisms one adapter declares.
///
/// Built with the chaining constructors so an adapter's `capabilities()` reads
/// as a table:
///
/// ```
/// use aa_core::integration::{DevToolCapabilities, IntegrationCapability as Cap};
///
/// let caps = DevToolCapabilities::new()
///     .supported(Cap::Discovery)
///     .supported(Cap::ManagedSettings)
///     .unsupported(Cap::ManagedLaunch, "Copilot is a VS Code extension and has no launch command");
///
/// assert!(caps.is_effective(Cap::Discovery));
/// assert!(!caps.is_effective(Cap::ManagedLaunch));
/// // Never declared at all — absent, not "unsupported".
/// assert!(!caps.is_effective(Cap::Hooks));
/// assert_eq!(caps.unsupported_reason(Cap::Hooks), None);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DevToolCapabilities {
    declared: BTreeMap<IntegrationCapability, CapabilitySupport>,
}

impl DevToolCapabilities {
    /// An empty declaration — every capability resolves to
    /// [`CapabilityResolution::Absent`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare `capability` with an explicit support value.
    #[must_use]
    pub fn declare(mut self, capability: IntegrationCapability, support: CapabilitySupport) -> Self {
        self.declared.insert(capability, support);
        self
    }

    /// Declare `capability` as [`CapabilitySupport::Supported`].
    #[must_use]
    pub fn supported(self, capability: IntegrationCapability) -> Self {
        self.declare(capability, CapabilitySupport::Supported)
    }

    /// Declare `capability` as [`CapabilitySupport::Unsupported`] with a
    /// user-facing reason.
    #[must_use]
    pub fn unsupported(self, capability: IntegrationCapability, reason: impl Into<Cow<'static, str>>) -> Self {
        self.declare(capability, CapabilitySupport::unsupported(reason))
    }

    /// Declare `capability` as available from `min` onwards, having detected
    /// `detected` on this host.
    #[must_use]
    pub fn requires_version(
        self,
        capability: IntegrationCapability,
        min: ToolVersion,
        detected: Option<ToolVersion>,
    ) -> Self {
        self.declare(capability, CapabilitySupport::RequiresVersion { min, detected })
    }

    /// The raw declaration map.
    pub fn declared(&self) -> &BTreeMap<IntegrationCapability, CapabilitySupport> {
        &self.declared
    }

    /// The declaration for `capability`, or `None` when it was never declared.
    pub fn support(&self, capability: IntegrationCapability) -> Option<&CapabilitySupport> {
        self.declared.get(&capability)
    }

    /// Resolve a declaration into its effective reading (ADR 0030 §3.4).
    ///
    /// * not declared ⇒ [`Absent`](CapabilityResolution::Absent)
    /// * `Supported` ⇒ [`Effective`](CapabilityResolution::Effective)
    /// * `Unsupported` ⇒ [`Unsupported`](CapabilityResolution::Unsupported)
    /// * `RequiresVersion { detected: None }` ⇒
    ///   [`Absent`](CapabilityResolution::Absent) — a missing version is a
    ///   missing comparison, never a pass
    /// * `RequiresVersion { detected: Some(v) }` ⇒ `Effective` when `v >= min`,
    ///   otherwise `Unsupported` (a substantiated "no")
    pub fn resolve(&self, capability: IntegrationCapability) -> CapabilityResolution {
        match self.declared.get(&capability) {
            None => CapabilityResolution::Absent,
            Some(CapabilitySupport::Supported) => CapabilityResolution::Effective,
            Some(CapabilitySupport::Unsupported { .. }) => CapabilityResolution::Unsupported,
            Some(CapabilitySupport::RequiresVersion { min, detected }) => match detected {
                None => CapabilityResolution::Absent,
                Some(detected) if detected >= min => CapabilityResolution::Effective,
                Some(_) => CapabilityResolution::Unsupported,
            },
        }
    }

    /// Shorthand for `resolve(capability) == CapabilityResolution::Effective`.
    pub fn is_effective(&self, capability: IntegrationCapability) -> bool {
        self.resolve(capability) == CapabilityResolution::Effective
    }

    /// The user-facing reason a capability is unavailable, when the adapter
    /// declared one. Returns `None` for absent capabilities — there is no reason
    /// to give for a question that was never answered.
    pub fn unsupported_reason(&self, capability: IntegrationCapability) -> Option<&str> {
        match self.declared.get(&capability) {
            Some(CapabilitySupport::Unsupported { reason }) => Some(reason.as_ref()),
            _ => None,
        }
    }

    /// Every capability that resolves to [`CapabilityResolution::Effective`].
    pub fn effective(&self) -> BTreeSet<IntegrationCapability> {
        self.declared
            .keys()
            .copied()
            .filter(|cap| self.is_effective(*cap))
            .collect()
    }

    /// Whether this declaration can substantiate a claim that model-bound
    /// traffic is inspected.
    ///
    /// Deliberately **not** satisfied by
    /// [`ModelGatewayBaseUrl`](IntegrationCapability::ModelGatewayBaseUrl) or
    /// [`HttpProxy`](IntegrationCapability::HttpProxy).
    pub fn can_intercept_model_path(&self) -> bool {
        self.is_effective(IntegrationCapability::ModelPathInterception)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_every_variant_exactly_once() {
        let unique: BTreeSet<_> = IntegrationCapability::ALL.iter().copied().collect();
        assert_eq!(unique.len(), IntegrationCapability::ALL.len());
    }

    #[test]
    fn base_url_redirection_cannot_satisfy_model_path_interception() {
        // The AAASM-5276 measurement: with ANTHROPIC_BASE_URL redirection the raw
        // synthetic secret reached the provider with no AASM component in the path.
        assert!(IntegrationCapability::ModelPathInterception.justifies_gateway_protection());
        assert!(!IntegrationCapability::ModelGatewayBaseUrl.justifies_gateway_protection());
        assert!(!IntegrationCapability::HttpProxy.justifies_gateway_protection());

        let routing_only = DevToolCapabilities::new()
            .supported(IntegrationCapability::ModelGatewayBaseUrl)
            .supported(IntegrationCapability::HttpProxy);
        assert!(
            !routing_only.can_intercept_model_path(),
            "routing capabilities must never add up to interception"
        );
    }

    #[test]
    fn an_undeclared_capability_is_absent_not_unsupported() {
        let caps = DevToolCapabilities::new().supported(IntegrationCapability::Discovery);
        assert_eq!(
            caps.resolve(IntegrationCapability::McpGovernance),
            CapabilityResolution::Absent
        );
        assert!(!caps.is_effective(IntegrationCapability::McpGovernance));
        assert_eq!(caps.unsupported_reason(IntegrationCapability::McpGovernance), None);
    }

    #[test]
    fn requires_version_without_a_detected_version_is_absent() {
        let caps =
            DevToolCapabilities::new().requires_version(IntegrationCapability::Hooks, ToolVersion::new(2, 0, 0), None);
        assert_eq!(caps.resolve(IntegrationCapability::Hooks), CapabilityResolution::Absent);
        assert!(!caps.is_effective(IntegrationCapability::Hooks));
    }

    #[test]
    fn requires_version_compares_when_a_version_is_known() {
        let too_old = DevToolCapabilities::new().requires_version(
            IntegrationCapability::Hooks,
            ToolVersion::new(2, 0, 0),
            Some(ToolVersion::new(1, 9, 0)),
        );
        assert_eq!(
            too_old.resolve(IntegrationCapability::Hooks),
            CapabilityResolution::Unsupported
        );

        let new_enough = DevToolCapabilities::new().requires_version(
            IntegrationCapability::Hooks,
            ToolVersion::new(2, 0, 0),
            Some(ToolVersion::new(2, 1, 220)),
        );
        assert!(new_enough.is_effective(IntegrationCapability::Hooks));
    }

    #[test]
    fn unsupported_carries_a_reason_a_user_can_read() {
        let caps = DevToolCapabilities::new().unsupported(
            IntegrationCapability::ManagedLaunch,
            "GitHub Copilot is a VS Code extension and has no launch command",
        );
        assert_eq!(
            caps.resolve(IntegrationCapability::ManagedLaunch),
            CapabilityResolution::Unsupported
        );
        assert!(caps
            .unsupported_reason(IntegrationCapability::ManagedLaunch)
            .is_some_and(|r| r.contains("VS Code extension")));
    }

    #[test]
    fn effective_returns_only_substantiated_capabilities() {
        let caps = DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .supported(IntegrationCapability::ManagedSettings)
            .unsupported(IntegrationCapability::ManagedLaunch, "no launch command")
            .requires_version(IntegrationCapability::Hooks, ToolVersion::new(2, 0, 0), None);

        let effective = caps.effective();
        assert_eq!(
            effective,
            BTreeSet::from([IntegrationCapability::Discovery, IntegrationCapability::ManagedSettings])
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn capabilities_round_trip_through_json() {
        let caps = DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .unsupported(IntegrationCapability::ManagedLaunch, "no launch command")
            .requires_version(
                IntegrationCapability::McpGovernance,
                ToolVersion::new(1, 2, 0),
                Some(ToolVersion::new(1, 3, 0)),
            );
        let json = serde_json::to_string(&caps).unwrap();
        let restored: DevToolCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, caps);
    }
}
