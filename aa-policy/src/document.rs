//! Validated, strongly-typed policy document types for aa-gateway.

use crate::scope::PolicyScope;

/// Validated network egress policy.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkPolicy {
    /// Domain glob patterns the agent may connect to.
    pub allowlist: Vec<String>,
}

/// Validated active-hours window.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveHours {
    /// Window start in `HH:MM` 24-hour format.
    pub start: String,
    /// Window end in `HH:MM` 24-hour format.
    pub end: String,
    /// IANA timezone name.
    pub timezone: String,
}

/// Validated schedule policy.
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulePolicy {
    /// Optional time window during which the agent is permitted to run.
    pub active_hours: Option<ActiveHours>,
}

/// Action to take when budget limit is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActionOnExceed {
    /// Deny individual requests but keep the agent active (default).
    #[default]
    Deny,
    /// Suspend the agent entirely until budget resets.
    Suspend,
}

/// Validated spend budget policy.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetPolicy {
    /// Maximum USD spend per calendar day; `None` means no limit.
    pub daily_limit_usd: Option<f64>,
    /// Maximum USD spend per calendar month; `None` means no limit.
    pub monthly_limit_usd: Option<f64>,
    /// AAASM-5087 — Maximum USD spend per calendar day, per team.
    /// Enforced independently of `daily_limit_usd` (which is the global cap).
    /// `None` means no per-team daily limit.
    pub team_daily_limit_usd: Option<f64>,
    /// AAASM-5087 — Maximum USD spend per calendar month, per team.
    /// `None` means no per-team monthly limit.
    pub team_monthly_limit_usd: Option<f64>,
    /// AAASM-2022 — Maximum USD spend per calendar day, per organisation.
    /// Enforced independently of `daily_limit_usd` (which is the global cap).
    /// `None` means no per-org daily limit.
    pub org_daily_limit_usd: Option<f64>,
    /// AAASM-2022 — Maximum USD spend per calendar month, per organisation.
    /// `None` means no per-org monthly limit.
    pub org_monthly_limit_usd: Option<f64>,
    /// IANA timezone for daily/monthly reset boundary. `None` means UTC.
    pub timezone: Option<String>,
    /// Action when budget is exceeded: deny individual requests or suspend agent.
    pub action_on_exceed: ActionOnExceed,
    /// Optional sub-day rollover window parsed from the YAML `window:` field.
    /// `None` preserves the historical calendar-day rollover behaviour.
    /// AAASM-1600.
    pub window: Option<std::time::Duration>,
}

/// Action to take when the credential / sensitive-data scanner produces
/// a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialAction {
    /// Refuse the action: engine returns `Deny` with reason
    /// `"credential detected"`; upstream never receives the payload.
    Block,
    /// Forward a redacted form of the payload upstream (default; preserves
    /// the historical behaviour from before this enum existed).
    #[default]
    RedactOnly,
    /// Forward the unmodified payload and raise an alert side-effect.
    /// Documented as a deliberate downgrade for low-risk audit-only modes.
    ///
    /// SECURITY (AAASM-3137): this forwards the *raw* secret upstream. Prefer
    /// [`CredentialAction::AlertAndRedact`] when an alert is wanted but the
    /// secret must still not leave the boundary.
    AlertOnly,
    /// Raise an alert side-effect **and** forward a redacted payload. This is
    /// the safe alerting mode: the operator gets notified of the finding, but
    /// the raw secret is redacted before it leaves the boundary regardless of
    /// the alert (AAASM-3137).
    AlertAndRedact,
}

/// Validated data / PII policy.
#[derive(Debug, Clone, PartialEq)]
pub struct DataPolicy {
    /// Compiled regex patterns for PII / credential detection.
    pub sensitive_patterns: Vec<String>,
    /// Action to take when the scanner produces a finding. Defaults to
    /// [`CredentialAction::RedactOnly`] so policies that omit the field
    /// keep the historical behaviour.
    pub credential_action: CredentialAction,
    /// AAASM-5354 — BCP-47 tags of the deterministic locale recognizer packs
    /// this policy asks the gateway to run.
    ///
    /// Carried verbatim. This crate is a leaf and does not know which packs a
    /// build contains; `aa_gateway::engine::detection::resolve_locale_packs`
    /// owns the catalogue and fails closed on a tag it does not recognise,
    /// rather than treating it as "no pack configured".
    ///
    /// **Empty by default, and that default is load-bearing.** Stage 6 runs on
    /// the synchronous pre-action path, where `credential_action: block` denies
    /// an agent's action before any byte leaves. AAASM-5353 measured the
    /// 統一編號 (business-registration) checksum in the `zh-TW` pack at a
    /// **22.0000%** residual: roughly one random eight-digit string in five
    /// satisfies it. Enabling that by default would put a one-in-five-wrong
    /// detector on the block path — which is this Epic's founding defect, a
    /// detector firing on ordinary content and denying a Chinese-speaking
    /// agent, aimed at a new population.
    ///
    /// So a pack is production-wired and genuinely reachable, but only when an
    /// operator names it here, having accepted that residual for their
    /// deployment. With the list empty the merged findings are byte-identical
    /// to the pre-AAASM-5354 two-pass scan.
    pub locale_packs: Vec<String>,
}

/// Per-policy approval escalation overrides.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalPolicy {
    /// Override escalation timeout in seconds for this policy.
    pub timeout_seconds: Option<u32>,
    /// Override the escalation role / approver group for this policy.
    pub escalation_role: Option<String>,
}

/// Validated per-tool policy entry.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolPolicy {
    /// Whether this tool is permitted.
    pub allow: bool,
    /// Max calls per hour; `None` means unlimited.
    pub limit_per_hour: Option<u32>,
    /// CEL expression that triggers human-in-the-loop approval.
    pub requires_approval_if: Option<String>,
}

/// Whether a policy document requires brokered egress (AAASM-6278, ADR 0038
/// amendment).
///
/// Mirrors `aa_isolation::egress::EgressPosture`'s two-value vocabulary by
/// name — same words, independently defined type, for the same reason
/// [`LeaseDomain`] below mirrors `aa_isolation::capability::CapabilityDomain`:
/// `aa-policy` cannot depend on `aa-isolation` (the dependency edge runs the
/// other way). Unlike [`LeaseDomain`], there is no tautology hazard to avoid
/// here — an egress posture is a restriction a policy author states directly,
/// not a grant checked against an independently-sourced requirement — so this
/// node is free to be read straight off the validated document rather than
/// routed through [`PolicyDocument::to_canonical`]. It still is not routed
/// through that bridge: see the `egress` field's own doc comment for why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressPosture {
    /// No egress-mediation property is required. The default — every
    /// document that states no `egress:` section reads this way, matching
    /// `aa_isolation::egress::EgressContract::not_required()`'s own
    /// rc.7-compatible default.
    #[default]
    NotRequired,
    /// Egress must be mediated by a broker meeting
    /// `aa_isolation::egress::EgressContract::broker_required()`'s stated
    /// properties, or the launch must be refused.
    BrokerRequired,
}

impl EgressPosture {
    /// Parse the wire name a policy author writes (snake_case). Returns
    /// `None` for an unrecognised word, so the validator can reject a typo
    /// rather than silently falling back to [`Self::NotRequired`].
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "not_required" => Some(Self::NotRequired),
            "broker_required" => Some(Self::BrokerRequired),
            _ => None,
        }
    }

    /// The wire name this posture round-trips through [`Self::parse`] under.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::BrokerRequired => "broker_required",
        }
    }
}

/// A capability domain a [`LeaseGrant`] may be issued against (AAASM-6275,
/// ADR 0038).
///
/// Mirrors `aa_isolation::capability::CapabilityDomain`'s variant vocabulary
/// by name — same words, independently defined type. The two must stay
/// separate for two reasons: `aa-policy` cannot depend on `aa-isolation` (the
/// dependency edge runs the other way; `aa-isolation`'s own crate docs on the
/// `aa-policy` → `aa-isolation` packaging cycle explain why), and — the one
/// that actually matters — a lease that collapsed onto the same domain type
/// as whatever produces this document's `ControlRequirement`s would let
/// `aa_isolation::authority::authority_gate`'s lease-vs-requirement check
/// become a tautology: the lease would always exactly match whatever
/// requirement it is checked against, because both would trace back to one
/// authored value. Keeping an independently-authored type here, fed by its
/// own `authority.leases` node rather than a projection of `filesystem` /
/// `syscalls` / `capabilities` / `network`, is what keeps "was this
/// explicitly leased" answerable from a source a `ControlRequirement` never
/// touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseDomain {
    /// Reading file content or metadata.
    FilesystemRead,
    /// Creating, writing, renaming or deleting filesystem entries.
    FilesystemWrite,
    /// Outbound network connections, by destination.
    NetworkEgress,
    /// Hostname resolution.
    NameResolution,
    /// Direct system-call access.
    Syscall,
    /// Creating child processes.
    ProcessCreation,
    /// Inter-process channels: sockets, shared memory, inherited descriptors.
    Ipc,
    /// The authority a child would inherit: environment secrets, tokens,
    /// open descriptors and sockets that carry credentials.
    Credential,
    /// Numeric ceilings: memory, CPU, process count, wall clock, file size,
    /// open descriptors.
    Resource,
    /// Staged, drift-checked materialization of a working directory's
    /// changes onto its base.
    WorkspaceTransaction,
}

impl LeaseDomain {
    /// Parse the wire name a policy author writes (snake_case). Returns
    /// `None` for an unrecognised word — a closed vocabulary, like
    /// `aa_security::policy::Syscall`'s, so the validator can reject a typo
    /// rather than silently drop the entry.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "filesystem_read" => Some(Self::FilesystemRead),
            "filesystem_write" => Some(Self::FilesystemWrite),
            "network_egress" => Some(Self::NetworkEgress),
            "name_resolution" => Some(Self::NameResolution),
            "syscall" => Some(Self::Syscall),
            "process_creation" => Some(Self::ProcessCreation),
            "ipc" => Some(Self::Ipc),
            "credential" => Some(Self::Credential),
            "resource" => Some(Self::Resource),
            "workspace_transaction" => Some(Self::WorkspaceTransaction),
            _ => None,
        }
    }

    /// The wire name this domain round-trips through [`Self::parse`] under.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem_read",
            Self::FilesystemWrite => "filesystem_write",
            Self::NetworkEgress => "network_egress",
            Self::NameResolution => "name_resolution",
            Self::Syscall => "syscall",
            Self::ProcessCreation => "process_creation",
            Self::Ipc => "ipc",
            Self::Credential => "credential",
            Self::Resource => "resource",
            Self::WorkspaceTransaction => "workspace_transaction",
        }
    }
}

/// What within a [`LeaseDomain`] a [`LeaseGrant`] covers (AAASM-6275).
///
/// Mirrors the shape of `aa_isolation::spec::RequirementScope`'s two scoped
/// variants (`Whole` / `Selectors`) — same concept, independently defined,
/// for the reason given on [`LeaseDomain`]. There is no `Limits` variant:
/// AAASM-6276's lowering decides whether and how to source a numeric ceiling
/// for [`LeaseDomain::Resource`]; authoring one here before that mapping
/// exists would be a field nothing reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseScope {
    /// The lease covers the whole domain, with no further restriction.
    ///
    /// Must be authored explicitly — the literal YAML string `"whole"` —
    /// because, unlike a restriction node, an *unstated* scope has no safe
    /// default on a grant. There is no reading under which omitting
    /// `scope:` entirely should mean this.
    Whole,
    /// Domain-specific selector strings: paths for filesystem domains,
    /// destinations for network domains, call names for syscalls.
    ///
    /// Opaque to this crate, exactly as
    /// `aa_isolation::spec::RequirementScope::Selectors` documents itself:
    /// carried and rendered, never parsed or matched here.
    Selectors(Vec<String>),
}

/// One authored capability-lease grant (AAASM-6275, ADR 0038).
///
/// This is policy *intent* — which domain, what scope, how it may be
/// delegated, and who/why it was authored — not an issued lease. It carries
/// no `LeaseId`, no `issued_at`/`expires_at` instant and no `RevocationState`:
/// those are issuance-time facts a future lowering pass (AAASM-6276) assigns
/// when it turns this into a real `aa_isolation::lease::CapabilityLease`, not
/// something a policy author can predict.
///
/// # Why this is never derived from `resource_requirements`
///
/// See [`LeaseDomain`]'s doc comment for the hazard this type exists to
/// avoid. Nothing in [`super::validator::PolicyValidator`]'s construction of
/// a `LeaseGrant` reads `filesystem`, `syscalls`, `capabilities` or `network`
/// — it reads only the document's own `authority.leases` entries — and
/// nothing should ever be added here that changes that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGrant {
    /// Which capability domain this lease grants authority over.
    pub domain: LeaseDomain,
    /// What within the domain the lease covers.
    pub scope: LeaseScope,
    /// Maximum number of times this lease may be exercised. `None` is
    /// uncapped by count (still bounded by `ttl_seconds` and revocation,
    /// once issued).
    pub max_count: Option<u64>,
    /// Seconds from issuance before this lease expires. `None` leaves expiry
    /// to the issuing mechanism.
    pub ttl_seconds: Option<u64>,
    /// Whether a child launch may inherit this lease, narrowed. Defaults to
    /// `false`.
    pub delegable: bool,
    /// Free-text identity reference this lease is issued on behalf of, when
    /// the author wants to record one.
    pub issuer: Option<String>,
    /// The named policy rule this lease was authored under.
    pub policy_rule: Option<String>,
    /// A reference to a recorded approval, when issuance was gated on one.
    pub approval_ref: Option<String>,
    /// Why this lease is granted, in words an operator can act on. Never a
    /// credential value.
    pub reason: String,
}

/// Fully validated policy document produced by [`super::validator::PolicyValidator`].
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDocument {
    /// Human-readable policy name from the YAML envelope `metadata.name`.
    /// `None` when parsed from the flat (non-envelope) format.
    pub name: Option<String>,
    /// Policy revision version from the YAML envelope `metadata.version`.
    /// `None` when parsed from the flat (non-envelope) format.
    pub policy_version: Option<String>,
    /// Schema version string.
    pub version: Option<String>,
    /// Hierarchical scope this policy applies to. Defaults to
    /// [`PolicyScope::Global`] when the `scope` YAML field is absent so
    /// pre-F92 policies keep their existing semantics.
    pub scope: PolicyScope,
    /// Network egress policy.
    pub network: Option<NetworkPolicy>,
    /// Schedule / active-hours policy.
    pub schedule: Option<SchedulePolicy>,
    /// Spend budget policy.
    pub budget: Option<BudgetPolicy>,
    /// Data / PII policy.
    pub data: Option<DataPolicy>,
    /// Seconds before an approval request times out. Default: 300.
    pub approval_timeout_secs: u32,
    /// Per-policy approval escalation overrides. `None` means use team routing defaults.
    pub approval_policy: Option<ApprovalPolicy>,
    /// Per-tool policies keyed by tool name.
    pub tools: std::collections::HashMap<String, ToolPolicy>,
    /// Capability allow/deny restrictions for this policy scope.
    pub capabilities: Option<aa_core::CapabilitySet>,
    /// AAASM-5751 — filesystem path scope for this policy scope.
    ///
    /// `None` means the operator stated nothing about paths — **not** that
    /// paths are unrestricted. See
    /// [`aa_security::policy::FilesystemPolicy`] for the three authored states
    /// and why an empty scope is deny-all rather than the absence of one.
    ///
    /// # Why this reuses the canonical type verbatim
    ///
    /// Most other cross-layer dimensions on this document have a gateway-side
    /// twin that [`PolicyDocument::to_canonical`] converts into. That pattern
    /// is what let the syscall node fall out of the projection unnoticed
    /// (AAASM-5753): a second type makes "carried across the bridge" a thing
    /// someone has to remember to do. Holding the canonical type itself makes
    /// the projection a move rather than a translation, so this node cannot
    /// acquire a second, divergent definition.
    pub filesystem: Option<aa_security::policy::FilesystemPolicy>,
    /// AAASM-5753 — kernel syscall allowlist for this policy scope.
    ///
    /// Holds [`aa_security::policy::SyscallAllowlist`] verbatim, for the reason
    /// spelled out on [`filesystem`](Self::filesystem) above: this field exists
    /// because the syscall node had no gateway-side representation, so
    /// [`PolicyDocument::to_canonical`] hard-coded the canonical node to `None`
    /// and discarded whatever an operator wrote. Reintroducing the omission as
    /// a gateway-side twin would recreate the translation step that went
    /// missing. The projection is a move.
    ///
    /// # Two authored states, and they are not the same fact
    ///
    /// | Authored form | Meaning |
    /// | --- | --- |
    /// | `None` — no `syscalls:` section | The operator stated nothing. **Not a grant** |
    /// | `Some` with a non-empty set | Only these calls are permitted |
    /// | `Some` with an empty set | A restriction is in force and permits nothing |
    ///
    /// The third row is the one that reads wrong if it collapses onto the
    /// first: `syscalls:` written with no `allow:` under it is the most
    /// restrictive posture available here, not the absence of a posture. This
    /// is the same reading [`aa_security::policy::FilesystemPolicy`] documents
    /// for an empty [`PathScope`](aa_security::policy::PathScope), and the same
    /// one `aa_security::policy::PolicyDocument::from_yaml` already gives the
    /// `syscalls:` section — so the two ingest paths for one on-disk contract
    /// answer this question identically rather than each inventing an answer.
    pub syscall_allowlist: Option<aa_security::policy::SyscallAllowlist>,
    /// AAASM-6275 — capability leases this policy document grants.
    ///
    /// Unlike [`filesystem`](Self::filesystem) and
    /// [`syscall_allowlist`](Self::syscall_allowlist), there is no tri-state
    /// "stated but empty" distinction to carry here: a lease is purely
    /// additive, so an `authority:` section that grants nothing is
    /// indistinguishable in effect from an absent one, and an empty `Vec`
    /// covers both. See [`LeaseGrant`] for why this is never a projection of
    /// [`filesystem`](Self::filesystem), [`syscall_allowlist`](Self::syscall_allowlist),
    /// [`capabilities`](Self::capabilities) or [`network`](Self::network).
    pub leases: Vec<LeaseGrant>,
    /// AAASM-6278 — this policy document's required egress-mediation posture.
    ///
    /// Defaults to [`EgressPosture::NotRequired`] when the document states no
    /// `egress:` section — the same rc.7-compatible default
    /// `aa_isolation::egress::EgressContract::not_required()` carries.
    /// Deliberately never routed through [`Self::to_canonical`]: that method
    /// projects onto `CanonPolicyDocument`, the exact AST
    /// `aa_isolation::lowering::lower_policy` reads to build
    /// `ControlRequirement`s, and an egress posture is a different kind of
    /// fact (what this run's mediating component must provide, not what the
    /// agent itself may do) consumed by `aa_isolation::egress::egress_gate`
    /// instead.
    pub egress: EgressPosture,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_document_default_tools_is_empty_map() {
        let doc = PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope: PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: std::collections::HashMap::new(),
            capabilities: None,
            filesystem: None,
            syscall_allowlist: None,
            leases: Vec::new(),
            egress: EgressPosture::NotRequired,
        };
        assert!(doc.tools.is_empty());
        // AAASM-5751 — an unstated path node. Read this as "nobody said",
        // never as "nothing is restricted".
        assert!(doc.filesystem.is_none());
        // AAASM-6275 — no leases authored.
        assert!(doc.leases.is_empty());
        // AAASM-6278 — no egress section authored.
        assert_eq!(doc.egress, EgressPosture::NotRequired);
    }

    #[test]
    fn egress_posture_round_trips_through_parse_and_as_str() {
        for posture in [EgressPosture::NotRequired, EgressPosture::BrokerRequired] {
            assert_eq!(EgressPosture::parse(posture.as_str()), Some(posture));
        }
    }

    #[test]
    fn egress_posture_rejects_an_unrecognised_word() {
        assert_eq!(EgressPosture::parse("broker_preferred"), None);
        assert_eq!(EgressPosture::parse(""), None);
    }

    #[test]
    fn lease_domain_round_trips_through_parse_and_as_str() {
        for domain in [
            LeaseDomain::FilesystemRead,
            LeaseDomain::FilesystemWrite,
            LeaseDomain::NetworkEgress,
            LeaseDomain::NameResolution,
            LeaseDomain::Syscall,
            LeaseDomain::ProcessCreation,
            LeaseDomain::Ipc,
            LeaseDomain::Credential,
            LeaseDomain::Resource,
            LeaseDomain::WorkspaceTransaction,
        ] {
            assert_eq!(LeaseDomain::parse(domain.as_str()), Some(domain));
        }
    }

    #[test]
    fn lease_domain_rejects_an_unrecognised_word() {
        assert_eq!(LeaseDomain::parse("filesystem_execute"), None);
        assert_eq!(LeaseDomain::parse(""), None);
    }

    #[test]
    fn network_policy_stores_allowlist() {
        let np = NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        };
        assert_eq!(np.allowlist.len(), 1);
    }

    #[test]
    fn tool_policy_allow_defaults() {
        let tp = ToolPolicy {
            allow: true,
            limit_per_hour: None,
            requires_approval_if: None,
        };
        assert!(tp.allow);
        assert!(tp.limit_per_hour.is_none());
    }

    #[test]
    fn credential_action_default_is_redact_only() {
        assert_eq!(CredentialAction::default(), CredentialAction::RedactOnly);
    }
}
