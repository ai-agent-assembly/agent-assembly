//! Lowering an effective AASM policy into execution capability requirements.
//!
//! [`lower_policy`] is the one deterministic mapping from the canonical policy
//! AST ([`aa_security::policy::PolicyDocument`]) onto the
//! [`ControlRequirement`]s this crate negotiates. It is pure: the same document
//! and the same options always produce the same requirements, in the same
//! order.
//!
//! Authority: ADR 0035 §4 (negotiation before the untrusted process starts) and
//! ADR 0033 §6 (the claim vocabulary). Implementation is AAASM-5707 under Epic
//! AAASM-5702.
//!
//! # What this module refuses to do
//!
//! It does not invent scope the policy schema cannot express. The schema is
//! narrower than [`CapabilityDomain`] is wide, and the honest response to that
//! is to *say so per domain*, not to lower a plausible-looking requirement that
//! no policy author wrote. Extending the schema is a public policy-contract
//! change made deliberately and recorded in an ADR before any code changes —
//! AAASM-5751 added the filesystem path-scope node that way, and nothing here
//! anticipates a node that has not been through that door.
//!
//! The single property this module exists to hold:
//!
//! > **"No policy source exists" is never "no restriction is required."**
//!
//! A domain policy cannot express is reported as
//! [`DomainCoverage::PolicyCannotExpress`], which produces no requirement *and*
//! no statement that the domain is safe. A caller that renders a plan without
//! reading [`PolicyLowering::unrepresentable`] is reporting an incomplete
//! boundary as a complete one.
//!
//! # Four states that must not collapse into one
//!
//! | State | Where it lives | Distinguished by |
//! | --- | --- | --- |
//! | Policy cannot express the requirement | [`DomainCoverage::PolicyCannotExpress`] | No requirement is emitted, and the gap is named |
//! | The backend cannot enforce the requirement | [`crate::plan::RefusalReason`] | Produced by [`negotiate`](crate::plan::negotiate), after lowering |
//! | The requirement is optional or degradable | [`RequirementPosture`] | Carried on the requirement itself |
//! | Nothing measured the requirement | [`aa_core::attestation::ClaimTerm::Unmeasured`] | A run-level fact, reached only through evidence |
//!
//! They are carried by four different types on purpose. A single "not covered"
//! flag would make a policy gap, a backend gap, a deliberate relaxation and an
//! unmeasured run indistinguishable in the audit trail — and the first and the
//! last differ in whether anyone ever intended a control at all.
//!
//! # What the current schema can actually source
//!
//! Measured against the canonical AST at AAASM-5704 (`666c97dbf`), revised for
//! the filesystem path-scope node added by AAASM-5751. Full detail travels per
//! domain in [`DomainLowering`]; this is the summary:
//!
//! | Domain | Source | Granularity |
//! | --- | --- | --- |
//! | [`Syscall`](CapabilityDomain::Syscall) | `syscalls.allow` | Enumerated — a closed 15-name vocabulary |
//! | [`NetworkEgress`](CapabilityDomain::NetworkEgress) | `network.allowlist`, `capabilities` `network_outbound` | Host globs only; no port, no protocol |
//! | [`FilesystemRead`](CapabilityDomain::FilesystemRead) | `filesystem.read.allow`, `capabilities` `file_read` | Enumerated path prefixes when scoped; whole-domain when the capability is denied |
//! | [`FilesystemWrite`](CapabilityDomain::FilesystemWrite) | `filesystem.write.allow`, `capabilities` `file_write` / `file_delete` | Enumerated path prefixes when scoped; whole-domain when the capability is denied |
//! | [`ProcessCreation`](CapabilityDomain::ProcessCreation) | `capabilities` `agent_spawn` / `terminal_exec` | Whole-domain boolean; no descendant ceiling |
//! | [`NameResolution`](CapabilityDomain::NameResolution) | — | Not expressible |
//! | [`Ipc`](CapabilityDomain::Ipc) | — | Not expressible |
//! | [`Credential`](CapabilityDomain::Credential) | — | Not expressible |
//! | [`Resource`](CapabilityDomain::Resource) | — | Not expressible |
//!
//! The last four are **accepted, measured risk**, not dead domains: the ADR
//! 0035 AAASM-5751 amendment records that a backend can enforce three of them
//! today and no operator can ask it to. They stay
//! [`DomainCoverage::PolicyCannotExpress`] and carry no coverage claim.
//!
//! # No backend vocabulary
//!
//! Nothing here names an operating-system or vendor mechanism, and nothing
//! branches on backend identity — a requirement lowered from a policy is the
//! same requirement whichever backend is asked about it (ADR 0035 §3). The
//! backend's own realization travels separately as [`crate::plan::Lowering`].

use std::collections::BTreeMap;

use aa_security::policy::{Capability, PolicyDocument};

use crate::capability::CapabilityDomain;
use crate::spec::{ControlRequirement, ExecutionSpec, RequirementPosture, RequirementScope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Prefix marking a [`RequirementScope::Selectors`] entry as a member of a
/// *permitted* set, rather than something to be stopped.
///
/// [`RequirementScope::Selectors`] is an opaque string list with no polarity
/// field, and every policy node that carries scope — `syscalls.allow`,
/// `network.allowlist` and `filesystem.<verb>.allow` — is an allow-list: each
/// names what may happen, and the requirement is to prevent everything else.
/// Emitting bare names would leave a backend to guess which of the two readings
/// applies, and the two are exact opposites.
///
/// Enumerating the complement instead was rejected: the complement of an
/// allow-list is unbounded (`syscalls.allow: [read]` must stop `ptrace`, which
/// the 15-name policy vocabulary cannot even spell), so a complement list would
/// under-state the requirement by exactly the calls that matter most.
///
/// Build entries with [`permit_only_selector`] and read them with
/// [`permitted_selector`] rather than matching the prefix by hand.
pub const PERMIT_ONLY_SELECTOR: &str = "permit-only:";

/// Render `name` as a permitted-set selector. See [`PERMIT_ONLY_SELECTOR`].
pub fn permit_only_selector(name: &str) -> String {
    format!("{PERMIT_ONLY_SELECTOR}{name}")
}

/// The permitted name inside a selector, or `None` if it is not one.
///
/// A backend uses this to read a lowered allow-list without knowing which
/// policy node produced it, and without a branch on the domain.
pub fn permitted_selector(selector: &str) -> Option<&str> {
    selector.strip_prefix(PERMIT_ONLY_SELECTOR)
}

/// How precisely policy could scope a requirement within its domain.
///
/// Recorded because "the policy restricts filesystem writes" and "the policy
/// restricts writes under `/etc`" are different security statements, and the
/// current schema can only make the first. A reader who cannot tell them apart
/// will over-read what the boundary guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ScopeGranularity {
    /// Policy named the individual members of a permitted set — syscall names,
    /// egress hosts. Carried as [`RequirementScope::Selectors`].
    Enumerated,
    /// Policy expressed a whole-domain boolean and nothing narrower was
    /// available to express. Carried as [`RequirementScope::Whole`].
    WholeDomainOnly,
}

/// What the policy document said about one [`CapabilityDomain`].
///
/// Three distinct facts, and the distinction is the point. Only
/// [`Lowered`](Self::Lowered) produces a requirement; the other two produce
/// none, for opposite reasons, and neither is a statement that the domain needs
/// no control.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DomainCoverage {
    /// The document expressed a restriction and it lowered to a requirement.
    Lowered {
        /// How precisely the requirement could be scoped.
        granularity: ScopeGranularity,
        /// The policy nodes that produced it, named so an operator can find
        /// the line they wrote.
        sourced_from: Vec<String>,
    },
    /// The schema has a node for this domain and this document left it unset.
    ///
    /// A statement about the *document*, not about the schema. Distinct from
    /// [`PolicyCannotExpress`](Self::PolicyCannotExpress): here the operator
    /// could have written a restriction and did not, so the remedy is to edit
    /// the policy — there is one to edit.
    NotStated {
        /// The policy node that would have carried it.
        node: String,
        /// What the schema documents an absent node to mean.
        schema_default: String,
    },
    /// The schema has no node that can express this domain at all.
    ///
    /// **Never read this as "no restriction is required."** It is the absence
    /// of a way to *ask*, not the presence of an answer. An execution boundary
    /// built from a policy with unrepresentable domains is incomplete, and the
    /// plan that carries it must say so.
    PolicyCannotExpress {
        /// Why, naming the nearest policy node and why it is not this one.
        detail: String,
    },
}

impl DomainCoverage {
    /// Whether this coverage produced a [`ControlRequirement`].
    pub fn expresses_requirement(&self) -> bool {
        matches!(self, Self::Lowered { .. })
    }

    /// Whether the policy schema cannot express this domain at all.
    pub fn is_unrepresentable(&self) -> bool {
        matches!(self, Self::PolicyCannotExpress { .. })
    }

    /// A stable lowercase identifier for reports and logs.
    ///
    /// The three tokens are distinct so a `--dry-run` reader, a log grep and an
    /// audit record all tell the three states apart without inferring from
    /// which fields are missing.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lowered { .. } => "lowered",
            Self::NotStated { .. } => "not_stated",
            Self::PolicyCannotExpress { .. } => "policy_cannot_express",
        }
    }
}

/// What became of one [`CapabilityDomain`] during lowering.
///
/// Produced for **every** domain in [`CapabilityDomain::ALL`], including the
/// ones policy cannot reach. A domain that simply went missing from the output
/// would be indistinguishable from one that was considered and found
/// unrepresentable, which is the confusion this whole module is shaped against.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DomainLowering {
    /// The domain.
    pub domain: CapabilityDomain,
    /// What the document said about it.
    pub coverage: DomainCoverage,
    /// What the schema cannot express about this domain *even when it is
    /// lowered* — the residual gap between what ADR 0035 asks a control to be
    /// scoped by and what a policy author can currently write.
    ///
    /// Empty means the lowering is complete for the domain. A non-empty list
    /// alongside [`DomainCoverage::Lowered`] is the partial case: something was
    /// expressed, and something else could not be.
    pub residual_gaps: Vec<String>,
}

impl DomainLowering {
    /// Whether everything ADR 0035 asks of this domain was expressible.
    pub fn is_complete(&self) -> bool {
        self.coverage.expresses_requirement() && self.residual_gaps.is_empty()
    }
}

/// Operator posture selections applied on top of a lowering.
///
/// **Not policy.** The policy schema has no posture node, and this module does
/// not add one — see the module documentation on AAASM-5751. Every requirement
/// lowered from a document is [`RequirementPosture::Required`] by default,
/// which is ADR 0035 §4's stated default ("the default for an unmet required
/// capability is refusal before launch"). Relaxing one is a separate, explicit
/// act by whoever is launching, and it is recorded on the requirement so the
/// plan and the evidence both carry it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoweringOptions {
    postures: BTreeMap<CapabilityDomain, RequirementPosture>,
}

impl LoweringOptions {
    /// Every lowered requirement is [`RequirementPosture::Required`].
    pub fn strict() -> Self {
        Self::default()
    }

    /// Select a weaker posture for one domain, deliberately.
    pub fn with_posture(mut self, domain: CapabilityDomain, posture: RequirementPosture) -> Self {
        self.postures.insert(domain, posture);
        self
    }

    /// The posture selected for `domain`, defaulting to
    /// [`RequirementPosture::Required`].
    pub fn posture_for(&self, domain: CapabilityDomain) -> RequirementPosture {
        self.postures
            .get(&domain)
            .copied()
            .unwrap_or(RequirementPosture::Required)
    }
}

/// The result of lowering one policy document.
///
/// Carries the requirements *and* the reason every domain that produced none
/// produced none. The two travel together because they are only safe to read
/// together: the requirement list alone reads as a complete boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PolicyLowering {
    requirements: Vec<ControlRequirement>,
    domains: Vec<DomainLowering>,
    unmapped: Vec<String>,
}

impl PolicyLowering {
    /// Every lowered requirement, in [`CapabilityDomain::ALL`] order.
    pub fn requirements(&self) -> &[ControlRequirement] {
        &self.requirements
    }

    /// What became of every domain, in [`CapabilityDomain::ALL`] order.
    ///
    /// Always nine entries: one per [`CapabilityDomain`], whether or not policy
    /// reached it.
    pub fn domains(&self) -> &[DomainLowering] {
        &self.domains
    }

    /// What became of one domain.
    ///
    /// Never `None` for a domain in [`CapabilityDomain::ALL`].
    pub fn coverage(&self, domain: CapabilityDomain) -> Option<&DomainLowering> {
        self.domains.iter().find(|d| d.domain == domain)
    }

    /// Domains the policy schema cannot express at all.
    ///
    /// The list `--dry-run` must render. An empty requirement for one of these
    /// domains is not a judgement that the domain is safe; it is the absence of
    /// any way for an operator to state a judgement.
    pub fn unrepresentable(&self) -> impl Iterator<Item = &DomainLowering> {
        self.domains.iter().filter(|d| d.coverage.is_unrepresentable())
    }

    /// Restrictions the document expressed that no [`CapabilityDomain`] can
    /// carry, named verbatim.
    ///
    /// The mirror image of [`unrepresentable`](Self::unrepresentable): there the
    /// policy could not state something the boundary has a domain for; here the
    /// policy stated something the boundary has no domain for. Both are silent
    /// losses of an operator's intent unless they are printed.
    pub fn unmapped(&self) -> &[String] {
        &self.unmapped
    }

    /// Attach every lowered requirement to `spec`.
    ///
    /// The only path from a policy to an [`ExecutionSpec`] in this module, and
    /// it is fallible on purpose. A document that lowers to nothing would
    /// otherwise produce a spec with an empty requirement list, which
    /// [`negotiate`](crate::plan::negotiate) resolves to
    /// [`LaunchPosture::Ready`](crate::plan::LaunchPosture::Ready) against any
    /// backend at all — including one that enforces nothing. "Ready" would then
    /// mean "we asked for nothing and got it", which is the precise shape of
    /// the failure this Epic exists to prevent.
    ///
    /// # Errors
    ///
    /// [`NoRequirementsLowered`] when the document expressed no restriction
    /// this execution boundary can carry.
    pub fn apply_to(&self, spec: ExecutionSpec) -> Result<ExecutionSpec, NoRequirementsLowered> {
        if self.requirements.is_empty() {
            return Err(NoRequirementsLowered {
                domains: self.domains.clone(),
            });
        }
        let mut spec = spec;
        for requirement in &self.requirements {
            spec = spec.with_requirement(requirement.clone());
        }
        Ok(spec)
    }
}

/// A policy that expressed no restriction this execution boundary can carry.
///
/// Distinct from a refusal by [`negotiate`](crate::plan::negotiate): no backend
/// was consulted and none is at fault. The document either restricts nothing,
/// or restricts only dimensions with no [`CapabilityDomain`] — and in both
/// cases launching would produce a boundary that asked for nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoRequirementsLowered {
    domains: Vec<DomainLowering>,
}

impl NoRequirementsLowered {
    /// What became of every domain, so the refusal can name the gaps.
    pub fn domains(&self) -> &[DomainLowering] {
        &self.domains
    }

    /// Domains the policy schema cannot express at all.
    pub fn unrepresentable(&self) -> impl Iterator<Item = &DomainLowering> {
        self.domains.iter().filter(|d| d.coverage.is_unrepresentable())
    }
}

impl core::fmt::Display for NoRequirementsLowered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the effective policy lowered to no execution requirement ({} of {} capability \
             domains cannot be expressed by the policy schema at all); an unrestricted \
             boundary is not what an empty requirement set means",
            self.unrepresentable().count(),
            self.domains.len(),
        )
    }
}

impl std::error::Error for NoRequirementsLowered {}

/// Lower a canonical policy document into execution capability requirements.
///
/// Deterministic and pure. Requirements come out in [`CapabilityDomain::ALL`]
/// order, and every domain gets a [`DomainLowering`] whether or not it produced
/// one.
///
/// Every requirement is [`RequirementIntent::PreventBeforeEffect`]: the policy
/// nodes read here are denials and allow-lists, which state what must not
/// happen, and there is no node by which an author asks only to be told about
/// something. A weaker posture is an operator selection carried in
/// [`LoweringOptions`], never inferred from the document.
///
/// [`RequirementIntent::PreventBeforeEffect`]: crate::spec::RequirementIntent::PreventBeforeEffect
pub fn lower_policy(policy: &PolicyDocument, options: &LoweringOptions) -> PolicyLowering {
    let mut requirements = Vec::new();
    let mut domains = Vec::with_capacity(CapabilityDomain::ALL.len());

    for domain in CapabilityDomain::ALL.iter().copied() {
        let (coverage, scope, residual_gaps) = match domain {
            CapabilityDomain::FilesystemRead => filesystem_read(policy),
            CapabilityDomain::FilesystemWrite => filesystem_write(policy),
            CapabilityDomain::NetworkEgress => network_egress(policy),
            CapabilityDomain::NameResolution => (unrepresentable(NAME_RESOLUTION_GAP), None, Vec::new()),
            CapabilityDomain::Syscall => syscall(policy),
            CapabilityDomain::ProcessCreation => process_creation(policy),
            CapabilityDomain::Ipc => (unrepresentable(IPC_GAP), None, Vec::new()),
            CapabilityDomain::Credential => (unrepresentable(CREDENTIAL_GAP), None, Vec::new()),
            CapabilityDomain::Resource => (unrepresentable(RESOURCE_GAP), None, Vec::new()),
        };

        if let Some(scope) = scope {
            // Descendant coverage stays at `ControlRequirement::prevent`'s
            // `ProcessTree` default. No policy node expresses descendant scope,
            // so there is nothing to lower here — and ADR 0035 §6 makes the
            // strict reading the correct one to keep when policy is silent: an
            // agent that escapes a control by spawning a child was never
            // subject to it.
            requirements.push(
                ControlRequirement::prevent(domain)
                    .with_posture(options.posture_for(domain))
                    .with_scope(scope),
            );
        }
        domains.push(DomainLowering {
            domain,
            coverage,
            residual_gaps,
        });
    }

    PolicyLowering {
        requirements,
        domains,
        unmapped: unmapped_statements(policy),
    }
}

// ---------------------------------------------------------------------------
// Per-domain lowering.
//
// Each returns the coverage, the scope to build a requirement from (`None` when
// no requirement is produced) and the residual gaps for the domain.
// ---------------------------------------------------------------------------

type DomainResult = (DomainCoverage, Option<RequirementScope>, Vec<String>);

fn filesystem_read(policy: &PolicyDocument) -> DomainResult {
    filesystem(
        policy,
        &[Capability::FileRead],
        policy.filesystem.as_ref().and_then(|fs| fs.read.as_ref()),
        "filesystem.read.allow",
        Vec::new(),
    )
}

fn filesystem_write(policy: &PolicyDocument) -> DomainResult {
    // `file_write` and `file_delete` both land on this one domain, which also
    // makes `aa_core::capability_is_denied`'s "a write deny implies a delete
    // deny" rule a no-op here: either capability alone already produces the
    // requirement.
    filesystem(
        policy,
        &[Capability::FileWrite, Capability::FileDelete],
        policy.filesystem.as_ref().and_then(|fs| fs.write.as_ref()),
        "filesystem.write.allow",
        vec![FILESYSTEM_VERB_GAP.to_string()],
    )
}

/// Both filesystem domains, which differ only in which capabilities and which
/// path node they read (AAASM-5751).
///
/// Four outcomes, in strictness order, and the ordering is the security
/// content:
///
/// 1. **A whole-domain capability restriction is in force** — the domain is
///    prevented outright. This outranks any path scope, exactly as a
///    `network_outbound` denial outranks `network.allowlist`: lowering the
///    narrower node under a broader denial would emit a requirement permitting
///    paths the same document forbids.
/// 2. **A path scope is stated and permits nothing** — an in-force restriction
///    with an empty permitted set. Also whole-domain prevention, because
///    "permit nothing" and "prevent everything" are the same requirement.
/// 3. **A path scope is stated and names prefixes** — enumerated selectors.
/// 4. **Neither node said anything** — [`DomainCoverage::NotStated`]. No
///    requirement, and no statement that the domain is safe.
///
/// The path-scope residual gap is reported exactly in the cases whose emitted
/// requirement is [`RequirementScope::Whole`], because those requirements are
/// genuinely not scoped by path. Reporting it against an enumerated scope would
/// name a gap the document has closed.
fn filesystem(
    policy: &PolicyDocument,
    capabilities: &[Capability],
    scope: Option<&aa_security::policy::PathScope>,
    node: &str,
    extra_gaps: Vec<String>,
) -> DomainResult {
    let whole_domain_gaps = || {
        let mut gaps = vec![
            FILESYSTEM_PATH_SCOPE_GAP.to_string(),
            FILESYSTEM_BACKEND_DEFAULTS_GAP.to_string(),
        ];
        gaps.extend(extra_gaps.iter().cloned());
        gaps
    };
    let scoped_gaps = || {
        let mut gaps = vec![
            FILESYSTEM_PREFIX_SEMANTICS_GAP.to_string(),
            FILESYSTEM_BACKEND_DEFAULTS_GAP.to_string(),
        ];
        gaps.extend(extra_gaps.iter().cloned());
        gaps
    };

    if let Some(sourced_from) = restriction_sources(policy, capabilities) {
        return (
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                sourced_from,
            },
            Some(RequirementScope::Whole),
            whole_domain_gaps(),
        );
    }

    let Some(scope) = scope else {
        return (
            not_stated(&format!("{CAPABILITY_NODE} / {node}"), FILESYSTEM_ABSENT_MEANING),
            None,
            whole_domain_gaps(),
        );
    };

    if scope.permits_nothing() {
        return (
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                sourced_from: vec![format!("{node} is in force and permits no path")],
            },
            Some(RequirementScope::Whole),
            whole_domain_gaps(),
        );
    }

    (
        DomainCoverage::Lowered {
            granularity: ScopeGranularity::Enumerated,
            sourced_from: vec![format!("{node} ({} path prefix(es))", scope.allow.len())],
        },
        Some(RequirementScope::Selectors(
            scope.iter().map(permit_only_selector).collect(),
        )),
        scoped_gaps(),
    )
}

/// Unlike [`filesystem`] and [`network_egress`], this domain cannot reuse the
/// generic [`restriction_sources`] over both `agent_spawn` and `terminal_exec`
/// (AAASM-5816).
///
/// `restriction_sources`'s allow-list-omission rule is correct per capability,
/// but this domain has no per-capability scope — it is a single whole-domain
/// boolean, so a restriction sourced from *either* capability produces the
/// exact same [`RequirementScope::Whole`] requirement as a restriction sourced
/// from *both*. Feeding it `[AgentSpawn, TerminalExec]` therefore let an
/// in-force allow-list that explicitly grants `terminal_exec` still collapse
/// to whole-domain prevention, purely because `agent_spawn` — a capability
/// with no wired [`GovernanceAction`](aa_core::GovernanceAction) anywhere in
/// the product yet — was not *also* named. `capabilities: allow:
/// [terminal_exec]` and `capabilities: deny: [terminal_exec]` lowered to the
/// same requirement, which is backwards: allow must not restrict what it
/// explicitly grants.
///
/// So the allow-list omission check here looks at `terminal_exec` alone — the
/// only capability this domain actually enforces (`GovernanceAction::ProcessExec`
/// maps to it, not to `agent_spawn`). An explicit `capabilities.deny` of
/// either capability still restricts the domain; that half was never the bug
/// and stays exactly as tested by
/// [`tests::agent_spawn_and_terminal_exec_each_reach_process_creation`].
fn process_creation(policy: &PolicyDocument) -> DomainResult {
    let gaps = vec![PROCESS_DESCENDANT_CEILING_GAP.to_string()];
    let mut sources = Vec::new();
    if let Some(set) = policy.capabilities.as_ref() {
        for capability in [Capability::AgentSpawn, Capability::TerminalExec] {
            if set.deny.contains(&capability) {
                sources.push(format!("capabilities.deny[{capability}]"));
            }
        }
        if !set.allow.is_empty() && !set.allow.contains(&Capability::TerminalExec) {
            sources.push("capabilities.allow omits terminal_exec (an allow-list restriction is in force)".to_string());
        }
    }
    if sources.is_empty() {
        (not_stated(CAPABILITY_NODE, CAPABILITY_ABSENT_MEANING), None, gaps)
    } else {
        (
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                sourced_from: sources,
            },
            Some(RequirementScope::Whole),
            gaps,
        )
    }
}

/// Egress has two policy sources at different granularities, and the stricter
/// one wins.
///
/// A `network_outbound` denial stops egress outright; `network.allowlist` names
/// the destinations that remain permitted. A document carrying both means "none
/// of these either", so the denial is lowered and the allow-list is not — the
/// reverse would lower a requirement that permits hosts the document denies.
fn network_egress(policy: &PolicyDocument) -> DomainResult {
    let gaps = vec![
        NETWORK_PORT_PROTOCOL_GAP.to_string(),
        NETWORK_NAME_RESOLUTION_GAP.to_string(),
    ];

    if let Some(sourced_from) = restriction_sources(policy, &[Capability::NetworkOutbound]) {
        return (
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                sourced_from,
            },
            Some(RequirementScope::Whole),
            gaps,
        );
    }

    let allowlist = policy.egress_allowlist();
    if allowlist.is_empty() {
        return (not_stated(NETWORK_NODE, NETWORK_ABSENT_MEANING), None, gaps);
    }
    (
        DomainCoverage::Lowered {
            granularity: ScopeGranularity::Enumerated,
            sourced_from: vec![format!("network.allowlist ({} host pattern(s))", allowlist.len())],
        },
        Some(RequirementScope::Selectors(
            allowlist.iter().map(|host| permit_only_selector(host)).collect(),
        )),
        gaps,
    )
}

/// Three outcomes, in strictness order, mirroring [`filesystem`] because the
/// two nodes pose the same question (AAASM-5753).
///
/// 1. **The node is absent** — [`DomainCoverage::NotStated`]. No requirement,
///    and no statement that the domain is safe.
/// 2. **The node is stated and permits nothing** — an in-force restriction with
///    an empty permitted set, which is whole-domain prevention. Reported as
///    [`RequirementScope::Whole`] rather than as zero selectors, because an
///    empty selector list renders as `selectors[0]:` and reads as a scope that
///    forgot to name its members rather than as the strictest posture the
///    schema can express.
/// 3. **The node is stated and names calls** — enumerated selectors.
fn syscall(policy: &PolicyDocument) -> DomainResult {
    let gaps = vec![
        SYSCALL_VOCABULARY_GAP.to_string(),
        SYSCALL_FAILURE_SEMANTICS_GAP.to_string(),
    ];
    let Some(allowlist) = policy.syscall_allowlist.as_ref() else {
        return (not_stated(SYSCALL_NODE, SYSCALL_ABSENT_MEANING), None, gaps);
    };
    if allowlist.permits_nothing() {
        return (
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                sourced_from: vec![format!("{SYSCALL_NODE} is in force and permits no syscall")],
            },
            Some(RequirementScope::Whole),
            gaps,
        );
    }
    (
        DomainCoverage::Lowered {
            granularity: ScopeGranularity::Enumerated,
            sourced_from: vec![format!("syscalls.allow ({} syscall(s))", allowlist.syscalls.len())],
        },
        Some(RequirementScope::Selectors(
            allowlist.iter().map(|call| permit_only_selector(call.name())).collect(),
        )),
        gaps,
    )
}

/// The policy nodes that restrict `capabilities`, or `None` if none do.
///
/// A capability is restricted when it is explicitly denied, or when an
/// allow-list restriction is in force and omits it — the same two-sided reading
/// `aa_gateway::PolicyEngine::capability_guard` applies at L7, so the execution
/// boundary and the gateway do not disagree about what a document means.
///
/// The canonical AST has no `allow_restricted` flag (`aa_core::CapabilitySet`
/// does, and `aa_policy::PolicyDocument::to_canonical` drops it), so "a
/// restriction is in force" is read here as a non-empty `allow`. The case the
/// flag exists for — a multi-tier cascade whose disjoint allow-lists intersect
/// to empty — therefore cannot be seen from this AST, and is reported as a
/// document that stated nothing rather than as a deny-all.
fn restriction_sources(policy: &PolicyDocument, capabilities: &[Capability]) -> Option<Vec<String>> {
    let set = policy.capabilities.as_ref()?;
    let allow_restricted = !set.allow.is_empty();
    let mut sources = Vec::new();
    for capability in capabilities {
        if set.deny.contains(capability) {
            sources.push(format!("capabilities.deny[{capability}]"));
        } else if allow_restricted && !set.allow.contains(capability) {
            sources.push(format!(
                "capabilities.allow omits {capability} (an allow-list restriction is in force)"
            ));
        }
    }
    (!sources.is_empty()).then_some(sources)
}

/// Restrictions the document expressed that no [`CapabilityDomain`] carries.
fn unmapped_statements(policy: &PolicyDocument) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(set) = policy.capabilities.as_ref() {
        for capability in &set.deny {
            match capability {
                Capability::FileRead
                | Capability::FileWrite
                | Capability::FileDelete
                | Capability::NetworkOutbound
                | Capability::TerminalExec
                | Capability::AgentSpawn => {}
                Capability::NetworkInbound | Capability::McpTool(_) | Capability::Model(_) => out.push(format!(
                    "capabilities.deny[{capability}] has no execution capability domain; it is \
                     governed at the control plane, not by this boundary"
                )),
            }
        }
    }
    let denied_tools = policy.tools.iter().filter(|tool| !tool.allow).count();
    if denied_tools > 0 {
        out.push(format!(
            "{denied_tools} tool rule(s) deny a named tool; tool identity has no execution \
             capability domain and is governed at the control plane"
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Gap and node text.
//
// Held as constants so the same words reach `--dry-run`, evidence and a test,
// and so a change to what the schema can express is a one-line diff rather than
// a search for prose.
// ---------------------------------------------------------------------------

const CAPABILITY_NODE: &str = "capabilities.deny / capabilities.allow";
const CAPABILITY_ABSENT_MEANING: &str =
    "no capability restriction was declared; the document neither grants nor withholds this domain";
const FILESYSTEM_ABSENT_MEANING: &str = "neither the capability node nor the filesystem path node declared \
     a restriction; the document neither grants nor withholds this domain";

const NETWORK_NODE: &str = "network.allowlist";
const NETWORK_ABSENT_MEANING: &str = "an absent or empty allowlist is documented as no egress restriction \
     (aa_security::policy::document::NetworkPolicy)";

const SYSCALL_NODE: &str = "syscalls.allow";
const SYSCALL_ABSENT_MEANING: &str = "an absent allowlist leaves syscalls unconstrained by this node. It \
     is the operator having said nothing, which is a different fact from a stated allowlist that permits \
     no call — that one is in force, and is reported here as whole-domain prevention (AAASM-5753)";

const FILESYSTEM_PATH_SCOPE_GAP: &str = "path scope: this requirement applies to every path. The schema \
     can express one (filesystem.read.allow / filesystem.write.allow, AAASM-5751) and this document either \
     denied the capability outright or left the path node unstated, so nothing narrowed it";
const FILESYSTEM_PREFIX_SEMANTICS_GAP: &str = "prefix semantics: a path scope names absolute directory \
     prefixes and nothing finer. There is no node for globs, extensions, file modes, or for what a symlink \
     or bind mount out of a permitted prefix should mean — a backend resolves those, and ADR 0035 asks the \
     policy to state them";
const FILESYSTEM_BACKEND_DEFAULTS_GAP: &str = "the sensitive-path deny defaults in \
     aa_security::policy::lower_to_ebpf (/etc, /root/.ssh, /var/run/secrets) are that layer's own defaults \
     rather than policy content, and are deliberately not re-derived here";
const FILESYSTEM_VERB_GAP: &str = "create, rename, write and delete are not separable: file_write and \
     file_delete both land on this one domain";

const NETWORK_PORT_PROTOCOL_GAP: &str =
    "port and protocol scope: ADR 0035 asks a network control to be scoped by destination, port and \
     protocol; network.allowlist carries host patterns only";
const NETWORK_NAME_RESOLUTION_GAP: &str = "hostname resolution is a separate domain and this allowlist does \
     not reach it; see the NameResolution entry";

const SYSCALL_VOCABULARY_GAP: &str = "the policy syscall vocabulary is a closed 15-name set \
     (aa_security::policy::syscall::Syscall); a call outside it cannot be named by an author, in either \
     direction";
const SYSCALL_FAILURE_SEMANTICS_GAP: &str = "ADR 0035 asks a syscall control to state its errno / kill / \
     trap / observe semantics; no policy node expresses which one is required";

const PROCESS_DESCENDANT_CEILING_GAP: &str = "no policy node expresses a maximum descendant count; the \
     capability grants are whole-domain booleans";

const NAME_RESOLUTION_GAP: &str = "no policy node names hostname resolution. network.allowlist is the \
     nearest, and it scopes egress destinations rather than resolution, which ADR 0035 separates because a \
     lookup can exfiltrate without an egress connection";
const IPC_GAP: &str = "no policy node names Unix sockets, shared memory, namespaces or inherited descriptors";
const CREDENTIAL_GAP: &str = "no policy node expresses ambient authority. data.credential_action is the \
     nearest and it is DLP redaction of scanned payload content (block / redact / alert), not control over \
     the environment variables, descriptors, sockets or tokens a child inherits (ADR 0035 §9)";
const RESOURCE_GAP: &str = "no policy node expresses a numeric ceiling. budget is USD spend, not CPU, \
     memory, PID count, wall clock, file size or open descriptors";

fn not_stated(node: &str, schema_default: &str) -> DomainCoverage {
    DomainCoverage::NotStated {
        node: node.to_string(),
        schema_default: schema_default.to_string(),
    }
}

fn unrepresentable(detail: &str) -> DomainCoverage {
    DomainCoverage::PolicyCannotExpress {
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use aa_security::policy::{CapabilitySet, FilesystemPolicy, NetworkPolicy, PathScope, SyscallAllowlist, ToolRule};

    use super::*;
    use crate::spec::{DescendantRequirement, IdentityRef, RequirementIntent};

    fn empty() -> PolicyDocument {
        PolicyDocument::default()
    }

    fn path_scope(paths: &[&str]) -> PathScope {
        PathScope::from_paths(paths).expect("fixture paths are valid")
    }

    /// A document whose only restriction is a filesystem path scope.
    fn with_paths(read: Option<&[&str]>, write: Option<&[&str]>) -> PolicyDocument {
        PolicyDocument {
            filesystem: Some(FilesystemPolicy {
                read: read.map(path_scope),
                write: write.map(path_scope),
            }),
            ..PolicyDocument::default()
        }
    }

    fn with_denies(denied: &[Capability]) -> PolicyDocument {
        let mut set = CapabilitySet::default();
        for capability in denied {
            set.deny.insert(capability.clone());
        }
        PolicyDocument {
            capabilities: Some(set),
            ..PolicyDocument::default()
        }
    }

    fn with_allows(allowed: &[Capability]) -> PolicyDocument {
        let mut set = CapabilitySet::default();
        for capability in allowed {
            set.allow.insert(capability.clone());
        }
        PolicyDocument {
            capabilities: Some(set),
            ..PolicyDocument::default()
        }
    }

    fn lower(policy: &PolicyDocument) -> PolicyLowering {
        lower_policy(policy, &LoweringOptions::strict())
    }

    fn coverage_of(lowering: &PolicyLowering, domain: CapabilityDomain) -> &DomainCoverage {
        &lowering
            .coverage(domain)
            .expect("every domain in CapabilityDomain::ALL has a lowering")
            .coverage
    }

    fn requirement_for(lowering: &PolicyLowering, domain: CapabilityDomain) -> Option<&ControlRequirement> {
        lowering.requirements().iter().find(|r| r.domain() == domain)
    }

    // -----------------------------------------------------------------------
    // Exhaustiveness: a domain can never go missing from the report.
    // -----------------------------------------------------------------------

    /// A domain absent from the output would be indistinguishable from one
    /// considered and found unrepresentable, which is the exact confusion the
    /// module is shaped against. Order is pinned too, because the requirement
    /// list is claimed to be deterministic.
    #[test]
    fn every_capability_domain_gets_a_lowering_in_a_fixed_order() {
        let lowering = lower(&empty());
        let reported: Vec<CapabilityDomain> = lowering.domains().iter().map(|d| d.domain).collect();
        assert_eq!(reported, CapabilityDomain::ALL.to_vec());
    }

    #[test]
    fn lowering_is_deterministic() {
        let mut policy = with_denies(&[Capability::FileWrite, Capability::AgentSpawn]);
        policy.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string(), "b.example".to_string()],
        });
        policy.syscall_allowlist = Some(SyscallAllowlist::from_names(["write", "read"]).unwrap());
        policy.filesystem = Some(FilesystemPolicy {
            read: Some(path_scope(&["/usr/share", "/workspace"])),
            write: Some(path_scope(&["/workspace/build"])),
        });
        assert_eq!(lower(&policy), lower(&policy));
    }

    // -----------------------------------------------------------------------
    // Syscall — the one domain policy can enumerate cleanly.
    // -----------------------------------------------------------------------

    /// Both directions. A stated allowlist lowers to enumerated selectors; an
    /// absent one lowers to nothing and says the document was silent. Asserting
    /// only the first would pass for a function that emits selectors
    /// unconditionally.
    #[test]
    fn syscall_allowlist_lowers_to_permitted_selectors_and_absence_does_not() {
        let mut policy = empty();
        policy.syscall_allowlist = Some(SyscallAllowlist::from_names(["read", "write"]).unwrap());
        let stated = lower(&policy);

        let requirement = requirement_for(&stated, CapabilityDomain::Syscall).expect("a stated allowlist lowers");
        assert_eq!(
            requirement.scope(),
            &RequirementScope::Selectors(vec!["permit-only:read".to_string(), "permit-only:write".to_string()])
        );
        assert!(matches!(
            coverage_of(&stated, CapabilityDomain::Syscall),
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::Enumerated,
                ..
            }
        ));

        let silent = lower(&empty());
        assert!(requirement_for(&silent, CapabilityDomain::Syscall).is_none());
        assert!(matches!(
            coverage_of(&silent, CapabilityDomain::Syscall),
            DomainCoverage::NotStated { .. }
        ));
    }

    /// The selector polarity is the whole reason the prefix exists: a backend
    /// reading `read` alone would have no way to tell "permit only these" from
    /// "stop these", and the two are exact opposites.
    #[test]
    fn permitted_selectors_round_trip_and_a_bare_name_is_not_one() {
        assert_eq!(permitted_selector(&permit_only_selector("read")), Some("read"));
        assert_eq!(permitted_selector("read"), None);
        assert_eq!(permitted_selector("deny:read"), None);
    }

    // -----------------------------------------------------------------------
    // Network egress — enumerated, but only by host.
    // -----------------------------------------------------------------------

    #[test]
    fn network_allowlist_lowers_to_permitted_hosts_and_absence_does_not() {
        let mut policy = empty();
        policy.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        let stated = lower(&policy);
        assert_eq!(
            requirement_for(&stated, CapabilityDomain::NetworkEgress)
                .expect("a stated allowlist lowers")
                .scope(),
            &RequirementScope::Selectors(vec!["permit-only:api.openai.com".to_string()])
        );

        let silent = lower(&empty());
        assert!(requirement_for(&silent, CapabilityDomain::NetworkEgress).is_none());
        assert!(matches!(
            coverage_of(&silent, CapabilityDomain::NetworkEgress),
            DomainCoverage::NotStated { .. }
        ));
    }

    /// An empty `allowlist:` is documented as "no egress restriction", so it is
    /// the document saying nothing rather than the document permitting nothing.
    /// Lowering it to an empty permitted set would invert its meaning into
    /// deny-all.
    #[test]
    fn an_empty_allowlist_is_silence_not_a_deny_all() {
        let mut policy = empty();
        policy.network = Some(NetworkPolicy { allowlist: Vec::new() });
        let lowering = lower(&policy);
        assert!(requirement_for(&lowering, CapabilityDomain::NetworkEgress).is_none());
        assert!(matches!(
            coverage_of(&lowering, CapabilityDomain::NetworkEgress),
            DomainCoverage::NotStated { .. }
        ));
    }

    /// A document carrying both means "none of these either". Lowering the
    /// allowlist would emit a requirement permitting hosts the same document
    /// denies outright.
    #[test]
    fn a_network_outbound_deny_outranks_the_allowlist() {
        let mut policy = with_denies(&[Capability::NetworkOutbound]);
        policy.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        let requirement = requirement_for(&lower(&policy), CapabilityDomain::NetworkEgress)
            .expect("a deny lowers")
            .clone();
        assert_eq!(requirement.scope(), &RequirementScope::Whole);
    }

    // -----------------------------------------------------------------------
    // Filesystem and process creation — booleans, and only booleans.
    // -----------------------------------------------------------------------

    #[test]
    fn file_read_deny_lowers_whole_domain_only_and_records_the_missing_path_scope() {
        let lowering = lower(&with_denies(&[Capability::FileRead]));
        let requirement = requirement_for(&lowering, CapabilityDomain::FilesystemRead).expect("a deny lowers");
        assert_eq!(requirement.scope(), &RequirementScope::Whole);
        assert!(matches!(
            coverage_of(&lowering, CapabilityDomain::FilesystemRead),
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                ..
            }
        ));

        // Lowered is not complete: the domain is expressed, its path scope is
        // not. Collapsing those two would be the over-read this field exists to
        // stop.
        let entry = lowering.coverage(CapabilityDomain::FilesystemRead).unwrap();
        assert!(!entry.residual_gaps.is_empty());
        assert!(!entry.is_complete());
    }

    /// Write and delete are separate policy verbs and one execution domain, so
    /// either alone must produce the requirement.
    #[test]
    fn file_write_and_file_delete_each_reach_filesystem_write() {
        for capability in [Capability::FileWrite, Capability::FileDelete] {
            let lowering = lower(&with_denies(std::slice::from_ref(&capability)));
            assert!(
                requirement_for(&lowering, CapabilityDomain::FilesystemWrite).is_some(),
                "{capability} did not reach FilesystemWrite"
            );
        }
        // The control: neither verb denied, no requirement.
        assert!(requirement_for(&lower(&empty()), CapabilityDomain::FilesystemWrite).is_none());
    }

    #[test]
    fn agent_spawn_and_terminal_exec_each_reach_process_creation() {
        for capability in [Capability::AgentSpawn, Capability::TerminalExec] {
            let lowering = lower(&with_denies(std::slice::from_ref(&capability)));
            assert!(
                requirement_for(&lowering, CapabilityDomain::ProcessCreation).is_some(),
                "{capability} did not reach ProcessCreation"
            );
        }
        assert!(requirement_for(&lower(&empty()), CapabilityDomain::ProcessCreation).is_none());
    }

    /// The same two-sided reading the gateway applies at L7: an in-force
    /// allow-list restricts what it omits. Both halves are asserted, so the
    /// test cannot pass against a function that restricts everything or
    /// nothing.
    #[test]
    fn an_in_force_allow_list_restricts_the_capabilities_it_omits() {
        let lowering = lower(&with_allows(&[Capability::FileRead]));
        assert!(
            requirement_for(&lowering, CapabilityDomain::FilesystemRead).is_none(),
            "file_read is in the allow-list and must not be restricted"
        );
        assert!(
            requirement_for(&lowering, CapabilityDomain::FilesystemWrite).is_some(),
            "file_write is omitted from an in-force allow-list and must be restricted"
        );
    }

    // -----------------------------------------------------------------------
    // Filesystem path scope (AAASM-5751).
    // -----------------------------------------------------------------------

    /// Both directions, and the granularity is what is asserted rather than
    /// merely "a requirement exists": a stated path scope lowers to enumerated
    /// permitted-prefix selectors, and an unstated one lowers to nothing at
    /// all. Asserting only the first would pass for a function that emits
    /// selectors unconditionally.
    #[test]
    fn a_stated_path_scope_lowers_to_enumerated_selectors_and_absence_does_not() {
        let stated = lower(&with_paths(Some(&["/workspace", "/usr/share/dict"]), None));

        let requirement =
            requirement_for(&stated, CapabilityDomain::FilesystemRead).expect("a stated path scope lowers");
        assert_eq!(
            requirement.scope(),
            &RequirementScope::Selectors(vec![
                "permit-only:/usr/share/dict".to_string(),
                "permit-only:/workspace".to_string(),
            ])
        );
        assert!(matches!(
            coverage_of(&stated, CapabilityDomain::FilesystemRead),
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::Enumerated,
                ..
            }
        ));

        // The verb the document did not scope stays unstated: scoping reads
        // must not fabricate a write requirement.
        assert!(requirement_for(&stated, CapabilityDomain::FilesystemWrite).is_none());
        assert!(matches!(
            coverage_of(&stated, CapabilityDomain::FilesystemWrite),
            DomainCoverage::NotStated { .. }
        ));

        // And with no path node at all, neither verb lowers.
        let silent = lower(&empty());
        assert!(requirement_for(&silent, CapabilityDomain::FilesystemRead).is_none());
        assert!(matches!(
            coverage_of(&silent, CapabilityDomain::FilesystemRead),
            DomainCoverage::NotStated { .. }
        ));
    }

    /// The selector polarity convention is reused, not re-invented: a lowered
    /// path reads back through the same `permitted_selector` a backend already
    /// uses for syscalls and hosts, with no domain branch.
    #[test]
    fn a_lowered_path_reads_back_through_the_existing_selector_convention() {
        let lowering = lower(&with_paths(Some(&["/workspace"]), None));
        let RequirementScope::Selectors(selectors) = requirement_for(&lowering, CapabilityDomain::FilesystemRead)
            .expect("a stated path scope lowers")
            .scope()
        else {
            panic!("a stated path scope lowers to selectors");
        };
        assert_eq!(
            selectors
                .iter()
                .filter_map(|s| permitted_selector(s))
                .collect::<Vec<_>>(),
            vec!["/workspace"]
        );
    }

    #[test]
    fn each_verb_reaches_only_its_own_domain() {
        let write_only = lower(&with_paths(None, Some(&["/workspace/build"])));
        assert!(requirement_for(&write_only, CapabilityDomain::FilesystemWrite).is_some());
        assert!(requirement_for(&write_only, CapabilityDomain::FilesystemRead).is_none());

        let read_only = lower(&with_paths(Some(&["/workspace"]), None));
        assert!(requirement_for(&read_only, CapabilityDomain::FilesystemRead).is_some());
        assert!(requirement_for(&read_only, CapabilityDomain::FilesystemWrite).is_none());
    }

    /// An in-force scope that permits nothing is the *most* restrictive thing
    /// an author can write, so it must lower to whole-domain prevention — not
    /// to an empty selector list, which a backend could read as "no selectors,
    /// nothing to do", and not to silence.
    #[test]
    fn a_scope_that_permits_nothing_lowers_to_whole_domain_prevention() {
        let lowering = lower(&with_paths(Some(&[]), None));
        let requirement =
            requirement_for(&lowering, CapabilityDomain::FilesystemRead).expect("an in-force empty scope lowers");
        assert_eq!(requirement.scope(), &RequirementScope::Whole);
        assert!(matches!(
            coverage_of(&lowering, CapabilityDomain::FilesystemRead),
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                ..
            }
        ));

        // The control: an *absent* verb, which is the case an empty scope is
        // easy to be confused with, lowers to nothing.
        assert!(requirement_for(
            &lower(&with_paths(None, Some(&["/x"]))),
            CapabilityDomain::FilesystemRead
        )
        .is_none());
    }

    /// A whole-domain capability denial outranks the path scope, the same way
    /// a `network_outbound` denial outranks `network.allowlist`. Lowering the
    /// path scope here would emit a requirement permitting `/workspace` in a
    /// document that denies reads outright.
    #[test]
    fn a_file_read_deny_outranks_the_path_scope() {
        let mut policy = with_denies(&[Capability::FileRead]);
        policy.filesystem = Some(FilesystemPolicy {
            read: Some(path_scope(&["/workspace"])),
            write: None,
        });
        let lowering = lower(&policy);
        let requirement = requirement_for(&lowering, CapabilityDomain::FilesystemRead).expect("a deny lowers");
        assert_eq!(requirement.scope(), &RequirementScope::Whole);

        // The control: the identical path scope without the deny lowers to
        // selectors, so the whole-domain result is attributable to the deny.
        let mut permitted = policy.clone();
        permitted.capabilities = None;
        assert!(matches!(
            requirement_for(&lower(&permitted), CapabilityDomain::FilesystemRead)
                .expect("a stated path scope lowers")
                .scope(),
            RequirementScope::Selectors(_)
        ));
    }

    /// The same reading for the other half of the two-sided capability rule: an
    /// in-force allow-list that omits `file_write` restricts the whole domain,
    /// which outranks a narrower write scope in the same document.
    #[test]
    fn an_in_force_allow_list_omission_outranks_the_path_scope() {
        let mut policy = with_allows(&[Capability::FileRead]);
        policy.filesystem = Some(FilesystemPolicy {
            read: None,
            write: Some(path_scope(&["/workspace/build"])),
        });
        assert_eq!(
            requirement_for(&lower(&policy), CapabilityDomain::FilesystemWrite)
                .expect("an omitted capability lowers")
                .scope(),
            &RequirementScope::Whole
        );
    }

    /// The residual-gap list must move with what the document actually closed.
    /// A path-scoped requirement no longer carries the "applies to every path"
    /// gap, and a whole-domain one still does — the two lists must differ, or
    /// the gap report is decorative.
    #[test]
    fn the_path_scope_gap_is_reported_only_where_the_requirement_is_unscoped() {
        let scoped = lower(&with_paths(Some(&["/workspace"]), None));
        let scoped_gaps = &scoped.coverage(CapabilityDomain::FilesystemRead).unwrap().residual_gaps;
        assert!(
            !scoped_gaps.iter().any(|g| g.contains("applies to every path")),
            "a path-scoped requirement must not report an unscoped-path gap: {scoped_gaps:?}"
        );
        assert!(
            scoped_gaps.iter().any(|g| g.contains("prefix semantics")),
            "a path-scoped requirement must still report what prefixes cannot express: {scoped_gaps:?}"
        );

        let whole = lower(&with_denies(&[Capability::FileRead]));
        let whole_gaps = &whole.coverage(CapabilityDomain::FilesystemRead).unwrap().residual_gaps;
        assert!(
            whole_gaps.iter().any(|g| g.contains("applies to every path")),
            "an unscoped requirement must report that it is unscoped: {whole_gaps:?}"
        );

        // Neither is complete: something is still unexpressible in both cases,
        // so a reader cannot take either as a full boundary.
        assert!(!scoped.coverage(CapabilityDomain::FilesystemRead).unwrap().is_complete());
        assert!(!whole.coverage(CapabilityDomain::FilesystemRead).unwrap().is_complete());
    }

    /// The negative control the ticket names. An **unset** path node must never
    /// become a silent allow: it produces no requirement, it is reported as
    /// `not_stated` rather than omitted, and a document carrying nothing else
    /// refuses to produce an execution spec at all.
    #[test]
    fn an_unset_path_node_is_a_refusal_not_a_silent_allow() {
        let lowering = lower(&empty());
        for domain in [CapabilityDomain::FilesystemRead, CapabilityDomain::FilesystemWrite] {
            assert!(
                requirement_for(&lowering, domain).is_none(),
                "{domain} lowered a requirement from a document that stated nothing"
            );
            let entry = lowering.coverage(domain).unwrap();
            assert_eq!(
                entry.coverage.as_str(),
                "not_stated",
                "{domain} must be reported, not omitted"
            );
            let DomainCoverage::NotStated { node, schema_default } = &entry.coverage else {
                unreachable!("checked immediately above");
            };
            assert!(
                node.contains("filesystem."),
                "{domain} must name the path node an operator could have written: {node}"
            );
            assert!(
                !schema_default.contains("unrestricted") && !schema_default.contains("permitted"),
                "{domain}'s absent-node meaning must not read as a grant: {schema_default}"
            );
        }

        // The refusal itself: nothing else in this document lowers either, so
        // the boundary refuses rather than reporting an unrestricted launch as
        // ready.
        lower(&empty())
            .apply_to(ExecutionSpec::new("python", IdentityRef::root("agent-1")))
            .expect_err("a document that scopes nothing must not yield a spec");

        // The control: stating the path node — and nothing else — is enough to
        // produce a spec, so the refusal above is attributable to the unset
        // node and not to `apply_to` refusing unconditionally.
        let attached = lower(&with_paths(Some(&["/workspace"]), None))
            .apply_to(ExecutionSpec::new("python", IdentityRef::root("agent-1")))
            .expect("a stated path scope yields a spec");
        assert_eq!(attached.requirements().len(), 1);
    }

    // -----------------------------------------------------------------------
    // The property the ticket exists for.
    // -----------------------------------------------------------------------

    /// Four domains have no policy node at all. Each must produce no
    /// requirement *and* say why — an absent requirement alone is what a reader
    /// mistakes for "nothing to restrict here".
    #[test]
    fn domains_with_no_policy_node_are_reported_rather_than_left_absent() {
        let lowering = lower(&empty());
        for domain in [
            CapabilityDomain::NameResolution,
            CapabilityDomain::Ipc,
            CapabilityDomain::Credential,
            CapabilityDomain::Resource,
        ] {
            assert!(
                requirement_for(&lowering, domain).is_none(),
                "{domain} lowered a requirement"
            );
            let entry = lowering.coverage(domain).unwrap();
            assert!(
                entry.coverage.is_unrepresentable(),
                "{domain} is not reported as a policy gap"
            );
            let DomainCoverage::PolicyCannotExpress { detail } = &entry.coverage else {
                unreachable!("checked immediately above");
            };
            assert!(!detail.is_empty(), "{domain} states no reason");
        }
        assert_eq!(lowering.unrepresentable().count(), 4);
    }

    /// AAASM-5751 — a domain stops reporting a gap **only** when the schema
    /// genuinely sourced it, and both directions are asserted against the same
    /// document so they cannot be satisfied separately.
    ///
    /// Adding a filesystem path scope moves `FilesystemRead` from
    /// `not_stated` to `lowered` at `Enumerated` granularity — the schema
    /// really did gain the ability to source it. It must move *nothing else*:
    /// the four domains no policy node reaches stay `policy_cannot_express`,
    /// with the same count and the same reasons. A change that closed one gap
    /// by quietly reclassifying the others would pass a one-sided test.
    #[test]
    fn sourcing_a_path_scope_moves_that_domain_and_no_other() {
        let before = lower(&empty());
        let after = lower(&with_paths(Some(&["/workspace"]), Some(&["/workspace/build"])));

        assert_eq!(
            coverage_of(&before, CapabilityDomain::FilesystemRead).as_str(),
            "not_stated"
        );
        assert_eq!(
            coverage_of(&after, CapabilityDomain::FilesystemRead).as_str(),
            "lowered"
        );
        assert_eq!(
            coverage_of(&after, CapabilityDomain::FilesystemWrite).as_str(),
            "lowered"
        );
        assert!(matches!(
            coverage_of(&after, CapabilityDomain::FilesystemWrite),
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::Enumerated,
                ..
            }
        ));

        let unreachable = [
            CapabilityDomain::NameResolution,
            CapabilityDomain::Ipc,
            CapabilityDomain::Credential,
            CapabilityDomain::Resource,
        ];
        for domain in unreachable {
            assert_eq!(
                coverage_of(&before, domain),
                coverage_of(&after, domain),
                "{domain} moved when a filesystem path scope was stated"
            );
            assert!(
                coverage_of(&after, domain).is_unrepresentable(),
                "{domain} stopped reporting"
            );
        }
        assert_eq!(before.unrepresentable().count(), 4);
        assert_eq!(after.unrepresentable().count(), 4);

        // And no requirement was fabricated for any of them.
        for domain in unreachable {
            assert!(
                requirement_for(&after, domain).is_none(),
                "{domain} lowered a requirement"
            );
        }
    }

    /// "Policy cannot express it" and "this document did not say" are both
    /// zero requirements, and they are not the same fact. The control is that
    /// the first stays put while the second moves: adding an egress allowlist
    /// turns `NetworkEgress` from `NotStated` into `Lowered` and leaves `Ipc`
    /// exactly where it was.
    #[test]
    fn a_policy_gap_is_distinct_from_a_silent_document_and_only_one_moves() {
        let silent = lower(&empty());
        assert_eq!(
            coverage_of(&silent, CapabilityDomain::NetworkEgress).as_str(),
            "not_stated"
        );
        assert_eq!(
            coverage_of(&silent, CapabilityDomain::Ipc).as_str(),
            "policy_cannot_express"
        );

        let mut policy = empty();
        policy.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        let stated = lower(&policy);
        assert_eq!(
            coverage_of(&stated, CapabilityDomain::NetworkEgress).as_str(),
            "lowered"
        );
        assert_eq!(
            coverage_of(&stated, CapabilityDomain::Ipc).as_str(),
            "policy_cannot_express"
        );
    }

    /// A document that restricts nothing this boundary can carry must not
    /// produce a spec. An empty requirement list negotiates to a Ready posture
    /// against any backend, including one that enforces nothing.
    #[test]
    fn a_policy_that_lowers_to_nothing_cannot_produce_an_execution_spec() {
        let spec = ExecutionSpec::new("python", IdentityRef::root("agent-1"));
        let refusal = lower(&empty())
            .apply_to(spec.clone())
            .expect_err("a policy expressing no restriction must not yield a spec");
        assert_eq!(refusal.unrepresentable().count(), 4);
        assert!(refusal.to_string().contains("no execution requirement"));

        // The control: one expressible restriction and the same call succeeds,
        // so the refusal is attributable to the empty lowering and not to
        // `apply_to` refusing unconditionally.
        let attached = lower(&with_denies(&[Capability::FileWrite]))
            .apply_to(spec)
            .expect("an expressible restriction yields a spec");
        assert_eq!(attached.requirements().len(), 1);
    }

    #[test]
    fn apply_to_attaches_every_lowered_requirement() {
        let mut policy = with_denies(&[Capability::FileWrite]);
        policy.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        policy.syscall_allowlist = Some(SyscallAllowlist::from_names(["read"]).unwrap());
        let lowering = lower(&policy);
        let spec = lowering
            .apply_to(ExecutionSpec::new("python", IdentityRef::root("agent-1")))
            .expect("three restrictions lower");
        assert_eq!(spec.requirements().len(), lowering.requirements().len());
        assert_eq!(spec.requirements(), lowering.requirements());
    }

    /// Restrictions the operator wrote that no execution domain carries are a
    /// silent loss of intent unless something prints them.
    #[test]
    fn restrictions_no_domain_can_carry_are_named_rather_than_dropped() {
        let policy = with_denies(&[Capability::NetworkInbound, Capability::McpTool("git".to_string())]);
        let lowering = lower(&policy);
        assert_eq!(lowering.unmapped().len(), 2);
        assert!(lowering.unmapped().iter().any(|s| s.contains("network_inbound")));
        assert!(lowering.unmapped().iter().any(|s| s.contains("mcp_tool:git")));

        // The control: a capability that does map is not reported as unmapped.
        assert!(lower(&with_denies(&[Capability::FileWrite])).unmapped().is_empty());
    }

    #[test]
    fn a_denied_tool_rule_is_reported_as_unmapped() {
        let policy = PolicyDocument {
            tools: vec![ToolRule {
                name: "write_file".to_string(),
                allow: false,
                requires_approval_if: None,
            }],
            ..PolicyDocument::default()
        };
        assert_eq!(lower(&policy).unmapped().len(), 1);

        let permitted = PolicyDocument {
            tools: vec![ToolRule {
                name: "write_file".to_string(),
                allow: true,
                requires_approval_if: None,
            }],
            ..PolicyDocument::default()
        };
        assert!(lower(&permitted).unmapped().is_empty());
    }

    // -----------------------------------------------------------------------
    // Posture and intent.
    // -----------------------------------------------------------------------

    /// The policy schema has no posture node, so a lowered requirement is
    /// `Required` — ADR 0035 §4's default. A weaker posture is an operator
    /// selection, and it has to be selected.
    #[test]
    fn posture_defaults_to_required_and_a_weaker_one_must_be_selected() {
        let policy = with_denies(&[Capability::FileWrite]);
        let strict = lower(&policy);
        assert_eq!(
            requirement_for(&strict, CapabilityDomain::FilesystemWrite)
                .unwrap()
                .posture(),
            RequirementPosture::Required
        );

        let relaxed = lower_policy(
            &policy,
            &LoweringOptions::strict().with_posture(
                CapabilityDomain::FilesystemWrite,
                RequirementPosture::DegradeIfUnavailable,
            ),
        );
        assert_eq!(
            requirement_for(&relaxed, CapabilityDomain::FilesystemWrite)
                .unwrap()
                .posture(),
            RequirementPosture::DegradeIfUnavailable
        );
    }

    /// Every policy node read here states what must not happen. Nothing in the
    /// schema asks only to be told about something, so nothing may lower to an
    /// observe-only intent — that would silently downgrade a denial.
    #[test]
    fn every_lowered_requirement_prevents_before_effect_across_the_process_tree() {
        let mut policy = with_denies(&[Capability::FileRead, Capability::FileWrite, Capability::AgentSpawn]);
        policy.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        policy.syscall_allowlist = Some(SyscallAllowlist::from_names(["read"]).unwrap());
        let lowering = lower(&policy);
        assert_eq!(lowering.requirements().len(), 5);
        for requirement in lowering.requirements() {
            assert_eq!(requirement.intent(), RequirementIntent::PreventBeforeEffect);
            assert_eq!(requirement.descendants(), DescendantRequirement::ProcessTree);
        }
    }
}
