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
//! change and is owned elsewhere (AAASM-5751); nothing here anticipates it.
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
//! Measured against the canonical AST at AAASM-5704 (`666c97dbf`). Full detail
//! travels per domain in [`DomainLowering`]; this is the summary:
//!
//! | Domain | Source | Granularity |
//! | --- | --- | --- |
//! | [`Syscall`](CapabilityDomain::Syscall) | `syscalls.allow` | Enumerated — a closed 15-name vocabulary |
//! | [`NetworkEgress`](CapabilityDomain::NetworkEgress) | `network.allowlist`, `capabilities` `network_outbound` | Host globs only; no port, no protocol |
//! | [`FilesystemRead`](CapabilityDomain::FilesystemRead) | `capabilities` `file_read` | Whole-domain boolean; no path scope |
//! | [`FilesystemWrite`](CapabilityDomain::FilesystemWrite) | `capabilities` `file_write` / `file_delete` | Whole-domain boolean; no path scope |
//! | [`ProcessCreation`](CapabilityDomain::ProcessCreation) | `capabilities` `agent_spawn` / `terminal_exec` | Whole-domain boolean; no descendant ceiling |
//! | [`NameResolution`](CapabilityDomain::NameResolution) | — | Not expressible |
//! | [`Ipc`](CapabilityDomain::Ipc) | — | Not expressible |
//! | [`Credential`](CapabilityDomain::Credential) | — | Not expressible |
//! | [`Resource`](CapabilityDomain::Resource) | — | Not expressible |
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
/// field, and the two policy nodes that carry scope — `syscalls.allow` and
/// `network.allowlist` — are both allow-lists: they name what may happen, and
/// the requirement is to prevent everything else. Emitting bare names would
/// leave a backend to guess which of the two readings applies, and the two are
/// exact opposites.
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
    let gaps = vec![
        FILESYSTEM_PATH_SCOPE_GAP.to_string(),
        FILESYSTEM_BACKEND_DEFAULTS_GAP.to_string(),
    ];
    match restriction_sources(policy, &[Capability::FileRead]) {
        Some(sourced_from) => (
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                sourced_from,
            },
            Some(RequirementScope::Whole),
            gaps,
        ),
        None => (not_stated(CAPABILITY_NODE, CAPABILITY_ABSENT_MEANING), None, gaps),
    }
}

fn filesystem_write(policy: &PolicyDocument) -> DomainResult {
    let gaps = vec![
        FILESYSTEM_PATH_SCOPE_GAP.to_string(),
        FILESYSTEM_BACKEND_DEFAULTS_GAP.to_string(),
        FILESYSTEM_VERB_GAP.to_string(),
    ];
    // `file_write` and `file_delete` both land on this one domain, which also
    // makes `aa_core::capability_is_denied`'s "a write deny implies a delete
    // deny" rule a no-op here: either capability alone already produces the
    // requirement.
    match restriction_sources(policy, &[Capability::FileWrite, Capability::FileDelete]) {
        Some(sourced_from) => (
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                sourced_from,
            },
            Some(RequirementScope::Whole),
            gaps,
        ),
        None => (not_stated(CAPABILITY_NODE, CAPABILITY_ABSENT_MEANING), None, gaps),
    }
}

fn process_creation(policy: &PolicyDocument) -> DomainResult {
    let gaps = vec![PROCESS_DESCENDANT_CEILING_GAP.to_string()];
    match restriction_sources(policy, &[Capability::AgentSpawn, Capability::TerminalExec]) {
        Some(sourced_from) => (
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                sourced_from,
            },
            Some(RequirementScope::Whole),
            gaps,
        ),
        None => (not_stated(CAPABILITY_NODE, CAPABILITY_ABSENT_MEANING), None, gaps),
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

fn syscall(policy: &PolicyDocument) -> DomainResult {
    let gaps = vec![
        SYSCALL_VOCABULARY_GAP.to_string(),
        SYSCALL_FAILURE_SEMANTICS_GAP.to_string(),
    ];
    let Some(allowlist) = policy.syscall_allowlist.as_ref() else {
        return (not_stated(SYSCALL_NODE, SYSCALL_ABSENT_MEANING), None, gaps);
    };
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

const NETWORK_NODE: &str = "network.allowlist";
const NETWORK_ABSENT_MEANING: &str = "an absent or empty allowlist is documented as no egress restriction \
     (aa_security::policy::document::NetworkPolicy)";

const SYSCALL_NODE: &str = "syscalls.allow";
const SYSCALL_ABSENT_MEANING: &str = "an absent allowlist leaves syscalls unconstrained. Note that \
     aa_policy::PolicyDocument::to_canonical always sets this node to None, so a document that reached \
     this AST through the gateway projection can never carry it however it was authored";

const FILESYSTEM_PATH_SCOPE_GAP: &str = "path scope: capability grants are whole-domain booleans and no \
     policy node names a path this requirement applies to";
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
