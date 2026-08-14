//! What a governed launch is, and what policy requires of it.
//!
//! An [`ExecutionSpec`] is backend-neutral by construction: no type in this
//! module can name a backend, a mechanism or a platform facility. That is the
//! structural half of ADR 0035 §3 — *"isolation class is not backend
//! identity"* — and it is why [`crate::plan::BackendIdentity`] appears only in
//! the plan and the evidence, never here.

use crate::capability::CapabilityDomain;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Who the launch is attributed to.
///
/// **Asserted, not verified.** This is a reference the caller supplies; nothing
/// in this crate authenticates it, and a governed launch must not present it as
/// a verified identity in any claim derived from these types. Verification, if
/// any, happens upstream and travels through its own evidence.
///
/// Lineage exists because ADR 0035 §6 requires sub-agent identity to be able to
/// become *narrower* while OS authority does not widen; recording the ancestry
/// is what lets a later ticket check that direction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IdentityRef {
    /// The agent this launch is attributed to.
    pub agent_id: String,
    /// The owning team, when the launch has one.
    pub team_id: Option<String>,
    /// Ancestor agent ids, outermost first. Empty for a root launch.
    pub lineage: Vec<String>,
}

impl IdentityRef {
    /// A root launch with no ancestry.
    pub fn root(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            team_id: None,
            lineage: Vec::new(),
        }
    }

    /// Set the owning team.
    pub fn with_team(mut self, team_id: impl Into<String>) -> Self {
        self.team_id = Some(team_id.into());
        self
    }

    /// Append an ancestor, outermost first.
    pub fn with_ancestor(mut self, agent_id: impl Into<String>) -> Self {
        self.lineage.push(agent_id.into());
        self
    }

    /// How many ancestors this launch has.
    pub fn depth(&self) -> usize {
        self.lineage.len()
    }
}

/// What policy asks a control to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RequirementIntent {
    /// The action must not take effect, and the decision must precede the
    /// effect.
    ///
    /// Satisfiable only by a capability for which
    /// [`CapabilityReport::can_prevent`] holds. An observing capability does
    /// not satisfy this and is never promoted to it.
    ///
    /// [`CapabilityReport::can_prevent`]: crate::capability::CapabilityReport::can_prevent
    PreventBeforeEffect,
    /// The action may proceed, but must produce evidence.
    Observe,
}

/// What happens when a requirement cannot be met.
///
/// The three variants are the whole of ADR 0035 §4's outcome space on the
/// policy side. In particular, degradation is opt-in *per requirement*: there
/// is no global "allow degradation" switch, because the answer differs between
/// "we could not limit memory" and "we could not stop network egress".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RequirementPosture {
    /// Unmet means refuse before spawn. The default posture for anything that
    /// matters.
    Required,
    /// Unmet is recorded and the launch proceeds. Never rendered as
    /// enforcement.
    Optional,
    /// Unmet means proceed in an explicitly degraded posture, recording both
    /// what was planned and what was achieved.
    ///
    /// The only way a [`RequirementIntent::PreventBeforeEffect`] requirement
    /// becomes non-fatal, and it must be chosen by the policy author for that
    /// specific requirement. ADR 0035 §4: an explicit degraded mode "must not
    /// present the run as equivalently protected".
    DegradeIfUnavailable,
}

impl RequirementPosture {
    /// Whether failing to meet this requirement must refuse the launch.
    pub fn refuses_on_failure(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// How far down the process tree policy needs a control to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DescendantRequirement {
    /// The control must cover the target process and its descendants.
    ///
    /// The right answer for anything an agent could evade by spawning a child,
    /// which is most things (ADR 0035 §6).
    ProcessTree,
    /// Covering the directly launched process is enough.
    TargetProcessOnly,
}

/// Numeric ceilings for [`CapabilityDomain::Resource`].
///
/// `None` means "policy states no ceiling", which is not the same as "no
/// ceiling is enforced" — the backend may impose its own, and that shows up in
/// evidence rather than here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResourceLimits {
    /// Maximum resident memory, in bytes.
    pub max_memory_bytes: Option<u64>,
    /// Maximum accumulated CPU time, in seconds.
    pub max_cpu_seconds: Option<u64>,
    /// Maximum number of processes in the tree.
    pub max_pids: Option<u32>,
    /// Maximum wall-clock lifetime, in seconds.
    pub max_wall_clock_seconds: Option<u64>,
    /// Maximum size of any single file the agent creates, in bytes.
    pub max_file_size_bytes: Option<u64>,
    /// Maximum simultaneously open file descriptors.
    pub max_open_files: Option<u32>,
}

impl ResourceLimits {
    /// Whether policy stated any ceiling at all.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What a requirement applies to within its domain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RequirementScope {
    /// The requirement covers the whole domain with no further scoping.
    Whole,
    /// Domain-specific selectors — paths for filesystem domains, destinations
    /// for network domains, call names for syscalls.
    ///
    /// **Opaque to this crate.** These strings are carried and rendered, never
    /// parsed or matched here. Interpreting a path glob or a CIDR block is the
    /// backend's job during lowering, and doing it here would put a matching
    /// semantics in the contract that every backend would then have to
    /// reimplement identically or silently diverge from.
    Selectors(Vec<String>),
    /// Numeric ceilings, for [`CapabilityDomain::Resource`].
    Limits(ResourceLimits),
}

/// How the launch treats the authority the child would otherwise inherit.
///
/// ADR 0035 §9 requires evidence to distinguish credentials *intentionally
/// delegated* to the child from ambient authority that *could not yet be
/// removed*. Those are different security postures with the same observable
/// outcome — the child can use the credential either way — so they cannot be
/// represented by one list.
///
/// **Names only, never values.** No field here holds credential material, and
/// none should be added. These structures are rendered into `--dry-run` output,
/// evidence and audit records; a secret placed here would be published by every
/// one of those paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialPosture {
    /// Environment variable names the child must not inherit.
    pub removed: Vec<String>,
    /// Names deliberately passed to the child, as a decision.
    pub delegated: Vec<String>,
    /// Names known to reach the child that policy wanted removed and the
    /// current implementation cannot remove.
    ///
    /// Non-empty here means the run is *not* least-authority, and evidence must
    /// say so rather than reporting the delegated set as the whole story.
    pub ambient_unremoved: Vec<String>,
}

impl CredentialPosture {
    /// Whether any authority reaches the child that policy did not intend.
    pub fn has_unremoved_ambient_authority(&self) -> bool {
        !self.ambient_unremoved.is_empty()
    }

    /// Names this posture reports in two lists that cannot both be true.
    ///
    /// The three lists answer one question — *does this name reach the child* —
    /// with three different answers, so a name in two of them makes the posture
    /// unreadable. Two pairs matter and both are checked:
    ///
    /// * `removed` ∩ `ambient_unremoved` is the failure this Epic exists to
    ///   prevent. It renders authority that **could not** be removed as
    ///   authority that **was**, and a reader who stops at `removed` concludes
    ///   the run is least-authority when it is not.
    /// * `removed` ∩ `delegated` is the same contradiction with the intent
    ///   reversed, and is just as unreadable.
    ///
    /// `delegated` ∩ `ambient_unremoved` is deliberately *not* an error: both
    /// mean the name reaches the child, so a posture carrying it is redundant
    /// rather than wrong, and rejecting it would fail a caller who recorded a
    /// delegation and a compatibility debt for the same variable.
    ///
    /// Empty for every posture [`crate::ambient::EnvironmentPlanner`] builds —
    /// it cannot construct one of these — so this predicate exists for the
    /// hand-written postures a caller may still assemble.
    pub fn contradictions(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .removed
            .iter()
            .filter(|name| self.ambient_unremoved.contains(name) || self.delegated.contains(name))
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

/// One policy-derived demand on the execution boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ControlRequirement {
    domain: CapabilityDomain,
    intent: RequirementIntent,
    posture: RequirementPosture,
    descendants: DescendantRequirement,
    scope: RequirementScope,
}

impl ControlRequirement {
    /// A requirement that the domain be denied before the effect, refusing the
    /// launch if it cannot be.
    ///
    /// Defaults to [`DescendantRequirement::ProcessTree`] and
    /// [`RequirementScope::Whole`]: the strictest reading, so that a caller who
    /// omits detail gets the safe answer and has to opt *down*.
    pub fn prevent(domain: CapabilityDomain) -> Self {
        Self {
            domain,
            intent: RequirementIntent::PreventBeforeEffect,
            posture: RequirementPosture::Required,
            descendants: DescendantRequirement::ProcessTree,
            scope: RequirementScope::Whole,
        }
    }

    /// A requirement that the domain produce evidence, refusing the launch if
    /// it cannot.
    pub fn observe(domain: CapabilityDomain) -> Self {
        Self {
            domain,
            intent: RequirementIntent::Observe,
            posture: RequirementPosture::Required,
            descendants: DescendantRequirement::ProcessTree,
            scope: RequirementScope::Whole,
        }
    }

    /// Set what happens when this requirement cannot be met.
    pub fn with_posture(mut self, posture: RequirementPosture) -> Self {
        self.posture = posture;
        self
    }

    /// Set how far down the process tree this requirement must reach.
    pub fn with_descendants(mut self, descendants: DescendantRequirement) -> Self {
        self.descendants = descendants;
        self
    }

    /// Set what within the domain this requirement applies to.
    pub fn with_scope(mut self, scope: RequirementScope) -> Self {
        self.scope = scope;
        self
    }

    /// The domain this requirement acts on.
    pub fn domain(&self) -> CapabilityDomain {
        self.domain
    }

    /// What the control is asked to do.
    pub fn intent(&self) -> RequirementIntent {
        self.intent
    }

    /// What happens when it cannot.
    pub fn posture(&self) -> RequirementPosture {
        self.posture
    }

    /// How far down the process tree it must reach.
    pub fn descendants(&self) -> DescendantRequirement {
        self.descendants
    }

    /// What within the domain it applies to.
    pub fn scope(&self) -> &RequirementScope {
        &self.scope
    }
}

/// The identity-bound, policy-derived statement of a process to run and the
/// boundary it must run inside.
///
/// # Why `String` argv
///
/// The program and its arguments are `String`, not `OsString`. A spec is
/// rendered into `--dry-run` output, evidence and audit records, all of which
/// must be reproducible and comparable; a non-UTF-8 argument has no faithful
/// representation in any of them. The consequence is a real limitation: a launch
/// whose argv is not valid UTF-8 cannot be described by this type and must be
/// rejected at the CLI boundary rather than lossily converted here. Losing the
/// launch is better than logging an argv that differs from the one that ran.
///
/// The working directory stays a [`PathBuf`] because it is a path, not a
/// rendered argument, and non-UTF-8 directory names are ordinary on real hosts.
///
/// [`PathBuf`]: std::path::PathBuf
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExecutionSpec {
    program: String,
    args: Vec<String>,
    working_dir: Option<std::path::PathBuf>,
    identity: IdentityRef,
    requirements: Vec<ControlRequirement>,
    credentials: CredentialPosture,
}

impl ExecutionSpec {
    /// A spec with no requirements yet.
    pub fn new(program: impl Into<String>, identity: IdentityRef) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            working_dir: None,
            identity,
            requirements: Vec::new(),
            credentials: CredentialPosture::default(),
        }
    }

    /// Set the argument vector, excluding the program name.
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Set the working directory.
    pub fn with_working_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Add a policy-derived requirement.
    pub fn with_requirement(mut self, requirement: ControlRequirement) -> Self {
        self.requirements.push(requirement);
        self
    }

    /// Set how inherited authority is treated.
    pub fn with_credentials(mut self, credentials: CredentialPosture) -> Self {
        self.credentials = credentials;
        self
    }

    /// The program to execute.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The argument vector, excluding the program name.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// The working directory, if policy fixed one.
    pub fn working_dir(&self) -> Option<&std::path::Path> {
        self.working_dir.as_deref()
    }

    /// Who the launch is attributed to. Asserted, not verified — see
    /// [`IdentityRef`].
    pub fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    /// Every policy-derived requirement, in declaration order.
    pub fn requirements(&self) -> &[ControlRequirement] {
        &self.requirements
    }

    /// How inherited authority is treated.
    pub fn credentials(&self) -> &CredentialPosture {
        &self.credentials
    }

    /// Requirements whose failure must refuse the launch.
    pub fn required(&self) -> impl Iterator<Item = &ControlRequirement> {
        self.requirements.iter().filter(|r| r.posture().refuses_on_failure())
    }
}
