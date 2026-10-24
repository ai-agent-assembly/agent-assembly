//! The pure lease decision for one policy query (AAASM-6259, ADR 0038 §31-34).
//!
//! [`LeaseGovernance`] is the operator-trusted state built once at startup;
//! [`decide`] maps `(governance, revoked ids, request, now)` to a
//! [`LeaseVerdict`] with no I/O, no clock read and no global state, so every
//! row of the table below is testable with an injected `now`.
//!
//! # Decision table (governed mode)
//!
//! | request | verdict |
//! |---|---|
//! | `TOOL_CALL`, tool declared `[none]`, `allow: true` | Permit |
//! | `TOOL_CALL`, tool declares domain classes, `allow: true` | Permit only if **every** class has a valid, un-revoked, whole-scope lease naming the governed subject |
//! | `TOOL_CALL`, undeclared tool | Deny |
//! | `TOOL_CALL`, tool with `allow: false` | Deny |
//! | `TOOL_CALL`, missing or empty tool name, or no `ToolCallContext` | Deny |
//! | `TOOL_CALL`, tool declaring `process_creation` or `syscall` | Deny |
//! | `TOOL_CALL`, any class this module does not recognise | Deny |
//! | `LLM_CALL`, `TOOL_RESULT`, context absent or of the matching kind | Permit, no lease |
//! | `LLM_CALL`, `TOOL_RESULT` carrying any other typed context (notably a `ToolCallContext`) | Deny |
//! | `FILE_OPERATION`, `NETWORK_CALL`, `PROCESS_EXEC`, `AGENT_SPAWN`, `UNSPECIFIED`, unknown codes | Deny |
//!
//! Tool names match exactly: no case folding, trimming or wildcard expansion,
//! and a `"*"` entry declares nothing (the validator refuses one). Leases do not
//! refresh: a leased tool denies from `issued_at + ttl` until an operator starts
//! a new run, which is fail-closed by design.
//!
//! A `Permit` is necessary, not sufficient: the seam falls through to the
//! gateway and local policy afterwards, so this gate can only restrict.
//!
//! # Why these rows
//!
//! * **`process_creation` / `syscall` tools are refused.** An admission check
//!   cannot bound a class that subsumes every other one: a tool that may spawn
//!   a process or issue raw syscalls is not confined by a lease the SDK-side
//!   wrapper consulted.
//! * **Typed classes are denied outright.** `FILE_OPERATION`, `NETWORK_CALL`
//!   and `PROCESS_EXEC` would need a typed filesystem or network claim to
//!   admit, and the request only carries an SDK-asserted `action_type`. No
//!   lease can be checked against a claim the gate has no trustworthy source
//!   for, so these never admit.
//! * **Selector-scoped leases never admit a tool.** A declaration names a
//!   domain, so the requirement is checked as [`RequirementScope::Whole`]; a
//!   lease limited to named selectors does not cover `Whole`.
//!
//! # Known limits
//!
//! * **Admission, not confinement.** This decides whether a cooperative
//!   SDK-wrapped call may proceed. It does not stop a process that bypasses
//!   the SDK.
//! * **`action_type` is SDK-asserted.** `LLM_CALL` and `TOOL_RESULT` need no
//!   lease, so a non-cooperative SDK can relabel a call as one of them **and
//!   omit the context** and be permitted here (still subject to the gateway and
//!   local policy). A relabel that leaves a `ToolCallContext` behind is denied;
//!   the omit-the-context relabel is the residual nothing in the request can
//!   reveal.
//! * **The subject is runtime-wide**, the server-side agent id, not a
//!   per-connection identity.
//! * **Verdicts are point-in-time.** A lease that lapses or is revoked while
//!   an approval is pending is not re-checked.
//! * A tool declaration is the operator's claim about the tool, not a
//!   measurement of it.
//!
//! Ignored on purpose, so a forged value cannot influence a verdict:
//! `agent_id`, `caller_agent_id`, `args_json`, `tool_source`, `target_url`,
//! trace and span ids, and the credential token.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use aa_core::PolicyDecision;
use aa_isolation::authority::admit_lease;
use aa_isolation::lease_lowering::{lower_leases, AuthoredLease, LeaseIssuance, LeaseLoweringError};
use aa_isolation::{
    AuthorityBuildError, AuthorityState, CapabilityDomain, CapabilityLease, EffectiveAuthority, IdentityRef,
    RequirementScope,
};
use aa_policy::resolve::PolicyResolution;
use aa_policy::ToolCapability;
use aa_proto::assembly::common::v1::ActionType;
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::CheckActionRequest;

use super::authored::{authored_lease_from, capability_domain_from};
use crate::pipeline::LeaseVerdict;

/// Longest tool name echoed into a deny reason. The name is SDK-supplied, so
/// the reason carries it escaped and bounded.
const MAX_NAME_IN_REASON: usize = 64;

/// What the operator declared for one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRequirement {
    /// `tools.<name>.allow`. A tool that is not allowed is never admitted by a
    /// lease: the lease gate only restricts, so it must not look more
    /// permissive than the policy it sits beside.
    pub allow: bool,
    /// `tools.<name>.capabilities`, exactly as declared.
    pub capabilities: Vec<ToolCapability>,
}

/// Issuance facts for the leases lowered from policy at startup. The caller
/// chooses them because the subject, clock and id scheme belong to the
/// runtime, not to the policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedIssuance {
    /// When the leases are issued; their TTLs count from here.
    pub issued_at: SystemTime,
    /// TTL applied to a grant that states none.
    pub default_ttl_seconds: u64,
    /// Issuer recorded on a grant that names none.
    pub default_issuer: String,
}

/// The set of revoked lease ids a decision consults.
///
/// A trait so this library does not depend on how revocation is stored:
/// `BTreeSet<String>` serves tests and simple callers, and on unix
/// [`LeaseState`](crate::lease::state::LeaseState) implements it directly, so
/// the record the operator CLI writes is what the gate reads.
pub trait RevokedLeases: std::fmt::Debug + Send + Sync {
    /// Whether the lease with id `id` has been revoked.
    fn is_revoked(&self, id: &str) -> bool;
}

impl RevokedLeases for BTreeSet<String> {
    fn is_revoked(&self, id: &str) -> bool {
        self.contains(id)
    }
}

#[cfg(unix)]
impl RevokedLeases for crate::lease::state::LeaseState {
    fn is_revoked(&self, id: &str) -> bool {
        // Inherent method of the same name; resolved first, so no recursion.
        crate::lease::state::LeaseState::is_revoked(self, id)
    }
}

/// Why governed mode cannot be built. Governed mode never falls back to
/// ungoverned: every variant means the runtime must refuse to start.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GovernanceError {
    /// No server-side agent id to bind leases to.
    EmptySubject,
    /// The policy did not resolve as an enforced load. `state` is
    /// [`PolicyResolution::state_token`]. A permissive, unconfigured or
    /// failed load carries no operator-trusted declarations.
    NotEnforced {
        /// The resolution's stable state token.
        state: &'static str,
    },
    /// An authored lease cannot be represented, for example `max_count`, which
    /// a runtime lease cannot count down.
    Lowering(LeaseLoweringError),
    /// Two leases for one capability domain.
    Authority(AuthorityBuildError),
    /// Two held leases share one id, so a revocation could not tell them apart.
    DuplicateLeaseId(String),
    /// The state record names a different subject than the one governed.
    StateSubjectMismatch,
    /// The state record was issued for a different policy than the one loaded.
    StateDigestMismatch,
    /// The caller's lease-id function refused a domain word.
    LeaseId {
        /// The domain word the id was requested for.
        domain: String,
        /// The id function's own explanation.
        detail: String,
    },
}

impl std::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySubject => write!(f, "governed mode needs a non-empty server-side agent id"),
            Self::NotEnforced { state } => write!(
                f,
                "governed mode needs an enforced policy load, but the policy resolved as `{state}`"
            ),
            Self::Lowering(e) => write!(f, "policy authors a lease governed mode cannot issue: {e}"),
            Self::Authority(e) => write!(f, "policy authors an inconsistent lease set: {e}"),
            Self::DuplicateLeaseId(id) => write!(f, "two leases share the id `{id}`"),
            Self::StateSubjectMismatch => write!(f, "the lease state record belongs to a different agent id"),
            Self::StateDigestMismatch => write!(f, "the lease state record was issued for a different policy"),
            Self::LeaseId { domain, detail } => write!(f, "no lease id for domain `{domain}`: {detail}"),
        }
    }
}

impl std::error::Error for GovernanceError {}

/// Operator-trusted state for governed decisions, built once at startup.
///
/// Every field comes from the operator-authored policy or the runtime's own
/// configuration. Nothing here is ever read from a request.
#[derive(Debug, Clone)]
pub struct LeaseGovernance {
    subject: String,
    tools: BTreeMap<String, ToolRequirement>,
    authority: EffectiveAuthority,
    /// Each lease with the id the revoked set knows it by.
    leased: Vec<(CapabilityLease, String)>,
    policy_digest: String,
}

impl LeaseGovernance {
    /// Build governance from an enforced policy resolution, lowering its
    /// authored leases through the same path `aasm run` uses.
    ///
    /// `subject` is the runtime's server-side agent id
    /// (`PipelineConfig.agent_id`), never an SDK-supplied one. `lease_id` maps
    /// a lease domain word (`filesystem_read`, ...) to the id the revoked set
    /// uses; for a record on disk it is `LeaseState::lease_id`, so the CLI and
    /// the gate derive identical ids from the same record.
    ///
    /// # Errors
    ///
    /// [`GovernanceError`] for anything that is not an enforced load, a lease
    /// that cannot be lowered (including `max_count`), or two leases for one
    /// domain. There is no fallback: the caller must refuse to start.
    pub fn from_resolution(
        resolution: &PolicyResolution,
        subject: &str,
        issuance: &GovernedIssuance,
        lease_id: &dyn Fn(&str) -> Result<String, String>,
    ) -> Result<Self, GovernanceError> {
        let PolicyResolution::Enforced {
            document,
            tool_capabilities,
            content_digest,
            ..
        } = resolution
        else {
            return Err(GovernanceError::NotEnforced {
                state: resolution.state_token(),
            });
        };
        if subject.is_empty() {
            return Err(GovernanceError::EmptySubject);
        }

        let authored: Vec<AuthoredLease> = resolution.lease_grants().iter().map(authored_lease_from).collect();
        let leases = lower_leases(
            &authored,
            &LeaseIssuance {
                subject: IdentityRef::root(subject),
                default_issuer: IdentityRef::root(issuance.default_issuer.clone()),
                issued_at: issuance.issued_at,
                default_ttl_seconds: issuance.default_ttl_seconds,
                // Internal only: the ids that matter are `lease_id`'s.
                id_prefix: "governed".to_string(),
            },
        )
        .map_err(GovernanceError::Lowering)?;

        // `allow` is read back from the adapter projection (`project_rules`
        // turns `allow: false` into a `Deny` rule named exactly like the tool;
        // `requires_approval_if` becomes `RequireApproval`, which is still an
        // allow as far as a lease is concerned). A tool with no rule cannot
        // occur, since the map is derived from the same tools, but if it did,
        // not-allowed is the safe reading.
        let tools = tool_capabilities
            .iter()
            .map(|(name, capabilities)| {
                let allow = document
                    .rules
                    .iter()
                    .any(|r| r.action_pattern == *name && r.decision != PolicyDecision::Deny);
                (
                    name.clone(),
                    ToolRequirement {
                        allow,
                        capabilities: capabilities.clone(),
                    },
                )
            })
            .collect();

        let leased = leases
            .into_iter()
            .zip(resolution.lease_grants())
            .map(|(lease, grant)| {
                let word = grant.domain.as_str();
                lease_id(word)
                    .map(|id| (lease, id))
                    .map_err(|detail| GovernanceError::LeaseId {
                        domain: word.to_string(),
                        detail,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Self::from_parts(subject, tools, leased, content_digest.clone())
    }

    /// Build governance from a policy and the run record `aasm lease` manages.
    ///
    /// Prefer this over [`from_resolution`](Self::from_resolution) in the
    /// wiring: the issue time, the lease ids and the revoked set all come from
    /// `state`, so they cannot disagree, and a record written for another
    /// subject or another policy is refused instead of silently governing with
    /// ids nobody revoked. `issued_at` is `state.issued_at()` seconds after the
    /// Unix epoch.
    ///
    /// # Errors
    ///
    /// [`GovernanceError::StateSubjectMismatch`] or
    /// [`GovernanceError::StateDigestMismatch`] when the record is for another
    /// subject or for a policy other than `resolution`, plus every error
    /// [`from_resolution`](Self::from_resolution) returns.
    #[cfg(unix)]
    pub fn from_state(
        resolution: &PolicyResolution,
        subject: &str,
        default_ttl_seconds: u64,
        default_issuer: &str,
        state: &crate::lease::state::LeaseState,
    ) -> Result<Self, GovernanceError> {
        if state.subject() != subject {
            return Err(GovernanceError::StateSubjectMismatch);
        }
        let digest = resolution
            .content_digest()
            .map(|d| d.strip_prefix("sha256:").unwrap_or(d));
        if digest != Some(state.policy_digest()) {
            return Err(GovernanceError::StateDigestMismatch);
        }
        Self::from_resolution(
            resolution,
            subject,
            &GovernedIssuance {
                issued_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(state.issued_at()),
                default_ttl_seconds,
                default_issuer: default_issuer.to_string(),
            },
            &|d| state.lease_id(d).map_err(|e| e.to_string()),
        )
    }

    /// Build governance from already-lowered parts.
    ///
    /// Public so a test or a later wiring step can supply leases directly. A
    /// lease whose subject differs from `subject` is accepted here and never
    /// admits: [`decide`] binds every admission to `subject`.
    ///
    /// # Errors
    ///
    /// [`GovernanceError::EmptySubject`], or [`GovernanceError::Authority`]
    /// for two leases naming one domain, [`GovernanceError::DuplicateLeaseId`]
    /// for two leases sharing an id.
    pub fn from_parts(
        subject: &str,
        tools: BTreeMap<String, ToolRequirement>,
        leased: Vec<(CapabilityLease, String)>,
        policy_digest: String,
    ) -> Result<Self, GovernanceError> {
        if subject.is_empty() {
            return Err(GovernanceError::EmptySubject);
        }
        let mut seen = BTreeSet::new();
        if let Some((_, dup)) = leased.iter().find(|(_, id)| !seen.insert(id.as_str())) {
            return Err(GovernanceError::DuplicateLeaseId(dup.clone()));
        }
        let leases: Vec<CapabilityLease> = leased.iter().map(|(l, _)| l.clone()).collect();
        let authority = EffectiveAuthority::from_leases(&leases).map_err(GovernanceError::Authority)?;
        Ok(Self {
            subject: subject.to_string(),
            tools,
            authority,
            leased,
            policy_digest,
        })
    }

    /// The server-side agent id every admission is bound to.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// `content_digest` of the policy this governance was built from, for
    /// attributing a decision to the document whose declarations it read.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// Ids of the leases this governance holds, in `authority.leases` order:
    /// the ids a revoked set is matched against.
    pub fn lease_ids(&self) -> impl Iterator<Item = &str> {
        self.leased.iter().map(|(_, id)| id.as_str())
    }

    fn lease_id_for(&self, lease: &CapabilityLease) -> Option<&str> {
        self.leased
            .iter()
            .find(|(l, _)| l.id() == lease.id())
            .map(|(_, id)| id.as_str())
    }

    /// The declaration for `tool`, if the operator declared one.
    pub fn tool(&self, tool: &str) -> Option<&ToolRequirement> {
        self.tools.get(tool)
    }
}

fn deny(reason: impl Into<String>) -> LeaseVerdict {
    LeaseVerdict::Deny { reason: reason.into() }
}

/// Decide one request. Pure: `now` and `revoked` are inputs.
///
/// `revoked` answers for the ids in [`LeaseGovernance::lease_ids`]; a revoked
/// lease does not admit regardless of its own validity window.
pub fn decide(
    governance: &LeaseGovernance,
    revoked: &dyn RevokedLeases,
    req: &CheckActionRequest,
    now: SystemTime,
) -> LeaseVerdict {
    match ActionType::try_from(req.action_type) {
        Ok(ActionType::LlmCall) => lease_free(req, |a| matches!(a, Action::LlmCall(_)), "LLM_CALL"),
        Ok(ActionType::ToolResult) => lease_free(req, |a| matches!(a, Action::ToolResult(_)), "TOOL_RESULT"),
        Ok(ActionType::ToolCall) => decide_tool(governance, revoked, req, now),
        Ok(other) => deny(format!("action type {other:?} is not admitted in governed mode")),
        Err(_) => deny(format!(
            "unknown action type {} is not admitted in governed mode",
            req.action_type
        )),
    }
}

/// Permit a lease-free action type, unless its context shows it is something
/// else. A request labelled `LLM_CALL` that carries a `ToolCallContext` (or any
/// other typed context) is a relabelled call, and the context is what the
/// SDK-asserted label was hiding; only an absent or matching context permits.
/// What remains is the omit-the-context relabel, which nothing in the request
/// can reveal.
fn lease_free(req: &CheckActionRequest, matches_label: impl Fn(&Action) -> bool, label: &str) -> LeaseVerdict {
    match req.context.as_ref().and_then(|c| c.action.as_ref()) {
        None => LeaseVerdict::Permit,
        Some(action) if matches_label(action) => LeaseVerdict::Permit,
        Some(_) => deny(format!("{label} carries a context for a different kind of action")),
    }
}

fn decide_tool(
    governance: &LeaseGovernance,
    revoked: &dyn RevokedLeases,
    req: &CheckActionRequest,
    now: SystemTime,
) -> LeaseVerdict {
    let Some(Action::ToolCall(call)) = req.context.as_ref().and_then(|c| c.action.as_ref()) else {
        return deny("tool call carries no tool call context");
    };
    let name = call.tool_name.as_str();
    if name.is_empty() {
        return deny("tool call names no tool");
    }
    let shown: String = name.chars().take(MAX_NAME_IN_REASON).collect();

    let Some(requirement) = governance.tools.get(name) else {
        return deny(format!("tool {shown:?} declares no capabilities"));
    };
    if !requirement.allow {
        return deny(format!("tool {shown:?} is not allowed by policy"));
    }

    let classes = requirement.capabilities.as_slice();
    if classes.is_empty() {
        return deny(format!("tool {shown:?} has an empty capability declaration"));
    }
    if classes.contains(&ToolCapability::NoAuthority) {
        // `none` is valid only as the sole word; anything else is malformed
        // and must not read as "needs nothing".
        return if classes.len() == 1 {
            LeaseVerdict::Permit
        } else {
            deny(format!("tool {shown:?} mixes `none` with other capabilities"))
        };
    }

    for class in classes {
        match class {
            ToolCapability::Domain(domain) => {
                if let Err(reason) = admit_class(governance, revoked, capability_domain_from(*domain), now) {
                    return deny(format!("tool {shown:?}: {reason}"));
                }
            }
            // Unreachable here (`none` returned above), but an arm that
            // permits would turn a future change to that early return into a
            // silent admit.
            ToolCapability::NoAuthority => return deny(format!("tool {shown:?} mixes `none` with other capabilities")),
            // `ToolCapability` is not `#[non_exhaustive]` today; if a class is
            // added, nothing has decided how to admit it.
            #[allow(unreachable_patterns)]
            _ => {
                return deny(format!(
                    "tool {shown:?} declares a capability class this gate does not recognise"
                ))
            }
        }
    }
    LeaseVerdict::Permit
}

fn admit_class(
    governance: &LeaseGovernance,
    revoked: &dyn RevokedLeases,
    domain: CapabilityDomain,
    now: SystemTime,
) -> Result<(), String> {
    match domain {
        CapabilityDomain::ProcessCreation | CapabilityDomain::Syscall => {
            return Err(format!(
                "`{domain}` cannot be bounded by an admission lease and is refused in governed mode"
            ));
        }
        CapabilityDomain::FilesystemRead
        | CapabilityDomain::FilesystemWrite
        | CapabilityDomain::NetworkEgress
        | CapabilityDomain::NameResolution
        | CapabilityDomain::Ipc
        | CapabilityDomain::Credential => {}
        // Launch-boundary authority, not something one call exercises; the
        // validator rejects them, and a table that carries one anyway is
        // refused rather than admitted.
        CapabilityDomain::Resource | CapabilityDomain::WorkspaceTransaction => {
            return Err(format!("`{domain}` is not a per-call capability class"));
        }
        // `CapabilityDomain` is `#[non_exhaustive]`: a domain added later has
        // had no decision made about it here, so it is refused, not admitted.
        _ => return Err(format!("`{domain}` is not a recognised capability class")),
    }

    let state = governance.authority.state(domain);
    // `admit_lease` admits everything for the rc.7 compatibility residual.
    // That state is never built from leases, but a gate must not depend on
    // that: anything other than a real lease is a deny.
    let AuthorityState::Leased(lease) = state else {
        return Err(format!("no lease for `{domain}`"));
    };
    // A held lease with no known id cannot be checked against the revoked
    // set, so it does not admit.
    let Some(id) = governance.lease_id_for(lease) else {
        return Err(format!("the lease for `{domain}` has no id"));
    };
    if revoked.is_revoked(id) {
        return Err(format!("the lease for `{domain}` is revoked"));
    }
    admit_lease(state, &governance.subject, domain, &RequirementScope::Whole, now)
        .map_err(|refusal| format!("lease for `{domain}` does not admit: {refusal}"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
    use aa_proto::assembly::policy::v1::{ActionContext, LlmCallContext, ToolCallContext};

    use super::*;

    const SUBJECT: &str = "server-agent";
    const TTL: u64 = 600;

    fn issued() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    fn mid() -> SystemTime {
        issued() + Duration::from_secs(TTL / 2)
    }

    fn issuance() -> GovernedIssuance {
        GovernedIssuance {
            issued_at: issued(),
            default_ttl_seconds: TTL,
            default_issuer: "test:policy".to_string(),
        }
    }

    fn paired(leases: Vec<CapabilityLease>) -> Vec<(CapabilityLease, String)> {
        leases
            .into_iter()
            .map(|l| {
                let id = l.id().as_str().to_string();
                (l, id)
            })
            .collect()
    }

    fn run_id(domain: &str) -> Result<String, String> {
        Ok(format!("run1:{domain}"))
    }

    const TOOLS: &str = "tools:
  calc: { allow: true, capabilities: [none] }
  reader: { allow: true, capabilities: [filesystem_read] }
  writer: { allow: true, capabilities: [filesystem_write] }
  copier: { allow: true, capabilities: [filesystem_read, filesystem_write] }
  fetch: { allow: true, capabilities: [network_egress, name_resolution] }
  denied_none: { allow: false, capabilities: [none] }
  denied_read: { allow: false, capabilities: [filesystem_read] }
  spawner: { allow: true, capabilities: [process_creation] }
  raw: { allow: true, capabilities: [syscall] }
  approver: { allow: true, requires_approval_if: \"true\", capabilities: [none] }
  undeclared: { allow: true }
";

    fn lease(domain: &str) -> String {
        format!("    - domain: {domain}\n      scope: whole\n      reason: test\n")
    }

    fn policy(leases: &[&str]) -> String {
        let mut yaml = TOOLS.to_string();
        if !leases.is_empty() {
            yaml.push_str("authority:\n  leases:\n");
            for l in leases {
                yaml.push_str(&lease(l));
            }
        }
        yaml
    }

    fn resolve(yaml: &str) -> PolicyResolution {
        aa_policy::resolve::classify(Path::new("test-policy.yaml"), yaml)
    }

    fn governance(leases: &[&str]) -> LeaseGovernance {
        let resolution = resolve(&policy(leases));
        assert_eq!(resolution.state_token(), "enforced", "{resolution:?}");
        LeaseGovernance::from_resolution(&resolution, SUBJECT, &issuance(), &run_id).expect("governance builds")
    }

    fn tool_call(name: &str) -> CheckActionRequest {
        CheckActionRequest {
            action_type: ActionType::ToolCall as i32,
            context: Some(ActionContext {
                action: Some(Action::ToolCall(ToolCallContext {
                    tool_name: name.to_string(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        }
    }

    fn action(action_type: i32) -> CheckActionRequest {
        CheckActionRequest {
            action_type,
            ..Default::default()
        }
    }

    fn none() -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn permitted(v: &LeaseVerdict) -> bool {
        matches!(v, LeaseVerdict::Permit)
    }

    fn assert_deny(v: LeaseVerdict, why: &str) -> String {
        match v {
            LeaseVerdict::Deny { reason } => reason,
            LeaseVerdict::Permit => panic!("expected Deny: {why}"),
        }
    }

    // ── action table ───────────────────────────────────────────────────────

    #[test]
    fn llm_call_and_tool_result_need_no_lease() {
        let g = governance(&[]);
        for t in [ActionType::LlmCall, ActionType::ToolResult] {
            assert!(permitted(&decide(&g, &none(), &action(t as i32), mid())), "{t:?}");
        }
    }

    #[test]
    fn a_lease_free_label_over_a_tool_call_context_is_denied() {
        let g = governance(&["filesystem_read"]);
        for t in [ActionType::LlmCall, ActionType::ToolResult] {
            let mut relabelled = tool_call("writer");
            relabelled.action_type = t as i32;
            assert_deny(
                decide(&g, &none(), &relabelled, mid()),
                &format!("{t:?} with ToolCall context"),
            );
            // Even a tool that needs no lease: the label is what is false.
            let mut calc = tool_call("calc");
            calc.action_type = t as i32;
            assert_deny(decide(&g, &none(), &calc, mid()), &format!("{t:?} calc"));
        }
        // Control: matching or absent context still permits.
        let llm = CheckActionRequest {
            action_type: ActionType::LlmCall as i32,
            context: Some(ActionContext {
                action: Some(Action::LlmCall(LlmCallContext::default())),
            }),
            ..Default::default()
        };
        assert!(permitted(&decide(&g, &none(), &llm, mid())));
        assert!(permitted(&decide(
            &g,
            &none(),
            &action(ActionType::ToolResult as i32),
            mid()
        )));
        // A different typed context is also a relabel.
        let file_under_llm = CheckActionRequest {
            action_type: ActionType::LlmCall as i32,
            context: Some(ActionContext {
                action: Some(Action::FileOp(Default::default())),
            }),
            ..Default::default()
        };
        assert_deny(
            decide(&g, &none(), &file_under_llm, mid()),
            "file context under LLM_CALL",
        );
    }

    #[test]
    fn typed_unspecified_and_unknown_action_types_are_denied_even_when_leased() {
        // Every domain is leased, so a deny cannot be explained by a missing lease.
        let g = governance(&[
            "filesystem_read",
            "filesystem_write",
            "network_egress",
            "name_resolution",
        ]);
        for t in [
            ActionType::FileOperation as i32,
            ActionType::NetworkCall as i32,
            ActionType::ProcessExec as i32,
            ActionType::AgentSpawn as i32,
            ActionType::ActionUnspecified as i32,
            99,
            -1,
        ] {
            assert_deny(decide(&g, &none(), &action(t), mid()), &format!("action type {t}"));
        }
    }

    // ── tool admission ─────────────────────────────────────────────────────

    #[test]
    fn a_tool_declared_none_is_permitted_with_no_lease_at_all() {
        let g = governance(&[]);
        assert!(permitted(&decide(&g, &none(), &tool_call("calc"), mid())));
        // `requires_approval_if` is still an allow as far as a lease goes.
        assert!(permitted(&decide(&g, &none(), &tool_call("approver"), mid())));
    }

    #[test]
    fn a_leased_class_is_permitted_and_every_class_of_a_multi_class_tool_is_required() {
        let g = governance(&["filesystem_read"]);
        assert!(permitted(&decide(&g, &none(), &tool_call("reader"), mid())));

        let g = governance(&["filesystem_read", "filesystem_write"]);
        assert!(permitted(&decide(&g, &none(), &tool_call("copier"), mid())));
    }

    #[test]
    fn a_missing_lease_denies() {
        let g = governance(&[]);
        let reason = assert_deny(decide(&g, &none(), &tool_call("reader"), mid()), "no lease");
        assert!(reason.contains("no lease"), "{reason}");
    }

    #[test]
    fn a_lease_for_another_capability_does_not_admit() {
        let read_only = governance(&["filesystem_read"]);
        assert_deny(
            decide(&read_only, &none(), &tool_call("writer"), mid()),
            "fs_read lease vs fs_write tool",
        );
        // One of two classes leased is not enough.
        assert_deny(
            decide(&read_only, &none(), &tool_call("copier"), mid()),
            "two-class tool, one lease",
        );
        let network_only = governance(&["network_egress"]);
        assert_deny(
            decide(&network_only, &none(), &tool_call("fetch"), mid()),
            "network_egress without name_resolution",
        );
    }

    #[test]
    fn expiry_and_not_yet_valid_are_judged_at_the_injected_instant() {
        let g = governance(&["filesystem_read"]);
        let req = tool_call("reader");
        let expiry = issued() + Duration::from_secs(TTL);

        assert!(permitted(&decide(&g, &none(), &req, issued())));
        assert!(permitted(&decide(&g, &none(), &req, expiry - Duration::from_secs(1))));
        assert_deny(decide(&g, &none(), &req, expiry), "expires_at is exclusive");
        assert_deny(
            decide(&g, &none(), &req, issued() - Duration::from_secs(1)),
            "before not_before",
        );
    }

    #[test]
    fn a_revoked_lease_id_denies_only_what_that_lease_admits() {
        let g = governance(&["filesystem_read", "filesystem_write"]);
        let ids: Vec<&str> = g.lease_ids().collect();
        assert_eq!(
            ids,
            ["run1:filesystem_read", "run1:filesystem_write"],
            "ids come from the lease-id function, in authority.leases order"
        );

        let revoked: BTreeSet<String> = ["run1:filesystem_read".to_string()].into();
        assert_deny(decide(&g, &revoked, &tool_call("reader"), mid()), "read lease revoked");
        assert_deny(
            decide(&g, &revoked, &tool_call("copier"), mid()),
            "one of two leases revoked",
        );
        assert!(permitted(&decide(&g, &revoked, &tool_call("writer"), mid())));

        // A revoked id that names no held lease changes nothing.
        let unrelated: BTreeSet<String> = ["run1:ipc".to_string()].into();
        assert!(permitted(&decide(&g, &unrelated, &tool_call("reader"), mid())));
    }

    #[test]
    fn a_selector_scoped_lease_never_admits_a_tool() {
        // One selector-scoped lease per admittable domain, each against a tool
        // that declares exactly that domain. Whole requirement vs selector
        // lease must be insufficient for every comparator.
        for domain in [
            "filesystem_read",
            "filesystem_write",
            "network_egress",
            "name_resolution",
            "ipc",
            "credential",
        ] {
            let yaml = format!(
                "tools:\n  t: {{ allow: true, capabilities: [{domain}] }}\n\
                 authority:\n  leases:\n    - domain: {domain}\n      scope:\n        - /workspace\n      reason: test\n"
            );
            let resolution = resolve(&yaml);
            assert_eq!(resolution.state_token(), "enforced", "{domain}: {resolution:?}");
            let g = LeaseGovernance::from_resolution(&resolution, SUBJECT, &issuance(), &run_id).unwrap();
            let reason = assert_deny(decide(&g, &none(), &tool_call("t"), mid()), domain);
            assert!(reason.contains("does not admit"), "{domain}: {reason}");

            // Control: the same document with a whole-scope lease does admit,
            // so the deny above is the scope and nothing else.
            let whole = yaml.replace("scope:\n        - /workspace", "scope: whole");
            let g = LeaseGovernance::from_resolution(&resolve(&whole), SUBJECT, &issuance(), &run_id).unwrap();
            assert!(
                permitted(&decide(&g, &none(), &tool_call("t"), mid())),
                "{domain} whole"
            );
        }
    }

    // ── refusals that no lease can lift ────────────────────────────────────

    #[test]
    fn undeclared_disallowed_and_malformed_tool_calls_are_denied() {
        let g = governance(&["filesystem_read"]);

        assert_deny(decide(&g, &none(), &tool_call("undeclared"), mid()), "declared nothing");
        assert_deny(decide(&g, &none(), &tool_call("not_in_policy"), mid()), "unknown tool");
        assert_deny(
            decide(&g, &none(), &tool_call("denied_none"), mid()),
            "allow:false [none]",
        );
        // allow:false stays denied even when the lease for its class is held.
        assert_deny(
            decide(&g, &none(), &tool_call("denied_read"), mid()),
            "allow:false leased",
        );
        assert_deny(decide(&g, &none(), &tool_call(""), mid()), "empty name");
        assert_deny(
            decide(&g, &none(), &action(ActionType::ToolCall as i32), mid()),
            "no context",
        );

        // TOOL_CALL whose context is some other variant carries no tool name.
        let wrong_context = CheckActionRequest {
            action_type: ActionType::ToolCall as i32,
            context: Some(ActionContext {
                action: Some(Action::LlmCall(LlmCallContext::default())),
            }),
            ..Default::default()
        };
        assert_deny(decide(&g, &none(), &wrong_context, mid()), "wrong context variant");
    }

    #[test]
    fn tool_names_match_exactly() {
        let g = governance(&[]);
        for name in ["Calc", "calc ", " calc", "calc\0", "calc/../calc"] {
            assert_deny(decide(&g, &none(), &tool_call(name), mid()), name);
        }
    }

    #[test]
    fn process_creation_and_syscall_tools_are_refused_even_with_a_whole_lease() {
        let g = governance(&["process_creation", "syscall"]);
        let reason = assert_deny(decide(&g, &none(), &tool_call("spawner"), mid()), "process_creation");
        assert!(reason.contains("refused in governed mode"), "{reason}");
        assert_deny(decide(&g, &none(), &tool_call("raw"), mid()), "syscall");
    }

    // ── what a request cannot influence ────────────────────────────────────

    #[test]
    fn request_fields_other_than_action_type_and_tool_name_have_no_effect() {
        let g = governance(&["filesystem_read"]);
        let spoof = |name: &str| {
            let mut req = tool_call(name);
            req.agent_id = Some(ProtoAgentId {
                agent_id: SUBJECT.to_string(),
                ..Default::default()
            });
            req.caller_agent_id = Some(ProtoAgentId {
                agent_id: "admin".to_string(),
                ..Default::default()
            });
            req.credential_token = "tok".to_string();
            req.trace_id = "trace".to_string();
            req.span_id = "span".to_string();
            if let Some(ActionContext {
                action: Some(Action::ToolCall(call)),
            }) = req.context.as_mut()
            {
                call.args_json = br#"{"capabilities":["none"],"allow":true,"lease":"gov-0"}"#.to_vec();
                call.tool_source = "none".to_string();
                call.target_url = "https://allowed.example/".to_string();
            }
            req
        };

        // Smuggled declarations do not turn a needing tool into `[none]`, an
        // undeclared tool into a declared one, or a missing lease into a held one.
        assert_deny(decide(&g, &none(), &spoof("writer"), mid()), "writer");
        assert_deny(decide(&g, &none(), &spoof("undeclared"), mid()), "undeclared");
        assert_deny(decide(&g, &none(), &spoof("denied_none"), mid()), "disallowed");
        // And the same spoof around a legitimate call changes nothing.
        assert_eq!(
            decide(&g, &none(), &spoof("reader"), mid()),
            decide(&g, &none(), &tool_call("reader"), mid())
        );
        assert!(permitted(&decide(&g, &none(), &spoof("reader"), mid())));

        // A forged agent id cannot borrow another subject's lease: the subject
        // is the governance's, so a request naming it neither helps nor hurts.
        let mut other = tool_call("writer");
        other.agent_id = Some(ProtoAgentId {
            agent_id: "agent-with-a-write-lease".to_string(),
            ..Default::default()
        });
        assert_deny(decide(&g, &none(), &other, mid()), "forged agent id");
    }

    #[test]
    fn a_lease_issued_to_another_subject_does_not_admit() {
        let lowered = |subject: &str| {
            let authored: Vec<AuthoredLease> = resolve(&policy(&["filesystem_read"]))
                .lease_grants()
                .iter()
                .map(authored_lease_from)
                .collect();
            lower_leases(
                &authored,
                &LeaseIssuance {
                    subject: IdentityRef::root(subject),
                    default_issuer: IdentityRef::root("test:policy"),
                    issued_at: issued(),
                    default_ttl_seconds: TTL,
                    id_prefix: "gov".to_string(),
                },
            )
            .unwrap()
        };
        let tools: BTreeMap<String, ToolRequirement> = [(
            "reader".to_string(),
            ToolRequirement {
                allow: true,
                capabilities: vec![ToolCapability::Domain(aa_policy::LeaseDomain::FilesystemRead)],
            },
        )]
        .into();

        let theirs =
            LeaseGovernance::from_parts(SUBJECT, tools.clone(), paired(lowered("someone-else")), "d".into()).unwrap();
        let reason = assert_deny(decide(&theirs, &none(), &tool_call("reader"), mid()), "other subject");
        assert!(reason.contains("does not admit"), "{reason}");

        // Control: the identical lease issued to the governed subject admits.
        let ours = LeaseGovernance::from_parts(SUBJECT, tools, paired(lowered(SUBJECT)), "d".into()).unwrap();
        assert!(permitted(&decide(&ours, &none(), &tool_call("reader"), mid())));
    }

    #[test]
    fn a_deny_reason_bounds_an_attacker_supplied_tool_name() {
        let g = governance(&[]);
        let name = format!("x\n\u{1b}[31m{}", "A".repeat(10_000));
        let reason = assert_deny(decide(&g, &none(), &tool_call(&name), mid()), "long name");
        assert!(reason.len() < 300, "{} bytes", reason.len());
        assert!(!reason.contains('\n') && !reason.contains('\u{1b}'), "{reason:?}");
    }

    // ── construction ───────────────────────────────────────────────────────

    #[test]
    fn governance_is_built_only_from_an_enforced_load() {
        let permissive = resolve("tools:\n  \"*\": { allow: true }\n");
        assert_eq!(permissive.state_token(), "permissive");
        let load_failed = PolicyResolution::LoadFailed {
            source: "p.yaml".into(),
            detail: "bad".into(),
        };
        let unconfigured = resolve("budget:\n  daily_limit_usd: 5.0\n");
        assert_eq!(unconfigured.state_token(), "unconfigured");

        for (resolution, state) in [
            (permissive, "permissive"),
            (load_failed, "load_failed"),
            (unconfigured, "unconfigured"),
        ] {
            let err = LeaseGovernance::from_resolution(&resolution, SUBJECT, &issuance(), &run_id).unwrap_err();
            assert_eq!(err, GovernanceError::NotEnforced { state });
        }
    }

    #[test]
    fn governance_refuses_a_max_count_lease_and_an_empty_subject() {
        let yaml = format!(
            "{TOOLS}authority:\n  leases:\n    - domain: filesystem_read\n      scope: whole\n      max_count: 3\n      reason: test\n"
        );
        let resolution = resolve(&yaml);
        assert_eq!(resolution.state_token(), "enforced", "{resolution:?}");
        let err = LeaseGovernance::from_resolution(&resolution, SUBJECT, &issuance(), &run_id).unwrap_err();
        assert!(matches!(err, GovernanceError::Lowering(_)), "{err:?}");

        let ok = resolve(&policy(&[]));
        assert_eq!(
            LeaseGovernance::from_resolution(&ok, "", &issuance(), &run_id).unwrap_err(),
            GovernanceError::EmptySubject
        );
    }

    #[test]
    fn governance_refuses_two_leases_for_one_domain() {
        let lowered = |index: usize| {
            lower_leases(
                &resolve(&policy(&["filesystem_read"]))
                    .lease_grants()
                    .iter()
                    .map(authored_lease_from)
                    .collect::<Vec<_>>(),
                &LeaseIssuance {
                    subject: IdentityRef::root(SUBJECT),
                    default_issuer: IdentityRef::root("test:policy"),
                    issued_at: issued(),
                    default_ttl_seconds: TTL,
                    id_prefix: format!("dup{index}"),
                },
            )
            .unwrap()
        };
        let mut leases = lowered(0);
        leases.extend(lowered(1));
        let err = LeaseGovernance::from_parts(SUBJECT, BTreeMap::new(), paired(leases), "d".into()).unwrap_err();
        assert_eq!(
            err,
            GovernanceError::Authority(AuthorityBuildError::DuplicateLeaseDomain(
                CapabilityDomain::FilesystemRead
            ))
        );
    }

    #[test]
    fn governance_records_the_policy_digest_and_declared_tools() {
        let resolution = resolve(&policy(&["filesystem_read"]));
        let g = LeaseGovernance::from_resolution(&resolution, SUBJECT, &issuance(), &run_id).unwrap();
        assert_eq!(Some(g.policy_digest()), resolution.content_digest());
        assert_eq!(g.subject(), SUBJECT);
        assert!(g.tool("reader").is_some_and(|t| t.allow));
        assert!(g.tool("denied_read").is_some_and(|t| !t.allow));
        assert!(g.tool("undeclared").is_none());
    }
    #[test]
    fn a_failing_lease_id_function_refuses_governance() {
        let resolution = resolve(&policy(&["filesystem_read"]));
        let err = LeaseGovernance::from_resolution(&resolution, SUBJECT, &issuance(), &|_| Err("bad".to_string()))
            .unwrap_err();
        assert_eq!(
            err,
            GovernanceError::LeaseId {
                domain: "filesystem_read".to_string(),
                detail: "bad".to_string()
            }
        );
    }

    /// The wiring contract: ids from `LeaseState::lease_id` and revocation
    /// answered by the same `LeaseState` the operator CLI writes.
    #[cfg(unix)]
    #[test]
    fn lease_state_supplies_both_the_ids_and_the_revoked_set() {
        use crate::lease::state::LeaseState;

        let resolution = resolve(&policy(&["filesystem_read", "filesystem_write"]));
        // `content_digest` is `sha256:<hex>`; the state record stores the bare hex.
        let digest = resolution
            .content_digest()
            .and_then(|d| d.strip_prefix("sha256:"))
            .unwrap()
            .to_string();
        let mut state = LeaseState::new_run(SUBJECT, &digest, 1_000_000).expect("run record");

        let g = LeaseGovernance::from_resolution(&resolution, SUBJECT, &issuance(), &|d| {
            state.lease_id(d).map_err(|e| e.to_string())
        })
        .unwrap();
        let read_id = state.lease_id("filesystem_read").unwrap();
        assert_eq!(g.lease_ids().next(), Some(read_id.as_str()));

        assert!(permitted(&decide(&g, &state, &tool_call("reader"), mid())));
        state.revoke([read_id.as_str()]).unwrap();
        assert_deny(
            decide(&g, &state, &tool_call("reader"), mid()),
            "revoked in the state record",
        );
        assert!(permitted(&decide(&g, &state, &tool_call("writer"), mid())));
    }
    #[test]
    fn duplicate_lease_ids_are_refused() {
        let lowered = lower_leases(
            &resolve(&policy(&["filesystem_read", "filesystem_write"]))
                .lease_grants()
                .iter()
                .map(authored_lease_from)
                .collect::<Vec<_>>(),
            &LeaseIssuance {
                subject: IdentityRef::root(SUBJECT),
                default_issuer: IdentityRef::root("t"),
                issued_at: issued(),
                default_ttl_seconds: TTL,
                id_prefix: "p".to_string(),
            },
        )
        .unwrap();
        let same: Vec<(CapabilityLease, String)> = lowered.into_iter().map(|l| (l, "same".to_string())).collect();
        assert_eq!(
            LeaseGovernance::from_parts(SUBJECT, BTreeMap::new(), same, "d".into()).unwrap_err(),
            GovernanceError::DuplicateLeaseId("same".to_string())
        );
    }

    #[cfg(unix)]
    mod from_state {
        use super::*;
        use crate::lease::state::LeaseState;

        fn hex(resolution: &PolicyResolution) -> String {
            resolution
                .content_digest()
                .and_then(|d| d.strip_prefix("sha256:"))
                .unwrap()
                .to_string()
        }

        #[test]
        fn issue_time_comes_from_the_state_record_not_the_caller() {
            let resolution = resolve(&policy(&["filesystem_read"]));
            let state_issued = 5_000_000;
            let state = LeaseState::new_run(SUBJECT, &hex(&resolution), state_issued).unwrap();
            let g = LeaseGovernance::from_state(&resolution, SUBJECT, TTL, "t", &state).unwrap();
            let start = SystemTime::UNIX_EPOCH + Duration::from_secs(state_issued);
            let req = tool_call("reader");

            assert!(permitted(&decide(&g, &state, &req, start)));
            assert!(permitted(&decide(
                &g,
                &state,
                &req,
                start + Duration::from_secs(TTL - 1)
            )));
            assert_deny(
                decide(&g, &state, &req, start + Duration::from_secs(TTL)),
                "TTL counts from the record's issued_at",
            );
            // The test helper's unrelated clock (1_000_000) is before the
            // record's issue time, so the lease is not yet valid there.
            assert_deny(
                decide(&g, &state, &req, mid()),
                "not valid before the record's issued_at",
            );
        }

        #[test]
        fn a_record_for_another_subject_or_policy_is_refused() {
            let resolution = resolve(&policy(&["filesystem_read"]));
            let other_subject = LeaseState::new_run("someone-else", &hex(&resolution), 1).unwrap();
            assert_eq!(
                LeaseGovernance::from_state(&resolution, SUBJECT, TTL, "t", &other_subject).unwrap_err(),
                GovernanceError::StateSubjectMismatch
            );
            let other_policy = LeaseState::new_run(SUBJECT, &"ab".repeat(32), 1).unwrap();
            assert_eq!(
                LeaseGovernance::from_state(&resolution, SUBJECT, TTL, "t", &other_policy).unwrap_err(),
                GovernanceError::StateDigestMismatch
            );
        }
    }
}
