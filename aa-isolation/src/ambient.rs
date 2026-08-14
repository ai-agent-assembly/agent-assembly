//! The authority a child would hold merely because its parent held it.
//!
//! ADR 0035 §9: *"inherited credentials, sensitive environment variables, open
//! file descriptors, sockets and similar ambient authority"* are capabilities,
//! not convenience. This module is the backend-neutral vocabulary for naming
//! that authority before a launch, so that an execution plan can say which parts
//! of it the child gets deliberately, which parts it does not get at all, and
//! which parts reach it anyway.
//!
//! # The one property this module exists to hold
//!
//! > **"Could not be removed" must never render as "removed".**
//!
//! [`CredentialPosture`] already has the three-way split that makes the
//! distinction expressible ([`removed`], [`delegated`],
//! [`ambient_unremoved`]). What was missing was a way to *build* one that cannot
//! contradict itself. [`EnvironmentPlanner`] is that: a name kept by a
//! [`CompatibilityException`] is placed in `ambient_unremoved` and is
//! structurally unable to also appear in `removed`, and
//! [`CredentialPosture::contradictions`] is the predicate that fails a
//! hand-built posture which does contradict itself.
//!
//! [`removed`]: CredentialPosture::removed
//! [`delegated`]: CredentialPosture::delegated
//! [`ambient_unremoved`]: CredentialPosture::ambient_unremoved
//!
//! # Names, never values
//!
//! Nothing here reads, stores or accepts an environment variable's *value*. Two
//! reasons, and the second is the load-bearing one:
//!
//! 1. Everything here is rendered into `--dry-run` output, evidence and audit
//!    records, and a value placed in any of these structures would be published
//!    by all three.
//! 2. **This is not a secret detector, and must not be mistaken for one.** What
//!    it provides is a *name-shaped lower bound*: a name that classifies here
//!    almost certainly carries authority, and a name that does not classify here
//!    is **not** evidence that its value is harmless. That asymmetry is why the
//!    planner removes everything it was not told to keep rather than removing
//!    only what it recognised — recognition is the wrong side of the boundary to
//!    build least authority on.
//!
//! # Two credential questions that are not the same question
//!
//! The word "credential" names two different problems in this product, and this
//! module answers exactly one of them.
//!
//! | Question | Answered by | Shape |
//! | --- | --- | --- |
//! | Can this process *reach* that authority? | here, and [`CapabilityDomain::Credential`] | Environment names, inherited descriptors, auth sockets, metadata endpoints |
//! | Is credential material *leaving* a boundary? | the sensitive-data programme's detection and redaction model | Content inspection, with a redaction verdict |
//!
//! They are related and not interchangeable. A redaction verdict about content
//! says nothing about which authority a process can reach, and nothing in this
//! module bounds what a scanner will find. No detection or redaction model is
//! implemented here, and none should be added merely because a `Credential`
//! capability domain exists in this crate.
//!
//! Nor is this a credential broker. Handing a child a *scoped, minted, revocable*
//! credential in place of the operator's own is a different mechanism with a
//! different trust boundary, and this module deliberately does not build one:
//! its whole vocabulary is *which names reach the child*, never *what a name is
//! worth*.
//!
//! # Why AASM's own variables are singled out
//!
//! ADR 0035 §5 keeps the supervisor outside the confined tree, and the Epic's
//! acceptance criterion is that operator/gateway credentials must not reach the
//! child *solely because the supervisor possesses them*. Starting from an empty
//! environment already achieves that for the default path. What
//! [`is_supervisor_credential`] adds is the second half: a supervisor credential
//! cannot become delegated by an ordinary [`EnvironmentPlanner::delegate`] call
//! either. The request is recorded in
//! [`EnvironmentPlan::withheld_supervisor_credentials`] rather than silently
//! honoured or silently dropped.
//!
//! The rule is deliberately narrower than "every AASM-prefixed variable".
//! `AA_AGENT_ID`, `AA_TRACE_ID` and `AA_GATEWAY_URL` are correlation and
//! endpoint data that a governed launch is *supposed* to hand its child; folding
//! them in would make the protection unusable and then bypassed.

use crate::capability::CapabilityDomain;
use crate::spec::CredentialPosture;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The kind of authority a named ambient item carries.
///
/// `#[non_exhaustive]`: this is an inventory of things that exist in the world,
/// and the world adds more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum AmbientAuthorityKind {
    /// A cloud provider credential, or a path to one.
    CloudCredential,
    /// A bearer token or API key for a hosted service.
    ServiceToken,
    /// A connection string that conventionally embeds a password.
    ConnectionString,
    /// An address of a process that will authenticate or sign on the holder's
    /// behalf.
    ///
    /// The credential itself never appears in the value: the value is a socket
    /// path or endpoint, and possessing it *is* the authority. An SSH agent
    /// socket lets its holder sign with a key it can never read, and a container
    /// daemon socket is ordinarily equivalent to host root.
    DelegatedAuthAgent,
    /// A variable that makes an instance-metadata service reachable, or
    /// redirects where it is looked for.
    ///
    /// The metadata service mints cloud credentials for anyone who can reach it,
    /// which is why this is both a credential and a network fact — see
    /// [`domains`](Self::domains).
    CloudMetadataEndpoint,
    /// AASM's own operator or gateway authority.
    SupervisorCredential,
}

impl AmbientAuthorityKind {
    /// Every kind, for exhaustive iteration in tests and reports.
    pub const ALL: &'static [Self] = &[
        Self::CloudCredential,
        Self::ServiceToken,
        Self::ConnectionString,
        Self::DelegatedAuthAgent,
        Self::CloudMetadataEndpoint,
        Self::SupervisorCredential,
    ];

    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CloudCredential => "cloud_credential",
            Self::ServiceToken => "service_token",
            Self::ConnectionString => "connection_string",
            Self::DelegatedAuthAgent => "delegated_auth_agent",
            Self::CloudMetadataEndpoint => "cloud_metadata_endpoint",
            Self::SupervisorCredential => "supervisor_credential",
        }
    }

    /// The capability domains a backend must control to actually stop this.
    ///
    /// More than one for the two kinds whose authority arrives over a channel
    /// rather than in a value: removing the variable does not remove the
    /// channel, so a backend that only replaces the environment has covered half
    /// of it. Reporting one domain would let a launch that controls the
    /// environment and nothing else read as having handled the whole item.
    pub fn domains(self) -> &'static [CapabilityDomain] {
        match self {
            Self::CloudCredential | Self::ServiceToken | Self::ConnectionString | Self::SupervisorCredential => {
                &[CapabilityDomain::Credential]
            }
            // The socket outlives the name: an inherited descriptor to the same
            // socket reaches the agent without the variable.
            Self::DelegatedAuthAgent => &[CapabilityDomain::Credential, CapabilityDomain::Ipc],
            // The endpoint has a well-known default address, so unsetting the
            // variable leaves it reachable to anything with egress.
            Self::CloudMetadataEndpoint => &[CapabilityDomain::Credential, CapabilityDomain::NetworkEgress],
        }
    }
}

/// Well-known instance-metadata service addresses.
///
/// Carried here as **data an operator and a backend can both read**, not as a
/// matcher. This crate does not interpret [`RequirementScope::Selectors`]
/// entries — that invariant is stated on the type and holds without exception —
/// so deciding whether a permitted egress destination reaches one of these is
/// the backend's job, where CIDR and hostname semantics already live.
///
/// The list is not exhaustive and cannot be: a metadata service is reachable
/// through any route to the link-local range, and a launch that permits broad
/// egress reaches it regardless of what is named here.
///
/// [`RequirementScope::Selectors`]: crate::spec::RequirementScope::Selectors
pub const CLOUD_METADATA_ENDPOINTS: &[&str] = &[
    // EC2 / GCE / Azure IMDS, and the OpenStack-derived services that reuse the
    // same link-local address.
    "169.254.169.254",
    // The IPv6 form of the same EC2 service.
    "fd00:ec2::254",
    // Azure Instance Metadata Service via its wire-server address.
    "168.63.129.16",
    "metadata.google.internal",
    "metadata.goog",
    // ECS task metadata and credential endpoints live on the task-local address.
    "169.254.170.2",
];

/// Name fragments that mark a variable as carrying opaque credential material.
///
/// Uppercase, matched as substrings, and deliberately over-inclusive: a
/// non-secret classified as a secret is removed from a child that probably did
/// not need it, while a secret that is not classified reaches an untrusted
/// process. `PASS` matching `COMPASS` is the price of `PASS` matching
/// `SMTP_PASS`, and it is the right way round.
///
/// `CRED` rather than `CREDENTIAL` so that `NATS_CREDS` is covered too.
const OPAQUE_SECRET_FRAGMENTS: &[&str] = &["TOKEN", "KEY", "SECRET", "PASSWORD", "PASS", "CRED", "AUTH"];

/// Suffixes of names that conventionally hold a `scheme://user:pass@host` URI.
const CONNECTION_STRING_SUFFIXES: &[&str] = &["_URL", "_URI", "_DSN"];

/// Prefixes AASM uses for its own variables.
const SUPERVISOR_PREFIXES: &[&str] = &["AA_", "AASM_", "AGENT_ASSEMBLY_"];

/// Exact names whose authority is a channel to an agent that signs or
/// authenticates for its holder.
const AUTH_AGENT_NAMES: &[&str] = &[
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "GNUPGHOME",
    "DBUS_SESSION_BUS_ADDRESS",
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "PODMAN_HOST",
];

/// Exact names that point at, enable or redirect an instance-metadata service.
const METADATA_ENDPOINT_NAMES: &[&str] = &[
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "ECS_CONTAINER_METADATA_URI",
    "ECS_CONTAINER_METADATA_URI_V4",
    "GCE_METADATA_HOST",
    "GCE_METADATA_ROOT",
    "GCE_METADATA_IP",
    "IMDS_ENDPOINT",
    "MSI_ENDPOINT",
    "IDENTITY_ENDPOINT",
    "AZURE_POD_IDENTITY_AUTHORITY_HOST",
];

/// Prefixes and exact names of cloud provider credentials, or paths to them.
const CLOUD_CREDENTIAL_PREFIXES: &[&str] = &["AWS_", "AZURE_", "GCP_", "GCLOUD_", "GOOGLE_", "ALIYUN_", "OCI_"];

/// Exact names that are a path to a credential file rather than a credential.
const CLOUD_CREDENTIAL_NAMES: &[&str] = &["KUBECONFIG", "BOTO_CONFIG", "CLOUDSDK_CONFIG"];

/// Whether an environment variable name is AASM's own operator or gateway
/// authority.
///
/// True only when the name carries **both** an AASM prefix and an opaque-secret
/// fragment. See the module documentation for why the prefix alone is not the
/// rule: `AA_AGENT_ID` and `AA_GATEWAY_URL` are things a governed launch hands
/// its child on purpose.
///
/// Connection-string shape is deliberately *not* part of this test.
/// `AA_GATEWAY_URL` is an endpoint the child legitimately needs; it is still
/// classified as [`AmbientAuthorityKind::ConnectionString`] by
/// [`classify_env_name`], so it is removed unless delegated — it just is not
/// *refused* delegation.
pub fn is_supervisor_credential(name: &str) -> bool {
    let upper = name.to_uppercase();
    SUPERVISOR_PREFIXES.iter().any(|p| upper.starts_with(p))
        && OPAQUE_SECRET_FRAGMENTS.iter().any(|f| upper.contains(f))
}

/// Classify an environment variable **name**, or `None` if nothing about the
/// name suggests ambient authority.
///
/// `None` is not a statement that the value is harmless — see the module
/// documentation. Case-insensitive, because a host's environment is not.
///
/// Order matters where the categories overlap, and the order is from most
/// specific to least: `AWS_EC2_METADATA_SERVICE_ENDPOINT` is a metadata endpoint
/// rather than a cloud credential, and `AA_JWT_SECRET` is supervisor authority
/// rather than a generic service token. Collapsing either would lose the
/// distinction the caller acts on.
pub fn classify_env_name(name: &str) -> Option<AmbientAuthorityKind> {
    let upper = name.to_uppercase();
    if METADATA_ENDPOINT_NAMES.contains(&upper.as_str()) {
        return Some(AmbientAuthorityKind::CloudMetadataEndpoint);
    }
    if AUTH_AGENT_NAMES.contains(&upper.as_str()) {
        return Some(AmbientAuthorityKind::DelegatedAuthAgent);
    }
    if is_supervisor_credential(&upper) {
        return Some(AmbientAuthorityKind::SupervisorCredential);
    }
    if CLOUD_CREDENTIAL_NAMES.contains(&upper.as_str())
        || (CLOUD_CREDENTIAL_PREFIXES.iter().any(|p| upper.starts_with(p))
            && OPAQUE_SECRET_FRAGMENTS.iter().any(|f| upper.contains(f)))
    {
        return Some(AmbientAuthorityKind::CloudCredential);
    }
    if CONNECTION_STRING_SUFFIXES.iter().any(|s| upper.ends_with(s)) {
        return Some(AmbientAuthorityKind::ConnectionString);
    }
    if OPAQUE_SECRET_FRAGMENTS.iter().any(|f| upper.contains(f)) {
        return Some(AmbientAuthorityKind::ServiceToken);
    }
    None
}

/// One inherited name and what it was classified as.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ClassifiedName {
    /// The environment variable's name. Never its value.
    pub name: String,
    /// What the name suggests it carries.
    pub kind: AmbientAuthorityKind,
}

/// A variable the launch keeps for compatibility despite policy asking for its
/// removal.
///
/// The existence of this type is the point. A transitional exception that is
/// merely *not implemented* is invisible; one that has to be constructed, named
/// and justified appears in the plan, in evidence and in `--dry-run` output, and
/// [`EnvironmentPlanner::plan`] routes it to
/// [`CredentialPosture::ambient_unremoved`] where it marks the run as not
/// least-authority.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompatibilityException {
    /// The environment variable name kept.
    pub name: String,
    /// Why it is kept, in words an operator can weigh.
    pub justification: String,
    /// The ticket tracking its removal, when one exists.
    ///
    /// `Option` rather than required: an exception without a ticket is still
    /// better recorded than not recorded, and forcing a value here would be
    /// answered with a placeholder.
    pub tracked_by: Option<String>,
}

impl CompatibilityException {
    /// An exception with a justification and no tracking ticket yet.
    pub fn new(name: impl Into<String>, justification: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            justification: justification.into(),
            tracked_by: None,
        }
    }

    /// Record the ticket tracking this exception's removal.
    pub fn tracked_by(mut self, ticket: impl Into<String>) -> Self {
        self.tracked_by = Some(ticket.into());
        self
    }
}

/// The environment a launch will hand its child, derived from the environment it
/// was launched with.
///
/// Produced only by [`EnvironmentPlanner::plan`], so the invariants below hold
/// by construction rather than by review:
///
/// * a name appears in exactly one of the posture's three lists;
/// * a [`CompatibilityException`]'s name is in `ambient_unremoved` and never in
///   `removed`;
/// * a name for which [`is_supervisor_credential`] holds is in `removed`, and
///   is additionally listed in [`withheld_supervisor_credentials`] when someone
///   asked for it to be delegated.
///
/// [`withheld_supervisor_credentials`]: Self::withheld_supervisor_credentials
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnvironmentPlan {
    posture: CredentialPosture,
    exceptions: Vec<CompatibilityException>,
    withheld_supervisor_credentials: Vec<String>,
    classified: Vec<ClassifiedName>,
}

impl EnvironmentPlan {
    /// The posture to put on an [`ExecutionSpec`](crate::spec::ExecutionSpec).
    pub fn posture(&self) -> &CredentialPosture {
        &self.posture
    }

    /// Take the posture, consuming the plan.
    pub fn into_posture(self) -> CredentialPosture {
        self.posture
    }

    /// The exceptions that were applied, in the order they were registered.
    ///
    /// Non-empty means the run is not least-authority, and the justifications
    /// here are what an operator reads to decide whether to accept it.
    pub fn exceptions(&self) -> &[CompatibilityException] {
        &self.exceptions
    }

    /// Supervisor credentials that were present and were kept from the child.
    ///
    /// Includes any that a caller asked to delegate: the request is recorded
    /// rather than honoured, so a plan shows that it was made and refused.
    pub fn withheld_supervisor_credentials(&self) -> &[String] {
        &self.withheld_supervisor_credentials
    }

    /// Every inherited name the classifier recognised, with its kind.
    ///
    /// The classifier's silence about a name is not in this list and must not be
    /// read as a clean bill of health — see the module documentation.
    pub fn classified(&self) -> &[ClassifiedName] {
        &self.classified
    }

    /// Whether the child receives only authority this plan decided to give it.
    ///
    /// False whenever any name reaches the child that policy asked to remove,
    /// which is exactly when [`CredentialPosture::ambient_unremoved`] is
    /// non-empty. A caller rendering a launch as least-authority must consult
    /// this rather than the delegated list.
    pub fn is_least_authority(&self) -> bool {
        !self.posture.has_unremoved_ambient_authority()
    }
}

/// Builds an [`EnvironmentPlan`] from the launching environment's variable
/// names.
///
/// # Why this replaces the environment rather than filtering it
///
/// A filter removes what it recognises and keeps everything else, so its
/// correctness depends on the completeness of a name heuristic that cannot be
/// complete. A replacement keeps what it was told to keep and removes everything
/// else, so an unrecognised credential is removed *because nobody named it*.
/// The failure mode of the first is a leaked secret; the failure mode of the
/// second is a child missing a variable, which surfaces immediately and is
/// fixed with a delegation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentPlanner {
    delegated: Vec<String>,
    exceptions: Vec<CompatibilityException>,
}

impl EnvironmentPlanner {
    /// A planner that delegates nothing and grants no exception.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pass this name through to the child, as a decision.
    ///
    /// A name for which [`is_supervisor_credential`] holds is **not** delegated
    /// by this call. It is removed, and the request appears in
    /// [`EnvironmentPlan::withheld_supervisor_credentials`]. There is no
    /// override in this crate: no protocol currently requires the child to hold
    /// AASM's own gateway authority, and an unused escape hatch would be a
    /// bypass waiting for its first caller.
    pub fn delegate(mut self, name: impl Into<String>) -> Self {
        self.delegated.push(name.into());
        self
    }

    /// Keep this name for compatibility, recording why.
    ///
    /// The name lands in [`CredentialPosture::ambient_unremoved`], never in
    /// `removed`.
    pub fn except(mut self, exception: CompatibilityException) -> Self {
        self.exceptions.push(exception);
        self
    }

    /// Classify the launching environment's names into a plan.
    ///
    /// `inherited` is the set of variable names present in the environment the
    /// launch inherits — **names only**. Names are deduplicated and each list in
    /// the resulting posture is sorted, so two runs over the same environment
    /// produce byte-identical evidence whatever order the host enumerated it in.
    ///
    /// A delegated or excepted name that is absent from `inherited` is simply
    /// not in the plan: it cannot reach the child, and reporting it as delegated
    /// would claim the child has something it does not.
    pub fn plan<I, S>(&self, inherited: I) -> EnvironmentPlan
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut names: Vec<String> = inherited.into_iter().map(Into::into).collect();
        names.sort();
        names.dedup();

        let mut posture = CredentialPosture::default();
        let mut exceptions = Vec::new();
        let mut withheld = Vec::new();
        let mut classified = Vec::new();

        for name in names {
            if let Some(kind) = classify_env_name(&name) {
                classified.push(ClassifiedName {
                    name: name.clone(),
                    kind,
                });
            }
            // Precedence, strictest first. Supervisor authority wins over both
            // explicit acts: an exception is a statement about compatibility
            // with the operator's own tooling, and AASM's gateway credential is
            // never that.
            if is_supervisor_credential(&name) {
                withheld.push(name.clone());
                posture.removed.push(name);
                continue;
            }
            if let Some(exception) = self.exceptions.iter().find(|e| e.name == name) {
                exceptions.push(exception.clone());
                posture.ambient_unremoved.push(name);
                continue;
            }
            if self.delegated.contains(&name) {
                posture.delegated.push(name);
                continue;
            }
            posture.removed.push(name);
        }

        posture.removed.sort();
        posture.delegated.sort();
        posture.ambient_unremoved.sort();
        withheld.sort();

        EnvironmentPlan {
            posture,
            exceptions,
            withheld_supervisor_credentials: withheld,
            classified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL` is hand-maintained; a variant added without it would vanish from
    /// every sweep that iterates it.
    #[test]
    fn all_lists_every_kind() {
        let count = AmbientAuthorityKind::ALL
            .iter()
            .map(|kind| match kind {
                AmbientAuthorityKind::CloudCredential
                | AmbientAuthorityKind::ServiceToken
                | AmbientAuthorityKind::ConnectionString
                | AmbientAuthorityKind::DelegatedAuthAgent
                | AmbientAuthorityKind::CloudMetadataEndpoint
                | AmbientAuthorityKind::SupervisorCredential => 1,
            })
            .sum::<usize>();
        assert_eq!(count, AmbientAuthorityKind::ALL.len());
        let mut seen = AmbientAuthorityKind::ALL.to_vec();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), AmbientAuthorityKind::ALL.len());
    }

    /// Every kind must name at least one domain, or a backend reading the plan
    /// has nothing to check the item against.
    #[test]
    fn every_kind_names_a_domain_and_is_a_credential_matter() {
        for kind in AmbientAuthorityKind::ALL {
            assert!(
                kind.domains().contains(&CapabilityDomain::Credential),
                "{} does not name the credential domain",
                kind.as_str()
            );
        }
    }

    /// The two kinds whose authority survives the variable's removal must say so
    /// with a second domain. Asserted as an exact set, not a count: a domain
    /// swapped for another would keep any count assertion green.
    #[test]
    fn channel_backed_authority_names_the_domain_that_carries_the_channel() {
        assert_eq!(
            AmbientAuthorityKind::DelegatedAuthAgent.domains(),
            [CapabilityDomain::Credential, CapabilityDomain::Ipc]
        );
        assert_eq!(
            AmbientAuthorityKind::CloudMetadataEndpoint.domains(),
            [CapabilityDomain::Credential, CapabilityDomain::NetworkEgress]
        );
        // The control: a kind whose authority *is* the value names one domain,
        // so the assertions above are not passing because everything has two.
        assert_eq!(
            AmbientAuthorityKind::ServiceToken.domains(),
            [CapabilityDomain::Credential]
        );
    }

    #[test]
    fn classification_prefers_the_more_specific_kind() {
        // Metadata beats cloud credential, though the name starts with `AWS_`
        // and contains no secret fragment at all.
        assert_eq!(
            classify_env_name("AWS_CONTAINER_CREDENTIALS_FULL_URI"),
            Some(AmbientAuthorityKind::CloudMetadataEndpoint)
        );
        // Supervisor beats service token, though `SECRET` would match both.
        assert_eq!(
            classify_env_name("AA_JWT_SECRET"),
            Some(AmbientAuthorityKind::SupervisorCredential)
        );
        // Cloud beats service token, though `KEY` would match both.
        assert_eq!(
            classify_env_name("AWS_SECRET_ACCESS_KEY"),
            Some(AmbientAuthorityKind::CloudCredential)
        );
    }

    #[test]
    fn representative_names_classify_as_expected() {
        for (name, expected) in [
            ("SSH_AUTH_SOCK", AmbientAuthorityKind::DelegatedAuthAgent),
            ("DOCKER_HOST", AmbientAuthorityKind::DelegatedAuthAgent),
            ("GITHUB_TOKEN", AmbientAuthorityKind::ServiceToken),
            ("ANTHROPIC_API_KEY", AmbientAuthorityKind::ServiceToken),
            ("DATABASE_URL", AmbientAuthorityKind::ConnectionString),
            ("KUBECONFIG", AmbientAuthorityKind::CloudCredential),
            ("AASM_API_KEY", AmbientAuthorityKind::SupervisorCredential),
            ("GCE_METADATA_HOST", AmbientAuthorityKind::CloudMetadataEndpoint),
        ] {
            assert_eq!(classify_env_name(name), Some(expected), "{name}");
        }
        // Case-insensitivity, because a host's environment is not uppercase by
        // rule.
        assert_eq!(
            classify_env_name("ssh_auth_sock"),
            Some(AmbientAuthorityKind::DelegatedAuthAgent)
        );
    }

    /// The classifier's silence has to be real silence, or the tests above would
    /// pass against a function that classified everything.
    #[test]
    fn ordinary_names_classify_as_nothing() {
        for name in ["PATH", "HOME", "LANG", "TERM", "EDITOR", "PWD", "SHLVL"] {
            assert_eq!(classify_env_name(name), None, "{name}");
        }
    }

    /// The narrowing that keeps the supervisor rule usable. If these three
    /// became supervisor credentials, a governed launch could not hand its child
    /// the identifiers the SDK correlates on, and the rule would be bypassed.
    #[test]
    fn aasm_correlation_variables_are_not_supervisor_credentials() {
        for name in ["AA_AGENT_ID", "AA_TRACE_ID", "AA_SESSION_ID", "AA_GATEWAY_URL"] {
            assert!(!is_supervisor_credential(name), "{name}");
        }
        // The control: names that differ only by carrying a secret fragment do
        // classify, so the assertions above are about the fragment and not about
        // the prefix being ignored entirely.
        for name in ["AA_GATEWAY_AUTH", "AA_JWT_SECRET", "AASM_API_KEY", "AA_SMTP_PASS"] {
            assert!(is_supervisor_credential(name), "{name}");
        }
    }

    /// A secret fragment without an AASM prefix is somebody else's credential,
    /// not the supervisor's.
    #[test]
    fn a_third_party_token_is_not_supervisor_authority() {
        assert!(!is_supervisor_credential("GITHUB_TOKEN"));
        assert!(!is_supervisor_credential("AWS_SECRET_ACCESS_KEY"));
    }

    // ---- the property this module exists for ------------------------------

    /// **The single property.** A name kept by an exception is reported as
    /// ambient authority that could not be removed, and is *not* reported as
    /// removed.
    ///
    /// The negative control is the same name through the same planner with the
    /// exception withdrawn: it lands in `removed` and out of
    /// `ambient_unremoved`. Without that pair the assertion below would also
    /// pass against a planner that put nothing anywhere.
    #[test]
    fn an_exception_is_never_reported_as_removed() {
        let inherited = ["PATH", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"];

        let kept = EnvironmentPlanner::new()
            .except(CompatibilityException::new(
                "SSH_AUTH_SOCK",
                "the agent's git remote is authenticated by the operator's SSH agent",
            ))
            .plan(inherited);
        assert!(
            kept.posture().ambient_unremoved.contains(&"SSH_AUTH_SOCK".to_string()),
            "{:?}",
            kept.posture()
        );
        assert!(
            !kept.posture().removed.contains(&"SSH_AUTH_SOCK".to_string()),
            "an exception was reported as removed: {:?}",
            kept.posture()
        );
        assert!(!kept.is_least_authority(), "a kept exception is not least authority");
        assert_eq!(kept.exceptions().len(), 1);

        // Negative control: withdraw the exception and nothing else changes.
        let dropped = EnvironmentPlanner::new().plan(inherited);
        assert!(dropped.posture().removed.contains(&"SSH_AUTH_SOCK".to_string()));
        assert!(dropped.posture().ambient_unremoved.is_empty());
        assert!(dropped.is_least_authority());
    }

    /// The two states an operator has to be able to tell apart, side by side in
    /// one plan: one credential removed, one kept as a documented exception.
    #[test]
    fn a_removed_credential_and_a_kept_one_are_distinguishable_in_one_plan() {
        let plan = EnvironmentPlanner::new()
            .except(CompatibilityException::new("GITHUB_TOKEN", "the agent pushes branches").tracked_by("AAASM-5711"))
            .plan(["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "PATH"]);
        assert_eq!(plan.posture().ambient_unremoved, ["GITHUB_TOKEN"]);
        assert!(plan.posture().removed.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
        assert_eq!(plan.exceptions()[0].tracked_by.as_deref(), Some("AAASM-5711"));
        assert!(plan.posture().contradictions().is_empty(), "{:?}", plan.posture());
    }

    /// A supervisor credential must not reach the child, and asking for it must
    /// leave a trace rather than being silently honoured or silently dropped.
    #[test]
    fn a_supervisor_credential_is_withheld_even_when_delegation_is_requested() {
        let plan = EnvironmentPlanner::new()
            .delegate("AA_GATEWAY_AUTH")
            .delegate("AA_AGENT_ID")
            .plan(["AA_GATEWAY_AUTH", "AA_AGENT_ID", "PATH"]);
        assert!(
            !plan.posture().delegated.contains(&"AA_GATEWAY_AUTH".to_string()),
            "supervisor authority was delegated: {:?}",
            plan.posture()
        );
        assert!(plan.posture().removed.contains(&"AA_GATEWAY_AUTH".to_string()));
        assert_eq!(plan.withheld_supervisor_credentials(), ["AA_GATEWAY_AUTH"]);
        // The control: an ordinary delegation through the same call does reach
        // the child, so the refusal above is about the classification and not
        // about `delegate` being inert.
        assert!(plan.posture().delegated.contains(&"AA_AGENT_ID".to_string()));
    }

    /// An exception cannot smuggle supervisor authority past the withholding.
    #[test]
    fn an_exception_does_not_override_supervisor_withholding() {
        let plan = EnvironmentPlanner::new()
            .except(CompatibilityException::new("AA_JWT_SECRET", "claimed to be needed"))
            .plan(["AA_JWT_SECRET"]);
        assert!(plan.posture().ambient_unremoved.is_empty(), "{:?}", plan.posture());
        assert_eq!(plan.posture().removed, ["AA_JWT_SECRET"]);
        assert_eq!(plan.withheld_supervisor_credentials(), ["AA_JWT_SECRET"]);
    }

    /// A delegated name that is not in the environment cannot reach the child,
    /// so the plan must not say it does.
    #[test]
    fn a_delegation_of_an_absent_name_claims_nothing() {
        let plan = EnvironmentPlanner::new().delegate("NOT_SET_ANYWHERE").plan(["PATH"]);
        assert!(plan.posture().delegated.is_empty(), "{:?}", plan.posture());
    }

    /// Everything not named is removed. That is the whole difference between
    /// replacing an environment and filtering one, and a planner that kept
    /// unrecognised names would pass every other test here.
    #[test]
    fn an_unrecognised_name_is_removed_rather_than_kept() {
        let plan = EnvironmentPlanner::new().plan(["SOME_INTERNAL_HANDOFF_VALUE"]);
        assert_eq!(plan.posture().removed, ["SOME_INTERNAL_HANDOFF_VALUE"]);
        assert!(plan.classified().is_empty(), "the name should not classify");
        assert!(plan.posture().delegated.is_empty());
    }

    /// Evidence has to be comparable between runs, so the output order cannot
    /// depend on the order the host enumerated its environment in.
    #[test]
    fn planning_is_order_independent_and_deduplicated() {
        let a = EnvironmentPlanner::new().plan(["B", "A", "C", "A"]);
        let b = EnvironmentPlanner::new().plan(["C", "A", "B"]);
        assert_eq!(a.posture(), b.posture());
        assert_eq!(a.posture().removed, ["A", "B", "C"]);
    }
}
