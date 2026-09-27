//! The versioned execution-receipt schema (AAASM-6166).
//!
//! `RECEIPT_SCHEMA` is bumped whenever a downstream reader of a stored receipt
//! would have to change to keep reading it — the same discipline
//! `aa_isolation::report::REPORT_SCHEMA` documents for `--dry-run`'s own
//! machine block. Adding an optional field is not such a change; removing or
//! renaming one is.
use super::canonical::{digest_of, CanonicalError, Digest, CANONICAL_FORM};
use super::text::{FieldName, ReceiptText};

/// The receipt schema identifier.
pub const RECEIPT_SCHEMA: &str = "aasm.execution.receipt/1";

/// The one kind of seal this build knows how to compute and check.
///
/// `#[non_exhaustive]` because a future kind is additive — deciding what it
/// would be (a real signature, an HMAC keyed by something a SaaS verifier
/// alone holds) is explicitly out of this ticket's scope; see `mod.rs`'s "What
/// this amendment does not decide".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReceiptSealKind {
    /// `sha256` over [`super::canonical::canonical_json`] of the body.
    ContentDigestSha256,
}

/// A content digest over [`ReceiptEnvelope::body`] — **not** a signature and
/// not a MAC. See `mod.rs`'s module documentation for what this does and does
/// not establish.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptSeal {
    /// The kind of seal.
    pub kind: ReceiptSealKind,
    /// The digest itself.
    pub digest: Digest,
    /// What computed it — an origin *label*, not an authenticated identity.
    /// No key exists anywhere in this design, so this field is exactly as
    /// trustworthy as the rest of the unsealed envelope metadata: an attacker
    /// who can rewrite `body` can rewrite this too.
    pub sealed_by: ReceiptText,
    /// When the seal was computed, in unix seconds.
    pub sealed_at_unix_secs: u64,
    /// The canonical form the digest was taken over.
    ///
    /// Recorded so a future canonicalization change is detectable rather than
    /// silently producing a mismatch — but note this field itself sits
    /// *outside* the digest (the digest covers `body` only), so it is not
    /// itself tamper-evident. See `mod.rs`'s "What the seal covers".
    pub canonical_form: ReceiptText,
}

/// The sealed execution receipt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptEnvelope {
    /// [`RECEIPT_SCHEMA`], recorded on the instance so an older reader can
    /// recognize a receipt it does not know how to read.
    pub schema: String,
    /// The seal over `body`.
    pub seal: ReceiptSeal,
    /// The receipt's content.
    pub body: ReceiptBody,
}

impl ReceiptEnvelope {
    /// Seal `body`: compute its digest and wrap it in a fresh envelope.
    pub fn seal(body: ReceiptBody) -> Result<Self, CanonicalError> {
        let digest = digest_of(&body)?;
        let sealed_at_unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(Self {
            schema: RECEIPT_SCHEMA.to_string(),
            seal: ReceiptSeal {
                kind: ReceiptSealKind::ContentDigestSha256,
                digest,
                sealed_by: ReceiptText::token("aasm"),
                sealed_at_unix_secs,
                canonical_form: ReceiptText::token(CANONICAL_FORM),
            },
            body,
        })
    }

    /// Whether the seal still covers `body` exactly — tamper-since-write
    /// detection, not proof of origin. See `mod.rs`.
    pub fn seal_holds(&self) -> Result<bool, CanonicalError> {
        let recomputed = digest_of(&self.body)?;
        Ok(recomputed == self.seal.digest)
    }
}

/// The receipt's content — everything the seal digests.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptBody {
    /// This launch's session id.
    pub run_id: String,
    /// This launch's trace id.
    pub trace_id: String,
    /// When the receipt was assembled, in unix seconds.
    pub recorded_at_unix_secs: u64,
    /// Who the run is attributed to. Asserted, not verified.
    pub asserted_identity: AssertedIdentity,
    /// What produced this receipt.
    pub producer: ProducerIdentity,
    /// The policy binding.
    pub policy: PolicyBinding,
    /// The spec binding.
    pub spec: SpecBinding,
    /// The backend binding. `None` when no execution-isolation boundary ran.
    pub backend: Option<BackendBinding>,
    /// Measured-versus-asserted host and build facts.
    pub host: Vec<super::host::MeasuredFact>,
    /// A digest of the guest/runtime image, when one could be computed.
    /// `None` on every backend today — see `mod.rs`'s deferred-scope list.
    pub runtime_image: Option<Digest>,
    /// This launch's capability leases.
    pub leases: Vec<LeaseBinding>,
    /// One outcome per [`aa_isolation::CapabilityDomain::ALL`] entry, always,
    /// in that order.
    pub domains: Vec<DomainOutcome>,
    /// Credential names only — never values.
    pub credentials: CredentialNames,
    /// A workspace-transaction binding. `None` today — see `mod.rs`.
    pub workspace: Option<WorkspaceBinding>,
    /// What the launch actually did.
    pub execution: ExecutionOutcome,
    /// Conditions that weakened some part of this receipt or the run it
    /// describes.
    pub degraded: Vec<DegradedCondition>,
    /// Every field a withholding was recorded against.
    pub withheld_fields: Vec<FieldName>,
    /// References to the runtime evidence records this receipt draws on.
    pub evidence_refs: Vec<EvidenceRef>,
}

impl ReceiptBody {
    /// The weakest honest one-word summary of this receipt's posture.
    ///
    /// Derived, never stored — a stored summary alongside the per-domain
    /// table would be two answers to one question, and a tampered receipt
    /// would only need to edit the cheaper one.
    pub fn posture(&self) -> &'static str {
        if self.backend.is_none() {
            return "no_boundary";
        }
        if !self.degraded.is_empty() {
            return "degraded";
        }
        "ready"
    }

    /// Wall-clock duration of the launch, in seconds.
    pub fn elapsed_secs(&self) -> u64 {
        self.execution
            .ended_at_unix_secs
            .saturating_sub(self.execution.started_at_unix_secs)
    }

    /// Whether no authority reaches the child beyond what policy intended.
    pub fn is_least_authority(&self) -> bool {
        self.credentials.ambient_unremoved.is_empty()
    }
}

/// Who the run is attributed to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AssertedIdentity {
    /// The agent this launch is attributed to. Asserted, not verified.
    pub agent_id: ReceiptText,
    /// The owning team, when the launch has one.
    pub team_id: Option<ReceiptText>,
    /// Ancestor agent ids, outermost first.
    pub lineage: Vec<ReceiptText>,
    /// How many ancestors this launch has.
    pub depth: usize,
}

/// What produced this receipt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProducerIdentity {
    /// The component that assembled this receipt.
    pub component: ReceiptText,
    /// This build's version (`CARGO_PKG_VERSION`).
    pub release: ReceiptText,
    /// This build's source revision, when recorded. `None` on every build
    /// today — no build script records one.
    pub source_revision: Option<ReceiptText>,
}

impl ProducerIdentity {
    /// The producer identity for this build.
    pub fn current() -> Self {
        Self {
            component: ReceiptText::token("aasm"),
            release: ReceiptText::screened(env!("CARGO_PKG_VERSION")),
            source_revision: option_env!("AASM_BUILD_SHA").map(ReceiptText::screened),
        }
    }
}

/// The effective policy binding for this launch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyBinding {
    /// A digest of the canonical policy AST the boundary was lowered from.
    /// `None` for an unconfigured or load-failed resolution.
    pub canonical_digest: Option<Digest>,
    /// The artifact the policy was read from, screened.
    pub source: Option<ReceiptText>,
    /// The resolution's own posture token (`enforced`, `permissive`,
    /// `unconfigured`, `load_failed`).
    pub resolution: ReceiptText,
    /// What the policy schema could not express, screened.
    pub unmapped: Vec<ReceiptText>,
}

/// The launch's `ExecutionSpec` binding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpecBinding {
    /// A digest of the spec's redaction-safe projection.
    pub digest: Digest,
    /// The program's basename only — never the full path or argv.
    pub program: ReceiptText,
    /// How many arguments followed the program.
    pub arg_count: usize,
    /// A digest of the full argv (program + args), never the values.
    pub argv_digest: Digest,
    /// A digest of the working directory's raw bytes, when one was set.
    pub working_dir_digest: Option<Digest>,
    /// How many requirements this spec carries with `RequirementPosture::Required`.
    pub required_count: usize,
    /// How many carry `RequirementPosture::Optional`.
    pub optional_count: usize,
    /// How many carry `RequirementPosture::DegradeIfUnavailable`.
    pub degrade_if_unavailable_count: usize,
}

/// The selected backend's binding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackendBinding {
    /// The backend's stable id.
    pub id: ReceiptText,
    /// The backend's version.
    pub version: ReceiptText,
    /// Where the backend implementation came from, screened.
    pub provenance_source: ReceiptText,
    /// The backend's SPDX license identifier.
    pub provenance_license: ReceiptText,
    /// Whether the backend implementation was modified from upstream.
    pub provenance_modified: bool,
    /// The backend's platform boundary token.
    pub platform_boundary: ReceiptText,
    /// How the backend was selected, when automatic selection ran.
    pub selection_mode: Option<ReceiptText>,
    /// Every candidate automatic selection considered.
    pub considered: Vec<ConsideredBinding>,
}

/// One candidate backend automatic selection considered.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsideredBinding {
    /// The candidate's id.
    pub id: ReceiptText,
    /// What became of it.
    pub verdict: ReceiptText,
    /// Domains it could not meet, when the verdict says so.
    pub unmet_domains: Vec<ReceiptText>,
}

/// One capability lease's binding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeaseBinding {
    /// The lease's id.
    pub lease_id: ReceiptText,
    /// A digest of the lease's redaction-safe projection — id, schema
    /// version, subject, domain, scope shape, validity window, delegation
    /// rule, revocation state, and a digest of the basis. Never the basis
    /// reason or scope selectors themselves.
    pub digest: Digest,
    /// The domain this lease grants.
    pub domain: ReceiptText,
    /// The lease this one was derived from, when it carries delegation
    /// provenance.
    pub derived_from_lease_id: Option<ReceiptText>,
    /// The provenance's inheritance mode token, when present.
    pub inheritance_mode: Option<ReceiptText>,
}

/// One [`aa_isolation::CapabilityDomain`]'s outcome.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DomainOutcome {
    /// The domain.
    pub domain: ReceiptText,
    /// What policy asked, as a token.
    pub requested: ReceiptText,
    /// What the boundary did about it, as a token.
    pub state: ReceiptText,
    /// What may be said about it, in ADR 0033 §6 vocabulary.
    pub claim: ReceiptText,
    /// What stands behind the claim.
    pub evidence_basis: ReceiptText,
    /// Why nothing is measured, when the state is unmeasured.
    pub unmeasured_reason: Option<ReceiptText>,
    /// The `Inconclusive` detail sentence, screened, when present.
    pub unmeasured_detail: Option<ReceiptText>,
    /// What the policy schema could not express about this domain, screened.
    pub residual_policy_gaps: Vec<ReceiptText>,
    /// Whether `EnforcementEvidence::supports_prevention_claim` held for this
    /// domain.
    pub prevention_supported: bool,
    /// Whether `EnforcementEvidence::is_independently_verified` held for this
    /// domain.
    pub independently_verified: bool,
}

/// Credential names only.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialNames {
    /// Names removed from the child's environment.
    pub removed: Vec<ReceiptText>,
    /// Names deliberately delegated to the child.
    pub delegated: Vec<ReceiptText>,
    /// Names known to reach the child that policy wanted removed and could
    /// not be.
    pub ambient_unremoved: Vec<ReceiptText>,
}

/// A workspace-transaction binding. Every field `None`/empty today — see
/// `mod.rs`'s deferred-scope list.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceBinding {
    /// A digest of the transaction's staged-versus-base diff, when computed.
    pub diff_digest: Option<Digest>,
    /// Whether the transaction committed.
    pub committed: Option<bool>,
}

/// What the launch actually did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionOutcome {
    /// When the launch started, in unix seconds.
    pub started_at_unix_secs: u64,
    /// When the launch ended, in unix seconds.
    pub ended_at_unix_secs: u64,
    /// The exit code, when the backend observed one. `None` does not mean
    /// failure — see [`aa_isolation::ExitDisposition`]'s own documentation.
    pub exit_code: Option<i32>,
    /// The backend's own description of an unobservable exit, screened.
    pub no_code_detail: Option<ReceiptText>,
    /// How the launch ended.
    pub termination: TerminationRecord,
}

/// How a launch ended.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[non_exhaustive]
pub enum TerminationRecord {
    /// The child exited on its own.
    SelfExited,
    /// The wall-clock ceiling was exceeded.
    WallClockCeilingExceeded {
        /// The ceiling, in seconds.
        ceiling_secs: u64,
        /// Whether the termination request was delivered.
        termination_delivered: bool,
        /// The backend's own detail, screened, when delivery failed.
        detail: Option<ReceiptText>,
    },
    /// An operator signal (SIGTERM/SIGINT) was forwarded.
    ///
    /// Additive with [`SelfExited`](Self::SelfExited) — the launcher forwards
    /// the signal and keeps waiting, so a run that received one may still end
    /// self-exited.
    OperatorRequested {
        /// Whether the forward was delivered successfully.
        forwarded: bool,
    },
}

/// A condition that weakened some part of this receipt or the run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DegradedCondition {
    /// The domain this concerns, when it concerns one. `None` means the
    /// condition is about the run as a whole.
    pub domain: Option<ReceiptText>,
    /// What kind of degradation.
    pub kind: DegradedKind,
    /// An operator-facing detail, screened.
    pub detail: ReceiptText,
}

/// A kind of degradation this receipt records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DegradedKind {
    /// A control fell short of what policy asked.
    ControlShortfall,
    /// A control policy asked for is not supported by the selected backend.
    ControlUnsupported,
    /// Nothing measured whether a control held.
    NotMeasured,
    /// Ambient authority reaches the child that policy wanted removed.
    UnremovedAmbientAuthority,
    /// A field was withheld by the credential screen.
    FieldWithheld,
    /// A fact that would be useful could not be produced (e.g. a
    /// runtime-image digest no backend computes today).
    FactUnavailable,
}

/// A reference to a runtime evidence record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvidenceRef {
    /// The evidence kind, lowercase.
    pub kind: ReceiptText,
    /// The domain this record concerns, when it concerns one.
    pub domain: Option<ReceiptText>,
    /// The claim term this record carries.
    pub claim: ReceiptText,
    /// A digest of the record's own detail text, never the text itself.
    pub detail_digest: Digest,
}

/// The projection this receipt's per-run digests are taken over — see
/// `project.rs` for why this is a private mirror type rather than
/// `aa_isolation::ExecutionSpec` derived directly (redaction, non-UTF-8 paths,
/// and keeping the `aa-isolation/serde` feature off).
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct SpecProjection {
    pub(super) program: String,
    pub(super) arg_count: usize,
    pub(super) working_dir_present: bool,
    pub(super) identity_agent_id: String,
    pub(super) identity_team_id: Option<String>,
    pub(super) identity_lineage: Vec<String>,
    pub(super) required_count: usize,
    pub(super) optional_count: usize,
    pub(super) degrade_if_unavailable_count: usize,
    pub(super) lease_ids: Vec<String>,
}

/// The projection a lease's digest is taken over. Never the basis reason or
/// scope selectors — see `project.rs`.
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct LeaseProjection {
    pub(super) id: String,
    pub(super) schema_version: u32,
    pub(super) subject_agent_id: String,
    pub(super) domain: &'static str,
    pub(super) scope_shape: &'static str,
    pub(super) scope_selector_count: usize,
    pub(super) not_before_unix_secs: u64,
    pub(super) expires_at_unix_secs: u64,
    pub(super) delegation: &'static str,
    pub(super) revocation: String,
    pub(super) basis_digest: String,
}
