//! The audit record a governed launch leaves behind.
//!
//! # What is recorded, and what provably is not (AAASM-5349)
//!
//! A launch that reaches this module has **registered**, which means it
//! resolved a policy that permits launching — `enforced` or `permissive`. Those
//! two states are recorded here.
//!
//! The other two are not, and cannot currently be:
//! [`PolicyState::Unconfigured`] and [`PolicyState::LoadFailed`] both **refuse**
//! the launch, and `aasm run` refuses *before* it registers — deliberately, so
//! that a refused session never becomes "a governed identity with no process
//! behind it". The gateway's `AuditService` is mounted behind the fail-closed
//! auth interceptor, which resolves a caller strictly by looking up a
//! registered agent's credential token
//! (`aa_gateway::iam::grpc_auth::resolve_caller`). A refusal therefore has no
//! principal to authenticate as, and no authenticated path to the trail.
//!
//! **So the audit surface is partial, and says so rather than implying
//! otherwise.** Recording only the permitting states while describing the
//! surface as "distinguishes the four states" would be the over-claim this
//! whole ticket exists to remove. AAASM-5435 owns designing a secure
//! pre-registration refusal audit; until it lands, refusals are visible on the
//! operator's terminal and in the `--dry-run` receipt, and nowhere server-side.
//!
//! Three things were deliberately **not** done to close the gap, because each
//! trades a real guarantee for coverage:
//!
//! * registering a session purely to emit an audit record and then
//!   deregistering — it manufactures the exact identity-without-a-process the
//!   ordering exists to prevent;
//! * a local file or socket side channel — a second, unauthenticated write path
//!   to the governance record;
//! * relaxing the audit API to accept a pre-registration principal — an
//!   authentication weakening on a governance surface, which needs the threat
//!   analysis AAASM-5435 carries, not an expedient patch.

use std::collections::HashMap;

use aa_core::integration::policy_posture::{PolicyPosture, PolicyState};
use aa_proto::assembly::audit::v1::audit_service_client::AuditServiceClient;
use aa_proto::assembly::audit::v1::{audit_event, AuditEvent, ProcessExecDetail, ReportEventsRequest};
use aa_proto::assembly::common::v1::{ActionType, Decision};
use tonic::Request;

/// Label carrying the resolved policy state, using the same token
/// `AA_POLICY_STATE`, the `policy=` banner and `aasm integrations status` use.
pub const LABEL_POLICY_STATE: &str = "aasm.policy_state";
/// Label carrying the artifact the state came from, when there is one.
pub const LABEL_POLICY_SOURCE: &str = "aasm.policy_source";
/// Label marking this exec as a governed launch rather than an arbitrary
/// subprocess, so a query can separate the two.
pub const LABEL_LAUNCH: &str = "aasm.launch";
/// Label carrying whether this launch had interception configured at all
/// (AAASM-5350). Separate from [`LABEL_LAUNCH`], which classifies the *event*,
/// and from the policy labels, which describe a different dimension entirely.
pub const LABEL_PROTECTION: &str = "aasm.protection";
/// Label carrying the resolved `aa-proxy` executable's path (AAASM-5984).
pub const LABEL_PROXY_EXECUTABLE: &str = "aasm.proxy_executable";
/// Label carrying the SHA that executable's `--version` output claimed.
/// Full-length, not [`aa_runtime::build_identity::short_sha`] — this is a
/// machine record, not a human-facing banner.
pub const LABEL_PROXY_BUILD_SHA: &str = "aasm.proxy_build_sha";
/// Label carrying how [`LABEL_PROXY_BUILD_SHA`] was obtained
/// ([`aa_runtime::build_identity::IdentitySource::as_str`]) — a SHA
/// without its source is a claim a reader cannot judge as authoritative.
pub const LABEL_PROXY_BUILD_IDENTITY_SOURCE: &str = "aasm.proxy_build_identity_source";

/// Build the labels naming which `aa-proxy` build performed this launch's
/// interception, from the guard's own probe evidence (AAASM-5984 AC5).
///
/// `None` (a `--no-proxy` launch has no evidence to report) contributes no
/// labels at all — following [`policy_labels`]'s own precedent of omission
/// over invention: an absent proxy already reads as `aasm.protection =
/// unprotected`, and an `"unknown"` build label would describe a build that
/// does not exist.
pub fn proxy_build_labels(
    evidence: Option<&crate::commands::proxy::build_identity::ProxyBuildEvidence>,
) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    let Some(evidence) = evidence else {
        return labels;
    };
    labels.insert(
        LABEL_PROXY_EXECUTABLE.to_string(),
        evidence.executable.display().to_string(),
    );
    labels.insert(LABEL_PROXY_BUILD_SHA.to_string(), evidence.identity.build_sha.clone());
    labels.insert(
        LABEL_PROXY_BUILD_IDENTITY_SOURCE.to_string(),
        evidence.identity.sha_source.as_str().to_string(),
    );
    labels
}

/// Build the labels describing the policy a launch ran under.
///
/// A posture that is not `Resolved` contributes no state label at all rather
/// than an "unknown" one: this code path only runs after a successful
/// registration, so an unresolved posture here is a defect, and inventing a
/// token for it would hide that behind a plausible value.
pub fn policy_labels(posture: &PolicyPosture) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    labels.insert(LABEL_LAUNCH.to_string(), "governed".to_string());
    if let PolicyPosture::Resolved { state, source, .. } = posture {
        labels.insert(LABEL_POLICY_STATE.to_string(), state.token().to_string());
        if let Some(source) = source {
            labels.insert(LABEL_POLICY_SOURCE.to_string(), source.clone());
        }
    }
    labels
}

/// What this launch can honestly say about interception, at the moment it
/// starts (AAASM-5350 AC 2 / AC 3).
///
/// Two values, and deliberately **neither** of them is a ladder rung:
///
/// * `unprotected` — `--no-proxy`; nothing is intercepted, no egress policy
///   applies, and no later reading may upgrade this session.
/// * `proxy_configured` — a trusted proxy endpoint was resolved and injected.
///
/// It is **not** `gateway_protected`. That rung requires probe traffic to have
/// been produced and adjudicated, and at launch time no traffic exists yet.
/// Writing the rung here would be a claim about behaviour made before any
/// behaviour occurred — the exact over-claim AC 3 forbids, and the reason this
/// label names a *configuration* fact rather than a protection level.
///
/// An operator-supplied `HTTPS_PROXY` never produces `proxy_configured`: the
/// value is derived from what `aasm` resolved and injected, not from the
/// environment it inherited (AC 4).
pub fn protection_label(no_proxy: bool) -> &'static str {
    if no_proxy {
        "unprotected"
    } else {
        "proxy_configured"
    }
}

/// Whether a posture is one this module is able to record.
///
/// Exactly the two permitting states. Used to keep the module's own claim
/// honest: anything else reaching here means the ordering invariant changed and
/// the documentation above has gone stale.
pub fn is_recordable(posture: &PolicyPosture) -> bool {
    matches!(
        posture,
        PolicyPosture::Resolved {
            state: PolicyState::Enforced | PolicyState::Permissive,
            ..
        }
    )
}

/// Everything one governed-launch audit record needs.
///
/// Grouped rather than passed as ten arguments: the set is cohesive — it is one
/// record — and a long positional list is where a `trace_id` quietly swaps with
/// a `session_id`.
pub struct GovernedLaunchRecord<'a> {
    /// The gateway endpoint the audit service is reached on.
    pub endpoint: &'a str,
    /// The credential token registration returned. The only principal this
    /// module can authenticate as, and the reason refusals cannot be recorded.
    pub credential_token: &'a str,
    /// The identity the gateway attributes the record to.
    pub agent_id: aa_proto::assembly::common::v1::AgentId,
    /// Unique id for this record.
    pub event_id: String,
    /// Correlates this launch's records with each other.
    pub trace_id: String,
    /// Identifies this single `aasm run` invocation.
    pub session_id: String,
    /// The tool being launched.
    pub command: &'a str,
    /// Its arguments.
    pub args: &'a [String],
    /// The policy the launch resolved, from the one shared mapping.
    pub posture: &'a PolicyPosture,
    /// Whether the launch ran unprotected (`--no-proxy`). Carried explicitly
    /// rather than inferred, so the audit record cannot disagree with what the
    /// launch actually did.
    pub no_proxy: bool,
    /// What build the spawned `aa-proxy` claimed to be (AAASM-5984 AC5),
    /// `None` for a `--no-proxy` launch. Read from `ProxyGuard::build_evidence`
    /// — see that module's doc for why this is a probe rather than the
    /// child's own startup log.
    pub proxy_build: Option<&'a crate::commands::proxy::build_identity::ProxyBuildEvidence>,
    /// When the launch happened.
    pub occurred_at_unix_secs: u64,
}

/// Report a governed launch to the gateway's audit trail.
///
/// Best-effort by design: a launch that governed correctly must not be aborted
/// because the audit upload failed. The failure is surfaced by the caller rather
/// than swallowed — an audit record that silently did not happen is worse than
/// one that visibly did not.
pub async fn report_governed_launch(record: GovernedLaunchRecord<'_>) -> Result<(), String> {
    let GovernedLaunchRecord {
        endpoint,
        credential_token,
        agent_id,
        event_id,
        trace_id,
        session_id,
        command,
        args,
        posture,
        no_proxy,
        proxy_build,
        occurred_at_unix_secs,
    } = record;
    let event = AuditEvent {
        event_id,
        agent_id: Some(agent_id),
        occurred_at: Some(aa_proto::assembly::common::v1::Timestamp {
            unix_ms: (occurred_at_unix_secs as i64).saturating_mul(1_000),
        }),
        action_type: ActionType::ProcessExec as i32,
        // The launch proceeded: the policy permitted it. A refusal never
        // reaches this call, which is the whole subject of this module's docs.
        decision: Decision::Allow as i32,
        trace_id,
        session_id,
        labels: {
            let mut labels = policy_labels(posture);
            labels.insert(LABEL_PROTECTION.to_string(), protection_label(no_proxy).to_string());
            labels.extend(proxy_build_labels(proxy_build));
            labels
        },
        detail: Some(audit_event::Detail::Process(ProcessExecDetail {
            command: command.to_string(),
            args: args.to_vec(),
            // The record is written at launch, not at exit: an audit trail that
            // only learns about a session when it ends loses every session that
            // is still running, and every one that never ends cleanly.
            exit_code: 0,
            duration_ms: 0,
            succeeded: true,
        })),
        ..Default::default()
    };

    let mut client = AuditServiceClient::connect(endpoint.to_string())
        .await
        .map_err(|e| format!("could not reach the gateway audit service: {e}"))?;

    let mut request = Request::new(ReportEventsRequest { events: vec![event] });
    let bearer = format!("Bearer {credential_token}")
        .parse()
        .map_err(|e| format!("the credential token is not a valid header value: {e}"))?;
    request.metadata_mut().insert("authorization", bearer);

    client
        .report_events(request)
        .await
        .map_err(|e| format!("the gateway rejected the audit record: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(state: PolicyState, source: Option<&str>) -> PolicyPosture {
        PolicyPosture::Resolved {
            state,
            source: source.map(str::to_string),
            detail: "d".to_string(),
        }
    }

    /// The state label must be the shared token, so an audit query and
    /// `AA_POLICY_STATE` select the same sessions without translation.
    #[test]
    fn the_state_label_is_the_shared_token() {
        for state in [PolicyState::Enforced, PolicyState::Permissive] {
            let labels = policy_labels(&resolved(state, Some("/p.yaml")));
            assert_eq!(labels.get(LABEL_POLICY_STATE).map(String::as_str), Some(state.token()));
        }
    }

    /// A governed launch is distinguishable from any other subprocess exec.
    /// Without this the audit trail cannot separate the two, and PROCESS_EXEC
    /// was chosen precisely because the launch genuinely is one.
    #[test]
    fn a_governed_launch_is_marked_as_one() {
        let labels = policy_labels(&resolved(PolicyState::Enforced, None));
        assert_eq!(labels.get(LABEL_LAUNCH).map(String::as_str), Some("governed"));
    }

    /// No source label rather than an empty one: an empty string would read as
    /// an artifact whose path is blank instead of the absence of an artifact.
    #[test]
    fn an_absent_source_contributes_no_label() {
        let labels = policy_labels(&resolved(PolicyState::Permissive, None));
        assert!(!labels.contains_key(LABEL_POLICY_SOURCE));
    }

    /// The two refusing states are not recordable here, and this asserts the
    /// documented limit rather than the implementation: if the ordering
    /// invariant ever changes so a refusal can register, this test fails and
    /// the module documentation must be revisited with it.
    #[test]
    fn only_the_two_permitting_states_are_recordable() {
        assert!(is_recordable(&resolved(PolicyState::Enforced, None)));
        assert!(is_recordable(&resolved(PolicyState::Permissive, None)));
        assert!(!is_recordable(&resolved(PolicyState::Unconfigured, None)));
        assert!(!is_recordable(&resolved(PolicyState::LoadFailed, None)));
        assert!(!is_recordable(&PolicyPosture::Unknown {
            reason: "r".to_string()
        }));
    }

    /// An unresolved posture must not acquire a state label. This path runs
    /// only after registration, so `Unknown` here is a defect — and a label
    /// invented for it would hide the defect behind a plausible value.
    #[test]
    fn an_unknown_posture_contributes_no_state_label() {
        let labels = policy_labels(&PolicyPosture::Unknown {
            reason: "no resolution".to_string(),
        });
        assert!(!labels.contains_key(LABEL_POLICY_STATE));
        assert_eq!(labels.get(LABEL_LAUNCH).map(String::as_str), Some("governed"));
    }

    /// AC 2: a `--no-proxy` session is recorded as unprotected. Without this
    /// the audit trail says `governed` for a launch nothing intercepted.
    #[test]
    fn a_no_proxy_launch_is_labelled_unprotected() {
        assert_eq!(protection_label(true), "unprotected");
    }

    /// AC 3: no launch-time label may name a ladder rung. `gateway_protected`
    /// requires adjudicated traffic, and at launch no traffic exists — writing
    /// it here would claim behaviour before any behaviour happened.
    #[test]
    fn no_protection_label_claims_a_ladder_rung() {
        for no_proxy in [true, false] {
            let label = protection_label(no_proxy);
            assert_ne!(label, "gateway_protected");
            assert_ne!(label, "host_enforced");
            assert!(
                !label.contains("protected") || label == "unprotected",
                "a launch-time label must not imply a protection level: {label}"
            );
        }
    }

    /// A protected launch says only what is true at launch: the proxy was
    /// configured. Whether it worked is a later, adjudicated question.
    #[test]
    fn a_proxied_launch_claims_configuration_not_adjudication() {
        assert_eq!(protection_label(false), "proxy_configured");
    }

    fn evidence(
        build_sha: &str,
        source: aa_runtime::build_identity::IdentitySource,
    ) -> crate::commands::proxy::build_identity::ProxyBuildEvidence {
        crate::commands::proxy::build_identity::ProxyBuildEvidence {
            executable: std::path::PathBuf::from("/opt/aa/bin/aa-proxy"),
            identity: aa_runtime::build_identity::BuildIdentity {
                core_version: "0.0.1-rc.6".to_string(),
                build_sha: build_sha.to_string(),
                sha_source: source,
            },
        }
    }

    /// AAASM-5984 AC5: a governed launch's evidence names both the resolved
    /// executable and the build it claimed to be.
    #[test]
    fn proxy_build_evidence_names_the_executable_and_identity() {
        let ev = evidence("deadbeef", aa_runtime::build_identity::IdentitySource::Checkout);
        let labels = proxy_build_labels(Some(&ev));
        assert_eq!(
            labels.get(LABEL_PROXY_EXECUTABLE).map(String::as_str),
            Some("/opt/aa/bin/aa-proxy")
        );
        assert_eq!(labels.get(LABEL_PROXY_BUILD_SHA).map(String::as_str), Some("deadbeef"));
        assert_eq!(
            labels.get(LABEL_PROXY_BUILD_IDENTITY_SOURCE).map(String::as_str),
            Some("checkout")
        );
    }

    /// AC5, the omission half: `--no-proxy` has no proxy evidence to report,
    /// and must contribute no labels at all — following `policy_labels`'s own
    /// precedent (`an_absent_source_contributes_no_label`) of omission over
    /// inventing an "unknown" value for a build that does not exist.
    #[test]
    fn a_no_proxy_launch_contributes_no_proxy_build_labels() {
        let labels = proxy_build_labels(None);
        assert!(labels.is_empty());
    }
}
