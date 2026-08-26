//! The DI-API version contract, driven over real sockets (AAASM-5628, 5674).
//!
//! # What this suite is for
//!
//! Raising `DI_API_MAX_SUPPORTED` is a public-contract change, and the ways it
//! can go wrong are not the ways a feature goes wrong. Three of them:
//!
//! 1. **An older peer stops working.** A version bump that only ever gets
//!    exercised at the newest version looks perfect until something ships that
//!    speaks the old one.
//! 2. **An older peer keeps working and silently misreads the new field.** The
//!    worse failure, because nothing fails.
//! 3. **A field the peer could not state gets fabricated** — filled in from a
//!    default, or from the client's own values — so a reader cannot tell "it
//!    did not say" from "it said this".
//!
//! Every test below therefore negotiates a *chosen* version over a real socket
//! and asserts on the frame that actually arrived, rather than on a function.
//! The defect AAASM-5628 records was never in a function: it was that the served
//! handshake carried no identity.
//!
//! # Why the version is what a peer can *say*, not what it can call
//!
//! None of v3, v4 and v5 adds a verb, so a v1–v4 peer is not `Degraded` and
//! loses no capability. What the version buys is the ability to name the reason
//! a field is missing: "this runtime speaks DI-API 3; build provenance arrived
//! in 4" rather than the vaguer "the field is missing". That is the property
//! [`an_older_peer_is_told_why_the_field_is_absent_not_handed_a_default`]
//! pins.
//!
//! v5 raises the stakes on the same shape. Provenance's absence degrades a
//! *claim about the peer*; the apply outcome's absence, misread, degrades into
//! a **success claim about the host** — `unchanged` says "your install was
//! already correct". So the v5 tests below assert not only that nothing is
//! fabricated but that the specific fabrication is unreachable, from both
//! directions.
//!
//! # v6 breaks the pattern, and the tests for it are shaped differently
//!
//! v3, v4 and v5 each added a field to a **reply**, which is why every test
//! above can assert on an arrived frame: the client holds the evidence. v6
//! (AAASM-5913) adds `PlanRequest.project_root` — a field on a **request** — and
//! proto3 discards an unknown field during decode. Against a v5 runtime the root
//! is gone before any handler runs: nothing is denied, nothing is degraded, and
//! the plan comes back authored under whichever directory the shared daemon was
//! spawned in. There is no frame in which that is visible, because an ignored
//! root and an unsent one decode identically.
//!
//! So the v6 tests assert on something the earlier ones never needed: that the
//! request **was not sent at all**, via
//! [`FakeLifecycle::calls`](super::testkit::FakeLifecycle::calls). "Nothing was
//! fabricated in the field's place" is the wrong property here — the field's
//! place is on the other side of the wire.

use super::apply_outcome::{ApplyMutation, MutationUnknown};
use super::client::{ClientError, DevIntClient, PlanRequest, TargetRequest};
use super::negotiate::{
    DI_API_APPLY_OUTCOME_SINCE, DI_API_MAX_SUPPORTED, DI_API_MIN_SUPPORTED, DI_API_POLICY_POSTURE_SINCE,
    DI_API_PROJECT_ROOT_SINCE, DI_API_PROVENANCE_SINCE,
};
use super::provenance::ProvenanceVerdict;
use super::scope::{TokenScope, ToolScope};
use super::testkit::{claude_code_id, FakeLifecycle, TestServer};
use super::verb::DiVerb;

/// Connect offering exactly `versions`, so the test *is* a peer of that vintage.
async fn connect_offering(server: &TestServer, versions: &[u32]) -> DevIntClient {
    let (token, _) = server.enrol("aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
    DevIntClient::connect_offering(
        server.socket_path(),
        "aasm",
        "0.0.0",
        Some(token.expose().to_string()),
        versions.to_vec(),
    )
    .await
    .expect("connect")
}

/// The negotiated version is the highest the peer offered, at every vintage.
///
/// A bump that accidentally pinned the answer to `DI_API_MAX_SUPPORTED` would
/// tell a v3 peer it speaks v4 — and it would then be sent a frame it cannot
/// read. Asserted across the whole window rather than at the two ends, because
/// the bug appears at whichever version the code happens to special-case.
#[tokio::test]
async fn every_version_in_the_window_negotiates_itself() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    for version in DI_API_MIN_SUPPORTED..=DI_API_MAX_SUPPORTED {
        let client = connect_offering(&server, &[version]).await;
        assert_eq!(
            client.negotiated().di_api_version,
            version,
            "a peer offering only v{version} must negotiate v{version}"
        );
    }
    server.shutdown().await;
}

/// v4 carries provenance; v3 and below do not. The exact addition, asserted.
///
/// This is the whole of what v4 adds: a `RuntimeProvenance` on the `HelloAck`.
/// If it ever arrives below `DI_API_PROVENANCE_SINCE`, a peer is being sent a
/// field its version did not promise; if it stops arriving at or above it, the
/// bump bought nothing.
#[tokio::test]
async fn v4_adds_provenance_to_the_ack_and_nothing_below_it_receives_one() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    for version in DI_API_MIN_SUPPORTED..=DI_API_MAX_SUPPORTED {
        let client = connect_offering(&server, &[version]).await;
        let provenance = client.negotiated().provenance.as_ref();
        if version >= DI_API_PROVENANCE_SINCE {
            let reported = provenance.unwrap_or_else(|| panic!("v{version} must carry provenance"));
            assert_eq!(reported.pid, std::process::id());
            assert!(!reported.identity.build_sha.is_empty());
            assert!(
                !reported.identity.sha_source.as_str().is_empty(),
                "the identity must say where it came from, or a peer cannot tell a real SHA from a placeholder"
            );
        } else {
            assert!(
                provenance.is_none(),
                "v{version} must not be sent a v{DI_API_PROVENANCE_SINCE} field"
            );
        }
    }
    server.shutdown().await;
}

/// An older peer remains fully usable — every verb still works at v3.
///
/// The compatibility claim, exercised rather than asserted: v3 and v4 add no
/// verb, so a v3 peer must still be able to call the whole lifecycle. A bump
/// that gated a verb on the new version would fail here.
#[tokio::test]
async fn an_older_peer_keeps_every_verb_it_had() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    for version in [
        DI_API_POLICY_POSTURE_SINCE,
        DI_API_PROVENANCE_SINCE,
        DI_API_APPLY_OUTCOME_SINCE,
    ] {
        let mut client = connect_offering(&server, &[version]).await;
        assert!(
            !client.negotiated().degraded,
            "v{version} adds no verb, so it cannot be degraded: {:?}",
            client.negotiated().unavailable_verbs
        );
        assert!(
            client.negotiated().unavailable_verbs.is_empty(),
            "v{version}: {:?}",
            client.negotiated().unavailable_verbs
        );
        for verb in DiVerb::ALL {
            assert!(client.negotiated().supports(verb), "v{version} lost {verb}");
        }
        // …and a verb actually answers, not merely reports itself available.
        assert!(
            client.status(&claude_code_id(), TargetRequest::default()).await.is_ok(),
            "v{version} must still be able to call the lifecycle"
        );
        assert_eq!(client.list_tools().await.expect("list").tools.len(), 1);
    }
    server.shutdown().await;
}

/// A peer too old to receive provenance is told *why*, and nothing is invented.
///
/// The third failure mode. `NotReported` names the negotiated version, so a
/// reader learns "this runtime speaks v3; provenance arrived in v4" instead of
/// being handed a fabricated identity or a bare absence. Critically, it is
/// **not** `Verified`: an unattributable answer is unattributable whether the
/// peer is old or lying.
#[tokio::test]
async fn an_older_peer_is_told_why_the_field_is_absent_not_handed_a_default() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    for version in DI_API_MIN_SUPPORTED..DI_API_PROVENANCE_SINCE {
        let client = connect_offering(&server, &[version]).await;
        let verdict = client.negotiated().provenance_verdict();

        assert!(!verdict.is_trustworthy(), "v{version}: {verdict:?}");
        let ProvenanceVerdict::NotReported { negotiated_version } = &verdict else {
            panic!("v{version} must report the field as unavailable, got {verdict:?}");
        };
        assert_eq!(*negotiated_version, version);
        assert!(
            verdict.detail().contains(&format!("v{version}")),
            "the reason must name the version that could not say: {}",
            verdict.detail()
        );

        // Nothing was invented in the field's place.
        assert!(
            client.negotiated().provenance.is_none(),
            "v{version} must carry no fabricated provenance"
        );
        assert_eq!(
            verdict.pid(),
            None,
            "a pid the peer never sent must not be filled in from anywhere"
        );
        assert!(
            verdict.comparison().is_none(),
            "no comparison can have run against an identity that was never sent"
        );
    }
    server.shutdown().await;
}

/// The verb space is unchanged by this bump.
///
/// AAASM-5628 raises the protocol version; it must not remove or rename a
/// public verb while doing so. The list below is transcribed from the wire
/// names as of the branch point, so a silent removal or rename fails here
/// rather than in a downstream client.
#[test]
fn no_public_verb_was_removed_or_renamed_by_the_version_bump() {
    let names: Vec<&str> = DiVerb::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "list_tools",
            "plan",
            "apply",
            "status",
            "verify",
            "repair",
            "remove",
            "scoped_events",
            "approval_relay",
        ],
        "the DI-API verb space is public contract — a bump may add, never remove or rename"
    );
}

// ── v5: the apply outcome (AAASM-5674) ──────────────────────────────────────

/// v5 carries the apply outcome; v4 and below do not. The exact addition.
///
/// **Old client, new peer.** The server is this build and serves the whole
/// window; the client offers exactly one version and is therefore a peer of
/// that vintage. A v1–v4 client must receive the frame its version promised —
/// sending a field it never negotiated is how a peer starts misparsing, and a
/// third-party client written against v4 has no reason to expect it.
#[tokio::test]
async fn v5_adds_the_apply_outcome_and_nothing_below_it_receives_one() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    for version in DI_API_MIN_SUPPORTED..=DI_API_MAX_SUPPORTED {
        let mut client = connect_offering(&server, &[version]).await;
        let applied = client
            .apply(&claude_code_id(), "plan-1", TargetRequest::default())
            .await
            .expect("apply");
        if version >= DI_API_APPLY_OUTCOME_SINCE {
            assert!(
                applied.outcome.is_some(),
                "v{version} must carry the apply outcome, or the bump bought nothing"
            );
        } else {
            assert!(
                applied.outcome.is_none(),
                "v{version} was sent a v{DI_API_APPLY_OUTCOME_SINCE} field it never negotiated"
            );
        }
        // The rest of the frame is untouched at every version: a bump may add,
        // never move or drop.
        assert_eq!(applied.plan_id, "plan-1");
        assert!(!applied.receipt_id.is_empty());
        assert!(!applied.steps.is_empty());
        assert_eq!(applied.achieved_level, "integrated");
    }
    server.shutdown().await;
}

/// **New client, old peer** — the direction that matters most.
///
/// A client that knows about v5 talks to a connection that negotiated v4. The
/// frame it gets back is byte-identical to what a genuinely older runtime
/// sends, and what it must conclude is `Unknown`, naming the version — **not**
/// `Unchanged`, which would tell a user their install was already correct on
/// the strength of a field nobody sent.
#[tokio::test]
async fn a_new_client_reading_an_older_peer_concludes_unknown_not_unchanged() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    for version in DI_API_MIN_SUPPORTED..DI_API_APPLY_OUTCOME_SINCE {
        let mut client = connect_offering(&server, &[version]).await;
        let applied = client
            .apply(&claude_code_id(), "plan-1", TargetRequest::default())
            .await
            .expect("apply");
        let mutation = client.negotiated().apply_mutation(&applied);

        assert_eq!(
            mutation,
            ApplyMutation::Unknown(MutationUnknown::NotReportedAtVersion {
                negotiated_version: version,
                since: DI_API_APPLY_OUTCOME_SINCE,
            }),
            "v{version} was read as something other than unknown"
        );
        assert_ne!(mutation, ApplyMutation::Unchanged, "v{version} fabricated a no-op");
        assert!(!mutation.is_authoritative(), "v{version}");
        assert!(!mutation.modified_the_host(), "v{version}");
        assert!(
            mutation.detail().contains(&format!("v{version}")),
            "the reason must name the version that could not say: {}",
            mutation.detail()
        );
        // Nothing was invented in the field's place.
        assert!(applied.outcome.is_none(), "v{version} carried a fabricated outcome");
    }
    server.shutdown().await;
}

/// Every outcome a peer can state survives a real socket, and is read back as
/// itself.
///
/// Driven through [`FakeLifecycle::reporting`] rather than through the
/// projection function, because the contract lives in a frame: a mapping that
/// encoded correctly and decoded onto a neighbour would pass a round-trip on
/// one struct and fail here.
#[tokio::test]
async fn every_stated_outcome_crosses_the_socket_as_itself() {
    for stated in [
        ApplyMutation::Changed,
        ApplyMutation::Unchanged,
        ApplyMutation::Failed {
            detail: "the settings write did not land".to_string(),
        },
        ApplyMutation::Unsupported {
            detail: "this executor cannot compare canonical forms".to_string(),
        },
        ApplyMutation::Unknown(MutationUnknown::Unspecified {
            detail: "the engine was interrupted".to_string(),
        }),
    ] {
        let server = TestServer::start(FakeLifecycle::reporting(stated.clone())).await;
        let mut client = connect_offering(&server, &[DI_API_APPLY_OUTCOME_SINCE]).await;
        let applied = client
            .apply(&claude_code_id(), "plan-1", TargetRequest::default())
            .await
            .expect("apply");
        let read = client.negotiated().apply_mutation(&applied);
        assert_eq!(read, stated, "{stated:?} did not survive the socket");
        // The two non-answers are non-answers on arrival, not merely on paper.
        assert_eq!(
            read.is_authoritative(),
            matches!(
                stated,
                ApplyMutation::Changed | ApplyMutation::Unchanged | ApplyMutation::Failed { .. }
            ),
            "{stated:?} changed standing on the wire"
        );
        server.shutdown().await;
    }
}

/// A v5 peer that states nothing is `Omitted`, and `Omitted` is not a no-op.
///
/// The missing-field case *at the carrying version* — distinct from the version
/// gap, and the one a field test alone would have to get right. Constructed by
/// asking a v5 connection's decoder to read a frame with no block, which is
/// exactly what a v5 peer that skipped the field would send.
#[test]
fn a_v5_peer_that_omits_the_block_is_not_read_as_unchanged() {
    let mutation = ApplyMutation::from_view(None, DI_API_APPLY_OUTCOME_SINCE);
    assert_eq!(
        mutation,
        ApplyMutation::Unknown(MutationUnknown::Omitted {
            negotiated_version: DI_API_APPLY_OUTCOME_SINCE
        })
    );
    assert_ne!(mutation, ApplyMutation::Unchanged);
    assert!(!mutation.is_authoritative());
}

// ── v6: the caller's project root (AAASM-5913) ───────────────────────────────

/// A directory a project-scope plan can legitimately name.
///
/// Real, because the server resolves and vets the root before anything else
/// (`parse_project_root`): a placeholder string would be refused for *being a
/// placeholder*, and every test below would then pass without ever reaching the
/// version gate it exists to exercise.
fn a_real_project_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// **New client, old peer — refused before the send.**
///
/// The direction that matters, and the one v3–v5 could afford to handle after
/// the fact. Those versions added fields to *replies*, so a new client reading
/// an old peer sees an absent field and can name the version. `project_root`
/// goes the other way: it is a field on the **request**, and proto3 drops an
/// unknown field during decode. A v5 runtime therefore never learns a root was
/// sent, does not deny, does not report a degraded connection, and answers with
/// a plan authored under its own working directory — AAASM-5913 exactly,
/// wearing a success.
///
/// Which is why this asserts on the *absence of a call*. There is no reply to
/// inspect for the property: a v5 peer that ignored the root and a v5 peer that
/// was never sent one produce byte-identical frames, so the only place the
/// mistake is still visible is before it leaves.
#[tokio::test]
async fn v6_is_required_for_project_scope_and_an_older_peer_is_refused_before_the_send() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let project = a_real_project_dir();
    for version in DI_API_MIN_SUPPORTED..DI_API_PROJECT_ROOT_SINCE {
        let mut client = connect_offering(&server, &[version]).await;
        let before = server.lifecycle().calls();

        let outcome = client
            .plan(PlanRequest {
                tool_id: &claude_code_id(),
                profile: "recommended",
                settings_scope: "project",
                project_root: project.path().to_str().expect("utf-8 tempdir"),
                ..PlanRequest::default()
            })
            .await;

        let Err(refused) = outcome else {
            panic!("v{version} must refuse project scope rather than send a root it will drop");
        };
        let ClientError::Incompatible(reported) = &refused else {
            panic!("v{version} must refuse on version grounds, got {refused:?}");
        };
        assert!(
            reported.reason.contains(&format!("DI-API {version}")),
            "the reason must name the version that cannot carry the root: {}",
            reported.reason
        );
        assert!(
            reported.reason.contains(&format!("DI-API {DI_API_PROJECT_ROOT_SINCE}")),
            "the reason must name the version that can: {}",
            reported.reason
        );
        assert!(
            !reported.remediation.is_empty(),
            "a refusal a user cannot act on is a dead end"
        );

        assert_eq!(
            server.lifecycle().calls(),
            before,
            "v{version} sent the request anyway — the root was dropped on arrival and the plan \
             was authored against the runtime's own directory"
        );

        // The refusal is local, so the connection must be untouched by it: a
        // gate that half-wrote a frame would desync every later call on a
        // connection the caller has every reason to keep using.
        assert!(
            client.status(&claude_code_id(), TargetRequest::default()).await.is_ok(),
            "v{version} lost the connection to a refusal that never reached the wire"
        );
    }
    server.shutdown().await;
}

/// **Positive control**: at v6 the same call reaches the service.
///
/// Without this, a gate that refused project scope at *every* version — or one
/// whose comparison was inverted — would satisfy the sweep above completely.
#[tokio::test]
async fn project_scope_reaches_the_service_at_v6() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let project = a_real_project_dir();
    let mut client = connect_offering(&server, &[DI_API_PROJECT_ROOT_SINCE]).await;
    let before = server.lifecycle().calls();

    let plan = client
        .plan(PlanRequest {
            tool_id: &claude_code_id(),
            profile: "recommended",
            settings_scope: "project",
            project_root: project.path().to_str().expect("utf-8 tempdir"),
            ..PlanRequest::default()
        })
        .await
        .expect("v6 carries the project root, so the plan must be authored");

    assert!(!plan.plan_id.is_empty());
    assert!(
        server.lifecycle().calls() > before,
        "the plan must have been served by the lifecycle, not fabricated by the client"
    );
    server.shutdown().await;
}

/// **Blast-radius control**: the gate touches project scope and nothing else.
///
/// User and managed destinations were never the caller's to name — the service
/// derives both from the host, so it has nothing to be told and no reason to
/// need v6. A gate written as "below v6, refuse" rather than "below v6, refuse
/// *project* scope" would break every older peer's entire lifecycle, which is a
/// far larger regression than the one being fixed.
#[tokio::test]
async fn user_and_managed_scope_are_untouched_by_the_project_root_gate() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    for version in DI_API_MIN_SUPPORTED..DI_API_PROJECT_ROOT_SINCE {
        for scope in ["user", "managed"] {
            let mut client = connect_offering(&server, &[version]).await;
            assert!(
                client
                    .plan(PlanRequest {
                        tool_id: &claude_code_id(),
                        profile: "recommended",
                        settings_scope: scope,
                        ..PlanRequest::default()
                    })
                    .await
                    .is_ok(),
                "v{version} lost {scope} scope to a gate that only concerns project scope"
            );
        }
    }
    server.shutdown().await;
}

/// A scope token the client cannot parse stays the **server's** to refuse.
///
/// `"Project"` is not a scope: the wire vocabulary is lower-case and
/// `parse_scope` is an exact match, deliberately, because a destination must be
/// named rather than inferred. The client could guess that this *means* project
/// scope and refuse it on version grounds — and then a caller with a typo would
/// be told to upgrade their runtime instead of being told the token is wrong.
/// Two competing refusals for one mistake is worse than one correct one, so the
/// gate declines to guess and the request travels.
#[tokio::test]
async fn an_unparseable_scope_token_is_refused_by_the_server_not_the_version_gate() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let project = a_real_project_dir();
    let mut client = connect_offering(&server, &[DI_API_PROJECT_ROOT_SINCE - 1]).await;

    let refused = client
        .plan(PlanRequest {
            tool_id: &claude_code_id(),
            profile: "recommended",
            settings_scope: "Project",
            project_root: project.path().to_str().expect("utf-8 tempdir"),
            ..PlanRequest::default()
        })
        .await
        .expect_err("an unknown scope token cannot be honoured");

    let ClientError::Denied(denial) = &refused else {
        panic!("the server owns rejecting an unknown scope token, got {refused:?}");
    };
    assert!(
        denial.message.contains("scope"),
        "the denial must name what was wrong: {}",
        denial.message
    );
    server.shutdown().await;
}

/// The version constants stay internally consistent.
///
/// `DI_API_PROVENANCE_SINCE` naming a version outside the served window would
/// describe a frame no connection can ever negotiate — a contract that reads
/// well and cannot be reached. A compile-time block rather than a test: the
/// values are constants, so a violation should stop the build rather than wait
/// for a test run.
const _: () = {
    assert!(DI_API_PROVENANCE_SINCE >= DI_API_MIN_SUPPORTED);
    // The project root is the newest addition. If it stops being so, the v6
    // sweeps above are pinning the wrong version and their "below this it is
    // refused" loops silently stop covering the top of the window.
    assert!(DI_API_PROJECT_ROOT_SINCE == DI_API_MAX_SUPPORTED);
    // The apply outcome was the newest addition until v6 (AAASM-5913), so its
    // sweeps now run over a strict interior of the window rather than up to its
    // top — as provenance's already did after AAASM-5674.
    assert!(DI_API_APPLY_OUTCOME_SINCE < DI_API_MAX_SUPPORTED);
    assert!(DI_API_APPLY_OUTCOME_SINCE > DI_API_PROVENANCE_SINCE);
    assert!(DI_API_PROVENANCE_SINCE < DI_API_MAX_SUPPORTED);
    assert!(DI_API_PROVENANCE_SINCE > DI_API_POLICY_POSTURE_SINCE);
    // The v6 sweep loops `MIN..PROJECT_ROOT_SINCE`; at equality that range is
    // empty and every assertion in it would vacuously hold.
    assert!(DI_API_PROJECT_ROOT_SINCE > DI_API_MIN_SUPPORTED);
};
