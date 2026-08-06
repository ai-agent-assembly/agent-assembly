//! The DI-API v3 → v4 version contract, driven over real sockets (AAASM-5628).
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
//! Neither v3 nor v4 adds a verb, so a v1–v3 peer is not `Degraded` and loses
//! no capability. What the version buys is the ability to name the reason a
//! field is missing: "this runtime speaks DI-API 3; build provenance arrived in
//! 4" rather than the vaguer "the field is missing". That is the property
//! [`an_older_peer_is_told_why_the_field_is_absent_not_handed_a_default`]
//! pins.

use super::client::DevIntClient;
use super::negotiate::{
    DI_API_MAX_SUPPORTED, DI_API_MIN_SUPPORTED, DI_API_POLICY_POSTURE_SINCE, DI_API_PROVENANCE_SINCE,
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
    for version in [DI_API_POLICY_POSTURE_SINCE, DI_API_PROVENANCE_SINCE] {
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
            client.status(&claude_code_id()).await.is_ok(),
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

/// The version constants stay internally consistent.
///
/// `DI_API_PROVENANCE_SINCE` naming a version outside the served window would
/// describe a frame no connection can ever negotiate — a contract that reads
/// well and cannot be reached. A compile-time block rather than a test: the
/// values are constants, so a violation should stop the build rather than wait
/// for a test run.
const _: () = {
    assert!(DI_API_PROVENANCE_SINCE >= DI_API_MIN_SUPPORTED);
    // Provenance is the newest addition. If it stops being so, the suite above
    // is pinning the wrong version and its "nothing below receives one" sweep
    // silently stops covering the top of the window.
    assert!(DI_API_PROVENANCE_SINCE == DI_API_MAX_SUPPORTED);
    assert!(DI_API_PROVENANCE_SINCE > DI_API_POLICY_POSTURE_SINCE);
};
