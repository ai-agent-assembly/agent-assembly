//! AAASM-5628's falsification suite, driven over real sockets.
//!
//! # Why these are separate tests, and must stay separate
//!
//! The ticket names three distinct failures, and a fix for one does not fix the
//! others:
//!
//! | Test | The failure it falsifies | What a fix for it alone cannot catch |
//! | --- | --- | --- |
//! | [`a_runtime_from_another_build_is_refused`] | a different checkout answered | a deleted binary, a second runtime |
//! | [`a_runtime_whose_executable_was_deleted_is_unidentifiable`] | the binary is gone, it keeps serving | a different build |
//! | [`two_runtimes_of_the_same_build_are_reported_not_resolved`] | two are answering | **anything identity-based** — they are the same build |
//! | [`reachability_alone_establishes_nothing`] | "the socket answered" read as "the right thing answered" | — |
//!
//! The third is the one that pins the design. Two runtimes compiled from the
//! same commit have byte-identical identities, so *no* build comparison can
//! notice there are two. A suite that only compared identities would pass while
//! the attribution failure it is supposed to catch went on happening — which is
//! exactly the family this bug belongs to: a check that ran against the wrong
//! thing is indistinguishable from one that passed.
//!
//! Everything below runs against a bound socket and a negotiated connection,
//! not against a function. The defect was never in a function: it was that the
//! *served handshake* carried no identity.

use std::path::PathBuf;

use super::client::DevIntClient;
use super::provenance::{
    self, BuildIdentity, ProvenanceVerdict, RuntimeMultiplicity, RuntimeProvenance, BUILD_SHA, UNKNOWN_SHA,
};
use super::scope::{TokenScope, ToolScope};
use super::socket;
use super::testkit::{claude_code_id, FakeLifecycle, TestServer};

/// A SHA that is definitely not this build's.
const OTHER_BUILD_SHA: &str = "0000000000000000000000000000000000000000";

/// Provenance for a plausible runtime from another checkout: same version, same
/// live executable, different commit.
fn another_checkout(executable_path: PathBuf) -> RuntimeProvenance {
    RuntimeProvenance {
        identity: BuildIdentity {
            core_version: BuildIdentity::of_this_build().core_version,
            build_sha: OTHER_BUILD_SHA.to_string(),
        },
        pid: 35_757,
        executable_path,
        source_path: "/Users/dev/another-checkout".to_string(),
        started_at_unix_secs: 1_700_000_000,
    }
}

async fn connect(server: &TestServer) -> DevIntClient {
    let (token, _) = server.enrol("aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
    DevIntClient::connect(server.socket_path(), "aasm", "0.0.0", Some(token.expose().to_string()))
        .await
        .expect("connect")
}

/// Falsification 1 — a runtime from build A, a client from build B.
///
/// The first reproduction: a runtime built from a different checkout answered
/// and reported `DI-API v2` where the checkout under test declared v3. Nothing
/// on any surface said which build had answered, so every measurement in that
/// campaign was silently against the wrong one.
///
/// Removing the identity comparison in `provenance::verify` turns this verdict
/// into `Verified` and fails here.
#[tokio::test]
async fn a_runtime_from_another_build_is_refused() {
    // A live executable on purpose: this must fail on *identity*, not on the
    // "executable is gone" branch, or it would prove the wrong check.
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = dir.path().join("aa-runtime");
    std::fs::write(&exe, b"a real binary from the wrong checkout").expect("write");

    let server = TestServer::start_reporting(FakeLifecycle::default(), another_checkout(exe)).await;
    let mut client = connect(&server).await;

    // The connection is entirely healthy — that is the trap.
    assert!(!client.negotiated().degraded);
    assert!(
        client.status(&claude_code_id()).await.is_ok(),
        "the wrong runtime answers verbs perfectly well; that is why reachability proves nothing"
    );

    let verdict = client.negotiated().provenance_verdict();
    assert!(
        !verdict.is_trustworthy(),
        "a runtime from another checkout must not be trusted, got {verdict:?}"
    );
    let ProvenanceVerdict::Mismatch {
        pid,
        expected,
        reported,
        source_path,
    } = &verdict
    else {
        panic!("expected a build mismatch, got {verdict:?}");
    };
    assert_eq!(*pid, 35_757, "the answering process must be named");
    assert_eq!(expected.build_sha, BUILD_SHA);
    assert_eq!(reported.build_sha, OTHER_BUILD_SHA);
    assert_eq!(source_path, "/Users/dev/another-checkout");

    // Distinct and actionable — never a generic failure, and never a
    // plausible-but-wrong product answer.
    let detail = verdict.detail();
    assert!(
        detail.contains(OTHER_BUILD_SHA.get(..12).expect("short sha")),
        "{detail}"
    );
    assert!(!detail.contains("not installed"), "{detail}");
    assert!(verdict.remediation().contains("35757"), "{}", verdict.remediation());

    server.shutdown().await;
}

/// Falsification 2 — a runtime whose executable was deleted keeps serving.
///
/// The second reproduction: a runtime whose worktree had been deleted reported
/// `claude-code … not_installed` while Claude Code was healthy and on `PATH`.
/// The build matched; the binary was gone. So this test uses **this build's own
/// identity** — a fix that only compares SHAs cannot pass it.
///
/// Removing the executable-presence branch in `provenance::verify` turns this
/// verdict into `Verified` and fails here.
#[tokio::test]
async fn a_runtime_whose_executable_was_deleted_is_unidentifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = dir.path().join("target").join("debug").join("aa-runtime");
    std::fs::create_dir_all(exe.parent().expect("parent")).expect("mkdir");
    std::fs::write(&exe, b"a binary that is about to be deleted").expect("write");

    let server = TestServer::start_reporting(
        FakeLifecycle::default(),
        RuntimeProvenance {
            executable_path: exe.clone(),
            ..RuntimeProvenance::detect()
        },
    )
    .await;
    assert_eq!(
        server.provenance().identity,
        BuildIdentity::of_this_build(),
        "this runtime is the build under test — only its binary is about to vanish"
    );

    // The worktree goes away while the runtime keeps serving.
    std::fs::remove_file(&exe).expect("delete the executable");

    let mut client = connect(&server).await;
    assert!(
        client.status(&claude_code_id()).await.is_ok(),
        "a runtime with no binary on disk still answers; that is the whole problem"
    );

    let verdict = client.negotiated().provenance_verdict();
    assert!(!verdict.is_trustworthy(), "got {verdict:?}");
    let ProvenanceVerdict::ExecutableMissing { pid, executable_path } = &verdict else {
        panic!("expected an unidentifiable runtime, got {verdict:?}");
    };
    assert_eq!(*pid, std::process::id());
    assert_eq!(executable_path, &exe.display().to_string());
    assert!(verdict.detail().contains("no longer exists"), "{}", verdict.detail());
    assert!(!verdict.detail().contains("not installed"), "{}", verdict.detail());

    server.shutdown().await;
}

/// Falsification 3 — two runtimes from the **same** build, both listening.
///
/// Observed during the campaign: pids 35757 and 87718, both verified against
/// the same commit, serving simultaneously. Both were correct, and the result
/// was still unattributable.
///
/// This test asserts that both runtimes pass the identity check **and** that
/// the multiplicity check still refuses — which is what makes it independent of
/// falsification 1. Removing the multiplicity check leaves the identity check
/// passing and fails here; removing the identity check leaves this one passing
/// and fails falsification 1.
#[tokio::test]
async fn two_runtimes_of_the_same_build_are_reported_not_resolved() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().join("run");
    let first_path = dir.join("devint.sock");
    let second_path = dir.join("devint-second.sock");

    let first = TestServer::start_at(first_path.clone(), FakeLifecycle::default()).await;
    let second = TestServer::start_at(second_path.clone(), FakeLifecycle::default()).await;

    // Identical builds. Every identity comparison below passes.
    assert_eq!(first.provenance().identity, second.provenance().identity);
    for server in [&first, &second] {
        let client = connect(server).await;
        assert!(
            client.negotiated().provenance_verdict().is_trustworthy(),
            "each runtime individually is the build under test — identity cannot see the duplicate"
        );
    }

    let reachable = socket::reachable_runtimes(&dir);
    assert_eq!(reachable.len(), 2, "both runtimes are listening: {reachable:?}");

    let verdict = provenance::multiplicity(&first_path, &reachable);
    assert!(
        !verdict.is_unambiguous(),
        "two reachable runtimes must never be silently resolved to one, got {verdict:?}"
    );
    let RuntimeMultiplicity::Ambiguous { answered, all } = &verdict else {
        panic!("expected an ambiguous runtime population, got {verdict:?}");
    };
    assert_eq!(answered, &first_path, "the client must say which one it reached");
    assert_eq!(all.len(), 2);
    let detail = verdict.detail();
    assert!(detail.contains("2 Agent Assembly runtimes"), "{detail}");
    assert!(
        detail.contains("devint-second.sock"),
        "the other must be named: {detail}"
    );
    assert_eq!(verdict.reachable_count(), 2);

    first.shutdown().await;
    second.shutdown().await;
}

/// Falsification 4 — reachability succeeding while identity mismatches.
///
/// A test asserting only that *some* runtime is reachable must not be enough to
/// pass this suite. Here every reachability signal the product has is green —
/// `discover` reports `Present`, the scan finds exactly one runtime, the
/// connection negotiates the newest version, and a lifecycle verb returns a
/// real answer — and the runtime is still the wrong build.
///
/// If a future change made the provenance check depend on reachability, this
/// test would pass its identity assertion for the wrong reason; the two
/// assertion groups below are therefore both required and both checked.
#[tokio::test]
async fn reachability_alone_establishes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = dir.path().join("aa-runtime");
    std::fs::write(&exe, b"present, healthy, and the wrong build").expect("write");

    let server = TestServer::start_reporting(FakeLifecycle::default(), another_checkout(exe)).await;
    let socket_dir = server.socket_path().parent().expect("parent").to_path_buf();

    // Every reachability signal is green.
    assert_eq!(
        socket::discover(server.socket_path()),
        socket::SocketDiscovery::Present(server.socket_path().to_path_buf())
    );
    let reachable = socket::reachable_runtimes(&socket_dir);
    assert_eq!(reachable, vec![server.socket_path().to_path_buf()]);
    assert!(provenance::multiplicity(server.socket_path(), &reachable).is_unambiguous());

    let mut client = connect(&server).await;
    assert_eq!(
        client.negotiated().di_api_version,
        super::negotiate::DI_API_MAX_SUPPORTED
    );
    assert_eq!(client.list_tools().await.expect("list").tools.len(), 1);

    // …and the answer is still not attributable to the build under test.
    assert!(
        !client.negotiated().provenance_verdict().is_trustworthy(),
        "a reachable, healthy, fully-negotiated runtime can still be the wrong one"
    );

    server.shutdown().await;
}

/// A runtime that *is* this build passes, so the suite is not vacuously strict.
///
/// Without this, every assertion above would also hold for a check that refused
/// unconditionally — which would break the product while looking rigorous.
#[tokio::test]
async fn the_build_under_test_is_verified_and_names_its_pid() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let client = connect(&server).await;

    let verdict = client.negotiated().provenance_verdict();
    assert!(verdict.is_trustworthy(), "got {verdict:?}");
    assert_eq!(
        verdict.pid(),
        Some(std::process::id()),
        "the pid is required provenance"
    );
    assert_eq!(verdict.as_str(), "verified");

    // The QA harness's requirement: the pid and the build are recoverable from
    // the connection that produced the result, not inferred afterwards.
    let reported = client.negotiated().provenance.as_ref().expect("v4 reports provenance");
    assert_eq!(reported.identity.build_sha, BUILD_SHA);
    assert_eq!(reported.pid, std::process::id());
    assert!(reported.executable_present);
    assert!(reported.started_at_unix_secs > 0);
    assert!(
        !reported.executable_path.is_empty(),
        "the executable must be nameable in the evidence"
    );

    server.shutdown().await;
}

/// A release binary and a local build are not the same build, even when both
/// report the same version.
///
/// `unknown` is what `build.rs` writes outside a checkout. Two of them match
/// each other; one against a real SHA does not — otherwise every mixed
/// install would read as verified.
#[tokio::test]
async fn a_build_with_no_checkout_does_not_match_a_local_build() {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = dir.path().join("aa-runtime");
    std::fs::write(&exe, b"installed from a published tarball").expect("write");

    let server = TestServer::start_reporting(
        FakeLifecycle::default(),
        RuntimeProvenance {
            identity: BuildIdentity {
                core_version: BuildIdentity::of_this_build().core_version,
                build_sha: UNKNOWN_SHA.to_string(),
            },
            executable_path: exe,
            ..RuntimeProvenance::detect()
        },
    )
    .await;
    let client = connect(&server).await;

    let verdict = client.negotiated().provenance_verdict();
    if BUILD_SHA == UNKNOWN_SHA {
        // This crate was itself built outside a checkout: the two genuinely are
        // the same build, and refusing them would break every published pairing.
        assert!(verdict.is_trustworthy(), "got {verdict:?}");
    } else {
        assert_eq!(verdict.as_str(), "mismatch", "got {verdict:?}");
    }

    server.shutdown().await;
}
