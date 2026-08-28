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

use super::client::{DevIntClient, TargetRequest};
use super::provenance::{
    self, BuildIdentity, IdentitySource, ProvenanceStanding, ProvenanceVerdict, RuntimeMultiplicity, RuntimeProvenance,
    BUILD_SHA, UNKNOWN_SHA,
};
use super::scope::{TokenScope, ToolScope};
use super::socket;
use super::testkit::{claude_code_id, FakeLifecycle, TestServer};

/// A SHA that is definitely not this build's.
const OTHER_BUILD_SHA: &str = "0000000000000000000000000000000000000000";

/// Provenance for a plausible runtime from another checkout: same version, same
/// live executable, different commit, and an authoritative source behind it —
/// so this falsifies on *identity*, not on the absence of one.
fn another_checkout(executable_path: PathBuf) -> RuntimeProvenance {
    RuntimeProvenance {
        identity: BuildIdentity {
            core_version: BuildIdentity::of_this_build().core_version,
            build_sha: OTHER_BUILD_SHA.to_string(),
            sha_source: IdentitySource::Checkout,
        },
        pid: 35_757,
        executable_path,
        source_path: "/Users/dev/another-checkout".to_string(),
        started_at_unix_secs: 1_700_000_000,
    }
}

/// An authoritative identity for the "client side" of a comparison.
///
/// Used where a test needs the *exact* verdict rather than merely "not
/// trustworthy". `BuildIdentity::of_this_build()` is only authoritative when the
/// test binary was itself compiled inside a checkout, so asserting `Mismatch`
/// against it would silently become an assertion about the build environment —
/// passing as `Unverifiable` on a CI runner with no `.git` and proving nothing.
fn expected_authoritative_identity() -> BuildIdentity {
    BuildIdentity {
        core_version: BuildIdentity::of_this_build().core_version,
        build_sha: "9999999999999999999999999999999999999999".to_string(),
        sha_source: IdentitySource::Checkout,
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
        client
            .status(
                &claude_code_id(),
                // Managed scope: user scope is mandatory-home-gated
                // (AAASM-5957) and this test is about provenance, not target
                // resolution.
                TargetRequest {
                    settings_scope: "managed",
                    ..TargetRequest::default()
                }
            )
            .await
            .is_ok(),
        "the wrong runtime answers verbs perfectly well; that is why reachability proves nothing"
    );

    assert!(
        !client.negotiated().provenance_verdict().is_trustworthy(),
        "a runtime from another checkout must not be trusted, got {:?}",
        client.negotiated().provenance_verdict()
    );

    // Against an authoritative client identity the verdict must be the *refuted*
    // one, not merely un-verified: this peer was shown to be a different build,
    // which is a different fact with a different remedy from "cannot tell".
    let expected_identity = expected_authoritative_identity();
    let verdict = client.negotiated().verify_against(&expected_identity);
    let ProvenanceVerdict::Mismatch {
        pid,
        expected,
        reported,
        source_path,
        comparison,
    } = &verdict
    else {
        panic!("expected a build mismatch, got {verdict:?}");
    };
    assert_eq!(verdict.standing(), ProvenanceStanding::Refuted);
    assert_eq!(*pid, 35_757, "the answering process must be named");
    assert_eq!(expected.build_sha, expected_identity.build_sha);
    assert_eq!(reported.build_sha, OTHER_BUILD_SHA);
    assert_eq!(source_path, "/Users/dev/another-checkout");
    assert_eq!(
        comparison.named(super::provenance::FieldStatus::Mismatched),
        vec!["build_sha"],
        "the diagnostic must name the field that disagreed"
    );

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
        client
            .status(
                &claude_code_id(),
                // Managed scope: user scope is mandatory-home-gated
                // (AAASM-5957) and this test is about provenance, not target
                // resolution.
                TargetRequest {
                    settings_scope: "managed",
                    ..TargetRequest::default()
                }
            )
            .await
            .is_ok(),
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

/// A packaged artifact's identity survives the wire and proves a match.
///
/// The unit tests compare two `BuildIdentity` values built in memory, which
/// cannot see whether `packaged` actually *reaches* the peer: a decode that
/// dropped the source token would leave those tests green while every real
/// packaged pairing silently degraded to `Unverifiable`. This drives the whole
/// path — server states it, wire carries it, client decodes and compares it.
///
/// `packaged` is what `build.rs` records when it reads `.cargo_vcs_info.json`,
/// the file `cargo package` writes into every `.crate` tarball naming the commit
/// the crate was published from.
#[tokio::test]
async fn a_packaged_artifact_identity_survives_the_wire_and_matches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = dir.path().join("aa-runtime");
    std::fs::write(&exe, b"installed from an official artifact").expect("write");

    let packaged = BuildIdentity {
        core_version: BuildIdentity::of_this_build().core_version,
        build_sha: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        sha_source: IdentitySource::Packaged,
    };
    let server = TestServer::start_reporting(
        FakeLifecycle::default(),
        RuntimeProvenance {
            identity: packaged.clone(),
            executable_path: exe,
            ..RuntimeProvenance::detect()
        },
    )
    .await;
    let client = connect(&server).await;

    // The source token crossed the wire intact — without it the comparison
    // below could not distinguish this from a placeholder.
    let reported = client.negotiated().provenance.as_ref().expect("v4 reports provenance");
    assert_eq!(reported.identity.sha_source, IdentitySource::Packaged);
    assert_eq!(reported.identity.build_sha, packaged.build_sha);
    assert!(reported.identity.is_authoritative());

    // A client from the same published artifact verifies.
    let same_artifact = client.negotiated().verify_against(&packaged);
    assert!(same_artifact.is_trustworthy(), "got {same_artifact:?}");
    assert_eq!(same_artifact.standing(), ProvenanceStanding::Verified);

    // A client from a *different* published artifact does not — version
    // equality is not build equality, which is the whole point of not using it.
    let other_artifact = client.negotiated().verify_against(&BuildIdentity {
        build_sha: "fedcba9876543210fedcba9876543210fedcba98".to_string(),
        ..packaged.clone()
    });
    assert_eq!(other_artifact.as_str(), "mismatch", "got {other_artifact:?}");
    assert_eq!(other_artifact.standing(), ProvenanceStanding::Refuted);

    server.shutdown().await;
}

/// Falsification 5 — a build with no identity is **never** verified, including
/// against another build with no identity.
///
/// The behaviour the owner decision rejects. `unknown` is what `build.rs` writes
/// when nothing authoritative could name a commit, and the previous revision
/// treated two of them as a match on the reasoning that two binaries from one
/// published tarball are one build. That reasoning holds just as well for two
/// binaries from two *unrelated* tarballs, so it establishes nothing.
///
/// Restoring the old boolean equality — `unknown == unknown ⇒ verified` — turns
/// the first assertion below into `Verified` and fails here.
#[tokio::test]
async fn a_build_with_no_identity_is_unverifiable_against_anything() {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = dir.path().join("aa-runtime");
    std::fs::write(&exe, b"installed from a published tarball").expect("write");

    let server = TestServer::start_reporting(
        FakeLifecycle::default(),
        RuntimeProvenance {
            identity: BuildIdentity {
                core_version: BuildIdentity::of_this_build().core_version,
                build_sha: UNKNOWN_SHA.to_string(),
                sha_source: IdentitySource::Absent,
            },
            executable_path: exe,
            ..RuntimeProvenance::detect()
        },
    )
    .await;
    let client = connect(&server).await;

    // Against a client that also has no identity: unverifiable, never verified.
    let against_unknown = client.negotiated().verify_against(&BuildIdentity {
        core_version: BuildIdentity::of_this_build().core_version,
        build_sha: UNKNOWN_SHA.to_string(),
        sha_source: IdentitySource::Absent,
    });
    assert!(
        !against_unknown.is_trustworthy(),
        "two builds that cannot say what they are have not been shown to be one build, got {against_unknown:?}"
    );
    assert_eq!(against_unknown.as_str(), "unverifiable", "got {against_unknown:?}");
    assert_eq!(against_unknown.standing(), ProvenanceStanding::Unverifiable);

    // Against a client that does have one: still unverifiable — the peer has
    // not been shown to be a *different* build, only to be unable to say.
    let against_known = client.negotiated().verify_against(&expected_authoritative_identity());
    assert_eq!(against_known.as_str(), "unverifiable", "got {against_known:?}");
    assert_eq!(against_known.standing(), ProvenanceStanding::Unverifiable);

    // And whatever this test binary was itself built from, the live path agrees.
    let live = client.negotiated().provenance_verdict();
    assert!(!live.is_trustworthy(), "got {live:?}");
    assert_eq!(
        live.standing(),
        ProvenanceStanding::Unverifiable,
        "a peer with no identity is unverifiable, not refuted: {live:?}"
    );
    // Whether this crate itself has an identity does not change the outcome —
    // which is precisely what the rejected boolean rule could not say.
    let _ = BUILD_SHA;

    server.shutdown().await;
}
