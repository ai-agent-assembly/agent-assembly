//! AAASM-5674's falsification suite: proving the fabricated `unchanged` is
//! unreachable, by building it.
//!
//! # What is being falsified
//!
//! The ticket's acceptance criterion is not "the new field works". It is that
//! **an older peer's answer cannot be read as a success claim** — and the only
//! honest way to show that is to write the reading that *does* fabricate one,
//! run it against the same frame the shipped code sees, and assert the two
//! disagree in exactly the direction that matters.
//!
//! Each shadow reading below is a transcription of a design that was considered
//! and rejected, not a strawman:
//!
//! | Shadow | The rejected design it transcribes | What it produces |
//! | --- | --- | --- |
//! | [`bool_shaped_reading`] | a proto3 `bool mutated` field on `ApplyView` | a false `unchanged` for **every** pre-v5 peer |
//! | [`reading_without_the_version_gate`] | the shipped enum, with the DI-API version check deleted | a success claim sourced from a field the connection never negotiated |
//!
//! # Why `unchanged` is the dangerous answer and `changed` is not
//!
//! Both are wrong when fabricated, but they fail in opposite directions. A
//! fabricated `changed` tells a user something happened that did not: annoying,
//! and self-correcting the moment they look. A fabricated `unchanged` tells
//! them **their machine is already in the state they asked for**. Nobody looks
//! at a no-op. That is the same shape as AAASM-5628's `unknown == unknown ⇒
//! match`: an absence resolved in the flattering direction, reported with
//! confidence, indistinguishable from the real thing.
//!
//! So every assertion here is one-sided on purpose: it is not enough that the
//! shipped reading differs from the shadow, it must specifically refuse to say
//! `unchanged` and refuse to be authoritative.

use prost::Message;

use aa_proto::assembly::devint::v1 as wire;

use super::apply_outcome::{ApplyMutation, MutationUnknown};
use super::client::{DevIntClient, TargetRequest};
use super::negotiate::{DI_API_APPLY_OUTCOME_SINCE, DI_API_MIN_SUPPORTED};
use super::projection;
use super::scope::{TokenScope, ToolScope};
use super::testkit::{claude_code_id, FakeLifecycle, TestServer};

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

/// **The rejected design, transcribed.** What a proto3 `bool mutated` field
/// would have produced.
///
/// proto3 scalars have no presence, so a peer that never sent the field and a
/// peer that sent `false` decode identically to `false`. There are exactly two
/// readings of one bit, and the one absence lands on is `unchanged` — a
/// success. This function is that reading, written out so the failure is
/// demonstrated rather than described.
fn bool_shaped_reading(applied: &wire::ApplyView) -> &'static str {
    // `false` is what a `bool` field decodes to when the peer never wrote it.
    let mutated = applied
        .outcome
        .as_ref()
        .is_some_and(|o| o.mutation == wire::ApplyMutation::Changed as i32);
    if mutated {
        "changed"
    } else {
        "unchanged"
    }
}

/// **The shipped decoder with its version gate deleted**, and nothing else
/// changed.
///
/// Kept structurally identical to [`ApplyMutation::from_view`] so the diff
/// between them is exactly the removed check. If the shipped decoder is
/// refactored and this stops mirroring it, the mirror is the thing to fix — the
/// test is only meaningful while the two differ by one gate.
fn reading_without_the_version_gate(outcome: Option<&wire::ApplyOutcomeView>) -> ApplyMutation {
    let Some(view) = outcome else {
        return ApplyMutation::Unknown(MutationUnknown::Omitted { negotiated_version: 0 });
    };
    match wire::ApplyMutation::try_from(view.mutation) {
        Ok(wire::ApplyMutation::Changed) => ApplyMutation::Changed,
        Ok(wire::ApplyMutation::Unchanged) => ApplyMutation::Unchanged,
        Ok(wire::ApplyMutation::Failed) => ApplyMutation::Failed {
            detail: view.detail.clone(),
        },
        Ok(wire::ApplyMutation::Unsupported) => ApplyMutation::Unsupported {
            detail: view.detail.clone(),
        },
        Ok(wire::ApplyMutation::Unspecified) => ApplyMutation::Unknown(MutationUnknown::Unspecified {
            detail: view.detail.clone(),
        }),
        Err(_) => ApplyMutation::Unknown(MutationUnknown::Unrecognised { value: view.mutation }),
    }
}

/// Falsification 1 — **the `bool` design fabricates a no-op for every older
/// peer**, over a real socket.
///
/// The ticket's acceptance criterion, executed. The server is this build and
/// serves the whole window; the client offers exactly one pre-v5 version, so
/// the `ApplyView` that arrives is byte-for-byte what a genuinely older runtime
/// would send. Against that frame:
///
/// - the rejected `bool` reading says **`unchanged`** — a success claim about
///   the user's machine, sourced from a field nobody sent;
/// - the shipped reading says `Unknown`, names the version, and is not
///   authoritative.
///
/// Restoring the `bool` design — or collapsing the five states onto two
/// anywhere downstream — turns the shipped assertion into the shadow one and
/// fails here.
#[tokio::test]
async fn the_rejected_bool_field_reports_a_false_unchanged_for_every_older_peer() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    for version in DI_API_MIN_SUPPORTED..DI_API_APPLY_OUTCOME_SINCE {
        let mut client = connect_offering(&server, &[version]).await;
        // Managed scope explicitly: an empty/user-scope target is refused by
        // the client below DI_API_USER_CONFIG_HOME_SINCE (AAASM-5957), which
        // this test's whole loop is below — this test is about apply_outcome
        // fabrication across old versions, not about the user-scope gate.
        let target = TargetRequest {
            settings_scope: "managed",
            ..TargetRequest::default()
        };
        let applied = client.apply(&claude_code_id(), "plan-1", target).await.expect("apply");

        // The fabrication, produced on demand.
        assert_eq!(
            bool_shaped_reading(&applied),
            "unchanged",
            "the falsification is vacuous at v{version} if the rejected design does not fabricate"
        );

        // The shipped reading of the same frame.
        let mutation = client.negotiated().apply_mutation(&applied);
        assert_ne!(
            mutation,
            ApplyMutation::Unchanged,
            "v{version} produced the exact claim this design exists to prevent"
        );
        assert!(
            !mutation.is_authoritative(),
            "v{version} treated an absence as an answer: {mutation:?}"
        );
        assert_eq!(
            mutation,
            ApplyMutation::Unknown(MutationUnknown::NotReportedAtVersion {
                negotiated_version: version,
                since: DI_API_APPLY_OUTCOME_SINCE,
            })
        );
    }
    server.shutdown().await;
}

/// Falsification 2 — **deleting the version gate consumes a field the
/// connection never negotiated**, on real wire bytes.
///
/// A frame is built by the real projection at v5, encoded and decoded through
/// prost — so these are the bytes a non-conforming peer, an intermediary, or a
/// peer that is simply not this build would put on the socket — and then read
/// as though the connection had negotiated v4.
///
/// - without the gate, the reading is `Unchanged`: a success claim about the
///   host, resting entirely on a field that was never part of the agreed
///   contract for this connection;
/// - with it, the reading is `Unknown`, naming v4.
///
/// This is why the gate is a version comparison and not merely a presence test.
/// A presence test asks "did something arrive?", which a hostile or broken peer
/// answers for you. The version asks "was this peer entitled to answer?", which
/// only the handshake can settle.
#[test]
fn deleting_the_version_gate_consumes_an_outcome_the_connection_never_negotiated() {
    let applied = super::lifecycle::AppliedIntegration {
        receipt: fixture_receipt(),
        mutation: ApplyMutation::Unchanged,
    };
    let served = projection::apply_view(&applied, DI_API_APPLY_OUTCOME_SINCE);
    let on_the_wire = wire::ApplyView::decode(served.encode_to_vec().as_slice()).expect("decode");
    let block = on_the_wire.outcome.as_ref().expect("the fixture states an outcome");

    let stale_version = DI_API_APPLY_OUTCOME_SINCE - 1;

    // The fabrication.
    assert_eq!(
        reading_without_the_version_gate(Some(block)),
        ApplyMutation::Unchanged,
        "the falsification is vacuous if the ungated reading does not consume the field"
    );

    // The shipped reading of the same bytes on the same connection.
    let gated = ApplyMutation::from_view(Some(block), stale_version);
    assert_ne!(gated, ApplyMutation::Unchanged);
    assert!(!gated.is_authoritative());
    assert_eq!(
        gated,
        ApplyMutation::Unknown(MutationUnknown::NotReportedAtVersion {
            negotiated_version: stale_version,
            since: DI_API_APPLY_OUTCOME_SINCE,
        })
    );
}

/// Falsification 3 — **the missing field at the carrying version**.
///
/// The case the version gate alone does not cover: a peer that negotiated v5,
/// promised an answer, and sent none. The `bool` reading calls it `unchanged`;
/// the shipped reading calls it `Omitted` and stays non-authoritative.
///
/// Kept separate from falsification 1 because a fix for one does not fix the
/// other — a client that gated on the version and then defaulted the field
/// would pass the first and fail this.
#[test]
fn a_promised_field_that_never_arrives_is_not_a_no_op() {
    let empty = wire::ApplyView {
        plan_id: "plan-1".to_string(),
        receipt_id: "receipt-1".to_string(),
        applied_at_unix_secs: 1_700_000_000,
        steps: Vec::new(),
        planned_level: "gateway_protected".to_string(),
        achieved_level: "integrated".to_string(),
        outcome: None,
    };
    let on_the_wire = wire::ApplyView::decode(empty.encode_to_vec().as_slice()).expect("decode");

    assert_eq!(bool_shaped_reading(&on_the_wire), "unchanged");

    let gated = ApplyMutation::from_view(on_the_wire.outcome.as_ref(), DI_API_APPLY_OUTCOME_SINCE);
    assert_ne!(gated, ApplyMutation::Unchanged);
    assert!(!gated.is_authoritative());
    assert_eq!(
        gated,
        ApplyMutation::Unknown(MutationUnknown::Omitted {
            negotiated_version: DI_API_APPLY_OUTCOME_SINCE
        })
    );
}

/// Falsification 4 — **the enum's zero value is the non-committal one**, on
/// real wire bytes.
///
/// The structural property that makes the whole design hold: a block whose
/// enum was never written decodes to `UNSPECIFIED`, so even a client that
/// forgets both gates cannot reach `Unchanged` from a defaulted field. Had the
/// zero value been `CHANGED` or `UNCHANGED`, every absence would land on a
/// determinate answer and the gates would be the only thing standing between a
/// peer and a fabricated claim.
#[test]
fn a_defaulted_block_cannot_decode_to_either_determinate_answer() {
    let defaulted = wire::ApplyOutcomeView::default();
    let on_the_wire = wire::ApplyOutcomeView::decode(defaulted.encode_to_vec().as_slice()).expect("decode");
    assert_eq!(on_the_wire.mutation, wire::ApplyMutation::Unspecified as i32);

    // Both readings — gated and ungated — agree here, which is the point: the
    // representation carries the safety, not the checks around it.
    for reading in [
        ApplyMutation::from_view(Some(&on_the_wire), DI_API_APPLY_OUTCOME_SINCE),
        reading_without_the_version_gate(Some(&on_the_wire)),
    ] {
        assert_ne!(reading, ApplyMutation::Unchanged);
        assert_ne!(reading, ApplyMutation::Changed);
        assert!(!reading.is_authoritative());
    }
}

/// A receipt to project. Its content is irrelevant to these tests; only the
/// outcome block is under examination.
fn fixture_receipt() -> aa_core::integration::IntegrationReceipt {
    use aa_core::dev_tool::DevToolKind;
    use aa_core::integration::{
        ProtectionLevel, ProtectionProfile, SettingsScope, SupportedToolVersions, ToolVersion, VersionSupport,
        LIFECYCLE_SCHEMA_VERSION,
    };

    aa_core::integration::IntegrationReceipt {
        schema_version: LIFECYCLE_SCHEMA_VERSION,
        receipt_id: "receipt-1".to_string(),
        plan_id: "plan-1".to_string(),
        tool: DevToolKind::ClaudeCode,
        profile: ProtectionProfile::Recommended,
        settings_scope: SettingsScope::User,
        applied_at_unix_secs: 1_700_000_000,
        versions: VersionSupport {
            adapter_version: ToolVersion::new(1, 0, 0),
            lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION,
            supported_tool_versions: SupportedToolVersions::any(),
        }
        .component_versions(),
        tool_version: None,
        steps: Vec::new(),
        planned_level: ProtectionLevel::GatewayProtected,
        achieved_level: ProtectionLevel::Integrated,
        achieved_evidence: Vec::new(),
        verified_at_unix_secs: None,
    }
}
