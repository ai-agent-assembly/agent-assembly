//! Threat-model tests for the DI-API (AAASM-5279, ADR 0030 V2/V3/V6–V9/V13).
//!
//! Each test names an adversary and the property that stops them. They run
//! against a **real server on a real socket**, because every property here is
//! a property of the served boundary rather than of a function: a scope check
//! that holds in a unit test but is never called by the dispatcher protects
//! nothing.
//!
//! | Adversary | Property |
//! | --- | --- |
//! | A compromised plugin | the verb space is closed; its token is scoped to one tool; there is no policy verb and no core passthrough |
//! | A thief with a stolen token | scope bounds the blast radius; expiry ends it; revocation ends it immediately, mid-connection |
//! | A replayer | a replayed request re-invokes only what the token already allowed, and dies with the token |
//! | A downgrader | the negotiated version is fixed; a second `Hello` is refused; a version-gated verb stays gated |
//! | An eavesdropper on the logs | no response and no audit event carries a token value or protected content |

use aa_proto::assembly::devint::v1 as wire;

use super::audit::DevIntAuditKind;
use super::codec::DiResponseFrame;
use super::negotiate::DI_API_MAX_SUPPORTED;
use super::scope::{TokenScope, ToolScope};
use super::testkit::{
    build_request, claude_code_id, connect_and_negotiate, hello_offering, FakeLifecycle, TestServer, LEAK_SENTINEL,
};
use super::verb::DiVerb;

fn expect_denied(frame: DiResponseFrame) -> wire::Denied {
    match frame {
        DiResponseFrame::Denied(denied) => denied,
        other => panic!("expected Denied, got {other:?}"),
    }
}

fn expect_response(frame: DiResponseFrame) -> wire::Response {
    match frame {
        DiResponseFrame::Response(response) => *response,
        other => panic!("expected Response, got {other:?}"),
    }
}

// ── Compromised plugin ───────────────────────────────────────────────────────

/// V3. The headline negative test: one token, one tool.
#[tokio::test]
async fn a_token_scoped_to_one_tool_cannot_touch_another_on_any_verb() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, record) = server.enrol(
        "vscode-aasm",
        TokenScope::full_lifecycle(ToolScope::tools([claude_code_id()])),
    );
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    for verb in DiVerb::ALL.into_iter().filter(|v| v.is_tool_scoped()) {
        // Its own tool: served.
        let ok = client.request(verb, &claude_code_id(), Some(&token)).await;
        assert!(
            matches!(ok, DiResponseFrame::Response(_)),
            "{verb} on the enrolled tool should be served, got {ok:?}"
        );

        // Another tool: refused, for every single verb.
        let denied = expect_denied(client.request(verb, "codex", Some(&token)).await);
        assert_eq!(
            denied.code,
            wire::DenyCode::OutOfScope as i32,
            "{verb} crossed to another tool"
        );
    }

    // …and the crossing attempts are all on the audit trail, named by
    // enrolment id rather than by token value.
    let out_of_scope: Vec<_> = server
        .audit()
        .events()
        .into_iter()
        .filter(|e| matches!(&e.kind, DevIntAuditKind::AuthFailure { outcome, .. } if *outcome == "out_of_scope"))
        .collect();
    assert_eq!(out_of_scope.len(), 8, "one audit event per cross-tool verb");
    for event in &out_of_scope {
        let DevIntAuditKind::AuthFailure { token_id, .. } = &event.kind else {
            unreachable!()
        };
        assert_eq!(token_id.as_ref(), Some(&record.token_id));
    }
    server.shutdown().await;
}

/// V8, on the wire. A compromised plugin cannot ask for a policy decision,
/// because no discriminant maps to one.
#[tokio::test]
async fn no_wire_discriminant_reaches_an_operation_outside_the_closed_set() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, _) = server.enrol("rogue", TokenScope::full_lifecycle(ToolScope::AllTools));
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    // Sweep well past the defined range, including the reserved zero and a
    // negative discriminant.
    for discriminant in [-7_i32, 0, 10, 11, 99, 1_000_000] {
        let denied = expect_denied(
            client
                .send_raw_request(wire::Request {
                    request_id: 1,
                    verb: discriminant,
                    capability_token: token.expose().to_string(),
                    tool_id: claude_code_id(),
                    ..Default::default()
                })
                .await,
        );
        assert_eq!(
            denied.code,
            wire::DenyCode::UnknownVerb as i32,
            "discriminant {discriminant} was not refused"
        );
    }
    assert_eq!(
        server.lifecycle().calls(),
        0,
        "no lifecycle operation may run for a verb outside the closed set"
    );
    server.shutdown().await;
}

/// V8. The DI-API's verb space and the SDK IPC verb space are disjoint, so
/// "the other socket's operation" is not reachable by renaming a field.
#[test]
fn the_di_verb_space_shares_no_operation_with_the_sdk_socket() {
    // The SDK socket's inbound tags are PolicyQuery, EventReport,
    // ApprovalResponse, Heartbeat, HandshakeProof. None of them is a DI verb,
    // and no DI verb is one of them.
    let sdk_operations = [
        "policy_query",
        "event_report",
        "approval_response",
        "heartbeat",
        "handshake_proof",
    ];
    for verb in DiVerb::ALL {
        assert!(
            !sdk_operations.contains(&verb.as_str()),
            "{verb} exists on both sockets"
        );
    }
}

/// A read-only enrolment — the shape a status widget or dashboard extension
/// would get — cannot mutate anything, even for a tool it is scoped to.
#[tokio::test]
async fn a_read_only_enrolment_cannot_mutate_the_integration() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, _) = server.enrol(
        "status-widget",
        TokenScope::read_only(ToolScope::tools([claude_code_id()])),
    );
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    for verb in DiVerb::ALL.into_iter().filter(|v| v.is_mutation()) {
        let denied = expect_denied(client.request(verb, &claude_code_id(), Some(&token)).await);
        assert_eq!(denied.code, wire::DenyCode::OutOfScope as i32, "{verb} was not refused");
    }
    // Reading still works, so the denial is scope and not a broken client.
    assert!(matches!(
        client.request(DiVerb::Status, &claude_code_id(), Some(&token)).await,
        DiResponseFrame::Response(_)
    ));
    assert_eq!(
        server.lifecycle().calls(),
        1,
        "only the permitted read reached the lifecycle port"
    );
    server.shutdown().await;
}

// ── Token theft, absence and expiry ──────────────────────────────────────────

/// V2. Absent, malformed and unknown tokens are each denied **and** audited,
/// and none of them can tell the others apart from the response.
#[tokio::test]
async fn absent_malformed_and_unknown_tokens_are_denied_and_audited_indistinguishably() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    server.enrol("legitimate", TokenScope::full_lifecycle(ToolScope::AllTools));
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    let stranger = super::token::CapabilityToken::generate();
    let cases: [(&str, Option<super::token::CapabilityToken>, &str); 3] = [
        ("absent", None, "token_absent"),
        (
            "malformed",
            Some(super::token::CapabilityToken::from_wire("not-a-token")),
            "token_malformed",
        ),
        ("unknown", Some(stranger), "token_unknown"),
    ];

    let mut wire_answers = Vec::new();
    for (label, token, expected_outcome) in cases {
        let denied = expect_denied(client.request(DiVerb::Status, &claude_code_id(), token.as_ref()).await);
        assert_eq!(
            denied.code,
            wire::DenyCode::Unauthenticated as i32,
            "{label} was not denied"
        );
        assert!(
            server.audit().has_auth_failure(expected_outcome),
            "{label} produced no audit event"
        );
        wire_answers.push((denied.code, denied.message.clone(), denied.remediation.clone()));
    }

    // The three answers are byte-identical apart from the request id, so a
    // prober cannot use the response to distinguish "no such token" from
    // "wrong shape" or "you sent nothing".
    assert_eq!(wire_answers[0], wire_answers[1]);
    assert_eq!(wire_answers[1], wire_answers[2]);
    assert_eq!(server.lifecycle().calls(), 0);
    server.shutdown().await;
}

/// V2. An expired enrolment is refused with an actionable code, and the audit
/// event names the enrolment that expired.
#[tokio::test]
async fn an_expired_token_is_denied_and_audited() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, record) = server.enrol_expired("stale-extension", TokenScope::full_lifecycle(ToolScope::AllTools));
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    let denied = expect_denied(client.request(DiVerb::Status, &claude_code_id(), Some(&token)).await);
    assert_eq!(denied.code, wire::DenyCode::TokenExpired as i32);
    assert!(denied.remediation.contains("rotate"));
    assert!(server.audit().has_auth_failure("token_expired"));

    let event = server
        .audit()
        .events()
        .into_iter()
        .find(|e| matches!(&e.kind, DevIntAuditKind::AuthFailure { outcome, .. } if *outcome == "token_expired"))
        .expect("expiry event");
    let DevIntAuditKind::AuthFailure { token_id, .. } = &event.kind else {
        unreachable!()
    };
    assert_eq!(token_id.as_ref(), Some(&record.token_id));
    assert_eq!(server.lifecycle().calls(), 0);
    server.shutdown().await;
}

/// The thief's best case: a valid, unexpired, stolen token. It still cannot do
/// more than the enrolment it was stolen from — which is the accepted-risk
/// mitigation ADR 0030 states, asserted rather than assumed.
#[tokio::test]
async fn a_stolen_token_is_bounded_by_the_scope_it_was_stolen_from() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (stolen, _) = server.enrol(
        "claude-code-extension",
        TokenScope::read_only(ToolScope::tools([claude_code_id()])),
    );
    // The thief connects as a brand-new client and presents the stolen secret.
    let mut thief = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    assert!(matches!(
        thief.request(DiVerb::Status, &claude_code_id(), Some(&stolen)).await,
        DiResponseFrame::Response(_)
    ));
    // …and no further. Not another tool, and not a mutation.
    assert_eq!(
        expect_denied(thief.request(DiVerb::Status, "codex", Some(&stolen)).await).code,
        wire::DenyCode::OutOfScope as i32
    );
    assert_eq!(
        expect_denied(thief.request(DiVerb::Remove, &claude_code_id(), Some(&stolen)).await).code,
        wire::DenyCode::OutOfScope as i32
    );
    server.shutdown().await;
}

/// V13, and the property that makes revocation real rather than advisory:
/// it lands on a connection that is already open and already authenticated.
#[tokio::test]
async fn revocation_kills_an_already_open_connection_mid_session() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, record) = server.enrol("vscode-aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    assert!(matches!(
        client.request(DiVerb::Status, &claude_code_id(), Some(&token)).await,
        DiResponseFrame::Response(_)
    ));

    assert!(server.tokens().revoke(&record.token_id));

    // Same connection, same negotiated version, same token — now refused.
    let denied = expect_denied(client.request(DiVerb::Status, &claude_code_id(), Some(&token)).await);
    assert_eq!(
        denied.code,
        wire::DenyCode::Unauthenticated as i32,
        "a revoked token must resolve to nothing, exactly like one that never existed"
    );
    server.shutdown().await;
}

/// Rotation never opens a window with no valid token, and revoking the old one
/// afterwards closes it completely — over the wire, not just in the store.
#[tokio::test]
async fn rotation_overlaps_and_then_the_old_token_dies() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (old, old_record) = server.enrol("vscode-aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
    let (new, _) = server
        .tokens()
        .rotate(&old_record.token_id, aa_core::integration::now_unix_secs(), 3600)
        .expect("rotate");
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    for token in [&old, &new] {
        assert!(
            matches!(
                client.request(DiVerb::Status, &claude_code_id(), Some(token)).await,
                DiResponseFrame::Response(_)
            ),
            "both tokens must work during the overlap"
        );
    }

    server.tokens().revoke(&old_record.token_id);
    assert_eq!(
        expect_denied(client.request(DiVerb::Status, &claude_code_id(), Some(&old)).await).code,
        wire::DenyCode::Unauthenticated as i32
    );
    assert!(matches!(
        client.request(DiVerb::Status, &claude_code_id(), Some(&new)).await,
        DiResponseFrame::Response(_)
    ));
    server.shutdown().await;
}

// ── Replay ───────────────────────────────────────────────────────────────────

/// V13. A captured request replayed verbatim re-invokes only a verb the token
/// was already scoped for, and lifecycle verbs are idempotent by AAASM-5278's
/// contract — so replay produces no state the legitimate client could not have
/// produced itself.
#[tokio::test]
async fn a_replayed_request_reaches_nothing_new() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, _) = server.enrol(
        "vscode-aasm",
        TokenScope::full_lifecycle(ToolScope::tools([claude_code_id()])),
    );
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    // Capture a legitimate apply, byte for byte.
    let captured = build_request(DiVerb::Apply, &claude_code_id(), Some(&token), 1);
    let first = expect_response(client.send_raw_request(captured.clone()).await);
    let first_apply = first.apply.expect("apply view");

    // Replay it five times, including on a fresh connection — the shape an
    // attacker who captured the frame would actually use.
    let mut replayer = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;
    for _ in 0..5 {
        let replayed = expect_response(replayer.send_raw_request(captured.clone()).await);
        assert_eq!(replayed.apply.expect("apply view"), first_apply, "replay diverged");
    }

    // And the replay dies with the token: the captured frame carries the
    // secret, so revoking it revokes the replay too.
    let record = server.tokens().live_records(aa_core::integration::now_unix_secs())[0].clone();
    server.tokens().revoke(&record.token_id);
    assert_eq!(
        expect_denied(replayer.send_raw_request(captured.clone()).await).code,
        wire::DenyCode::Unauthenticated as i32
    );
    server.shutdown().await;
}

/// A replayed request cannot be re-pointed at another tool: the token is
/// checked against the tool id in the frame, so editing the frame invalidates
/// the authorization it was replayed for.
#[tokio::test]
async fn a_replayed_request_cannot_be_re_pointed_at_another_tool() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, _) = server.enrol(
        "vscode-aasm",
        TokenScope::full_lifecycle(ToolScope::tools([claude_code_id()])),
    );
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    let mut tampered = build_request(DiVerb::Apply, &claude_code_id(), Some(&token), 1);
    tampered.tool_id = "codex".to_string();
    assert_eq!(
        expect_denied(client.send_raw_request(tampered).await).code,
        wire::DenyCode::OutOfScope as i32
    );
    server.shutdown().await;
}

// ── Version downgrade ────────────────────────────────────────────────────────

/// V6. A client below the floor gets a deterministic `Incompatible` with
/// remediation — never a silent downgrade into older behaviour.
#[tokio::test]
async fn a_below_floor_client_gets_incompatible_with_remediation_not_a_downgrade() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let mut raw = server.connect_raw().await;
    raw.send_hello(hello_offering(&[0])).await;
    match raw.read().await {
        DiResponseFrame::Incompatible(incompatible) => {
            assert!(incompatible.reason.contains("below the supported floor"));
            assert!(!incompatible.remediation.is_empty());
        }
        other => panic!("expected Incompatible, got {other:?}"),
    }
    // The connection is closed rather than left in a half-negotiated state.
    assert!(raw.try_read().await.is_none());
    server.shutdown().await;
}

/// V6. The negotiated version is fixed for the connection's lifetime, so a
/// mid-connection renegotiation — the way a downgrade would be staged — is a
/// protocol violation.
#[tokio::test]
async fn a_mid_connection_downgrade_attempt_is_refused() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, _) = server.enrol("vscode-aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    // Negotiated at the ceiling; now try to talk the server down to v1.
    client.send_hello(hello_offering(&[1])).await;
    let denied = expect_denied(client.read().await);
    assert_eq!(denied.code, wire::DenyCode::ProtocolViolation as i32);
    assert!(denied.message.contains("fixed for the life of a connection"));
    assert!(server.audit().events().iter().any(
        |e| matches!(&e.kind, DevIntAuditKind::ProtocolFailure { reason } if *reason == "renegotiation_attempted")
    ));

    // …and the connection still speaks the version it originally agreed, so
    // the refused downgrade did not leave it in a lesser state either.
    assert!(matches!(
        client
            .request(DiVerb::ScopedEvents, &claude_code_id(), Some(&token))
            .await,
        DiResponseFrame::Response(_)
    ));
    server.shutdown().await;
}

/// V6. A client that legitimately negotiates the older version cannot reach a
/// verb that version does not have, even with a token scoped for it.
#[tokio::test]
async fn a_degraded_connection_cannot_reach_a_verb_its_version_lacks() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, _) = server.enrol("old-extension", TokenScope::full_lifecycle(ToolScope::AllTools));
    let mut client = connect_and_negotiate(&server, hello_offering(&[1])).await;

    for verb in [DiVerb::ScopedEvents, DiVerb::ApprovalRelay] {
        let denied = expect_denied(client.request(verb, &claude_code_id(), Some(&token)).await);
        assert_eq!(
            denied.code,
            wire::DenyCode::UnavailableAtVersion as i32,
            "{verb} leaked into a v1 connection"
        );
        assert!(denied.remediation.contains("v2"));
    }
    // The verbs v1 does have still work, so this is a version gate and not a
    // broken connection.
    assert!(matches!(
        client.request(DiVerb::Status, &claude_code_id(), Some(&token)).await,
        DiResponseFrame::Response(_)
    ));
    server.shutdown().await;
}

/// An unauthenticated caller learns nothing about the verbs that exist at a
/// version it did not negotiate: auth is checked first, so the answer is
/// `UNAUTHENTICATED`, not `UNAVAILABLE_AT_VERSION`.
#[tokio::test]
async fn version_gating_is_not_an_oracle_for_unauthenticated_callers() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let mut client = connect_and_negotiate(&server, hello_offering(&[1])).await;
    let denied = expect_denied(client.request(DiVerb::ScopedEvents, &claude_code_id(), None).await);
    assert_eq!(denied.code, wire::DenyCode::Unauthenticated as i32);
    server.shutdown().await;
}

// ── Data minimisation, end to end ────────────────────────────────────────────

/// V7, over the socket. The fake lifecycle returns a plan whose environment
/// injection carries a live-looking secret; nothing that crosses the wire, and
/// nothing the audit trail records, contains it.
#[tokio::test]
async fn nothing_that_leaves_the_boundary_carries_a_secret_or_a_token() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let (token, _) = server.enrol("vscode-aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;

    for verb in DiVerb::ALL {
        let frame = client.request(verb, &claude_code_id(), Some(&token)).await;
        let rendered = format!("{frame:?}");
        assert!(!rendered.contains(LEAK_SENTINEL), "{verb} leaked a step value");
        assert!(!rendered.contains(token.expose()), "{verb} echoed the capability token");
    }

    // The audit trail is the other thing that leaves the request: it must name
    // the enrolment, never the secret, and never protected content.
    let audited = format!("{:?}", server.audit().events());
    assert!(
        !audited.contains(token.expose()),
        "an audit event carried the token value"
    );
    assert!(
        !audited.contains(LEAK_SENTINEL),
        "an audit event carried protected content"
    );
    server.shutdown().await;
}

/// Denials are the other response path, and the one most likely to be written
/// carelessly. None of them echoes what was presented.
#[tokio::test]
async fn a_denial_never_echoes_what_was_presented() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let mut client = connect_and_negotiate(&server, hello_offering(&[DI_API_MAX_SUPPORTED])).await;
    let stranger = super::token::CapabilityToken::generate();

    let denied = expect_denied(client.request(DiVerb::Status, &claude_code_id(), Some(&stranger)).await);
    let rendered = format!("{denied:?}");
    assert!(!rendered.contains(stranger.expose()));
    // Nor does it hint at how close the token came to resolving.
    for hint in ["prefix", "matched", "expired at", "similar"] {
        assert!(!rendered.contains(hint), "the denial hints at {hint}");
    }
    server.shutdown().await;
}

// ── Transport ────────────────────────────────────────────────────────────────

/// V9. The socket the server actually bound is `0600` inside a `0700`
/// directory, asserted by reading the filesystem back while the server is live.
#[tokio::test]
async fn the_live_socket_is_owner_only_in_an_owner_only_directory() {
    use std::os::unix::fs::PermissionsExt;

    let server = TestServer::start(FakeLifecycle::default()).await;
    let path = server.socket_path().to_path_buf();
    let socket_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let dir_mode = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777;
    assert_eq!(socket_mode, 0o600, "the live DI-API socket is not owner-only");
    assert_eq!(dir_mode, 0o700, "the live DI-API socket directory is not owner-only");
    server.shutdown().await;
}

/// The DI-API and SDK sockets are different files, which is what makes agent
/// traffic unreachable from a DI client by construction (§5.1).
#[tokio::test]
async fn the_di_socket_is_not_the_sdk_socket() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let di_path = server.socket_path().to_string_lossy().to_string();
    assert!(di_path.ends_with("devint.sock"));
    assert!(
        !di_path.contains("aa-runtime-"),
        "the DI-API must not squat the SDK socket"
    );
    server.shutdown().await;
}

/// An oversized length prefix is refused without allocating for it, and the
/// connection ends rather than resynchronising into the attacker's stream.
#[tokio::test]
async fn an_oversized_frame_ends_the_connection_without_allocating() {
    use tokio::io::AsyncWriteExt;

    let server = TestServer::start(FakeLifecycle::default()).await;
    let mut stream = tokio::net::UnixStream::connect(server.socket_path())
        .await
        .expect("connect");

    let mut hostile = vec![super::codec::TAG_REQUEST];
    prost::encoding::encode_varint(4 * 1024 * 1024 * 1024, &mut hostile);
    stream.write_all(&hostile).await.expect("write");
    stream.flush().await.expect("flush");

    // The server closes; a read returns EOF rather than a frame.
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await;
    assert!(matches!(read, Ok(Ok(0))), "the connection should have been closed");
    server.shutdown().await;
}

/// A peer that never negotiates is dropped rather than held open forever.
///
/// Runs on a paused clock so the five-second slow-loris bound is asserted in
/// milliseconds: tokio auto-advances time whenever every task is parked, which
/// is exactly the state a silent peer produces.
#[tokio::test(start_paused = true)]
async fn a_peer_that_never_negotiates_is_dropped() {
    let server = TestServer::start(FakeLifecycle::default()).await;
    let _silent = tokio::net::UnixStream::connect(server.socket_path())
        .await
        .expect("connect");

    // The timeout is audited, which is how an operator sees a stalling client.
    for _ in 0..200 {
        if server
            .audit()
            .events()
            .iter()
            .any(|e| matches!(&e.kind, DevIntAuditKind::ProtocolFailure { reason } if *reason == "negotiation_timeout"))
        {
            server.shutdown().await;
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the negotiation timeout was never reached");
}
