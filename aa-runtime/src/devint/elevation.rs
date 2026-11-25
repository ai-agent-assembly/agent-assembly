//! The runtime half of terminal elevation — AAASM-6491, DI-API 8.
//!
//! # Why the runtime asks the client instead of prompting
//!
//! An apply, repair or removal runs inside the detached runtime, whose stdio is
//! null, so it cannot ask anyone for a password. The *client* that sent the
//! request owns the operator's terminal. So while a request is in flight the
//! runtime may send that client an [`ElevationRequest`](wire::ElevationRequest)
//! on the **same connection**, block until the client answers with an
//! [`ElevationResult`](wire::ElevationResult), and then continue. There is no new
//! verb: the verb space stays closed, and a frame that is not the answer to a
//! request this runtime sent is a protocol violation.
//!
//! # What this module refuses to trust
//!
//! The answer is untrusted input. Anything other than a result for this exact
//! `request_id` and `sequence`, an `UNSPECIFIED` outcome, EOF, or silence past
//! the timeout is read as **cancelled** — and the engine's existing rollback then
//! runs. No failure here is ever read as success.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;

use aa_core::integration::{ElevatedKind, ElevatedOperation, ElevationBroker, ElevationOutcome, ElevationPurpose};
use aa_proto::assembly::devint::v1 as wire;

use super::codec::{self, DiFrame, DiResponseFrame};

/// How long an operator gets to answer one elevation request.
pub const DEFAULT_ELEVATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long a client may spend on one elevation before it must give up on its
/// own, measured from the moment it receives the request.
///
/// Deliberately shorter than [`DEFAULT_ELEVATION_TIMEOUT`]. After the runtime's
/// timeout it has cancelled the operation, rolled back and closed the
/// connection; a client that went on to mutate the host then would change it
/// behind a receipt that says it did not. The margin covers the transit of the
/// request and the client's own cleanup after its last decision.
pub const CLIENT_ELEVATION_BUDGET: Duration = Duration::from_secs(8 * 60);

/// One elevation request on its way from a blocking broker to the connection
/// task that owns the socket.
pub(crate) struct BrokerCall {
    pub(crate) request: wire::ElevationRequest,
    pub(crate) reply: mpsc::Sender<ElevationOutcome>,
}

/// The [`ElevationBroker`] a connection hands to the lifecycle for one request.
///
/// `perform` is called from a blocking thread (`spawn_blocking`) and parks on a
/// std channel until the connection task has run the exchange. The connection
/// task always answers, so no timeout is needed here: a dropped connection drops
/// the reply sender and `perform` reads that as cancelled.
#[derive(Debug)]
pub(crate) struct ChannelBroker {
    request_id: u64,
    next_sequence: AtomicU32,
    calls: UnboundedSender<BrokerCall>,
}

impl ChannelBroker {
    pub(crate) fn new(request_id: u64, calls: UnboundedSender<BrokerCall>) -> Self {
        Self {
            request_id,
            next_sequence: AtomicU32::new(1),
            calls,
        }
    }
}

impl ElevationBroker for ChannelBroker {
    fn perform(&self, operation: &ElevatedOperation) -> ElevationOutcome {
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let (reply, answer) = mpsc::channel();
        let call = BrokerCall {
            request: to_wire(self.request_id, sequence, operation),
            reply,
        };
        if self.calls.send(call).is_err() {
            return ElevationOutcome::Cancelled("the connection to the client closed".to_string());
        }
        answer
            .recv()
            .unwrap_or_else(|_| ElevationOutcome::Cancelled("the connection to the client closed".to_string()))
    }
}

/// The wire form of an operation. Paths and a digest only.
pub(crate) fn to_wire(request_id: u64, sequence: u32, operation: &ElevatedOperation) -> wire::ElevationRequest {
    wire::ElevationRequest {
        request_id,
        sequence,
        kind: match operation.kind {
            ElevatedKind::InstallFile => wire::ElevationKind::InstallFile,
            ElevatedKind::DeleteFile => wire::ElevationKind::DeleteFile,
        } as i32,
        purpose: match operation.purpose {
            ElevationPurpose::PlaceReviewed => wire::ElevationPurpose::PlaceReviewed,
            ElevationPurpose::RestoreBackup => wire::ElevationPurpose::RestoreBackup,
            ElevationPurpose::Remove => wire::ElevationPurpose::Remove,
        } as i32,
        target: operation.target.display().to_string(),
        staged_path: operation
            .staged
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        staged_sha256: operation.staged_sha256.clone().unwrap_or_default(),
    }
}

/// Read a client's result as an outcome. `UNSPECIFIED` and any value this build
/// does not know fail closed.
pub(crate) fn outcome_from_wire(result: &wire::ElevationResult) -> ElevationOutcome {
    let detail = result.detail.clone();
    match wire::ElevationResultCode::try_from(result.outcome) {
        Ok(wire::ElevationResultCode::Completed) => ElevationOutcome::Completed,
        Ok(wire::ElevationResultCode::Denied) => ElevationOutcome::Denied(detail),
        Ok(wire::ElevationResultCode::Cancelled) => ElevationOutcome::Cancelled(detail),
        Ok(wire::ElevationResultCode::Unavailable) => ElevationOutcome::Unavailable(detail),
        Ok(wire::ElevationResultCode::NonInteractive) => ElevationOutcome::NonInteractive(detail),
        Ok(wire::ElevationResultCode::Unspecified) | Err(_) => {
            ElevationOutcome::Cancelled("the client's answer did not state an outcome".to_string())
        }
    }
}

/// What one exchange concluded, and whether the connection can still be trusted.
pub(crate) struct Exchange {
    pub(crate) outcome: ElevationOutcome,
    /// The peer answered with something other than the awaited result, or the
    /// transport failed. The connection is closed once the request finishes.
    pub(crate) poisoned: bool,
}

/// Send one request and wait for its answer.
///
/// The only frame accepted while waiting is an `ElevationResult` for exactly
/// this `request_id` and `sequence`. Everything else cancels the operation.
pub(crate) async fn exchange<R, W>(
    reader: &mut R,
    writer: &mut W,
    request: wire::ElevationRequest,
    timeout: Duration,
) -> Exchange
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let (request_id, sequence) = (request.request_id, request.sequence);
    if codec::write_frame(writer, DiResponseFrame::ElevationRequest(request))
        .await
        .is_err()
    {
        return Exchange {
            outcome: ElevationOutcome::Cancelled("the client went away before it could be asked".to_string()),
            poisoned: true,
        };
    }
    match tokio::time::timeout(timeout, codec::read_frame(reader)).await {
        Err(_) => Exchange {
            outcome: ElevationOutcome::Cancelled(format!(
                "no answer within {} seconds; nothing was changed",
                timeout.as_secs()
            )),
            // A late answer would desynchronise the stream.
            poisoned: true,
        },
        Ok(Err(_)) => Exchange {
            outcome: ElevationOutcome::Cancelled("the client closed the connection".to_string()),
            poisoned: true,
        },
        Ok(Ok(DiFrame::ElevationResult(result))) if result.request_id == request_id && result.sequence == sequence => {
            Exchange {
                outcome: outcome_from_wire(&result),
                poisoned: false,
            }
        }
        Ok(Ok(_)) => Exchange {
            outcome: ElevationOutcome::Cancelled(
                "the client answered with a frame that was not the awaited elevation result".to_string(),
            ),
            poisoned: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_client_budget_ends_well_before_the_runtime_gives_up() {
        assert!(
            CLIENT_ELEVATION_BUDGET + Duration::from_secs(60) <= DEFAULT_ELEVATION_TIMEOUT,
            "a client must stop mutating at least a minute before the runtime cancels"
        );
    }

    fn operation() -> ElevatedOperation {
        ElevatedOperation {
            kind: ElevatedKind::InstallFile,
            purpose: ElevationPurpose::PlaceReviewed,
            target: PathBuf::from("/t"),
            staged: Some(PathBuf::from("/s")),
            staged_sha256: Some("ab".repeat(32)),
        }
    }

    #[test]
    fn the_wire_form_carries_paths_and_a_digest_only() {
        let wire = to_wire(4, 2, &operation());
        assert_eq!((wire.request_id, wire.sequence), (4, 2));
        assert_eq!(wire.target, "/t");
        assert_eq!(wire.staged_path, "/s");
        assert_eq!(wire.staged_sha256.len(), 64);
        assert_eq!(wire.kind, wire::ElevationKind::InstallFile as i32);
    }

    #[test]
    fn an_unspecified_or_unknown_outcome_fails_closed() {
        for code in [0, 99] {
            let outcome = outcome_from_wire(&wire::ElevationResult {
                request_id: 1,
                sequence: 1,
                outcome: code,
                detail: String::new(),
            });
            assert!(matches!(outcome, ElevationOutcome::Cancelled(_)), "{code}: {outcome:?}");
        }
    }

    fn result(request_id: u64, sequence: u32, outcome: wire::ElevationResultCode) -> wire::ElevationResult {
        wire::ElevationResult {
            request_id,
            sequence,
            outcome: outcome as i32,
            detail: "d".to_string(),
        }
    }

    async fn run_exchange(
        reply: Option<DiFrame>,
        timeout: Duration,
        hold_open: bool,
    ) -> (Exchange, Option<wire::ElevationRequest>) {
        let (server_side, mut client_side) = tokio::io::duplex(64 * 1024);
        let (mut reader, mut writer) = tokio::io::split(server_side);
        let request = to_wire(7, 1, &operation());
        let client = async move {
            let frame = codec::read_response_frame(&mut client_side).await.ok();
            if let Some(reply) = reply {
                codec::write_client_frame(&mut client_side, reply).await.expect("reply");
            }
            if hold_open {
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            frame
        };
        let (exchanged, frame) = tokio::join!(exchange(&mut reader, &mut writer, request, timeout), client);
        let seen = match frame {
            Some(DiResponseFrame::ElevationRequest(r)) => Some(r),
            _ => None,
        };
        (exchanged, seen)
    }

    #[tokio::test]
    async fn a_matching_result_completes_and_the_request_reached_the_client() {
        let (done, seen) = run_exchange(
            Some(DiFrame::ElevationResult(result(
                7,
                1,
                wire::ElevationResultCode::Completed,
            ))),
            Duration::from_secs(5),
            false,
        )
        .await;
        assert_eq!(done.outcome, ElevationOutcome::Completed);
        assert!(!done.poisoned);
        assert_eq!(seen.expect("client saw a request").sequence, 1);
    }

    #[tokio::test]
    async fn a_mismatched_id_or_sequence_cancels_and_poisons_the_connection() {
        for (id, seq) in [(8, 1), (7, 2)] {
            let (done, _) = run_exchange(
                Some(DiFrame::ElevationResult(result(
                    id,
                    seq,
                    wire::ElevationResultCode::Completed,
                ))),
                Duration::from_secs(5),
                false,
            )
            .await;
            assert!(
                matches!(done.outcome, ElevationOutcome::Cancelled(_)),
                "{:?}",
                done.outcome
            );
            assert!(done.poisoned);
        }
    }

    #[tokio::test]
    async fn a_different_frame_than_the_result_cancels() {
        let (done, _) = run_exchange(
            Some(DiFrame::Hello(wire::Hello::default())),
            Duration::from_secs(5),
            false,
        )
        .await;
        assert!(matches!(done.outcome, ElevationOutcome::Cancelled(_)));
        assert!(done.poisoned);
    }

    #[tokio::test]
    async fn an_unspecified_result_cancels_without_poisoning() {
        let (done, _) = run_exchange(
            Some(DiFrame::ElevationResult(result(
                7,
                1,
                wire::ElevationResultCode::Unspecified,
            ))),
            Duration::from_secs(5),
            false,
        )
        .await;
        assert!(matches!(done.outcome, ElevationOutcome::Cancelled(_)));
        assert!(!done.poisoned);
    }

    #[tokio::test]
    async fn eof_cancels() {
        let (done, _) = run_exchange(None, Duration::from_secs(5), false).await;
        assert!(
            matches!(done.outcome, ElevationOutcome::Cancelled(_)),
            "{:?}",
            done.outcome
        );
        assert!(done.poisoned);
    }

    #[tokio::test]
    async fn silence_past_the_timeout_cancels() {
        let (done, _) = run_exchange(None, Duration::from_millis(50), true).await;
        match done.outcome {
            ElevationOutcome::Cancelled(detail) => assert!(detail.contains("no answer"), "{detail}"),
            other => panic!("expected cancelled, got {other:?}"),
        }
        assert!(done.poisoned);
    }

    #[tokio::test]
    async fn a_closed_connection_cancels_a_blocked_broker() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<BrokerCall>();
        let broker = ChannelBroker::new(3, tx);
        let handle = tokio::task::spawn_blocking(move || broker.perform(&operation()));
        // Receive the call and drop it without answering, as a dying connection
        // task would.
        let call = rx.recv().await.expect("call");
        assert_eq!(call.request.request_id, 3);
        drop(call);
        let outcome = handle.await.expect("join");
        assert!(matches!(outcome, ElevationOutcome::Cancelled(_)), "{outcome:?}");
    }
}

/// The connection-level behaviour, over a real socket and the real server loop.
///
/// These run on Linux: nothing here touches `sudo`, a terminal or macOS.
#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::devint::scope::{TokenScope, ToolScope};
    use crate::devint::testkit::{claude_code_id, connect_and_negotiate, hello_offering, FakeLifecycle, TestServer};
    use crate::devint::verb::DiVerb;
    use std::path::PathBuf;

    fn op() -> ElevatedOperation {
        ElevatedOperation {
            kind: ElevatedKind::InstallFile,
            purpose: ElevationPurpose::PlaceReviewed,
            target: PathBuf::from("/t"),
            staged: Some(PathBuf::from("/s")),
            staged_sha256: Some("ab".repeat(32)),
        }
    }
    async fn wait_for_outcomes(server: &TestServer, count: usize) -> Vec<ElevationOutcome> {
        for _ in 0..400 {
            let got = server.lifecycle().elevation_outcomes();
            if got.len() >= count {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the lifecycle never recorded {count} elevation outcome(s)");
    }

    fn denial_detail(frame: DiResponseFrame) -> String {
        match frame {
            DiResponseFrame::Denied(d) => d.message,
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_v8_apply_asks_the_client_and_continues_on_completed() {
        let server = TestServer::start(FakeLifecycle::elevating(op())).await;
        let (token, _) = server.enrol("aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[8])).await;
        client
            .send_request(DiVerb::Apply, &claude_code_id(), Some(&token), 41)
            .await;

        let DiResponseFrame::ElevationRequest(asked) = client.read().await else {
            panic!("expected an elevation request");
        };
        assert_eq!((asked.request_id, asked.sequence), (41, 1));
        assert_eq!(asked.staged_sha256.len(), 64);
        client
            .send_elevation_result(wire::ElevationResult {
                request_id: 41,
                sequence: 1,
                outcome: wire::ElevationResultCode::Completed as i32,
                detail: String::new(),
            })
            .await;

        assert!(matches!(client.read().await, DiResponseFrame::Response(_)));
        assert_eq!(wait_for_outcomes(&server, 1).await, vec![ElevationOutcome::Completed]);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn a_denied_answer_reaches_the_lifecycle_and_the_request_fails() {
        let server = TestServer::start(FakeLifecycle::elevating(op())).await;
        let (token, _) = server.enrol("aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[8])).await;
        client
            .send_request(DiVerb::Apply, &claude_code_id(), Some(&token), 5)
            .await;
        let DiResponseFrame::ElevationRequest(_) = client.read().await else {
            panic!("expected an elevation request");
        };
        client
            .send_elevation_result(wire::ElevationResult {
                request_id: 5,
                sequence: 1,
                outcome: wire::ElevationResultCode::Denied as i32,
                detail: "sudo: 3 incorrect password attempts".into(),
            })
            .await;
        let detail = denial_detail(client.read().await);
        assert!(detail.contains("Denied"), "{detail}");
        assert!(matches!(
            wait_for_outcomes(&server, 1).await[0],
            ElevationOutcome::Denied(_)
        ));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn a_client_that_disconnects_mid_request_cancels_the_operation() {
        let server = TestServer::start(FakeLifecycle::elevating(op())).await;
        let (token, _) = server.enrol("aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[8])).await;
        client
            .send_request(DiVerb::Apply, &claude_code_id(), Some(&token), 6)
            .await;
        let DiResponseFrame::ElevationRequest(_) = client.read().await else {
            panic!("expected an elevation request");
        };
        drop(client);
        assert!(matches!(
            wait_for_outcomes(&server, 1).await[0],
            ElevationOutcome::Cancelled(_)
        ));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn silence_past_the_timeout_cancels_the_operation() {
        let server =
            TestServer::start_with_elevation_timeout(FakeLifecycle::elevating(op()), Duration::from_millis(150)).await;
        let (token, _) = server.enrol("aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[8])).await;
        client
            .send_request(DiVerb::Apply, &claude_code_id(), Some(&token), 7)
            .await;
        let DiResponseFrame::ElevationRequest(_) = client.read().await else {
            panic!("expected an elevation request");
        };
        // Say nothing.
        let detail = denial_detail(client.read().await);
        assert!(detail.contains("Cancelled"), "{detail}");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn a_mismatched_answer_cancels_and_closes_the_connection() {
        let server = TestServer::start(FakeLifecycle::elevating(op())).await;
        let (token, _) = server.enrol("aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[8])).await;
        client
            .send_request(DiVerb::Apply, &claude_code_id(), Some(&token), 8)
            .await;
        let DiResponseFrame::ElevationRequest(_) = client.read().await else {
            panic!("expected an elevation request");
        };
        client
            .send_elevation_result(wire::ElevationResult {
                request_id: 8,
                sequence: 99,
                outcome: wire::ElevationResultCode::Completed as i32,
                detail: String::new(),
            })
            .await;
        let detail = denial_detail(client.read().await);
        assert!(detail.contains("Cancelled"), "{detail}");
        assert!(client.try_read().await.is_none(), "the connection must be closed");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn an_unsolicited_result_is_a_protocol_violation() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let mut client = connect_and_negotiate(&server, hello_offering(&[8])).await;
        client
            .send_elevation_result(wire::ElevationResult {
                request_id: 1,
                sequence: 1,
                outcome: wire::ElevationResultCode::Completed as i32,
                detail: String::new(),
            })
            .await;
        match client.read().await {
            DiResponseFrame::Denied(d) => assert_eq!(d.code, wire::DenyCode::ProtocolViolation as i32),
            other => panic!("expected Denied, got {other:?}"),
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn a_connection_negotiated_below_v8_is_never_sent_an_elevation_frame() {
        let server = TestServer::start(FakeLifecycle::elevating(op())).await;
        let (token, _) = server.enrol("aasm", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[7])).await;
        client
            .send_request(DiVerb::Apply, &claude_code_id(), Some(&token), 9)
            .await;
        assert!(
            matches!(client.read().await, DiResponseFrame::Response(_)),
            "a v7 peer must get its response directly"
        );
        assert!(server.lifecycle().elevation_outcomes().is_empty());
        let target = server.lifecycle().last_target().expect("apply was reached");
        assert!(target.elevation.broker.is_none());
        server.shutdown().await;
    }
}
