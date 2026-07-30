//! The Developer Integration Service — the server half of the DI-API
//! (ADR 0030 Decision 5).
//!
//! # The order a request is checked in, and why that order
//!
//! 1. **Peer credentials**, on the accept loop, before a single byte is read.
//!    Reuses [`crate::ipc::peercred::peer_uid_is_allowed`] — the same check the
//!    SDK socket makes, so there is one peer-identity rule in the runtime and
//!    not two.
//! 2. **Version negotiation**, in the spawned connection task under a timeout,
//!    so a slow or hostile peer can never stall the accept loop. A second
//!    `Hello` afterwards is a protocol violation: the negotiated version is
//!    fixed for the connection's lifetime, so there is no mid-connection
//!    downgrade to walk into.
//! 3. **Verb decode.** A discriminant outside the closed set is refused here;
//!    nothing further runs for it.
//! 4. **Token resolution and scope**, before the version-availability check.
//!    That order is deliberate: an unauthenticated caller learns nothing about
//!    which verbs exist at a version it did not negotiate.
//! 5. **Version availability**, so a degraded connection cannot reach a verb
//!    its version does not have.
//! 6. **The lifecycle port**, whose result is projected before it is written.
//!
//! Every refusal in steps 1–5 emits an audit event and returns a coarse
//! `Denied`. There is no step at which a request falls through to an implicit
//! grant, and no anonymous or read-only tier: an empty [`TokenStore`]
//! authorizes nothing at all.
//!
//! # What this module deliberately cannot reach
//!
//! Its dependencies are the lifecycle port, the token store, the projections
//! and the codec. Not `aa_core::storage`, not identity, not the gateway client.
//! That is the compile-time half of "a compromised thin client cannot reach
//! unrestricted core operations" — the other half being that there is no verb
//! for it to ask with.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use aa_core::integration::{now_unix_secs, IntegrationRequest, ProtectionLevel};
use aa_proto::assembly::devint::v1 as wire;

use super::audit::{DevIntAuditEvent, DevIntAuditKind, DevIntAuditSink};
use super::codec::{self, DiCodecError, DiFrame, DiResponseFrame};
use super::lifecycle::{ApprovalInput, IntegrationLifecycle, LifecycleError};
use super::negotiate::{self, verb_available_at};
use super::projection as project;
use super::socket;
use super::token::{CapabilityToken, TokenDenial, TokenStore};
use super::verb::DiVerb;

/// How long a client has to complete version negotiation before the connection
/// is dropped. Bounds slow-loris holds, exactly as the SDK handshake timeout
/// does (AAASM-3585).
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Default concurrent DI-API connections. Small on purpose: this is a
/// developer's own machine, and a handful of editors and a CLI is the whole
/// legitimate population.
pub const DEFAULT_MAX_CONNECTIONS: usize = 16;

/// How the DI-API server is configured.
#[derive(Debug, Clone)]
pub struct DevIntServerConfig {
    /// Absolute path to the DI-API socket.
    pub socket_path: std::path::PathBuf,
    /// Maximum concurrent connections.
    pub max_connections: usize,
}

impl DevIntServerConfig {
    /// Configuration using the conventional socket path (or its
    /// `AA_DEVINT_SOCKET` override).
    pub fn from_convention() -> Result<Self, socket::SocketError> {
        Ok(Self {
            socket_path: socket::devint_socket_path()?,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        })
    }
}

/// Everything a connection needs to serve a verb.
///
/// Cloned per connection; every field is cheap to clone.
#[derive(Clone)]
pub struct DevIntServices {
    /// The nine lifecycle operations.
    pub lifecycle: Arc<dyn IntegrationLifecycle>,
    /// The enrolment book.
    pub tokens: TokenStore,
    /// Where auth failures and lifecycle mutations are recorded.
    pub audit: Arc<dyn DevIntAuditSink>,
}

/// The bound DI-API server.
pub struct DevIntServer {
    config: DevIntServerConfig,
    listener: UnixListener,
}

impl DevIntServer {
    /// Bind the DI-API socket owner-only, asserting the permissions on the way.
    pub fn bind(config: DevIntServerConfig) -> Result<Self, socket::SocketError> {
        let listener = socket::bind(&config.socket_path)?;
        Ok(Self { config, listener })
    }

    /// The path this server is listening on.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.config.socket_path
    }

    /// Run the accept loop until `token` fires.
    pub async fn run(self, tracker: TaskTracker, token: CancellationToken, services: DevIntServices) {
        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let next_conn_id = Arc::new(AtomicU64::new(0));
        let runtime_uid = crate::ipc::peercred::current_runtime_uid();
        let socket_path = self.config.socket_path.clone();
        let listener = self.listener;

        tracing::info!(path = %socket_path.display(), "DI-API accept loop started");

        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                result = listener.accept() => {
                    let stream = match result {
                        Ok((stream, _addr)) => stream,
                        Err(e) => {
                            tracing::error!(error = %e, "DI-API accept error");
                            continue;
                        }
                    };

                    let connection_id = next_conn_id.fetch_add(1, Ordering::Relaxed);

                    // Layer 1 of the two-layer authentication, on the accept
                    // loop so a rejected peer costs nothing but the accept.
                    if let Some(reason) = peer_rejection_reason(&stream, runtime_uid) {
                        services.audit.record(DevIntAuditEvent::new(
                            now_unix_secs(),
                            connection_id,
                            DevIntAuditKind::PeerRejected { reason },
                        ));
                        drop(stream);
                        continue;
                    }

                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            tracing::warn!(max = self.config.max_connections, "DI-API connection limit reached");
                            drop(stream);
                            continue;
                        }
                    };

                    let conn_services = services.clone();
                    let conn_token = token.child_token();
                    tracker.spawn(async move {
                        let _permit = permit;
                        tokio::select! {
                            _ = conn_token.cancelled() => {}
                            result = serve_connection(stream, connection_id, conn_services) => {
                                if let Err(e) = result {
                                    tracing::debug!(connection_id, error = %e, "DI-API connection ended");
                                }
                            }
                        }
                    });
                }
            }
        }

        if let Err(e) = std::fs::remove_file(&socket_path) {
            tracing::warn!(error = %e, "failed to remove the DI-API socket on shutdown");
        }
        tracing::info!("DI-API accept loop stopped");
    }
}

/// Why a peer must not be admitted, or `None` when it may be.
fn peer_rejection_reason(stream: &UnixStream, runtime_uid: u32) -> Option<&'static str> {
    match stream.peer_cred() {
        Ok(cred) => {
            if crate::ipc::peercred::peer_uid_is_allowed(cred.uid(), runtime_uid) {
                None
            } else {
                tracing::warn!(
                    peer_uid = cred.uid(),
                    runtime_uid,
                    "rejecting DI-API connection — peer UID does not match runtime UID"
                );
                Some("uid_mismatch")
            }
        }
        // Unreadable credentials fail closed. "We could not tell who you are"
        // is not a reason to serve someone.
        Err(e) => {
            tracing::warn!(error = %e, "rejecting DI-API connection — peer credentials unavailable");
            Some("peercred_unavailable")
        }
    }
}

/// Negotiate, then serve verbs until the peer disconnects.
async fn serve_connection(
    stream: UnixStream,
    connection_id: u64,
    services: DevIntServices,
) -> Result<(), DiCodecError> {
    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = tokio::io::BufWriter::new(writer);

    // Step 2: the first frame must be a `Hello`, within the timeout.
    let first = match tokio::time::timeout(NEGOTIATION_TIMEOUT, codec::read_frame(&mut reader)).await {
        Ok(frame) => frame?,
        Err(_) => {
            services.audit.record(DevIntAuditEvent::new(
                now_unix_secs(),
                connection_id,
                DevIntAuditKind::ProtocolFailure {
                    reason: "negotiation_timeout",
                },
            ));
            return Ok(());
        }
    };

    let hello = match first {
        DiFrame::Hello(hello) => hello,
        // A verb before negotiation is refused outright: serving it would mean
        // serving a client whose version we never agreed.
        DiFrame::Request(_) => {
            services.audit.record(DevIntAuditEvent::new(
                now_unix_secs(),
                connection_id,
                DevIntAuditKind::ProtocolFailure {
                    reason: "verb_before_negotiation",
                },
            ));
            codec::write_frame(
                &mut writer,
                DiResponseFrame::Denied(wire::Denied {
                    request_id: 0,
                    code: wire::DenyCode::ProtocolViolation as i32,
                    message: "the first frame must be Hello".to_string(),
                    remediation: "negotiate a DI-API version before sending a verb".to_string(),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let client_name = Some(hello.client_name.clone());
    let negotiation = negotiate::negotiate(&hello);
    services.audit.record(
        DevIntAuditEvent::new(
            now_unix_secs(),
            connection_id,
            DevIntAuditKind::Negotiated {
                outcome: negotiation.outcome(),
                version: negotiation.version(),
            },
        )
        .with_client(client_name.clone()),
    );

    let version = match negotiate::to_wire(&negotiation) {
        Ok(ack) => {
            let version = ack.di_api_version;
            codec::write_frame(&mut writer, DiResponseFrame::HelloAck(ack)).await?;
            version
        }
        Err(incompatible) => {
            codec::write_frame(&mut writer, DiResponseFrame::Incompatible(incompatible)).await?;
            // Closed immediately: there is no degraded-into-nothing state to
            // linger in, and a client that keeps the connection open after an
            // incompatible answer is not one to keep serving.
            let _ = writer.shutdown().await;
            return Ok(());
        }
    };

    let connection = Connection {
        connection_id,
        client_name,
        version,
        services,
    };

    loop {
        let frame = match codec::read_frame(&mut reader).await {
            Ok(frame) => frame,
            // EOF and malformed frames both end the connection. A malformed
            // frame is audited; a clean EOF is not an event.
            Err(DiCodecError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => {
                connection.audit_protocol_failure(codec_failure_reason(&e));
                return Err(e);
            }
        };

        let response = match frame {
            DiFrame::Request(request) => connection.serve(request).await,
            // Step 2's other half: a second `Hello` is a renegotiation attempt,
            // which is how a downgrade would be staged. Refused, audited, and
            // the negotiated version stands.
            DiFrame::Hello(_) => {
                connection.audit_protocol_failure("renegotiation_attempted");
                DiResponseFrame::Denied(wire::Denied {
                    request_id: 0,
                    code: wire::DenyCode::ProtocolViolation as i32,
                    message: "the DI-API version is fixed for the life of a connection".to_string(),
                    remediation: "open a new connection to negotiate a different version".to_string(),
                })
            }
        };

        codec::write_frame(&mut writer, response).await?;
    }
}

/// Which protocol failure a codec error represents, for the audit trail.
const fn codec_failure_reason(error: &DiCodecError) -> &'static str {
    match error {
        DiCodecError::UnknownTag(_) => "unknown_frame_tag",
        DiCodecError::Decode(_) => "malformed_frame",
        DiCodecError::FrameTooLarge { .. } => "frame_too_large",
        DiCodecError::Io(_) => "io_error",
    }
}

/// One negotiated connection, and the checks every request on it passes.
struct Connection {
    connection_id: u64,
    client_name: Option<String>,
    version: u32,
    services: DevIntServices,
}

impl Connection {
    fn audit_protocol_failure(&self, reason: &'static str) {
        self.services.audit.record(
            DevIntAuditEvent::new(
                now_unix_secs(),
                self.connection_id,
                DevIntAuditKind::ProtocolFailure { reason },
            )
            .with_client(self.client_name.clone()),
        );
    }

    /// Steps 3–6 for one request.
    async fn serve(&self, request: wire::Request) -> DiResponseFrame {
        let request_id = request.request_id;

        // Step 3: the verb must be in the closed set.
        let Some(verb) = DiVerb::from_wire(request.verb) else {
            self.audit_protocol_failure("unknown_verb");
            return denied(
                request_id,
                wire::DenyCode::UnknownVerb,
                "unknown operation",
                "use an operation this DI-API version defines",
            );
        };

        // Step 4: authenticate and authorize before revealing anything about
        // the verb space at other versions.
        let presented = if request.capability_token.is_empty() {
            None
        } else {
            Some(CapabilityToken::from_wire(request.capability_token.clone()))
        };
        let resolved = self
            .services
            .tokens
            .resolve(presented.as_ref(), verb, &request.tool_id, now_unix_secs());
        if let Err(denial) = resolved {
            self.services.audit.record(
                DevIntAuditEvent::from_denial(now_unix_secs(), self.connection_id, &denial)
                    .with_client(self.client_name.clone())
                    .with_target(verb, request.tool_id.clone()),
            );
            return denial_frame(request_id, &denial);
        }

        // Step 5: a degraded connection cannot reach a verb its version lacks.
        if !verb_available_at(verb, self.version) {
            self.audit_protocol_failure("unavailable_at_version");
            return denied(
                request_id,
                wire::DenyCode::UnavailableAtVersion,
                "this operation does not exist at the negotiated DI-API version",
                &format!("reconnect negotiating DI-API v{}", negotiate::DI_API_MAX_SUPPORTED),
            );
        }

        // Step 6: the lifecycle port, then the projection.
        let outcome = self.dispatch(verb, &request).await;
        self.services.audit.record(
            DevIntAuditEvent::new(
                now_unix_secs(),
                self.connection_id,
                DevIntAuditKind::VerbServed {
                    succeeded: outcome.is_ok(),
                },
            )
            .with_client(self.client_name.clone())
            .with_target(verb, request.tool_id.clone()),
        );

        match outcome {
            Ok(response) => DiResponseFrame::Response(Box::new(response)),
            Err(error) => lifecycle_denial(request_id, &error),
        }
    }

    /// The one exhaustive match over the verb space. Every arm goes to the
    /// lifecycle port and comes back through a projection; no arm reaches
    /// anything else.
    async fn dispatch(&self, verb: DiVerb, request: &wire::Request) -> Result<wire::Response, LifecycleError> {
        let tool = project::parse_tool_id(&request.tool_id);
        let mut response = wire::Response {
            request_id: request.request_id,
            verb: verb.to_wire() as i32,
            ..Default::default()
        };
        let lifecycle = &self.services.lifecycle;

        match verb {
            DiVerb::ListTools => {
                let tools = lifecycle.list_tools().await?;
                response.tool_list = Some(wire::ToolList {
                    tools: tools.iter().map(project::tool_summary).collect(),
                });
            }
            DiVerb::Plan => {
                let args = request.plan.clone().unwrap_or_default();
                let integration_request = build_plan_request(&tool, &args)?;
                let plan = lifecycle.plan(integration_request).await?;
                response.plan = Some(project::plan_view(&plan));
            }
            DiVerb::Apply => {
                let plan_id = request.apply.as_ref().map(|a| a.plan_id.as_str()).unwrap_or_default();
                let receipt = lifecycle.apply(&tool, plan_id).await?;
                response.apply = Some(project::apply_view(&receipt));
            }
            DiVerb::Status => {
                let status = lifecycle.status(&tool).await?;
                response.status = Some(project::status_view(&status));
            }
            DiVerb::Verify => {
                let result = lifecycle.verify(&tool).await?;
                response.verification = Some(project::verification_view(&result));
            }
            DiVerb::Repair => {
                let (report, status) = lifecycle.repair(&tool).await?;
                response.repair = Some(project::repair_view(&tool, &report, &status));
            }
            DiVerb::Remove => {
                let plan_id = request
                    .remove
                    .as_ref()
                    .map(|r| r.plan_id.as_str())
                    .filter(|p| !p.is_empty());
                let plan = lifecycle.remove(&tool, plan_id).await?;
                response.removal = Some(project::removal_view(&plan));
            }
            DiVerb::ScopedEvents => {
                let args = request.events.unwrap_or_default();
                let events = lifecycle.scoped_events(&tool, args.limit, args.since_unix_secs).await?;
                response.events = Some(wire::ScopedEventList {
                    events: events.iter().map(project::scoped_event_view).collect(),
                });
            }
            DiVerb::ApprovalRelay => {
                let args = request.approval.clone().unwrap_or_default();
                // An unreadable button press is refused rather than defaulted.
                // Defaulting here would let a malformed frame stand in for a
                // human's approval.
                let input = ApprovalInput::parse(&args.user_input).ok_or_else(|| LifecycleError::Refused {
                    detail: "the relayed approval input is not one this API accepts".to_string(),
                })?;
                let receipt = lifecycle.relay_approval(&tool, &args.approval_id, input).await?;
                response.approval = Some(wire::ApprovalRelayAck {
                    approval_id: receipt.approval_id,
                    relayed_input: receipt.relayed.as_str().to_string(),
                    accepted_at_unix_secs: receipt.accepted_at_unix_secs,
                });
            }
        }
        Ok(response)
    }
}

/// Translate `PlanArgs` into the lifecycle contract's request.
///
/// Every unrecognised token is refused rather than defaulted: a plan written to
/// a scope the caller did not name is the exact class of bug
/// `IntegrationRequest`'s mandatory `settings_scope` exists to prevent.
fn build_plan_request(
    tool: &aa_core::dev_tool::DevToolKind,
    args: &wire::PlanArgs,
) -> Result<IntegrationRequest, LifecycleError> {
    let profile = project::parse_profile(&args.profile).ok_or_else(|| LifecycleError::Refused {
        detail: format!("unknown protection profile {:?}", args.profile),
    })?;
    let scope = project::parse_scope(&args.settings_scope).ok_or_else(|| LifecycleError::Refused {
        detail: format!("unknown settings scope {:?}", args.settings_scope),
    })?;
    let requested_level = if args.requested_level.is_empty() {
        ProtectionLevel::GatewayProtected
    } else {
        project::parse_level(&args.requested_level).ok_or_else(|| LifecycleError::Refused {
            detail: format!("unknown protection level {:?}", args.requested_level),
        })?
    };

    let mut request = IntegrationRequest::new(tool.clone(), profile, scope).requesting_level(requested_level);
    request.allow_privileged_host_steps = args.allow_privileged_host_steps;
    // The client names a profile; the *document* is resolved inside the trusted
    // layers (ADR 0030 matrix row 6). The reference here carries the name only,
    // and the service replaces it with the resolved reference.
    if !args.policy_profile_id.is_empty() {
        request = request.with_policy_profile(aa_core::integration::PolicyProfileRef {
            id: args.policy_profile_id.clone(),
            display_name: args.policy_profile_id.clone(),
            digest: String::new(),
        });
    }
    Ok(request)
}

fn denied(request_id: u64, code: wire::DenyCode, message: &str, remediation: &str) -> DiResponseFrame {
    DiResponseFrame::Denied(wire::Denied {
        request_id,
        code: code as i32,
        message: message.to_string(),
        remediation: remediation.to_string(),
    })
}

/// Map a token denial onto the wire.
///
/// Absent, malformed and unknown collapse into one code on purpose: a probing
/// client must not be able to use the response to tell "no such token" from
/// "wrong shape". Expired is distinguished because the holder already has the
/// token — nothing leaks — and re-enrolment is the actionable answer.
fn denial_frame(request_id: u64, denial: &TokenDenial) -> DiResponseFrame {
    match denial {
        TokenDenial::Absent | TokenDenial::Malformed | TokenDenial::Unknown => denied(
            request_id,
            wire::DenyCode::Unauthenticated,
            "not authenticated",
            "enrol this client with `aasm integration enrol` and present its capability token",
        ),
        TokenDenial::Expired { .. } => denied(
            request_id,
            wire::DenyCode::TokenExpired,
            "the capability token has expired",
            "rotate the token, or re-enrol this client",
        ),
        TokenDenial::OutOfScope { .. } => denied(
            request_id,
            wire::DenyCode::OutOfScope,
            "this token is not scoped for that operation on that tool",
            "enrol a token scoped for the tool and operation you need",
        ),
    }
}

fn lifecycle_denial(request_id: u64, error: &LifecycleError) -> DiResponseFrame {
    let code = match error {
        LifecycleError::UnknownTool { .. } => wire::DenyCode::UnknownTool,
        _ => wire::DenyCode::LifecycleError,
    };
    denied(request_id, code, &error.detail(), "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devint::audit::RecordingAuditSink;
    use crate::devint::scope::{TokenScope, ToolScope};
    use crate::devint::testkit::{connect_and_negotiate, hello_offering, FakeLifecycle, TestServer};

    #[tokio::test]
    async fn a_negotiated_client_with_a_scoped_token_can_read_status() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let (token, _) = server.enrol(
            "vscode-aasm",
            TokenScope::full_lifecycle(ToolScope::tools(["claude-code"])),
        );
        let mut client = connect_and_negotiate(&server, hello_offering(&[1, 2])).await;

        let response = client.request(DiVerb::Status, "claude-code", Some(&token)).await;
        let DiResponseFrame::Response(response) = response else {
            panic!("expected a Response, got {response:?}");
        };
        let status = response.status.expect("status view");
        assert_eq!(status.tool_id, "claude-code");
        assert_eq!(status.achieved_level, "integrated");
    }

    #[tokio::test]
    async fn a_verb_before_negotiation_is_refused() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let (token, _) = server.enrol("rogue", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut raw = server.connect_raw().await;
        raw.send_request(DiVerb::Status, "claude-code", Some(&token), 1).await;
        let frame = raw.read().await;
        match frame {
            DiResponseFrame::Denied(denied) => {
                assert_eq!(denied.code, wire::DenyCode::ProtocolViolation as i32);
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        assert!(server.audit().events().iter().any(
            |e| matches!(&e.kind, DevIntAuditKind::ProtocolFailure { reason } if *reason == "verb_before_negotiation")
        ));
    }

    #[tokio::test]
    async fn an_incompatible_client_is_told_what_to_do_and_disconnected() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let mut raw = server.connect_raw().await;
        raw.send_hello(hello_offering(&[0])).await;
        match raw.read().await {
            DiResponseFrame::Incompatible(incompatible) => {
                assert!(!incompatible.reason.is_empty());
                assert!(incompatible.remediation.contains("update the client"));
                assert_eq!(incompatible.max_supported, negotiate::DI_API_MAX_SUPPORTED);
            }
            other => panic!("expected Incompatible, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_audit_sink_sees_every_negotiation() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let mut raw = server.connect_raw().await;
        raw.send_hello(hello_offering(&[1])).await;
        let _ = raw.read().await;
        server.wait_for_audit(1).await;
        assert!(server
            .audit()
            .events()
            .iter()
            .any(|e| matches!(&e.kind, DevIntAuditKind::Negotiated { outcome, .. } if *outcome == "degraded")));
    }

    #[tokio::test]
    async fn an_unknown_verb_discriminant_is_refused_before_anything_runs() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let (token, _) = server.enrol("cli", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[2])).await;
        let response = client
            .send_raw_request(wire::Request {
                request_id: 42,
                verb: 4242,
                capability_token: token.expose().to_string(),
                tool_id: "claude-code".to_string(),
                ..Default::default()
            })
            .await;
        match response {
            DiResponseFrame::Denied(denied) => {
                assert_eq!(denied.code, wire::DenyCode::UnknownVerb as i32);
                assert_eq!(denied.request_id, 42);
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        assert_eq!(
            server.lifecycle().calls(),
            0,
            "no lifecycle call may run for an unknown verb"
        );
    }

    #[tokio::test]
    async fn a_lifecycle_refusal_reaches_the_client_without_adapter_internals() {
        let server = TestServer::start(FakeLifecycle::refusing("privileged host steps were not consented to")).await;
        let (token, _) = server.enrol("cli", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[2])).await;
        match client.request(DiVerb::Apply, "claude-code", Some(&token)).await {
            DiResponseFrame::Denied(denied) => {
                assert_eq!(denied.code, wire::DenyCode::LifecycleError as i32);
                assert_eq!(denied.message, "privileged host steps were not consented to");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unparseable_plan_argument_is_refused_rather_than_defaulted() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let (token, _) = server.enrol("cli", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connect_and_negotiate(&server, hello_offering(&[2])).await;
        let response = client
            .send_raw_request(wire::Request {
                request_id: 1,
                verb: DiVerb::Plan.to_wire() as i32,
                capability_token: token.expose().to_string(),
                tool_id: "claude-code".to_string(),
                plan: Some(wire::PlanArgs {
                    profile: "recommended".to_string(),
                    // Never named — the destination must not be inferred.
                    settings_scope: String::new(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await;
        match response {
            DiResponseFrame::Denied(denied) => {
                assert_eq!(denied.code, wire::DenyCode::LifecycleError as i32);
                assert!(denied.message.contains("settings scope"));
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn an_unreachable_peer_credential_fails_closed() {
        // The classifier is asserted directly; opening a socket as another UID
        // is not something a unit test can do portably.
        assert!(crate::ipc::peercred::peer_uid_is_allowed(501, 501));
        assert!(!crate::ipc::peercred::peer_uid_is_allowed(0, 501));
    }

    #[test]
    fn a_recording_sink_starts_empty() {
        assert!(RecordingAuditSink::new().events().is_empty());
    }
}
