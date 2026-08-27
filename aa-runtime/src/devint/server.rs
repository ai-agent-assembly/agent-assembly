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
use super::lifecycle::{ApprovalInput, IntegrationLifecycle, LifecycleError, LifecycleTarget};
use super::negotiate::{self, verb_available_at};
use super::projection as project;
use super::provenance::RuntimeProvenance;
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
///
/// # `#[non_exhaustive]` (AAASM-5669)
///
/// This struct is `pub` with `pub` fields in a **published** crate, so every
/// field added to it is a source break for any out-of-crate struct literal —
/// `provenance` already was one. Marking it non-exhaustive moves that cost to
/// this commit and pays it once: from here, callers build it through
/// [`Self::new`] plus the `with_*` seams, and adding a field is additive.
/// It is not an API removal and not an ABI change; see
/// `docs/src/compatibility.md`.
#[derive(Clone)]
#[non_exhaustive]
pub struct DevIntServices {
    /// The nine lifecycle operations.
    pub lifecycle: Arc<dyn IntegrationLifecycle>,
    /// The enrolment book.
    pub tokens: TokenStore,
    /// Where auth failures and lifecycle mutations are recorded.
    pub audit: Arc<dyn DevIntAuditSink>,
    /// Which build is answering (AAASM-5628).
    ///
    /// Captured once, at construction, and shared by every connection. A field
    /// rather than a call inside the handshake so a test can serve a *different*
    /// build's identity over a real socket — the mismatch this exists to catch
    /// cannot otherwise be reproduced without two compilations.
    pub provenance: Arc<RuntimeProvenance>,
}

impl DevIntServices {
    /// Services that report the running process as their provenance.
    pub fn new(lifecycle: Arc<dyn IntegrationLifecycle>, tokens: TokenStore, audit: Arc<dyn DevIntAuditSink>) -> Self {
        Self {
            lifecycle,
            tokens,
            audit,
            provenance: Arc::new(RuntimeProvenance::detect()),
        }
    }

    /// The same services, answering with `provenance` rather than the running
    /// process's own.
    ///
    /// The seam [`Self::new`] cannot cover, and the reason it is `pub`: serving
    /// a *different* build's identity over a real socket is the only way to
    /// reproduce the mismatch the DI-API's provenance check exists to catch
    /// without producing two actual compilations of the runtime. `aa-cli`'s
    /// provenance tests are the out-of-crate caller.
    pub fn with_provenance(mut self, provenance: Arc<RuntimeProvenance>) -> Self {
        self.provenance = provenance;
        self
    }
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

    let version = match negotiate::to_wire(&negotiation, &services.provenance) {
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
            DiFrame::Request(request) => connection.serve(*request).await,
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
                &format!(
                    "reconnect negotiating DI-API v{} or newer",
                    negotiate::verb_available_since(verb)
                ),
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
                // The same target the read verbs use, vetted the same way: the
                // project a plan is executed from has to mean what the project a
                // plan was authored for meant, or comparing them proves nothing.
                let target = build_target(request)?;
                let applied = lifecycle.apply(&tool, plan_id, &target).await?;
                // The negotiated version, not this runtime's maximum: a peer is
                // sent the frame its own version promised (AAASM-5674).
                response.apply = Some(project::apply_view(&applied, self.version));
            }
            DiVerb::Status => {
                let target = build_target(request)?;
                let status = lifecycle.status(&tool, &target).await?;
                response.status = Some(project::status_view(&status));
            }
            DiVerb::Verify => {
                let target = build_target(request)?;
                let result = lifecycle.verify(&tool, &target).await?;
                response.verification = Some(project::verification_view(
                    &result,
                    &crate::devint::service::resolve_host_policy(),
                ));
            }
            DiVerb::Repair => {
                let target = build_target(request)?;
                let (report, status) = lifecycle.repair(&tool, &target).await?;
                response.repair = Some(project::repair_view(&tool, &report, &status));
            }
            DiVerb::Remove => {
                let target = build_target(request)?;
                let plan_id = request
                    .remove
                    .as_ref()
                    .map(|r| r.plan_id.as_str())
                    .filter(|p| !p.is_empty());
                let plan = lifecycle.remove(&tool, &target, plan_id).await?;
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
    request.project_root = parse_project_root(scope, &args.project_root)?;
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

/// Translate `TargetArgs` into the installation a read-or-reverse verb acts on.
///
/// The same vetting as [`build_plan_request`], through the same
/// [`parse_project_root`], so "which project" cannot come to mean one thing when
/// a plan is authored and another when it is later reported on.
///
/// An absent `target` is an unspecified one rather than a refusal: it is what a
/// pre-DI-API-6 client sends, and on a host with a single user-scope
/// installation that request is answerable. What it cannot reach is a
/// project-scope receipt — the service refuses there, because an unspecified
/// target names no project and this daemon's own directory is not a substitute.
fn build_target(request: &wire::Request) -> Result<LifecycleTarget, LifecycleError> {
    let args = request.target.clone().unwrap_or_default();
    let scope = if args.settings_scope.is_empty() {
        None
    } else {
        Some(
            project::parse_scope(&args.settings_scope).ok_or_else(|| LifecycleError::Refused {
                detail: format!("unknown settings scope {:?}", args.settings_scope),
            })?,
        )
    };
    // `parse_project_root` reads the scope only to decide whether an empty root
    // is a refusal, and for an unnamed scope it is not one — the caller has not
    // yet said they mean a project. Standing in for that with `User` here is
    // therefore a statement about emptiness, not a scope decision: the actual
    // scope stays `None` below, and the service still refuses a project-scope
    // receipt that this target cannot name.
    let empty_is_allowed = scope.unwrap_or(aa_core::integration::SettingsScope::User);
    let project_root = parse_project_root(empty_is_allowed, &args.project_root)?;
    Ok(LifecycleTarget {
        settings_scope: scope,
        project_root,
    })
}

/// Resolve `PlanArgs::project_root` for `scope`, refusing rather than defaulting.
///
/// # Why this is a refusal and not a fallback (AAASM-5913)
///
/// The obvious fallback for an absent project root is this process's own working
/// directory. This process is a daemon shared by every client on the host, spawned
/// once from whichever directory started it: that fallback wrote one caller's
/// managed keys into an unrelated repository's checked-in `.claude/settings.json`
/// and changed its mind on every daemon restart. There is no working directory
/// here that means what the caller means, so a Project-scope request that names no
/// project is refused with a message that says why.
///
/// A relative path is refused for the same reason: relative to *what* would be
/// this process's working directory again, so accepting one reintroduces the
/// defect through the back door.
///
/// # Why absolute is not enough, and what canonicalisation buys
///
/// `Path::starts_with` — which is what
/// [`IntegrationPlan::validate`](aa_core::integration::IntegrationPlan::validate)
/// uses to hold a project-scope write inside the project — compares components
/// and does not normalise anything. `/a/b/../../..` "starts with" `/a/b`, so an
/// unnormalised root turns the containment check into a formality. Every root is
/// therefore resolved through the filesystem here, once, at the boundary, and
/// what travels onward on the request is the canonical form. A symlinked project
/// root resolves to its target rather than to the name the caller used, which is
/// also what makes the path the plan discloses the path that will actually be
/// written.
///
/// Requiring the directory to already exist is part of the same argument.
/// [`write_preserving_mode`](aa_core::integration) creates missing parents, so a
/// root that does not exist yet would have the service *materialise* a directory
/// tree of the caller's choosing — a caller-named destination, which ADR 0030
/// matrix row 6 forbids. A project you are working in exists.
///
/// # The surfaces a project root may not be
///
/// A root that contains a configuration surface makes project scope an alias for
/// a different scope. The sharpest case: with `CLAUDE_CONFIG_DIR` unset,
/// `cd ~ && … --scope project` derives `$HOME/.claude/settings.json`, which is
/// byte-identical to the user-scope destination — and the containment check
/// passes trivially, because the destination was derived *from* the root it is
/// being checked against. It would then file a project-scope receipt describing
/// the user surface, leaving user-scope and project-scope `remove` contending for
/// the same bytes with different recorded prior state. `/` fails the same way for
/// every surface at once.
fn parse_project_root(
    scope: aa_core::integration::SettingsScope,
    raw: &str,
) -> Result<Option<std::path::PathBuf>, LifecycleError> {
    use aa_core::integration::SettingsScope;

    if raw.is_empty() {
        if scope == SettingsScope::Project {
            return Err(LifecycleError::Refused {
                detail: "a project-scoped plan must name the project it is for. This service is \
                         shared by every client on this host and cannot tell which project a \
                         caller means from its own working directory, so it will not guess one"
                    .to_string(),
            });
        }
        return Ok(None);
    }

    let path = std::path::PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(LifecycleError::Refused {
            detail: format!(
                "the project root {raw:?} is not absolute, and a relative path would be resolved \
                 against this service's own working directory rather than the caller's"
            ),
        });
    }
    if !path.is_dir() {
        return Err(LifecycleError::Refused {
            detail: format!(
                "the project root {raw:?} is not an existing directory. It is not created here: a \
                 service that materialised a directory a caller named would be taking its \
                 destination from the caller"
            ),
        });
    }
    let canonical = path.canonicalize().map_err(|e| LifecycleError::Refused {
        detail: format!("the project root {raw:?} could not be resolved on this host: {e}"),
    })?;
    if let Some(surface) = owned_surface_within(&canonical, &surfaces_not_owned_by_a_project()) {
        return Err(LifecycleError::Refused {
            detail: format!(
                "the project root {} contains {}, so a project-scoped write there would land on a \
                 surface that belongs to another scope and be recorded as if it did not",
                canonical.display(),
                surface.display()
            ),
        });
    }
    Ok(Some(canonical))
}

/// A configuration surface `root` would swallow, if it swallows one.
///
/// The test is containment rather than equality, and in this direction: `root` is
/// rejected when a surface lies *at or under* it. Equality alone would let `$HOME`
/// through while rejecting `$HOME/.claude`, and `$HOME` is the case that actually
/// happens — a user with a dotfiles repository checked out at their home
/// directory, running `--scope project` from it.
///
/// `surfaces` is a parameter so the rule can be tested against synthetic paths
/// instead of against the running process's own environment.
fn owned_surface_within(root: &std::path::Path, surfaces: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
    surfaces.iter().find(|surface| surface.starts_with(root)).cloned()
}

/// The directories this host keeps configuration and integration state in.
///
/// Resolved from the environment here rather than taken from an adapter's
/// `ClaudeCodePaths`, because this refusal has to hold for *every* adapter,
/// including one added later that never consults these variables. Canonicalised
/// where they exist so the comparison is against the same form the project root
/// was resolved to; a path that does not exist cannot be an alias for anything
/// and is compared as written.
///
/// The managed-settings default comes from `aa_core::dev_tool`, not
/// `aa-devtool-claude-code` — this module (`devint`) is unconditionally
/// compiled into the published `aa-runtime` crate (ADR 0030 §6.3: adapters
/// are out-of-tree-consumable, so this refusal boundary is reachable even
/// when no `aa-devtool-*` crate is compiled in), and `aa-devtool-claude-code`
/// is `publish = false` (AAASM-2340). A stripped-region default here would
/// make the refusal set adapter-dependent, contradicting the "holds for
/// *every* adapter" invariant above (AAASM-5987).
fn surfaces_not_owned_by_a_project() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;

    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let home = var("HOME");

    let claude_config = var("CLAUDE_CONFIG_DIR").or_else(|| home.as_ref().map(|h| h.join(".claude")));
    let codex_config = home.as_ref().map(|h| h.join(".codex"));
    let state = var("AASM_STATE_DIR").or_else(|| home.as_ref().map(|h| h.join(".aasm")));
    let ca = var("AA_CA_DIR").or_else(|| home.as_ref().map(|h| h.join(".aa")));
    let managed =
        var("AASM_CLAUDE_MANAGED_ROOT").unwrap_or_else(|| PathBuf::from(aa_core::dev_tool::MANAGED_SETTINGS_DIR));

    [claude_config, codex_config, state, ca, Some(managed)]
        .into_iter()
        .flatten()
        .map(|p| p.canonicalize().unwrap_or(p))
        .collect()
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

    use aa_core::integration::SettingsScope;

    /// Every adversarial project root the AAASM-5913 review put through the
    /// production logic, and what each one is an attempt at.
    ///
    /// The point of the table is that before canonicalisation *all* of these were
    /// accepted and *all* of them then passed the containment check in
    /// `IntegrationPlan::validate`, because the destination is derived from the
    /// root it is checked against. A containment check with no reachable trigger
    /// is not a check.
    #[test]
    fn a_project_root_that_is_not_a_project_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("repo");
        std::fs::create_dir_all(&real).unwrap();
        let file = dir.path().join("a-file");
        std::fs::write(&file, "not a directory").unwrap();

        for (raw, why) in [
            ("", "an unnamed project at project scope"),
            ("relative/path", "a path resolved against this service's directory"),
            (
                dir.path().join("nope").to_str().unwrap(),
                "a directory the service would have had to create",
            ),
            (file.to_str().unwrap(), "a file standing in for a directory"),
        ] {
            let refusal = parse_project_root(SettingsScope::Project, raw).expect_err(why);
            assert!(
                matches!(refusal, LifecycleError::Refused { .. }),
                "{why}: {raw:?} produced {refusal:?}"
            );
        }

        // The positive control, so the refusals above are not vacuous.
        let accepted = parse_project_root(SettingsScope::Project, real.to_str().unwrap())
            .expect("a real directory is a usable project root")
            .expect("project scope resolves a root");
        assert_eq!(accepted, real.canonicalize().unwrap());
    }

    /// `..` is why absolute is not the same claim as normalised.
    #[test]
    fn a_project_root_is_normalised_before_anything_is_derived_from_it() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join("nested")).unwrap();

        let traversal = repo.join("nested").join("..");
        let resolved = parse_project_root(SettingsScope::Project, traversal.to_str().unwrap())
            .expect("the path resolves")
            .expect("project scope resolves a root");

        assert_eq!(resolved, repo.canonicalize().unwrap());
        // `Path::starts_with` is component-wise: unnormalised, this "starts with"
        // the nested directory it actually escapes.
        assert!(traversal.starts_with(repo.join("nested")));
        assert!(!resolved.starts_with(repo.join("nested")));
    }

    #[test]
    fn a_project_root_holding_another_scopes_surface_is_refused() {
        let home = std::path::PathBuf::from("/synthetic/home");
        let surfaces = vec![
            home.join(".claude"),
            home.join(".aasm"),
            std::path::PathBuf::from(aa_core::dev_tool::MANAGED_SETTINGS_DIR),
        ];

        // `$HOME` itself: `--scope project` from a dotfiles repository checked out
        // at the home directory derives the *user*-scope settings file, and then
        // files a project receipt describing it.
        assert_eq!(
            owned_surface_within(&home, &surfaces),
            Some(home.join(".claude")),
            "a root containing the user surface must be refused"
        );
        // `/` swallows every surface at once.
        assert!(owned_surface_within(std::path::Path::new("/"), &surfaces).is_some());
        // The managed surface's own parent is no better than the managed surface.
        assert!(owned_surface_within(std::path::Path::new("/Library"), &surfaces).is_some());
        // An ordinary project holds none of them.
        assert!(owned_surface_within(&home.join("code").join("repo"), &surfaces).is_none());
        // Nor does a sibling that merely shares a prefix with one.
        assert!(owned_surface_within(&home.join(".claude-notes"), &surfaces).is_none());
    }

    #[test]
    fn a_root_is_only_required_where_a_destination_is_derived_from_it() {
        // User and managed scope use the root for disclosure only, so not knowing
        // it costs a warning rather than correctness.
        for scope in [SettingsScope::User, SettingsScope::Managed] {
            assert_eq!(parse_project_root(scope, "").expect("optional here"), None);
        }
    }

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
