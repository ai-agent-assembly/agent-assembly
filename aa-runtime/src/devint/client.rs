//! A minimal reference DI-API client for thin integration shells.
//!
//! # What this is for
//!
//! AAASM-5279 requires "a generated/reference client available for thin
//! integration shells". This is that reference: the smallest correct client,
//! written so an extension author (or AAASM-5282's real client) can read it
//! and see exactly what a well-behaved client does, in order:
//!
//! 1. **Discover** the socket, and treat its absence as *the runtime is not
//!    running* — a bootstrap prompt, not a retry loop ([`DevIntClient::discover`]).
//! 2. **Negotiate** before anything else, and *surface* a degraded outcome
//!    rather than swallowing it ([`DevIntClient::connect`]).
//! 3. **Present a capability token on every request.** There is no anonymous
//!    tier to fall back to, so a client with no token has nothing to do but
//!    tell the user to enrol.
//! 4. **Render what the service computed.** Never derive a protection state
//!    locally — a locally derived state is a claim wearing a measurement's
//!    clothes (ADR 0030 forbidden design 10), which is why this client returns
//!    the service's [`wire::StatusView`] verbatim and offers no way to compute
//!    one.
//!
//! It is deliberately thin: no retries, no caching, no background reconnect,
//! no state machine beyond "negotiated or not". AAASM-5282 builds the real
//! client; this one exists so that work starts from a correct skeleton and so
//! the server has an independent consumer in its tests.

use std::path::{Path, PathBuf};

use tokio::io::{BufReader, BufWriter};
use tokio::net::UnixStream;

use aa_proto::assembly::devint::v1 as wire;

use super::codec::{self, DiCodecError, DiFrame, DiResponseFrame};
use super::negotiate::{DI_API_MAX_SUPPORTED, DI_API_MIN_SUPPORTED};
use super::provenance::{self, BuildIdentity, PeerProvenance, ProvenanceVerdict};
use super::socket::{self, SocketDiscovery};
use super::verb::DiVerb;
use aa_core::integration::LIFECYCLE_SCHEMA_VERSION;

/// Why a client call did not produce a response.
#[derive(Debug)]
pub enum ClientError {
    /// The socket is not there. The runtime is not running: prompt the user to
    /// start it, do not retry silently.
    RuntimeNotRunning {
        /// Where the client looked.
        path: PathBuf,
    },
    /// The socket path could not be resolved at all.
    Discovery(socket::SocketError),
    /// Connecting or framing failed.
    Transport(DiCodecError),
    /// The server refused the version. Carries the actionable remediation.
    Incompatible(wire::Incompatible),
    /// The server refused the request.
    Denied(wire::Denied),
    /// The server answered something this client did not ask for.
    UnexpectedFrame,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::RuntimeNotRunning { path } => write!(
                f,
                "the AASM runtime is not running (no socket at {}); start it and try again",
                path.display()
            ),
            ClientError::Discovery(e) => write!(f, "cannot locate the DI-API socket: {e}"),
            ClientError::Transport(e) => write!(f, "DI-API transport error: {e}"),
            ClientError::Incompatible(i) => write!(f, "{} — {}", i.reason, i.remediation),
            ClientError::Denied(d) => write!(f, "{} — {}", d.message, d.remediation),
            ClientError::UnexpectedFrame => f.write_str("the DI-API server sent an unexpected frame"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<DiCodecError> for ClientError {
    fn from(e: DiCodecError) -> Self {
        ClientError::Transport(e)
    }
}

/// What the server said about this connection's version.
///
/// `Degraded` is returned to the caller rather than absorbed, because a client
/// that silently proceeds on a degraded connection will show a user a feature
/// that is not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The agreed DI-API version.
    pub di_api_version: u32,
    /// The running core version.
    pub core_version: String,
    /// Whether some verbs are missing.
    pub degraded: bool,
    /// Which verbs are missing, when degraded.
    pub unavailable_verbs: Vec<String>,
    /// Why, and what to do, when degraded.
    pub degraded_reason: String,
    /// What to do about it.
    pub remediation: String,
    /// Which build answered, when the peer was new enough to say (AAASM-5628).
    ///
    /// `None` means the peer predates
    /// [`DI_API_PROVENANCE_SINCE`](super::negotiate::DI_API_PROVENANCE_SINCE)
    /// — *not* that it has no identity. Reading the first as the second is how
    /// an unattributable answer gets recorded as an attributable one.
    pub provenance: Option<PeerProvenance>,
}

impl Negotiated {
    /// Build a negotiated view from the `HelloAck` the server sent.
    pub fn from_ack(ack: wire::HelloAck) -> Self {
        Self {
            di_api_version: ack.di_api_version,
            core_version: ack.core_version,
            degraded: ack.outcome == wire::NegotiationOutcome::Degraded as i32,
            unavailable_verbs: ack.unavailable_verbs,
            degraded_reason: ack.degraded_reason,
            remediation: ack.remediation,
            provenance: ack.provenance.as_ref().map(PeerProvenance::from_wire),
        }
    }

    /// Whether `verb` is usable on this connection.
    ///
    /// A client should call this before offering the corresponding UI, instead
    /// of discovering the gap when a user presses the button.
    pub fn supports(&self, verb: DiVerb) -> bool {
        !self.unavailable_verbs.iter().any(|v| v == verb.as_str())
    }

    /// Whether the runtime that answered is the build this client belongs to.
    ///
    /// Compared against [`BuildIdentity::of_this_build`], which both halves read
    /// from the same compiled `aa-runtime`: equal values mean "compiled
    /// together", which is the only claim worth making here. Port reachability
    /// is never sufficient — the socket was reachable in both of AAASM-5628's
    /// reproductions.
    pub fn provenance_verdict(&self) -> ProvenanceVerdict {
        self.verify_against(&BuildIdentity::of_this_build())
    }

    /// [`Self::provenance_verdict`] against an explicit expected identity.
    pub fn verify_against(&self, expected: &BuildIdentity) -> ProvenanceVerdict {
        provenance::verify(self.provenance.as_ref(), expected, self.di_api_version)
    }
}

/// A connected, negotiated DI-API client.
pub struct DevIntClient {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: BufWriter<tokio::net::unix::OwnedWriteHalf>,
    negotiated: Negotiated,
    token: Option<String>,
    next_request_id: u64,
}

impl DevIntClient {
    /// Look for a running runtime without connecting.
    pub fn discover() -> Result<SocketDiscovery, ClientError> {
        let path = socket::devint_socket_path().map_err(ClientError::Discovery)?;
        Ok(socket::discover(&path))
    }

    /// Connect to `path` and negotiate.
    ///
    /// `capability_token` is the secret written by the enrolment step. It is
    /// `Option` because a client may legitimately connect with none — to read
    /// the negotiated versions and then tell the user to enrol — but every verb
    /// will be denied until one is supplied.
    pub async fn connect(
        path: &Path,
        client_name: &str,
        client_version: &str,
        capability_token: Option<String>,
    ) -> Result<Self, ClientError> {
        Self::connect_offering(
            path,
            client_name,
            client_version,
            capability_token,
            // Offer the whole window this build understands. Offering a
            // narrower set than the client implements is how a client talks
            // itself into a degraded connection for no reason.
            (DI_API_MIN_SUPPORTED..=DI_API_MAX_SUPPORTED).collect(),
        )
        .await
    }

    /// [`Self::connect`] with an explicit offered version window.
    ///
    /// A test seam, not a supported configuration: the only reason to offer
    /// less than this build implements is to *be* an older peer, which is
    /// exactly what the version-contract suite needs and what no shipped client
    /// should ever do. Behind `test-fixtures` so it cannot be reached from a
    /// release build.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn connect_offering(
        path: &Path,
        client_name: &str,
        client_version: &str,
        capability_token: Option<String>,
        di_api_versions: Vec<u32>,
    ) -> Result<Self, ClientError> {
        Self::connect_inner(path, client_name, client_version, capability_token, di_api_versions).await
    }

    #[cfg(not(any(test, feature = "test-fixtures")))]
    async fn connect_offering(
        path: &Path,
        client_name: &str,
        client_version: &str,
        capability_token: Option<String>,
        di_api_versions: Vec<u32>,
    ) -> Result<Self, ClientError> {
        Self::connect_inner(path, client_name, client_version, capability_token, di_api_versions).await
    }

    async fn connect_inner(
        path: &Path,
        client_name: &str,
        client_version: &str,
        capability_token: Option<String>,
        di_api_versions: Vec<u32>,
    ) -> Result<Self, ClientError> {
        if !path.exists() {
            return Err(ClientError::RuntimeNotRunning {
                path: path.to_path_buf(),
            });
        }
        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| ClientError::Transport(DiCodecError::Io(e)))?;
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        codec::write_client_frame(
            &mut writer,
            DiFrame::Hello(wire::Hello {
                client_name: client_name.to_string(),
                client_version: client_version.to_string(),
                di_api_versions,
                lifecycle_schema_versions: vec![LIFECYCLE_SCHEMA_VERSION],
            }),
        )
        .await?;

        let negotiated = match codec::read_response_frame(&mut reader).await? {
            DiResponseFrame::HelloAck(ack) => Negotiated::from_ack(ack),
            DiResponseFrame::Incompatible(incompatible) => return Err(ClientError::Incompatible(incompatible)),
            _ => return Err(ClientError::UnexpectedFrame),
        };

        Ok(Self {
            reader,
            writer,
            negotiated,
            token: capability_token,
            next_request_id: 1,
        })
    }

    /// What was agreed for this connection.
    pub fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// Every tool the runtime knows about.
    pub async fn list_tools(&mut self) -> Result<wire::ToolList, ClientError> {
        let response = self.call(self.request(DiVerb::ListTools, "")).await?;
        response.tool_list.ok_or(ClientError::UnexpectedFrame)
    }

    /// Author a dry run for `tool_id`.
    pub async fn plan(
        &mut self,
        tool_id: &str,
        profile: &str,
        settings_scope: &str,
        policy_profile_id: &str,
        allow_privileged_host_steps: bool,
        requested_level: &str,
    ) -> Result<wire::PlanView, ClientError> {
        let mut request = self.request(DiVerb::Plan, tool_id);
        request.plan = Some(wire::PlanArgs {
            profile: profile.to_string(),
            requested_level: requested_level.to_string(),
            settings_scope: settings_scope.to_string(),
            allow_privileged_host_steps,
            policy_profile_id: policy_profile_id.to_string(),
        });
        let response = self.call(request).await?;
        response.plan.ok_or(ClientError::UnexpectedFrame)
    }

    /// Apply a plan the user has reviewed and approved.
    pub async fn apply(&mut self, tool_id: &str, plan_id: &str) -> Result<wire::ApplyView, ClientError> {
        let mut request = self.request(DiVerb::Apply, tool_id);
        request.apply = Some(wire::ApplyArgs {
            plan_id: plan_id.to_string(),
        });
        let response = self.call(request).await?;
        response.apply.ok_or(ClientError::UnexpectedFrame)
    }

    /// Read the protection state the service derived.
    ///
    /// Returned verbatim. This client offers no way to compute or upgrade a
    /// state locally, and a client built on it should render
    /// `observed_at_unix_secs` alongside the level: the claim is "verified at
    /// T", not "true now".
    pub async fn status(&mut self, tool_id: &str) -> Result<wire::StatusView, ClientError> {
        let response = self.call(self.request(DiVerb::Status, tool_id)).await?;
        response.status.ok_or(ClientError::UnexpectedFrame)
    }

    /// Run the protection test.
    pub async fn verify(&mut self, tool_id: &str) -> Result<wire::VerificationView, ClientError> {
        let response = self.call(self.request(DiVerb::Verify, tool_id)).await?;
        response.verification.ok_or(ClientError::UnexpectedFrame)
    }

    /// Repair drift.
    pub async fn repair(&mut self, tool_id: &str) -> Result<wire::RepairView, ClientError> {
        let response = self.call(self.request(DiVerb::Repair, tool_id)).await?;
        response.repair.ok_or(ClientError::UnexpectedFrame)
    }

    /// Author and execute the reversal.
    pub async fn remove(&mut self, tool_id: &str, plan_id: &str) -> Result<wire::RemovalView, ClientError> {
        let mut request = self.request(DiVerb::Remove, tool_id);
        request.remove = Some(wire::RemoveArgs {
            plan_id: plan_id.to_string(),
        });
        let response = self.call(request).await?;
        response.removal.ok_or(ClientError::UnexpectedFrame)
    }

    /// Recent, already-redacted security events for this integration.
    pub async fn scoped_events(
        &mut self,
        tool_id: &str,
        limit: u32,
        since_unix_secs: u64,
    ) -> Result<wire::ScopedEventList, ClientError> {
        let mut request = self.request(DiVerb::ScopedEvents, tool_id);
        request.events = Some(wire::ScopedEventsArgs { limit, since_unix_secs });
        let response = self.call(request).await?;
        response.events.ok_or(ClientError::UnexpectedFrame)
    }

    /// Relay a human's approval input to the decision authority.
    ///
    /// The acknowledgement says the input was accepted for adjudication. It is
    /// **not** a verdict, and a client must not render it as one.
    pub async fn relay_approval(
        &mut self,
        tool_id: &str,
        approval_id: &str,
        user_input: &str,
    ) -> Result<wire::ApprovalRelayAck, ClientError> {
        let mut request = self.request(DiVerb::ApprovalRelay, tool_id);
        request.approval = Some(wire::ApprovalRelayArgs {
            approval_id: approval_id.to_string(),
            user_input: user_input.to_string(),
        });
        let response = self.call(request).await?;
        response.approval.ok_or(ClientError::UnexpectedFrame)
    }

    fn request(&self, verb: DiVerb, tool_id: &str) -> wire::Request {
        wire::Request {
            request_id: self.next_request_id,
            verb: verb.to_wire() as i32,
            capability_token: self.token.clone().unwrap_or_default(),
            tool_id: tool_id.to_string(),
            ..Default::default()
        }
    }

    async fn call(&mut self, request: wire::Request) -> Result<wire::Response, ClientError> {
        self.next_request_id += 1;
        codec::write_client_frame(&mut self.writer, DiFrame::Request(request)).await?;
        match codec::read_response_frame(&mut self.reader).await? {
            DiResponseFrame::Response(response) => Ok(*response),
            DiResponseFrame::Denied(denied) => Err(ClientError::Denied(denied)),
            _ => Err(ClientError::UnexpectedFrame),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devint::scope::{TokenScope, ToolScope};
    use crate::devint::testkit::{claude_code_id, TestServer};
    use crate::devint::testkit::{FakeLifecycle, LEAK_SENTINEL};

    async fn connected(server: &TestServer, token: Option<String>) -> DevIntClient {
        DevIntClient::connect(server.socket_path(), "reference-client", "0.1.0", token)
            .await
            .expect("connect")
    }

    #[tokio::test]
    async fn the_reference_client_drives_the_whole_lifecycle() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let (token, _) = server.enrol("reference-client", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connected(&server, Some(token.expose().to_string())).await;

        assert!(!client.negotiated().degraded);
        assert_eq!(client.negotiated().di_api_version, DI_API_MAX_SUPPORTED);
        assert!(!client.negotiated().core_version.is_empty());

        let tool = claude_code_id();
        assert_eq!(client.list_tools().await.expect("list").tools.len(), 1);
        let plan = client
            .plan(&tool, "recommended", "user", "team-default", false, "")
            .await
            .expect("plan");
        assert_eq!(plan.plan_id, "plan-1");
        assert_eq!(
            client.apply(&tool, &plan.plan_id).await.expect("apply").receipt_id,
            "receipt-1"
        );
        assert_eq!(client.status(&tool).await.expect("status").achieved_level, "integrated");
        assert_eq!(client.verify(&tool).await.expect("verify").outcome, "passed");
        assert_eq!(client.repair(&tool).await.expect("repair").repaired, vec!["settings"]);
        assert_eq!(
            client.remove(&tool, "plan-1").await.expect("remove").plan_id,
            "removal-1"
        );
        assert_eq!(
            client.scoped_events(&tool, 10, 0).await.expect("events").events.len(),
            1
        );
        let ack = client
            .relay_approval(&tool, "approval-1", "approve")
            .await
            .expect("relay");
        assert_eq!(ack.relayed_input, "approve");

        server.shutdown().await;
    }

    #[tokio::test]
    async fn a_plan_rendered_by_the_client_carries_no_step_values() {
        // End to end this time: the fake's plan is poisoned, so this asserts the
        // socket path as a whole, not just the projection function.
        let server = TestServer::start(FakeLifecycle::default()).await;
        let (token, _) = server.enrol("reference-client", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connected(&server, Some(token.expose().to_string())).await;
        let plan = client
            .plan(&claude_code_id(), "recommended", "user", "team-default", false, "")
            .await
            .expect("plan");
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains(LEAK_SENTINEL), "the client received a step value");
        // …and still received something worth showing a user.
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].managed_keys, vec!["ANTHROPIC_AUTH_TOKEN"]);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn a_client_with_no_token_is_denied_every_verb() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let mut client = connected(&server, None).await;
        // Negotiation still succeeds — that is how a client learns what to tell
        // the user — but there is no anonymous tier behind it.
        assert_eq!(client.negotiated().di_api_version, DI_API_MAX_SUPPORTED);
        match client.status(&claude_code_id()).await {
            Err(ClientError::Denied(denied)) => {
                assert_eq!(denied.code, wire::DenyCode::Unauthenticated as i32);
                assert!(denied.remediation.contains("enrol"));
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn a_degraded_connection_is_reported_rather_than_absorbed() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        // Speak the wire directly to force a v1-only offer; the reference
        // client always offers its whole window, which is the correct
        // behaviour and therefore cannot produce this case.
        let mut raw = server.connect_raw().await;
        raw.send_hello(crate::devint::testkit::hello_offering(&[1])).await;
        let DiResponseFrame::HelloAck(ack) = raw.read().await else {
            panic!("expected HelloAck");
        };
        let negotiated = Negotiated::from_ack(ack);
        assert!(negotiated.degraded);
        assert!(!negotiated.supports(DiVerb::ScopedEvents));
        assert!(negotiated.supports(DiVerb::Status));
        assert!(!negotiated.remediation.is_empty());
        server.shutdown().await;
    }

    #[tokio::test]
    async fn connecting_to_an_absent_socket_reports_a_stopped_runtime() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("devint.sock");
        match DevIntClient::connect(&path, "reference-client", "0.1.0", None).await {
            Err(ClientError::RuntimeNotRunning { path: reported }) => assert_eq!(reported, path),
            Err(other) => panic!("expected RuntimeNotRunning, got {other:?}"),
            Ok(_) => panic!("expected RuntimeNotRunning, got a connected client"),
        }
    }
}
