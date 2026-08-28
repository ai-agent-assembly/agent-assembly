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
use std::time::Duration;

use tokio::io::{BufReader, BufWriter};
use tokio::net::UnixStream;

use aa_proto::assembly::devint::v1 as wire;

use super::apply_outcome::ApplyMutation;
use super::codec::{self, DiCodecError, DiFrame, DiResponseFrame};
use super::negotiate::{DI_API_MAX_SUPPORTED, DI_API_MIN_SUPPORTED, DI_API_PROJECT_ROOT_SINCE};
use super::projection::parse_scope;
use super::provenance::{self, BuildIdentity, PeerProvenance, ProvenanceVerdict};
use super::socket::{self, SocketDiscovery};
use super::verb::DiVerb;
use aa_core::integration::{SettingsScope, LIFECYCLE_SCHEMA_VERSION};

/// How long the DI-API handshake may take before the runtime is treated as
/// non-responsive (AAASM-5667).
///
/// Neither half of the handshake is bounded by anything else: `connect` can
/// wait on a full backlog, and the `HelloAck` read waits forever against a peer
/// that accepted the connection and then said nothing. `aasm` opens this
/// handshake on every `integrations` invocation, so without a bound a
/// same-UID process that binds `devint.sock` and never answers hangs the CLI
/// outright. Same-UID is already inside the trust boundary (ADR 0030 §5.1) —
/// this is an availability bound, not an authentication one.
///
/// Generous by design. A healthy runtime answers `Hello` as soon as it accepts,
/// so the only thing this delays is a diagnosis; making it tight would risk
/// turning a loaded machine into a spurious "runtime not responding".
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The error a handshake that ran out of time reports.
///
/// Deliberately an `io::ErrorKind::TimedOut` inside the existing
/// [`ClientError::Transport`] rather than a new enum variant: `ClientError` is
/// a public, exhaustively-matchable enum, and adding a variant would be a
/// source break for out-of-crate callers — the very kind of break AAASM-5669
/// is about. The sentence names the socket and the bound, so the diagnostic
/// loses nothing by travelling in the existing variant.
fn handshake_timed_out(path: &Path, timeout: Duration) -> ClientError {
    ClientError::Transport(DiCodecError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "the runtime at {} did not complete the DI-API handshake within {:?}; \
             it may be a process that bound the socket without serving it",
            path.display(),
            timeout
        ),
    )))
}

/// Refuse `project` scope on a connection whose peer cannot carry a project
/// root (AAASM-5913).
///
/// Shared by `Plan`, which chooses a destination, and by the read-or-reverse
/// verbs, which name the installation they act on: both carry a `project_root`,
/// and neither can be honoured by a peer that does not know the field exists.
///
/// The check is *before the send*, and that is the whole point. `project_root`
/// is `PlanArgs` field 6 and `TargetArgs` field 2, both added at
/// [`DI_API_PROJECT_ROOT_SINCE`](super::negotiate::DI_API_PROJECT_ROOT_SINCE);
/// proto3 discards an unknown field during decode, so a pre-v6 runtime never
/// learns one was sent. It does not deny the request, does not report a
/// degraded connection, and does not leave the field visibly empty on the
/// caller's side either — the plan simply comes back authored under the
/// daemon's own working directory, which is the original defect wearing a
/// successful response. No amount of inspecting the reply recovers this,
/// because the two cases are byte-identical: a v5 runtime that ignored the root
/// and a v5 runtime that was never sent one produce the same `PlanView`.
///
/// The scope token is parsed with [`parse_scope`] rather than compared as a
/// string, so "is this project scope" means exactly what the server will decide
/// it means. A token this client cannot parse is passed through untouched: the
/// server owns rejecting it, and guessing here would turn one clear refusal
/// into two competing ones.
///
/// Reported as [`ClientError::Incompatible`] built locally — not sent by the
/// peer — for the reason [`handshake_timed_out`] does the same thing: that enum
/// is `pub` and exhaustively matchable, so a new variant would be a source
/// break (AAASM-5669), and a version-shaped refusal carrying reason,
/// remediation and the supported window is precisely what `Incompatible`
/// already models. The reason names the negotiated version, so nothing is lost
/// by the origin being local.
fn refuse_project_scope_below_v6(negotiated_version: u32, settings_scope: &str) -> Result<(), ClientError> {
    if negotiated_version >= DI_API_PROJECT_ROOT_SINCE {
        return Ok(());
    }
    if parse_scope(settings_scope) != Some(SettingsScope::Project) {
        return Ok(());
    }
    Err(ClientError::Incompatible(wire::Incompatible {
        reason: format!(
            "this connection negotiated DI-API {negotiated_version}; a caller-chosen project root \
             arrived in DI-API {DI_API_PROJECT_ROOT_SINCE}, so a project-scope request made over \
             it would be resolved against the runtime's own working directory rather than yours"
        ),
        remediation: format!(
            "upgrade the running AASM runtime to one speaking DI-API \
             {DI_API_PROJECT_ROOT_SINCE} or later, then retry; user and managed scope are \
             unaffected and work against this runtime as-is"
        ),
        min_supported: DI_API_MIN_SUPPORTED,
        max_supported: DI_API_MAX_SUPPORTED,
    }))
}

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

    /// What an [`apply`](DevIntClient::apply) said about whether the host
    /// changed.
    ///
    /// The **only** supported way to read it. Taking `ApplyView::outcome`
    /// directly skips the version gate, and the version is not decoration here:
    /// a peer below
    /// [`DI_API_APPLY_OUTCOME_SINCE`](super::negotiate::DI_API_APPLY_OUTCOME_SINCE)
    /// never promised the field, so its absence means *cannot say* rather than
    /// `unchanged`. Resolving that in the permissive direction is a fabricated
    /// success claim (AAASM-5674), which is why the decision is made here —
    /// against the negotiated version this struct already holds — rather than
    /// left for each caller to remember.
    pub fn apply_mutation(&self, applied: &wire::ApplyView) -> ApplyMutation {
        ApplyMutation::from_view(applied.outcome.as_ref(), self.di_api_version)
    }
}

/// Everything a `Plan` invocation carries.
///
/// A struct rather than a parameter list because the two shortest fields are
/// both `&str` and both optional-by-emptiness: `plan(tool, profile, scope, "",
/// false, "", "")` read as a row of placeholders, and a project root added to
/// that row (AAASM-5913) would be indistinguishable at the call site from the
/// policy profile beside it. Named fields make the caller state which of them it
/// is leaving empty.
///
/// # `Default` is kept, deliberately, and it does undercut the paragraph above
///
/// `..PlanRequest::default()` lets a caller *not* state a field, which is the
/// placeholder row again in another spelling — and for `project_root` it spells
/// `""`, the value that is a refusal at project scope. That is a real cost and it
/// is accepted rather than unnoticed: every `..default()` site is a test, both
/// production callers name every field, and the invariant does not rest on the
/// type either way. Empty is refused twice — client-side before the send, and at
/// the service boundary — because `""` is a *legitimate* root at user and managed
/// scope, so no type-level default could distinguish "none to state" from
/// "forgot", and something had to check the scope. Dropping the derive would move
/// seven test callsites and buy no invariant that is not already enforced.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlanRequest<'a> {
    /// Which tool to author a plan for.
    pub tool_id: &'a str,
    /// The protection profile to author against.
    pub profile: &'a str,
    /// Which settings surface the plan may write: `user`, `project`, `managed`.
    pub settings_scope: &'a str,
    /// The policy profile to resolve, or `""` for the service's default.
    pub policy_profile_id: &'a str,
    /// Whether the caller has opted into the one privileged step.
    pub allow_privileged_host_steps: bool,
    /// The protection level asked for, or `""` for the profile's own.
    pub requested_level: &'a str,
    /// The absolute path of the project the **caller** is in, resolved by the
    /// caller at invocation time.
    ///
    /// Mandatory at `project` scope: the service is shared and long-lived, so a
    /// caller that does not say which project it means leaves the service with
    /// nothing to name but whichever directory it was spawned in — which is the
    /// defect in AAASM-5913, not a fallback. Pass `""` when there is none to
    /// state and expect a refusal, not a default, if the scope needed one.
    pub project_root: &'a str,
}

/// Which installed integration a read-or-reverse invocation is about.
///
/// `Status`, `Verify`, `Repair` and `Remove` all act on something that is
/// already installed, and until DI-API 6 they carried no way to say *which*
/// installation that was. The service filled the gap from its own working
/// directory, which is a daemon's, not a caller's — AAASM-5913. This is how a
/// caller says it instead.
///
/// Both fields are optional-by-emptiness, and empty means different things:
///
/// * `settings_scope: ""` — "there should be exactly one installation of this
///   tool; act on it". Right in the common case, and the service refuses rather
///   than picks when the one it finds needs a project the caller did not name.
/// * `project_root: ""` — "this invocation names no project". Not "use yours":
///   a service that substituted its own would be the defect again.
#[derive(Debug, Clone, Copy, Default)]
pub struct TargetRequest<'a> {
    /// Which surface the installation is on — `user`, `project`, `managed` — or
    /// `""` to let the service find the one that exists.
    pub settings_scope: &'a str,
    /// The absolute path of the project the **caller** is in, resolved by the
    /// caller at invocation time, or `""` when it has none to state.
    ///
    /// Compared, never resolved into a destination — against the receipt for a
    /// read or reverse verb, and against the plan's authoring project for an
    /// apply, where nothing is installed yet. Either way a project-scope
    /// operation the caller cannot name is refused.
    pub project_root: &'a str,
    /// What this caller stated about its own launch environment (AAASM-5993),
    /// or `None` to state nothing.
    ///
    /// Names and presence only — see
    /// [`CallerEnvironment`](aa_core::integration::CallerEnvironment)'s own
    /// documentation for why a value can never reach this field. Needs no
    /// DI-API version gate: unlike `project_root`, a peer that predates it
    /// discards it on decode and falls back to the same "nothing stated"
    /// reading a `None` here already produces — there is no false-claim-of-
    /// safety direction for this field to be silently dropped into.
    pub caller_env: Option<&'a aa_core::integration::CallerEnvironment>,
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
        Self::connect_within(
            path,
            client_name,
            client_version,
            capability_token,
            di_api_versions,
            HANDSHAKE_TIMEOUT,
        )
        .await
    }

    /// [`Self::connect_inner`] with the handshake bound supplied, so a test
    /// need not wait out [`HANDSHAKE_TIMEOUT`] to prove the bound exists.
    async fn connect_within(
        path: &Path,
        client_name: &str,
        client_version: &str,
        capability_token: Option<String>,
        di_api_versions: Vec<u32>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        if !path.exists() {
            return Err(ClientError::RuntimeNotRunning {
                path: path.to_path_buf(),
            });
        }
        let handshake = Self::handshake(path, client_name, client_version, capability_token, di_api_versions);
        match tokio::time::timeout(timeout, handshake).await {
            Ok(result) => result,
            Err(_) => Err(handshake_timed_out(path, timeout)),
        }
    }

    /// Connect, say `Hello`, and read the answer.
    ///
    /// Everything here is unbounded on its own — `connect` can wait on a full
    /// backlog and `read_response_frame` waits forever on a peer that accepted
    /// and then said nothing — which is why it is only ever reached through
    /// [`Self::connect_within`].
    async fn handshake(
        path: &Path,
        client_name: &str,
        client_version: &str,
        capability_token: Option<String>,
        di_api_versions: Vec<u32>,
    ) -> Result<Self, ClientError> {
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

    /// Author a dry run for [`PlanRequest::tool_id`].
    ///
    /// Refuses before sending if this connection negotiated a version that
    /// cannot carry [`PlanRequest::project_root`] and the scope needs one — see
    /// [`refuse_project_scope_below_v6`].
    pub async fn plan(&mut self, args: PlanRequest<'_>) -> Result<wire::PlanView, ClientError> {
        refuse_project_scope_below_v6(self.negotiated.di_api_version, args.settings_scope)?;
        let mut request = self.request(DiVerb::Plan, args.tool_id);
        request.plan = Some(wire::PlanArgs {
            profile: args.profile.to_string(),
            requested_level: args.requested_level.to_string(),
            settings_scope: args.settings_scope.to_string(),
            allow_privileged_host_steps: args.allow_privileged_host_steps,
            policy_profile_id: args.policy_profile_id.to_string(),
            project_root: args.project_root.to_string(),
        });
        let response = self.call(request).await?;
        response.plan.ok_or(ClientError::UnexpectedFrame)
    }

    /// Apply a plan the user has reviewed and approved.
    ///
    /// `target` says which project the caller is applying *from*. A plan id is
    /// handed out by the service and can be presented later, from anywhere, so
    /// the id alone does not establish that this caller may execute this plan
    /// here; the service compares the two projects and refuses when they
    /// disagree (AAASM-5913).
    ///
    /// The scope is left to the target as it is for the read verbs. A plan
    /// already carries the scope it was authored at, and a second, client-stated
    /// one could only contradict it.
    pub async fn apply(
        &mut self,
        tool_id: &str,
        plan_id: &str,
        target: TargetRequest<'_>,
    ) -> Result<wire::ApplyView, ClientError> {
        let mut request = self.targeted(DiVerb::Apply, tool_id, target)?;
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
    pub async fn status(&mut self, tool_id: &str, target: TargetRequest<'_>) -> Result<wire::StatusView, ClientError> {
        let request = self.targeted(DiVerb::Status, tool_id, target)?;
        let response = self.call(request).await?;
        response.status.ok_or(ClientError::UnexpectedFrame)
    }

    /// Run the protection test.
    pub async fn verify(
        &mut self,
        tool_id: &str,
        target: TargetRequest<'_>,
    ) -> Result<wire::VerificationView, ClientError> {
        let request = self.targeted(DiVerb::Verify, tool_id, target)?;
        let response = self.call(request).await?;
        response.verification.ok_or(ClientError::UnexpectedFrame)
    }

    /// Repair drift.
    pub async fn repair(&mut self, tool_id: &str, target: TargetRequest<'_>) -> Result<wire::RepairView, ClientError> {
        let request = self.targeted(DiVerb::Repair, tool_id, target)?;
        let response = self.call(request).await?;
        response.repair.ok_or(ClientError::UnexpectedFrame)
    }

    /// Author and execute the reversal.
    pub async fn remove(
        &mut self,
        tool_id: &str,
        plan_id: &str,
        target: TargetRequest<'_>,
    ) -> Result<wire::RemovalView, ClientError> {
        let mut request = self.targeted(DiVerb::Remove, tool_id, target)?;
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

    /// A request for a verb that acts on an installation the caller must name.
    ///
    /// One builder for all four rather than four copies of the same three
    /// lines: the version refusal is the part that must not be forgotten, and a
    /// verb that forgot it would send a project root into a peer that discards
    /// it undetectably ([`refuse_project_scope_below_v6`]).
    ///
    /// The target is attached unconditionally, empty fields included. An absent
    /// `TargetArgs` and one saying "no scope, no project" decode identically on
    /// a v6 peer, so there is nothing to gain by omitting it and one fewer
    /// branch by not trying.
    fn targeted(&self, verb: DiVerb, tool_id: &str, target: TargetRequest<'_>) -> Result<wire::Request, ClientError> {
        refuse_project_scope_below_v6(self.negotiated.di_api_version, target.settings_scope)?;
        let mut request = self.request(verb, tool_id);
        let (caller_env_examined, caller_env_present) = match target.caller_env {
            Some(env) => (
                env.examined_names().map(str::to_string).collect(),
                env.present_names().map(str::to_string).collect(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        request.target = Some(wire::TargetArgs {
            settings_scope: target.settings_scope.to_string(),
            project_root: target.project_root.to_string(),
            caller_env_examined,
            caller_env_present,
        });
        Ok(request)
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
        codec::write_client_frame(&mut self.writer, DiFrame::Request(Box::new(request))).await?;
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

    /// AAASM-5667 — a peer that accepts the connection and never answers must
    /// fail the handshake on a deadline, not hold the caller forever.
    ///
    /// This is the shape a same-UID process that binds `devint.sock` without
    /// serving it takes: `connect()` succeeds, `Hello` is written, and the
    /// `HelloAck` read never completes. Before the bound existed there was no
    /// error to return and no time at which the call gave up.
    #[tokio::test]
    async fn a_socket_that_accepts_and_never_answers_fails_on_a_deadline() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("devint.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        // Accept and hold the connection open, answering nothing at all. The
        // guard keeps the accepted stream alive so the client's read blocks
        // rather than seeing EOF.
        let stalled = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            std::future::pending::<()>().await;
            drop(stream);
        });

        let started = std::time::Instant::now();
        let error = DevIntClient::connect_within(
            &path,
            "reference-client",
            "0.1.0",
            None,
            vec![DI_API_MAX_SUPPORTED],
            Duration::from_millis(200),
        )
        .await
        .err()
        .expect("a runtime that never answers must not produce a client");
        let elapsed = started.elapsed();
        stalled.abort();

        assert!(
            elapsed < Duration::from_secs(5),
            "the handshake must give up on its own deadline, took {elapsed:?}"
        );
        match error {
            ClientError::Transport(DiCodecError::Io(io)) => {
                assert_eq!(io.kind(), std::io::ErrorKind::TimedOut, "{io}");
                assert!(
                    io.to_string().contains("did not complete the DI-API handshake"),
                    "the diagnostic must say what timed out: {io}"
                );
            }
            other => panic!("expected a timed-out transport error, got {other:?}"),
        }
    }

    /// **Positive control** for the test above: the same bound, against a real
    /// server, still produces a negotiated client.
    ///
    /// Without this, a `connect_within` that always timed out — or one whose
    /// deadline was far too tight to be usable — would pass the stall test
    /// while breaking every real connection.
    #[tokio::test]
    async fn the_same_bound_still_admits_a_runtime_that_answers() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let client = DevIntClient::connect_within(
            server.socket_path(),
            "reference-client",
            "0.1.0",
            None,
            vec![DI_API_MAX_SUPPORTED],
            Duration::from_millis(200),
        )
        .await
        .expect("a responsive runtime must still negotiate");
        assert_eq!(client.negotiated().di_api_version, DI_API_MAX_SUPPORTED);
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
            .plan(PlanRequest {
                tool_id: &tool,
                profile: "recommended",
                settings_scope: "user",
                policy_profile_id: "team-default",
                ..PlanRequest::default()
            })
            .await
            .expect("plan");
        assert_eq!(plan.plan_id, "plan-1");
        assert_eq!(
            client
                .apply(&tool, &plan.plan_id, TargetRequest::default())
                .await
                .expect("apply")
                .receipt_id,
            "receipt-1"
        );
        assert_eq!(
            client
                .status(&tool, TargetRequest::default())
                .await
                .expect("status")
                .achieved_level,
            "integrated"
        );
        assert_eq!(
            client
                .verify(&tool, TargetRequest::default())
                .await
                .expect("verify")
                .outcome,
            "passed"
        );
        assert_eq!(
            client
                .repair(&tool, TargetRequest::default())
                .await
                .expect("repair")
                .repaired,
            vec!["settings"]
        );
        assert_eq!(
            client
                .remove(&tool, "plan-1", TargetRequest::default())
                .await
                .expect("remove")
                .plan_id,
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
            .plan(PlanRequest {
                tool_id: &claude_code_id(),
                profile: "recommended",
                settings_scope: "user",
                policy_profile_id: "team-default",
                ..PlanRequest::default()
            })
            .await
            .expect("plan");
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains(LEAK_SENTINEL), "the client received a step value");
        // …and still received something worth showing a user.
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].managed_keys, vec!["ANTHROPIC_AUTH_TOKEN"]);
        server.shutdown().await;
    }

    /// AAASM-5993, over a real socket: a caller-stated environment sent by the
    /// client is the same one the service receives, name for name.
    ///
    /// Goes through `targeted()`'s encode, the real codec, and
    /// `server::build_target`'s decode — not a direct construction of
    /// `LifecycleTarget` — so this is a statement about the wire, which
    /// `FakeLifecycle::last_target` observes after decode.
    #[tokio::test]
    async fn a_caller_stated_environment_crosses_the_wire_intact() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let (token, _) = server.enrol("reference-client", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connected(&server, Some(token.expose().to_string())).await;

        let mut caller_env =
            aa_core::integration::CallerEnvironment::stating(["ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK"]);
        caller_env = caller_env.present("ANTHROPIC_BASE_URL");

        client
            .status(
                &claude_code_id(),
                TargetRequest {
                    caller_env: Some(&caller_env),
                    ..TargetRequest::default()
                },
            )
            .await
            .expect("status");

        let received = server
            .lifecycle()
            .last_target()
            .expect("status must have reached the service")
            .caller_env
            .expect("a caller-stated environment must decode to Some, never None");
        assert_eq!(
            received.state_of("ANTHROPIC_BASE_URL"),
            aa_core::integration::EnvVarState::Set,
            "examined-and-present must survive the round trip"
        );
        assert_eq!(
            received.state_of("CLAUDE_CODE_USE_BEDROCK"),
            aa_core::integration::EnvVarState::Unset,
            "examined-and-absent must survive the round trip, not collapse into NotStated"
        );
        assert_eq!(
            received.state_of("CLAUDE_CODE_USE_VERTEX"),
            aa_core::integration::EnvVarState::NotStated,
            "a name the caller never mentioned must stay NotStated, not default to Unset"
        );
        server.shutdown().await;
    }

    /// A `TargetRequest` with `caller_env: None` — the state of every client
    /// that predates AAASM-5993, and of one that has nothing to state — decodes
    /// to a `CallerEnvironment` where every name reads `NotStated`. This is
    /// [`build_caller_env`](super::server::build_caller_env)'s empty-input case,
    /// exercised over the real wire rather than by calling the function
    /// directly, so a future change to the codec that stopped sending an empty
    /// `TargetArgs` at all would still be caught here.
    #[tokio::test]
    async fn no_caller_statement_decodes_to_every_name_unstated() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let (token, _) = server.enrol("reference-client", TokenScope::full_lifecycle(ToolScope::AllTools));
        let mut client = connected(&server, Some(token.expose().to_string())).await;

        client
            .status(&claude_code_id(), TargetRequest::default())
            .await
            .expect("status");

        let received = server
            .lifecycle()
            .last_target()
            .expect("status must have reached the service")
            .caller_env
            .expect("even a client stating nothing decodes to Some(empty), never None");
        assert_eq!(
            received.state_of("ANTHROPIC_BASE_URL"),
            aa_core::integration::EnvVarState::NotStated
        );
        server.shutdown().await;
    }

    /// A real value behind a watched name — set in this process's actual
    /// environment, the same source `aa-cli`'s `caller_launch_environment`
    /// reads — never reaches the bytes `targeted()` builds, even though the
    /// name it is set under does.
    ///
    /// `#[serial]`-free because nextest runs each test in its own process; a
    /// libtest binary run without nextest would race this against any other
    /// test touching `ANTHROPIC_BASE_URL`, which is why every other test in
    /// this workspace that needs a real env mutation documents the same
    /// reliance on process-per-test isolation rather than adding its own lock.
    #[tokio::test]
    async fn targeted_never_encodes_the_value_behind_a_watched_name() {
        // SAFETY (in the "this is a deliberate, test-scoped mutation" sense,
        // not unsafe code): nextest gives this test its own process, so no
        // other test observes this.
        std::env::set_var("ANTHROPIC_BASE_URL", LEAK_SENTINEL);
        let mut caller_env = aa_core::integration::CallerEnvironment::stating(["ANTHROPIC_BASE_URL"]);
        if std::env::var_os("ANTHROPIC_BASE_URL").is_some() {
            caller_env = caller_env.present("ANTHROPIC_BASE_URL");
        }
        let request = wire::Request {
            request_id: 1,
            verb: DiVerb::Status as i32,
            capability_token: String::new(),
            tool_id: "claude-code".to_string(),
            plan: None,
            apply: None,
            remove: None,
            events: None,
            approval: None,
            target: Some(wire::TargetArgs {
                settings_scope: String::new(),
                project_root: String::new(),
                caller_env_examined: caller_env.examined_names().map(str::to_string).collect(),
                caller_env_present: caller_env.present_names().map(str::to_string).collect(),
            }),
        };
        let encoded = format!("{request:?}");
        assert!(
            encoded.contains("ANTHROPIC_BASE_URL"),
            "the name must cross — otherwise this test proves nothing"
        );
        assert!(
            !encoded.contains(LEAK_SENTINEL),
            "the real value behind the name must never appear in the encoded request: {encoded}"
        );
        std::env::remove_var("ANTHROPIC_BASE_URL");
    }

    #[tokio::test]
    async fn a_client_with_no_token_is_denied_every_verb() {
        let server = TestServer::start(FakeLifecycle::default()).await;
        let mut client = connected(&server, None).await;
        // Negotiation still succeeds — that is how a client learns what to tell
        // the user — but there is no anonymous tier behind it.
        assert_eq!(client.negotiated().di_api_version, DI_API_MAX_SUPPORTED);
        match client.status(&claude_code_id(), TargetRequest::default()).await {
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
