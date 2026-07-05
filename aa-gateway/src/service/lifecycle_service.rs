//! `AgentLifecycleService` tonic trait implementation wiring gRPC RPCs to [`AgentRegistry`].

use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime};

use chrono::Utc;
use tokio::sync::{mpsc, Mutex};
use tonic::{Request, Response, Status};

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AuditEntry, AuditEventType};
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleService;
use aa_proto::assembly::agent::v1::{
    ChallengeRequest, ChallengeResponse, ControlCommand, ControlStreamRequest, DeregisterRequest, DeregisterResponse,
    HeartbeatRequest, HeartbeatResponse, RegisterRequest, RegisterResponse,
};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;

use crate::engine::PolicyEngine;
use crate::events::publisher::agent_status_changed_to_envelope;
use crate::registry::convert::{proto_agent_id_to_key, validate_proto_agent_id};
use crate::registry::store::AgentRecord;
use crate::registry::token::{generate_credential_token, validate_token};
use crate::registry::{AgentRegistry, AgentStatus, LineageError, OrphanMode, RegistryError, SuspendReason};
use crate::service::TenancyMode;

/// Default heartbeat interval returned to agents at registration (seconds).
const DEFAULT_HEARTBEAT_INTERVAL_SEC: i64 = 30;

/// Length in bytes of a server-issued registration-challenge nonce (AAASM-3866).
pub(crate) const CHALLENGE_NONCE_LEN: usize = 32;

/// How long a registration-challenge nonce stays valid after it is issued
/// (AAASM-3866). Short enough to bound replay/precompute windows, long enough to
/// cover a client's RequestChallenge → Register round-trip.
pub(crate) const CHALLENGE_TTL: Duration = Duration::from_secs(30);

/// Draw a fresh, unpredictable challenge nonce from the OS-seeded thread CSPRNG.
///
/// Shared by every [`ChallengeStoreLike`] implementation so the nonce is
/// generated identically regardless of where it is stored.
pub(crate) fn fresh_nonce() -> Vec<u8> {
    rand::random::<[u8; CHALLENGE_NONCE_LEN]>().to_vec()
}

/// Absolute expiry of a freshly-issued nonce, as Unix-epoch milliseconds — the
/// value returned to the client in `ChallengeResponse.expires_at_unix_ms`.
pub(crate) fn challenge_expiry_unix_ms() -> i64 {
    Utc::now().timestamp_millis() + CHALLENGE_TTL.as_millis() as i64
}

/// A single outstanding registration challenge, keyed in
/// [`InMemoryChallengeStore`] by its random nonce bytes.
struct IssuedChallenge {
    /// did:key the nonce was issued for — re-checked at Register so a nonce
    /// cannot be redirected to a different identity.
    agent_id: String,
    /// Hex public key the nonce was issued for — re-checked at Register so a
    /// nonce cannot be replayed to register a different key.
    public_key: String,
    /// Monotonic instant after which the nonce is rejected as expired.
    expires_at: Instant,
}

/// Replica-shared store of outstanding registration-challenge nonces
/// (AAASM-3866, made replica-shared by AAASM-3882).
///
/// The store is the single-use + time-bound + identity-binding gate that makes
/// the registration possession proof non-replayable: a nonce is unpredictable
/// (CSPRNG), removed the first time it is consumed, rejected once expired, and
/// only accepted for the exact agent_id + public_key it was issued for.
///
/// AAASM-3866 shipped only the [`InMemoryChallengeStore`] implementation, which
/// keeps nonces in process-local memory and so assumes a **single gateway
/// replica**: behind a multi-replica load balancer, `RequestChallenge` and
/// `Register` can land on different replicas, so a nonce issued by replica A is
/// unknown to replica B and `Register` fails closed (`Unauthenticated`). This
/// trait abstracts the store so a horizontally-scaled, production gateway can
/// inject a shared backend — the Redis-backed `RedisChallengeStore` in
/// [`crate::storage::challenge`] — via [`AgentLifecycleServiceImpl::with_challenge_store`],
/// while dev/single-replica keeps the zero-dependency in-memory default.
///
/// Every implementation MUST preserve all three guarantees **across replicas**:
///
/// * **single-use** — [`consume`] removes the nonce atomically, before the
///   binding/expiry checks, so any attempt (even a replay or a redirect to a
///   different identity) permanently burns it;
/// * **time-bound** — a nonce is rejected once [`CHALLENGE_TTL`] has elapsed;
/// * **identity-binding** — a nonce is only accepted for the exact `agent_id` +
///   `public_key` it was issued for.
///
/// [`consume`]: ChallengeStoreLike::consume
#[async_trait::async_trait]
pub trait ChallengeStoreLike: Send + Sync {
    /// Issue a fresh random nonce bound to `agent_id` + `public_key`, returning
    /// the nonce bytes and its absolute expiry as Unix-epoch milliseconds.
    /// Errors (e.g. a shared backend being unreachable) fail closed so no
    /// challenge is handed out that cannot later be consumed.
    async fn issue(&self, agent_id: &str, public_key: &str) -> Result<(Vec<u8>, i64), Status>;

    /// Consume the nonce: verify it was issued (single-use — removed on
    /// consume), not expired, and bound to this `agent_id` + `public_key`.
    /// Returns `Status::unauthenticated` otherwise so Register fails closed.
    async fn consume(&self, nonce: &[u8], agent_id: &str, public_key: &str) -> Result<(), Status>;
}

/// In-memory, process-local [`ChallengeStoreLike`] (AAASM-3866).
///
/// The default store: correct for single-replica / dev deployments and for
/// tests. The backing map lives behind an `Arc` so cheap clones share one
/// backend — modelling, within a single process, the "one shared store fronted
/// by N replicas" topology a production [`ChallengeStoreLike`] must support. For
/// an actually cross-process shared store, inject the Redis-backed
/// implementation instead.
#[derive(Clone, Default)]
pub struct InMemoryChallengeStore {
    issued: Arc<StdMutex<HashMap<Vec<u8>, IssuedChallenge>>>,
}

#[async_trait::async_trait]
impl ChallengeStoreLike for InMemoryChallengeStore {
    /// Opportunistically purges already-expired entries so the map cannot grow
    /// unbounded under a flood of challenge requests that never register.
    async fn issue(&self, agent_id: &str, public_key: &str) -> Result<(Vec<u8>, i64), Status> {
        let nonce = fresh_nonce();
        let now = Instant::now();
        let expires_at = now + CHALLENGE_TTL;
        {
            let mut issued = self.issued.lock().unwrap_or_else(|e| e.into_inner());
            issued.retain(|_, c| c.expires_at > now);
            issued.insert(
                nonce.clone(),
                IssuedChallenge {
                    agent_id: agent_id.to_owned(),
                    public_key: public_key.to_owned(),
                    expires_at,
                },
            );
        }
        Ok((nonce, challenge_expiry_unix_ms()))
    }

    /// The nonce is removed before the binding/expiry checks so any consumption
    /// attempt — including a replay or a redirect to a different identity —
    /// permanently burns it.
    async fn consume(&self, nonce: &[u8], agent_id: &str, public_key: &str) -> Result<(), Status> {
        if nonce.is_empty() {
            return Err(Status::unauthenticated(
                "missing registration_nonce — call RequestChallenge before Register (AAASM-3866)",
            ));
        }
        let entry = {
            let mut issued = self.issued.lock().unwrap_or_else(|e| e.into_inner());
            issued.remove(nonce)
        }
        .ok_or_else(|| Status::unauthenticated("unknown or already-used registration nonce"))?;

        if Instant::now() > entry.expires_at {
            return Err(Status::unauthenticated(
                "registration nonce expired — request a fresh challenge",
            ));
        }
        if entry.agent_id != agent_id || entry.public_key != public_key {
            return Err(Status::unauthenticated(
                "registration nonce was not issued for this agent_id + public_key",
            ));
        }
        Ok(())
    }
}

/// Verify an agent's proof of possession of its registering key (AAASM-3591,
/// hardened by AAASM-3866).
///
/// `proof` must be a raw 64-byte Ed25519 signature over `challenge` that
/// verifies under `verifying_key`. `challenge` is the server-issued, single-use
/// [`ChallengeStoreLike`] nonce (no longer the public, deterministic `agent_id`),
/// so the proof cannot be precomputed or replayed. Returns
/// `Status::unauthenticated` when the proof is missing, malformed, or does not
/// verify — so no `credential_token` is minted for a caller that merely presents
/// a public key it does not hold.
/// Resolve the authoritative per-agent `enforcement_mode` override to store for
/// a *self-registering* agent, dropping any client-supplied claim that would
/// *weaken* enforcement (AAASM-4121).
///
/// `enforcement_mode` is a downgrade lever: on the `CheckAction` hot path a
/// stored `Observe`/`Disabled` mode rewrites a `Deny`/`RequiresApproval` into an
/// audited `Allow` (`engine::transform_for_observe_mode`). `Register` is the
/// unauthenticated bootstrap path — its only gate is an Ed25519 possession-proof
/// over a server nonce, which proves *key ownership*, NOT authorization. So a
/// self-registering agent must not be able to neutralize its own governance by
/// claiming `enforcement_mode = Observe/Disabled`.
///
/// Only a claim that *strengthens* enforcement (`Enforce`) is honored; a weaker
/// claim is dropped to `None` so the server-side default (`Enforce`, resolved in
/// `resolve_enforcement_mode`) governs. Operator-driven observe→enforce rollout
/// belongs in server-side policy/config, never a client registration claim.
/// Mirrors the trust-boundary treatment of forged tenancy in
/// `PolicyServiceImpl::apply_authoritative_tenancy` (AAASM-3992).
fn authoritative_enforcement_mode(proto_value: i32) -> Option<aa_core::EnforcementMode> {
    match aa_core::EnforcementMode::from_proto_i32(proto_value) {
        Some(aa_core::EnforcementMode::Enforce) => Some(aa_core::EnforcementMode::Enforce),
        Some(weaker) => {
            tracing::warn!(
                ?weaker,
                "ignoring client-supplied weaker enforcement_mode on self-registration; \
                 defaulting to Enforce (AAASM-4121)"
            );
            None
        }
        None => None,
    }
}

fn verify_possession_proof(
    verifying_key: &ed25519_dalek::VerifyingKey,
    challenge: &[u8],
    proof: &[u8],
) -> Result<(), Status> {
    if proof.is_empty() {
        return Err(Status::unauthenticated(
            "missing possession_proof — credential_token requires proof of key possession",
        ));
    }
    let sig_bytes: [u8; 64] = proof
        .try_into()
        .map_err(|_| Status::unauthenticated("possession_proof must be a 64-byte Ed25519 signature"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(challenge, &signature)
        .map_err(|_| Status::unauthenticated("possession_proof did not verify against public_key"))?;
    Ok(())
}

/// gRPC service implementation wiring `Register` / `Heartbeat` / `Deregister` /
/// `ControlStream` to the in-memory [`AgentRegistry`].
pub struct AgentLifecycleServiceImpl {
    registry: Arc<AgentRegistry>,
    policy_engine: Option<Arc<PolicyEngine>>,
    /// Optional channel for emitting `AgentForceDeregistered` audit entries when
    /// `sweep_aged_agents` evicts agents during heartbeat processing.
    audit_tx: Option<mpsc::Sender<AuditEntry>>,
    audit_seq: Arc<AtomicU64>,
    audit_last_hash: Arc<Mutex<[u8; 32]>>,
    /// Replica-shared store of outstanding registration-challenge nonces
    /// (AAASM-3866; made replica-shared by AAASM-3882). Defaults to the
    /// process-local [`InMemoryChallengeStore`]; a horizontally-scaled gateway
    /// injects a shared backend via [`Self::with_challenge_store`].
    challenges: Arc<dyn ChallengeStoreLike>,
    /// Deployment tenancy posture (AAASM-4032). Defaults to
    /// [`TenancyMode::Untenanted`] so OSS/single-tenant deployments register
    /// team-less agents exactly as before; in [`TenancyMode::Tenanted`],
    /// `Register` rejects an agent that carries no `team_id`.
    tenancy_mode: TenancyMode,
}

impl AgentLifecycleServiceImpl {
    /// Create a new service backed by the given agent registry.
    pub fn new(registry: Arc<AgentRegistry>) -> Self {
        Self {
            registry,
            policy_engine: None,
            audit_tx: None,
            audit_seq: Arc::new(AtomicU64::new(0)),
            audit_last_hash: Arc::new(Mutex::new([0u8; 32])),
            challenges: Arc::new(InMemoryChallengeStore::default()),
            tenancy_mode: TenancyMode::default(),
        }
    }

    /// Create a new service with both an agent registry and a policy engine.
    ///
    /// When a policy engine is provided, the heartbeat handler can check budget
    /// state and auto-resume agents that were suspended due to budget limits.
    pub fn with_policy_engine(registry: Arc<AgentRegistry>, policy_engine: Arc<PolicyEngine>) -> Self {
        Self {
            registry,
            policy_engine: Some(policy_engine),
            audit_tx: None,
            audit_seq: Arc::new(AtomicU64::new(0)),
            audit_last_hash: Arc::new(Mutex::new([0u8; 32])),
            challenges: Arc::new(InMemoryChallengeStore::default()),
            tenancy_mode: TenancyMode::default(),
        }
    }

    /// Attach an audit channel so `sweep_aged_agents` evictions emit
    /// `AgentForceDeregistered` audit entries during heartbeat processing.
    pub fn with_audit_tx(mut self, audit_tx: mpsc::Sender<AuditEntry>) -> Self {
        self.audit_tx = Some(audit_tx);
        self
    }

    /// Replace the default in-memory registration-challenge store with a shared
    /// one (AAASM-3882).
    ///
    /// A multi-replica gateway behind a load balancer MUST inject a replica-
    /// shared store (e.g. the Redis-backed `RedisChallengeStore` in
    /// [`crate::storage::challenge`]) here so a nonce issued by `RequestChallenge`
    /// on one replica can be consumed by `Register` on another. Without this the
    /// default [`InMemoryChallengeStore`] is process-local and cross-replica
    /// registration fails closed.
    pub fn with_challenge_store(mut self, challenges: Arc<dyn ChallengeStoreLike>) -> Self {
        self.challenges = challenges;
        self
    }

    /// Set the deployment tenancy posture (AAASM-4032).
    ///
    /// In [`TenancyMode::Tenanted`], `Register` rejects a team-less agent
    /// (empty/absent `team_id`) with `FailedPrecondition`. Under the default
    /// [`TenancyMode::Untenanted`], registration is unchanged.
    pub fn with_tenancy_mode(mut self, mode: TenancyMode) -> Self {
        self.tenancy_mode = mode;
        self
    }
}

type ControlStreamOutput = Pin<Box<dyn tokio_stream::Stream<Item = Result<ControlCommand, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl AgentLifecycleService for AgentLifecycleServiceImpl {
    /// AAASM-3866: issue a fresh, single-use, server-random nonce bound to the
    /// caller's `agent_id` + `public_key`. The agent signs this nonce and returns
    /// it as `RegisterRequest.possession_proof` / `registration_nonce`. Issuing
    /// the challenge server-side is what stops a caller who merely *knows* an
    /// agent_id from precomputing a valid proof — the signed value is now
    /// unpredictable.
    async fn request_challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        validate_proto_agent_id(proto_id).map_err(|e| Status::invalid_argument(e.to_string()))?;

        // Validate public_key shape here too so a challenge is only ever issued
        // for a well-formed key — the same key the proof must later verify under.
        if req.public_key.is_empty() {
            return Err(Status::invalid_argument("missing public_key"));
        }
        let pk_bytes =
            hex::decode(&req.public_key).map_err(|_| Status::invalid_argument("public_key is not valid hex"))?;
        let pk_array: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("public_key must be 32 bytes (64 hex chars)"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&pk_array)
            .map_err(|_| Status::invalid_argument("invalid Ed25519 public key"))?;

        let (nonce, expires_at_unix_ms) = self.challenges.issue(&proto_id.agent_id, &req.public_key).await?;

        tracing::debug!(agent_id = ?proto_id.agent_id, "registration challenge issued");

        Ok(Response::new(ChallengeResponse {
            nonce,
            expires_at_unix_ms,
        }))
    }

    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        validate_proto_agent_id(proto_id).map_err(|e| Status::invalid_argument(e.to_string()))?;

        // AAASM-4032: in a Tenanted deployment posture, every agent MUST belong
        // to a team. Reject a team-less registration up front (before the
        // possession-proof challenge is consumed) so a caller cannot register an
        // agent that would then pass every tenant's cross-tenant fallback check.
        // Under the default Untenanted posture this guard is inert.
        if self.tenancy_mode == TenancyMode::Tenanted && proto_id.team_id.is_empty() {
            return Err(Status::failed_precondition(
                "tenanted gateway: registration requires a non-empty team_id (AAASM-4032)",
            ));
        }

        if req.public_key.is_empty() {
            return Err(Status::invalid_argument("missing public_key"));
        }

        // Validate that public_key is a valid Ed25519 public key (32 bytes, hex-encoded).
        let pk_bytes =
            hex::decode(&req.public_key).map_err(|_| Status::invalid_argument("public_key is not valid hex"))?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("public_key must be 32 bytes (64 hex chars)"))?,
        )
        .map_err(|_| Status::invalid_argument("invalid Ed25519 public key"))?;

        // AAASM-3591 / AAASM-3866: prove the caller actually HOLDS the private
        // key for `public_key` before minting a credential_token. Without this,
        // anyone who can reach the unauthenticated gRPC port can present any
        // valid Ed25519 public key and mint a token.
        //
        // The proof must sign the *server-issued nonce* the caller obtained from
        // RequestChallenge — NOT the public, deterministic `agent_id` (which any
        // attacker who knows the id could sign in advance, then replay). Consume
        // the nonce first (single-use, time-bound, bound to this exact
        // agent_id + public_key); only then verify the signature over it.
        //
        // Coordinates with AAASM-3416 (broad per-endpoint authn): this is the
        // minimal credential_token possession gate; a future authn interceptor
        // layers on top of (does not replace) it.
        self.challenges
            .consume(&req.registration_nonce, &proto_id.agent_id, &req.public_key)
            .await?;
        verify_possession_proof(&verifying_key, &req.registration_nonce, &req.possession_proof)?;

        let agent_key = proto_agent_id_to_key(proto_id);
        let credential_token = generate_credential_token();
        let now = Utc::now();

        // Capture topology echo values before `req` is partially moved into `AgentRecord` below.
        let echo_parent_agent_id = req.parent_agent_id.clone();
        let echo_team_id = if proto_id.team_id.is_empty() {
            None
        } else {
            Some(proto_id.team_id.clone())
        };
        // AAASM-2008 — capture org_id from proto into AgentRecord so the
        // multi-tenancy tier is queryable as a first-class field.
        let echo_org_id = if proto_id.org_id.is_empty() {
            None
        } else {
            Some(proto_id.org_id.clone())
        };

        // Compute root_agent_id, parent_key, and depth server-side before building the record.
        // Root agents: root = self, depth = 0, parent_key = None.
        // Sub-agents: inherit parent's root (or parent itself), depth = parent.depth + 1.
        // Fail with INVALID_ARGUMENT if the declared parent is not registered.
        let (root_agent_id, resolved_parent_key, agent_depth) = if let Some(ref parent_str) = echo_parent_agent_id {
            let parent_proto_id = ProtoAgentId {
                org_id: proto_id.org_id.clone(),
                team_id: proto_id.team_id.clone(),
                agent_id: parent_str.clone(),
            };
            let pk = proto_agent_id_to_key(&parent_proto_id);
            let parent = self
                .registry
                .get(&pk)
                .ok_or_else(|| Status::invalid_argument("parent_agent_id not found in registry"))?;
            let root = Some(parent.root_agent_id.unwrap_or(parent.agent_id));
            let depth = parent.depth + 1;
            (root, Some(pk), depth)
        } else {
            (Some(agent_key), None, 0u32)
        };

        let record = AgentRecord {
            agent_id: agent_key,
            name: req.name,
            framework: req.framework,
            version: req.version,
            risk_tier: req.risk_tier,
            tool_names: req.tool_names,
            public_key: req.public_key,
            credential_token: credential_token.clone(),
            metadata: BTreeMap::from_iter(req.metadata),
            registered_at: now,
            last_heartbeat: now,
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: Vec::new(),
            recent_events: std::collections::VecDeque::new(),
            recent_traces: Vec::new(),
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: req.parent_agent_id,
            team_id: echo_team_id.clone(),
            depth: agent_depth,
            delegation_reason: req.delegation_reason,
            spawned_by_tool: req.spawned_by_tool,
            root_agent_id,
            children: Vec::new(),
            parent_key: resolved_parent_key,
            enforcement_mode: authoritative_enforcement_mode(req.enforcement_mode),
            org_id: echo_org_id,
        };

        self.registry.register_persisted(record).await.map_err(|e| match e {
            RegistryError::AlreadyRegistered(_) => Status::already_exists(e.to_string()),
            RegistryError::Lineage(LineageError::CircularDelegation { .. })
            | RegistryError::Lineage(LineageError::MaxDepthExceeded { .. }) => Status::invalid_argument(e.to_string()),
            _ => Status::internal(e.to_string()),
        })?;

        tracing::info!(agent_id = ?proto_id.agent_id, "agent registered");

        // root_agent_id is Copy ([u8;16]) so we can use it after moving into record above.
        let echo_root = root_agent_id.map(|b| b.to_vec());

        Ok(Response::new(RegisterResponse {
            credential_token,
            assigned_policy: String::new(),
            heartbeat_interval_sec: DEFAULT_HEARTBEAT_INTERVAL_SEC,
            parent_agent_id: echo_parent_agent_id,
            team_id: echo_team_id,
            root_agent_id: echo_root,
        }))
    }

    async fn heartbeat(&self, request: Request<HeartbeatRequest>) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        let agent_key = proto_agent_id_to_key(proto_id);

        validate_token(&self.registry, &agent_key, &req.credential_token)
            .map_err(|_| Status::unauthenticated("invalid credential token"))?;

        self.registry
            .update_heartbeat(&agent_key)
            .map_err(|e| Status::not_found(e.to_string()))?;

        let status = self.registry.agent_status(&agent_key).unwrap_or(AgentStatus::Active);

        // Lazy auto-resume: if agent was suspended due to budget and budget has
        // since reset (daily/monthly boundary crossed), resume the agent.
        let should_suspend = match status {
            AgentStatus::Suspended(SuspendReason::BudgetExceeded) => {
                let within_budget = self
                    .policy_engine
                    .as_ref()
                    .map(|pe| pe.is_within_budget(&agent_key))
                    .unwrap_or(false);
                if within_budget {
                    let _ = self.registry.resume_agent(&agent_key);
                    tracing::info!(agent_id = ?proto_id.agent_id, "auto-resumed: budget reset");
                    false
                } else {
                    true
                }
            }
            AgentStatus::Suspended(_) => true,
            _ => false,
        };

        tracing::debug!(agent_id = ?proto_id.agent_id, should_suspend, "heartbeat received");

        // Piggyback TTL sweep on every heartbeat: deregister agents past max_agent_age
        // and emit AgentForceDeregistered audit entries when an audit channel is wired in.
        let now_secs = Utc::now().timestamp() as u64;
        let evicted = self.registry.sweep_aged_agents(now_secs);
        if !evicted.is_empty() {
            if let Some(ref tx) = self.audit_tx {
                let timestamp_ns = Timestamp::from(SystemTime::now()).as_nanos();
                let mut last_hash = self.audit_last_hash.lock().await;
                for key in &evicted {
                    let seq = self.audit_seq.fetch_add(1, Ordering::Relaxed);
                    let entry = AuditEntry::new(
                        seq,
                        timestamp_ns,
                        AuditEventType::AgentForceDeregistered,
                        AgentId::from_bytes(*key),
                        SessionId::from_bytes([0u8; 16]),
                        r#"{"reason":"age_exceeded"}"#.to_owned(),
                        *last_hash,
                    );
                    *last_hash = *entry.entry_hash();
                    let _ = tx.try_send(entry);
                }
            }
        }

        Ok(Response::new(HeartbeatResponse {
            policy_updated: false,
            should_suspend,
        }))
    }

    async fn deregister(&self, request: Request<DeregisterRequest>) -> Result<Response<DeregisterResponse>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        let agent_key = proto_agent_id_to_key(proto_id);

        validate_token(&self.registry, &agent_key, &req.credential_token)
            .map_err(|_| Status::unauthenticated("invalid credential token"))?;

        let (_, effects) = self
            .registry
            .deregister_persisted(&agent_key, OrphanMode::Suspend)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        for effect in &effects {
            let envelope = agent_status_changed_to_envelope(effect, "parent agent deregistered");
            tracing::debug!(
                agent_id = %effect.agent_id_str,
                action = %effect.action,
                %envelope,
                "orphan effect applied"
            );
        }

        tracing::info!(agent_id = ?proto_id.agent_id, reason = %req.reason, "agent deregistered");

        Ok(Response::new(DeregisterResponse {
            success: true,
            agent_id: proto_id.agent_id.clone(),
        }))
    }

    type ControlStreamStream = ControlStreamOutput;

    async fn control_stream(
        &self,
        request: Request<ControlStreamRequest>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        let agent_key = proto_agent_id_to_key(proto_id);

        validate_token(&self.registry, &agent_key, &req.credential_token)
            .map_err(|_| Status::unauthenticated("invalid credential token"))?;

        let rx = self
            .registry
            .open_control_stream(&agent_key)
            .map_err(|e| Status::not_found(e.to_string()))?;

        tracing::info!(agent_id = ?proto_id.agent_id, "control stream opened");

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::ControlStreamStream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn valid_possession_proof_is_accepted() {
        let sk = key();
        let challenge = b"did:key:z6MkExampleAgent";
        let proof = sk.sign(challenge).to_bytes().to_vec();
        assert!(verify_possession_proof(&sk.verifying_key(), challenge, &proof).is_ok());
    }

    #[test]
    fn missing_possession_proof_is_unauthenticated() {
        let sk = key();
        let err = verify_possession_proof(&sk.verifying_key(), b"did", &[]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn forged_possession_proof_is_unauthenticated() {
        let sk = key();
        let challenge = b"did:key:z6MkExampleAgent";
        let mut proof = sk.sign(challenge).to_bytes().to_vec();
        proof[0] ^= 0xFF;
        let err = verify_possession_proof(&sk.verifying_key(), challenge, &proof).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn proof_signed_over_a_different_challenge_is_unauthenticated() {
        let sk = key();
        let proof = sk.sign(b"other-did").to_bytes().to_vec();
        let err = verify_possession_proof(&sk.verifying_key(), b"did:key:expected", &proof).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn wrong_length_possession_proof_is_unauthenticated() {
        let sk = key();
        let err = verify_possession_proof(&sk.verifying_key(), b"did", &[1, 2, 3]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // ── InMemoryChallengeStore (AAASM-3866) ──────────────────────────────────

    const DID: &str = "did:key:z6MkExampleAgent";
    const PK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[tokio::test]
    async fn issued_nonce_is_random_and_consumable_once() {
        let store = InMemoryChallengeStore::default();
        let (n1, _) = store.issue(DID, PK).await.unwrap();
        let (n2, _) = store.issue(DID, PK).await.unwrap();
        assert_eq!(n1.len(), CHALLENGE_NONCE_LEN);
        assert_ne!(n1, n2, "two issued nonces must differ (CSPRNG)");

        // First consume succeeds; the same nonce is now burned (single-use).
        assert!(store.consume(&n1, DID, PK).await.is_ok());
        let replay = store.consume(&n1, DID, PK).await.unwrap_err();
        assert_eq!(replay.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn empty_nonce_is_rejected() {
        let store = InMemoryChallengeStore::default();
        let err = store.consume(&[], DID, PK).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn unknown_nonce_is_rejected() {
        let store = InMemoryChallengeStore::default();
        let err = store.consume(&[9u8; CHALLENGE_NONCE_LEN], DID, PK).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn nonce_bound_to_a_different_identity_is_rejected() {
        let store = InMemoryChallengeStore::default();
        let (nonce, _) = store.issue(DID, PK).await.unwrap();
        // Wrong agent_id.
        let err = store.consume(&nonce, "did:key:z6MkOther", PK).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn nonce_bound_to_a_different_public_key_is_rejected() {
        let store = InMemoryChallengeStore::default();
        let (nonce, _) = store.issue(DID, PK).await.unwrap();
        let other_pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let err = store.consume(&nonce, DID, other_pk).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn expired_nonce_is_rejected() {
        let store = InMemoryChallengeStore::default();
        let nonce = vec![1u8; CHALLENGE_NONCE_LEN];
        // Insert a nonce that already expired one second ago.
        store.issued.lock().unwrap().insert(
            nonce.clone(),
            IssuedChallenge {
                agent_id: DID.to_owned(),
                public_key: PK.to_owned(),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        let err = store.consume(&nonce, DID, PK).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn expires_at_unix_ms_is_in_the_future() {
        let store = InMemoryChallengeStore::default();
        let (_, expires_at_unix_ms) = store.issue(DID, PK).await.unwrap();
        assert!(expires_at_unix_ms > Utc::now().timestamp_millis());
    }

    // ── Cross-replica behaviour (AAASM-3882) ─────────────────────────────────
    //
    // Two `InMemoryChallengeStore` clones share one Arc-backed map, modelling
    // two gateway replicas pointed at a single shared store. This is the exact
    // RequestChallenge-on-A → Register-on-B handshake that a process-local store
    // would break behind a multi-replica load balancer.

    #[tokio::test]
    async fn nonce_issued_on_one_handle_is_consumable_on_another_exactly_once() {
        let replica_a = InMemoryChallengeStore::default();
        let replica_b = replica_a.clone();

        // Replica A issues the challenge…
        let (nonce, _) = replica_a.issue(DID, PK).await.unwrap();
        // …and replica B (a different handle over the same backend) consumes it.
        assert!(
            replica_b.consume(&nonce, DID, PK).await.is_ok(),
            "a nonce issued on replica A must be consumable on replica B"
        );
        // Single-use holds across handles: B already burned it, so A cannot reuse it.
        let replay = replica_a.consume(&nonce, DID, PK).await.unwrap_err();
        assert_eq!(replay.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn expiry_is_enforced_across_handles() {
        let replica_a = InMemoryChallengeStore::default();
        let replica_b = replica_a.clone();

        let nonce = vec![2u8; CHALLENGE_NONCE_LEN];
        // Replica A's backend holds a nonce that already expired.
        replica_a.issued.lock().unwrap().insert(
            nonce.clone(),
            IssuedChallenge {
                agent_id: DID.to_owned(),
                public_key: PK.to_owned(),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        // Replica B sees the same backend and still rejects the expired nonce.
        let err = replica_b.consume(&nonce, DID, PK).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
