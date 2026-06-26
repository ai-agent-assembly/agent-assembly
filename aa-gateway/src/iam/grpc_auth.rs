//! gRPC agent-plane authentication interceptor (AAASM-3788; advances the
//! agent-plane-auth umbrella AAASM-3418 / AAASM-3419 / AAASM-3429).
//!
//! Closes the unauthenticated gRPC agent plane (`:50051`). Before this, the
//! `approval`, `audit`, `topology`, and `secrets` services performed **zero**
//! credential/caller/tenant validation — any peer that reached the port could
//! decide approvals, forge audit entries, or enumerate topology cross-tenant.
//!
//! The interceptor reads the agent credential token from request metadata,
//! resolves it against the registry's credential reverse-index
//! ([`AgentRegistry::find_by_credential_token`]) to a [`VerifiedCaller`]
//! carrying the caller's tenant (team / org), and injects that into the request
//! extensions so handlers can trust it. Two modes are provided:
//!
//! * [`auth_interceptor`] — **fail-closed**. A missing, malformed, or
//!   unregistered credential is rejected with `Status::unauthenticated` and the
//!   [`METRIC_GRPC_AUTH_REJECTED`] counter is incremented. Applied to the four
//!   previously-unauthenticated services.
//! * [`enrich_interceptor`] — **never rejects**. When a valid credential is
//!   present it injects the [`VerifiedCaller`]; otherwise it passes the request
//!   through untouched. Applied to services that already self-validate the body
//!   token authoritatively (`lifecycle`, `policy`) so a verified identity is
//!   available *consistently* without double-rejecting or breaking the
//!   unauthenticated bootstrap `Register` and policy optional-enrichment paths.
//!
//! mTLS is an OPTIONAL transport hardening layered on top of this token layer;
//! see [`super::grpc_tls::GrpcTlsConfig`] and `SECURITY.md` for the deployment
//! posture (default: loopback bind).

use std::sync::Arc;

use tonic::{Request, Status};

use crate::registry::AgentRegistry;

/// Metadata key (lowercase ASCII) carrying the agent credential token.
///
/// Clients may instead present a standard `authorization: Bearer <token>`
/// header; both forms are accepted by [`extract_token`].
pub const CREDENTIAL_METADATA_KEY: &str = "x-aa-credential-token";

/// Metric counter incremented once per rejected (unauthenticated / invalid)
/// RPC. Labelled with `reason = "missing" | "invalid"`. Satisfies the
/// rejected-unauthenticated-requests metric AC of AAASM-3418.
pub const METRIC_GRPC_AUTH_REJECTED: &str = "aa_grpc_auth_rejected_total";

/// Verified identity of an authenticated gRPC caller, derived from a credential
/// token and injected into the request extensions by the interceptors.
///
/// Handlers read it via `request.extensions().get::<VerifiedCaller>()`. Under
/// [`auth_interceptor`] its presence is guaranteed (the request is rejected
/// otherwise); under [`enrich_interceptor`] it may be absent.
#[derive(Debug, Clone)]
pub struct VerifiedCaller {
    /// Registry key (16-byte agent UUID) of the credential owner.
    pub agent_key: [u8; 16],
    /// Team the caller belongs to, if any.
    pub team_id: Option<String>,
    /// Organization (tenant) the caller belongs to, if any.
    pub org_id: Option<String>,
}

impl VerifiedCaller {
    /// Canonical agent UUID string of the caller — the authoritative attribution
    /// identity (e.g. used as `decided_by` for approval decisions so the audit
    /// trail records the real caller rather than an attacker-supplied string).
    pub fn agent_id_str(&self) -> String {
        uuid::Uuid::from_bytes(self.agent_key).to_string()
    }
}

/// Extract the credential token from request metadata.
///
/// Accepts either the dedicated [`CREDENTIAL_METADATA_KEY`] header or a standard
/// `authorization: Bearer <token>` header (case-insensitive scheme). Returns
/// `None` when neither is present or the value is empty / non-ASCII.
fn extract_token(req: &Request<()>) -> Option<String> {
    let md = req.metadata();
    token_from_credential_header(md).or_else(|| token_from_authorization_header(md))
}

/// Read a non-empty, trimmed token from the dedicated [`CREDENTIAL_METADATA_KEY`]
/// header. Returns `None` for an absent, non-ASCII, or empty value.
fn token_from_credential_header(md: &tonic::metadata::MetadataMap) -> Option<String> {
    let token = md.get(CREDENTIAL_METADATA_KEY)?.to_str().ok()?.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// Read a non-empty, trimmed token from a standard `authorization: Bearer <token>`
/// header (case-insensitive scheme). Returns `None` for an absent, non-ASCII,
/// non-bearer, or empty value.
fn token_from_authorization_header(md: &tonic::metadata::MetadataMap) -> Option<String> {
    let value = md.get("authorization")?.to_str().ok()?.trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// Resolve a credential token to a [`VerifiedCaller`] against the registry's
/// credential reverse-index. Returns `None` when the token is not registered.
fn resolve_caller(registry: &AgentRegistry, token: &str) -> Option<VerifiedCaller> {
    let agent_key = registry.find_by_credential_token(token)?;
    let record = registry.get(&agent_key)?;
    Some(VerifiedCaller {
        agent_key,
        team_id: record.team_id.clone(),
        org_id: record.org_id.clone(),
    })
}

/// Build a fail-closed authentication interceptor bound to `registry`.
///
/// Rejects any request whose credential token is missing, malformed, or not
/// registered with `Status::unauthenticated`, incrementing
/// [`METRIC_GRPC_AUTH_REJECTED`]. On success injects the resolved
/// [`VerifiedCaller`] into the request extensions.
///
/// The returned closure captures an `Arc<AgentRegistry>` and is `Clone`, so it
/// can be shared across every service via `XServer::with_interceptor`.
pub fn auth_interceptor(
    registry: Arc<AgentRegistry>,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |mut req: Request<()>| {
        let Some(token) = extract_token(&req) else {
            metrics::counter!(METRIC_GRPC_AUTH_REJECTED, "reason" => "missing").increment(1);
            return Err(Status::unauthenticated("missing credential token"));
        };
        match resolve_caller(&registry, &token) {
            Some(caller) => {
                req.extensions_mut().insert(caller);
                Ok(req)
            }
            None => {
                metrics::counter!(METRIC_GRPC_AUTH_REJECTED, "reason" => "invalid").increment(1);
                Err(Status::unauthenticated("invalid credential token"))
            }
        }
    }
}

/// Build a non-rejecting enrichment interceptor bound to `registry`.
///
/// When a valid credential token is present, injects the [`VerifiedCaller`];
/// otherwise passes the request through untouched. Applied to services that
/// self-validate authoritatively (`lifecycle`, `policy`) so a verified identity
/// is available consistently without double-rejecting or breaking the
/// unauthenticated bootstrap `Register` / optional-enrichment paths.
pub fn enrich_interceptor(
    registry: Arc<AgentRegistry>,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |mut req: Request<()>| {
        if let Some(token) = extract_token(&req) {
            if let Some(caller) = resolve_caller(&registry, &token) {
                req.extensions_mut().insert(caller);
            }
        }
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::AgentRecord;
    use std::collections::BTreeMap;
    use std::collections::VecDeque;

    fn record(agent_id: [u8; 16], token: &str, team: Option<&str>, org: Option<&str>) -> AgentRecord {
        AgentRecord {
            agent_id,
            name: "test".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "deadbeef".into(),
            credential_token: token.into(),
            metadata: BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: crate::registry::AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: VecDeque::new(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: team.map(|s| s.to_owned()),
            org_id: org.map(|s| s.to_owned()),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key: None,
            enforcement_mode: None,
        }
    }

    fn req_with_token(token: Option<&str>) -> Request<()> {
        let mut req = Request::new(());
        if let Some(t) = token {
            req.metadata_mut().insert(CREDENTIAL_METADATA_KEY, t.parse().unwrap());
        }
        req
    }

    #[test]
    fn auth_interceptor_rejects_missing_token() {
        let registry = Arc::new(AgentRegistry::new());
        let mut intercept = auth_interceptor(registry);
        let err = intercept(req_with_token(None)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn auth_interceptor_rejects_invalid_token() {
        let registry = Arc::new(AgentRegistry::new());
        let mut intercept = auth_interceptor(registry);
        let err = intercept(req_with_token(Some("not-a-registered-token"))).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn auth_interceptor_admits_valid_token_and_injects_caller() {
        let registry = Arc::new(AgentRegistry::new());
        registry
            .register(record([9u8; 16], "tok-abc", Some("team-a"), Some("org-x")))
            .unwrap();
        let mut intercept = auth_interceptor(Arc::clone(&registry));

        let req = intercept(req_with_token(Some("tok-abc"))).expect("valid token admitted");
        let caller = req.extensions().get::<VerifiedCaller>().expect("caller injected");
        assert_eq!(caller.agent_key, [9u8; 16]);
        assert_eq!(caller.team_id.as_deref(), Some("team-a"));
        assert_eq!(caller.org_id.as_deref(), Some("org-x"));
    }

    #[test]
    fn auth_interceptor_accepts_bearer_authorization_header() {
        let registry = Arc::new(AgentRegistry::new());
        registry.register(record([3u8; 16], "tok-bearer", None, None)).unwrap();
        let mut intercept = auth_interceptor(Arc::clone(&registry));

        let mut req = Request::new(());
        req.metadata_mut()
            .insert("authorization", "Bearer tok-bearer".parse().unwrap());
        let req = intercept(req).expect("bearer token admitted");
        assert!(req.extensions().get::<VerifiedCaller>().is_some());
    }

    #[test]
    fn enrich_interceptor_passes_through_without_token() {
        let registry = Arc::new(AgentRegistry::new());
        let mut intercept = enrich_interceptor(registry);
        let req = intercept(req_with_token(None)).expect("enrich never rejects");
        assert!(req.extensions().get::<VerifiedCaller>().is_none());
    }

    #[test]
    fn enrich_interceptor_injects_caller_when_token_valid() {
        let registry = Arc::new(AgentRegistry::new());
        registry
            .register(record([5u8; 16], "tok-enrich", Some("team-b"), None))
            .unwrap();
        let mut intercept = enrich_interceptor(Arc::clone(&registry));
        let req = intercept(req_with_token(Some("tok-enrich"))).expect("enrich never rejects");
        let caller = req.extensions().get::<VerifiedCaller>().expect("caller injected");
        assert_eq!(caller.team_id.as_deref(), Some("team-b"));
    }

    #[test]
    fn enrich_interceptor_ignores_invalid_token() {
        let registry = Arc::new(AgentRegistry::new());
        let mut intercept = enrich_interceptor(registry);
        let req = intercept(req_with_token(Some("bogus"))).expect("enrich never rejects");
        assert!(req.extensions().get::<VerifiedCaller>().is_none());
    }

    #[test]
    fn verified_caller_agent_id_str_is_canonical_uuid() {
        let caller = VerifiedCaller {
            agent_key: [0u8; 16],
            team_id: None,
            org_id: None,
        };
        assert_eq!(caller.agent_id_str(), "00000000-0000-0000-0000-000000000000");
    }

    // Behavior locks for the `extract_token` precedence/trim/fall-through logic
    // split into helpers by the AAASM-3823 S3776 refactor (must not change).
    #[test]
    fn extract_token_prefers_credential_header_over_authorization() {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert(CREDENTIAL_METADATA_KEY, "cred-tok".parse().unwrap());
        req.metadata_mut()
            .insert("authorization", "Bearer bearer-tok".parse().unwrap());
        assert_eq!(extract_token(&req).as_deref(), Some("cred-tok"));
    }

    #[test]
    fn extract_token_falls_back_to_authorization_when_credential_empty() {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert(CREDENTIAL_METADATA_KEY, "   ".parse().unwrap());
        req.metadata_mut()
            .insert("authorization", "Bearer bearer-tok".parse().unwrap());
        assert_eq!(extract_token(&req).as_deref(), Some("bearer-tok"));
    }

    #[test]
    fn extract_token_trims_credential_value() {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert(CREDENTIAL_METADATA_KEY, "  spaced  ".parse().unwrap());
        assert_eq!(extract_token(&req).as_deref(), Some("spaced"));
    }

    #[test]
    fn extract_token_accepts_lowercase_bearer_scheme() {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert("authorization", "bearer low-tok".parse().unwrap());
        assert_eq!(extract_token(&req).as_deref(), Some("low-tok"));
    }

    #[test]
    fn extract_token_none_when_no_headers() {
        let req = Request::new(());
        assert_eq!(extract_token(&req), None);
    }
}
