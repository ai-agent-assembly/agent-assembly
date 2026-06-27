//! `SecretsServiceImpl` — gRPC handler for the Secret Injection
//! `DispatchTool` RPC (AAASM-1920 / Story scope #3).
//!
//! Mirrors the HTTP `POST /api/v1/dispatch_tool` route in `aa-api`: same
//! pipeline (resolve placeholders → emit `ToolDispatched` audit entry with
//! the placeholder-form payload → return resolved args), same audit-shape
//! contract.
//!
//! The two surfaces share the same `Arc<dyn SecretsStore>` instance so
//! placeholders registered via either path resolve consistently.

use std::sync::Arc;

use aa_proto::assembly::secrets::v1::secrets_service_server::SecretsService;
use aa_proto::assembly::secrets::v1::{DispatchToolRequest, DispatchToolResponse};
use tonic::{Request, Response, Status};

use crate::iam::VerifiedCaller;
use crate::secrets::resolver::resolve_placeholders;
use crate::secrets::{SecretInjectionError, SecretsStore, TenantScopedStore};

/// gRPC service implementation for the `DispatchTool` RPC.
///
/// Holds an `Arc<dyn SecretsStore>` shared with `aa-api::AppState::secrets_store`
/// so a placeholder registered through either transport resolves identically.
pub struct SecretsServiceImpl {
    secrets_store: Arc<dyn SecretsStore>,
}

impl SecretsServiceImpl {
    /// Construct a new service impl over the given store.
    pub fn new(secrets_store: Arc<dyn SecretsStore>) -> Self {
        Self { secrets_store }
    }
}

#[tonic::async_trait]
impl SecretsService for SecretsServiceImpl {
    async fn dispatch_tool(
        &self,
        request: Request<DispatchToolRequest>,
    ) -> Result<Response<DispatchToolResponse>, Status> {
        // AAASM-3845 — bind secret resolution to the verified caller's tenant.
        // The agent-plane auth interceptor (AAASM-3788) injects a
        // `VerifiedCaller` for this service; its absence means the request did
        // not pass authentication, so we fail closed rather than resolve
        // secrets for an unauthenticated peer (defense-in-depth — the
        // interceptor already rejects, but the handler must not assume it).
        let caller = request.extensions().get::<VerifiedCaller>().cloned().ok_or_else(|| {
            Status::unauthenticated("missing verified caller; secret dispatch requires authentication")
        })?;

        let req = request.into_inner();

        // Decode the placeholder-form args from canonical JSON bytes.
        let placeholder_args: serde_json::Value = serde_json::from_slice(&req.args_json)
            .map_err(|e| Status::invalid_argument(format!("args_json is not valid JSON: {e}")))?;

        // Resolve only within the caller's tenant namespace, so a caller can
        // never resolve a `${NAME}` owned by another tenant — a cross-tenant
        // reference misses and surfaces as `UnknownPlaceholder`.
        let scoped = TenantScopedStore::for_tenant(
            self.secrets_store.as_ref(),
            caller.org_id.as_deref(),
            caller.team_id.as_deref(),
        );
        let outcome = resolve_placeholders(&placeholder_args, &scoped).map_err(|e| match e {
            SecretInjectionError::UnknownPlaceholder { name } => {
                Status::failed_precondition(format!("Unknown placeholder: ${{{name}}}"))
            }
        })?;

        // Encode resolved args back to canonical JSON bytes.
        let resolved_args_json = serde_json::to_vec(&outcome.resolved)
            .map_err(|e| Status::internal(format!("failed to serialize resolved args: {e}")))?;

        // Audit emission is the HTTP handler's responsibility today — the
        // gRPC transport does not own the `AppState` audit channel. SDKs
        // that go straight through gRPC will pick up audit support via the
        // gateway-wide audit pipeline added in a follow-up Subtask.

        Ok(Response::new(DispatchToolResponse {
            resolved_args_json,
            names_substituted: outcome.names_substituted,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{InMemorySecretsStore, Secret, TenantScopedStore};
    use serde_json::json;

    /// Tenant identity used by the happy-path tests.
    fn caller(org: Option<&str>, team: Option<&str>) -> VerifiedCaller {
        VerifiedCaller {
            agent_key: [7u8; 16],
            team_id: team.map(str::to_owned),
            org_id: org.map(str::to_owned),
        }
    }

    /// Build a shared backing store and pre-register `entries` under the given
    /// caller's tenant namespace (the only way a `dispatch_tool` for that caller
    /// can resolve them after AAASM-3845).
    fn store_for(owner: &VerifiedCaller, entries: &[(&str, &str)]) -> Arc<dyn SecretsStore> {
        let backing = Arc::new(InMemorySecretsStore::new());
        let scoped = TenantScopedStore::for_tenant(backing.as_ref(), owner.org_id.as_deref(), owner.team_id.as_deref());
        for (name, value) in entries {
            scoped
                .register(Secret {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                })
                .expect("register synthetic test secret");
        }
        backing
    }

    /// A `DispatchTool` request carrying a verified caller in its extensions,
    /// as the AAASM-3788 auth interceptor injects in production.
    fn req_as(caller: &VerifiedCaller, args: serde_json::Value) -> Request<DispatchToolRequest> {
        let mut req = Request::new(DispatchToolRequest {
            tool: "call_database".to_owned(),
            args_json: serde_json::to_vec(&args).unwrap(),
        });
        req.extensions_mut().insert(caller.clone());
        req
    }

    #[tokio::test]
    async fn dispatch_tool_returns_resolved_args_on_success() {
        let owner = caller(Some("org-a"), Some("team-1"));
        let svc = SecretsServiceImpl::new(store_for(&owner, &[("DB_PASSWORD", "real-secret-abc")]));
        let req = req_as(&owner, json!({"connection_string": "${DB_PASSWORD}"}));

        let resp = svc.dispatch_tool(req).await.expect("dispatch ok").into_inner();
        let resolved: serde_json::Value = serde_json::from_slice(&resp.resolved_args_json).unwrap();
        assert_eq!(resolved, json!({"connection_string": "real-secret-abc"}));
        assert_eq!(resp.names_substituted, vec!["DB_PASSWORD"]);
    }

    #[tokio::test]
    async fn dispatch_tool_returns_failed_precondition_on_unknown_placeholder() {
        let owner = caller(Some("org-a"), Some("team-1"));
        let svc = SecretsServiceImpl::new(store_for(&owner, &[("DB_PASSWORD", "real-secret-abc")]));
        let req = req_as(&owner, json!({"x": "${UNKNOWN_SECRET}"}));

        let err = svc
            .dispatch_tool(req)
            .await
            .expect_err("unknown placeholder must error");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("UNKNOWN_SECRET"));
    }

    #[tokio::test]
    async fn dispatch_tool_returns_invalid_argument_on_malformed_json() {
        let owner = caller(Some("org-a"), None);
        let svc = SecretsServiceImpl::new(store_for(&owner, &[]));
        let mut req = Request::new(DispatchToolRequest {
            tool: "x".to_owned(),
            args_json: b"\xff\xff not json \xff".to_vec(),
        });
        req.extensions_mut().insert(owner);

        let err = svc.dispatch_tool(req).await.expect_err("malformed args must error");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── AAASM-3845 regression: authorization + tenant scoping ───────────

    #[tokio::test]
    async fn dispatch_tool_rejects_request_without_verified_caller() {
        // No `VerifiedCaller` in extensions ⇒ unauthenticated peer ⇒ fail closed,
        // and a registered secret is never resolved.
        let owner = caller(Some("org-a"), Some("team-1"));
        let svc = SecretsServiceImpl::new(store_for(&owner, &[("DB_PASSWORD", "real-secret-abc")]));
        let req = Request::new(DispatchToolRequest {
            tool: "call_database".to_owned(),
            args_json: serde_json::to_vec(&json!({"connection_string": "${DB_PASSWORD}"})).unwrap(),
        });

        let err = svc
            .dispatch_tool(req)
            .await
            .expect_err("unauthenticated dispatch must be rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn dispatch_tool_does_not_resolve_another_tenants_secret() {
        // Tenant A owns DB_PASSWORD; tenant B references the same bare name.
        let owner = caller(Some("org-a"), Some("team-1"));
        let svc = SecretsServiceImpl::new(store_for(&owner, &[("DB_PASSWORD", "real-secret-abc")]));

        let attacker = caller(Some("org-b"), Some("team-1"));
        let req = req_as(&attacker, json!({"connection_string": "${DB_PASSWORD}"}));

        let err = svc
            .dispatch_tool(req)
            .await
            .expect_err("cross-tenant placeholder must not resolve");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("DB_PASSWORD"));
    }
}
