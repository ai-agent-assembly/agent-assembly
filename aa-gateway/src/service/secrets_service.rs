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

use crate::secrets::resolver::resolve_placeholders;
use crate::secrets::{SecretInjectionError, SecretsStore};

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
        let req = request.into_inner();

        // Decode the placeholder-form args from canonical JSON bytes.
        let placeholder_args: serde_json::Value = serde_json::from_slice(&req.args_json)
            .map_err(|e| Status::invalid_argument(format!("args_json is not valid JSON: {e}")))?;

        // Resolve placeholders against the shared store.
        let outcome = resolve_placeholders(&placeholder_args, self.secrets_store.as_ref()).map_err(|e| match e {
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
    use crate::secrets::{InMemorySecretsStore, Secret};
    use serde_json::json;

    fn populated_store(entries: &[(&str, &str)]) -> Arc<dyn SecretsStore> {
        let store = InMemorySecretsStore::new();
        for (name, value) in entries {
            store
                .register(Secret {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                })
                .expect("register synthetic test secret");
        }
        Arc::new(store)
    }

    #[tokio::test]
    async fn dispatch_tool_returns_resolved_args_on_success() {
        let svc = SecretsServiceImpl::new(populated_store(&[("DB_PASSWORD", "real-secret-abc")]));
        let req = Request::new(DispatchToolRequest {
            tool: "call_database".to_owned(),
            args_json: serde_json::to_vec(&json!({"connection_string": "${DB_PASSWORD}"})).unwrap(),
        });

        let resp = svc.dispatch_tool(req).await.expect("dispatch ok").into_inner();
        let resolved: serde_json::Value = serde_json::from_slice(&resp.resolved_args_json).unwrap();
        assert_eq!(resolved, json!({"connection_string": "real-secret-abc"}));
        assert_eq!(resp.names_substituted, vec!["DB_PASSWORD"]);
    }

    #[tokio::test]
    async fn dispatch_tool_returns_failed_precondition_on_unknown_placeholder() {
        let svc = SecretsServiceImpl::new(populated_store(&[("DB_PASSWORD", "real-secret-abc")]));
        let req = Request::new(DispatchToolRequest {
            tool: "call_database".to_owned(),
            args_json: serde_json::to_vec(&json!({"x": "${UNKNOWN_SECRET}"})).unwrap(),
        });

        let err = svc
            .dispatch_tool(req)
            .await
            .expect_err("unknown placeholder must error");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("UNKNOWN_SECRET"));
    }

    #[tokio::test]
    async fn dispatch_tool_returns_invalid_argument_on_malformed_json() {
        let svc = SecretsServiceImpl::new(populated_store(&[]));
        let req = Request::new(DispatchToolRequest {
            tool: "x".to_owned(),
            args_json: b"\xff\xff not json \xff".to_vec(),
        });

        let err = svc.dispatch_tool(req).await.expect_err("malformed args must error");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
