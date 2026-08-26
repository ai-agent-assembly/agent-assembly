//! AAASM-5930 — a real gateway carrying **both** `AgentLifecycleService`
//! (so a real `aasm run` session can register) and `PolicyService` (so a
//! real MCP `tools/call` reaching `aa-proxy`'s MCP enforcement bridge,
//! `aa_proxy::mcp_enforce`, gets a real policy adjudication) on one endpoint.
//!
//! Neither existing test double is sufficient on its own for a real governed
//! launch that also proves policy-gated tool-call enforcement:
//!
//! * `grpc_gateway_support::GrpcGateway` (AAASM-1112) implements only
//!   `AgentLifecycleService` — a real launch can register, but any MCP
//!   `tools/call` the proxy tries to adjudicate has nothing to ask and the
//!   proxy's `mcp_fail_open` config decides the outcome, not a real policy.
//! * `e2e_mcp_interceptor.rs`'s inline `proxy_e2e::start_gateway_with_mcp_policy`
//!   implements only `PolicyService` — real MCP enforcement, but nothing for
//!   `aasm run`'s own registration gate (AAASM-5323) to call, so the launch
//!   never gets past that precondition.
//!
//! Both services share one `Arc<AgentRegistry>`, matching how the real
//! `aa-gateway` binary (`aa-gateway/src/server.rs::serve_tcp`) wires them —
//! not two independently-consistent gateways that happen to sit behind the
//! same port.

use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::{AgentLifecycleServiceImpl, PolicyServiceImpl};
use aa_gateway::PolicyEngine;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use tokio::sync::mpsc;
use tonic::transport::Server;

/// Boot a combined `AgentLifecycleService` + `PolicyService` gRPC gateway
/// backed by the YAML policy at `policy_path`, on a free loopback port.
///
/// Returns the `http://` endpoint string `AA_GATEWAY_ENDPOINT` expects, and
/// the registry so a caller can assert on what actually registered (e.g. the
/// real `did:key` a governed launch derived, per AAASM-5323).
pub async fn start_full_gateway(policy_path: &Path) -> anyhow::Result<(String, Arc<AgentRegistry>)> {
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(
        PolicyEngine::load_from_file(policy_path, alert_tx)
            .map_err(|e| anyhow::anyhow!("policy fixture must load cleanly: {e:?}"))?,
    );
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, _audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let policy_service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    );
    let lifecycle_service = AgentLifecycleServiceImpl::new(Arc::clone(&registry));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = Server::builder()
            .add_service(PolicyServiceServer::new(policy_service))
            .add_service(AgentLifecycleServiceServer::new(lifecycle_service))
            .serve_with_incoming(incoming)
            .await;
    });
    // Mirrors proxy_e2e::start_gateway_with_mcp_policy's own settle beat — the
    // listener is bound synchronously above, but give the spawned task a
    // moment to actually reach `serve_with_incoming` before any caller dials.
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    Ok((format!("http://{addr}"), registry))
}
