//! `AssemblyClient` — the FFI-agnostic core of an Agent Assembly SDK session.
//!
//! Owns the lifecycle of the IPC connection to `aa-runtime` and provides the
//! event-shipping API (`report_event` / `report_llm_call` / `report_edge` /
//! `shutdown`) that the per-language FFI shims wrap. Every method returns a
//! plain [`Result`]`<_, `[`SdkClientError`]`>`; there is no language-runtime
//! (pyo3 / napi / cgo) coupling in this crate.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::config::AssemblyConfig;
use crate::error::SdkClientError;
use crate::gateway::{build_register_request, GatewayRegistrationClient};
use crate::ipc::{IpcCommand, IpcHandle};
#[cfg(feature = "preflight")]
use crate::preflight::Preflight;

/// How long [`AssemblyClient::query_policy`] blocks for a runtime decision
/// before failing open with [`SdkClientError::QueryFailed`].
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Handle to an active Agent Assembly session.
///
/// Wraps the background IPC connection to `aa-runtime`. Construct one with
/// [`AssemblyClient::new`], report events through it, and call
/// [`AssemblyClient::shutdown`] when done (the FFI shims tie this to their
/// language's resource-management protocol, e.g. Python's context manager).
pub struct AssemblyClient {
    inner: Mutex<Option<IpcHandle>>,
    detected_frameworks: Vec<String>,
    /// Credential token issued by the gateway at [`register`](Self::register).
    /// `None` until registration succeeds; attached to every `CheckActionRequest`
    /// so the gateway's `validate_credential_token` does not deny the call.
    credential_token: Mutex<Option<String>>,
    #[cfg(feature = "preflight")]
    preflight: Option<Preflight>,
}

impl AssemblyClient {
    /// Create a client with the default advisory preflight enabled (when the
    /// `preflight` feature is on).
    pub fn new(ipc_handle: IpcHandle, detected_frameworks: Vec<String>) -> Self {
        Self {
            inner: Mutex::new(Some(ipc_handle)),
            detected_frameworks,
            credential_token: Mutex::new(None),
            #[cfg(feature = "preflight")]
            preflight: Some(Preflight::new()),
        }
    }

    /// Create a client with an explicit advisory preflight configuration.
    ///
    /// Pass `None` to disable local preflight (the runtime still scans
    /// authoritatively), or `Some(preflight)` to use a custom one.
    #[cfg(feature = "preflight")]
    pub fn with_preflight(
        ipc_handle: IpcHandle,
        detected_frameworks: Vec<String>,
        preflight: Option<Preflight>,
    ) -> Self {
        Self {
            inner: Mutex::new(Some(ipc_handle)),
            detected_frameworks,
            credential_token: Mutex::new(None),
            preflight,
        }
    }

    /// Apply the advisory preflight redactor to user-supplied text.
    ///
    /// Advisory only — the runtime re-scans every event authoritatively.
    #[cfg(feature = "preflight")]
    fn apply_preflight(&self, details: String) -> String {
        match &self.preflight {
            Some(pf) => pf.advisory_redact(details),
            None => details,
        }
    }

    #[cfg(not(feature = "preflight"))]
    fn apply_preflight(&self, details: String) -> String {
        details
    }

    /// Register this agent with the governance gateway over a direct gRPC call
    /// and store the issued `credential_token`.
    ///
    /// Per ADR 0004 this is the *only* direct SDK→gateway call; `CheckAction`
    /// continues to flow through the `aa-runtime` UDS forward. The stored token
    /// is then attached to every [`query_policy`](Self::query_policy) request so
    /// the gateway's `validate_credential_token` does not deny a registered
    /// agent.
    ///
    /// `config` supplies the agent identity (its `agent_id` is derived into a
    /// `did:key` + a consistent Ed25519 `public_key`) and the gateway gRPC
    /// endpoint. Returns the assigned policy id from the gateway on success.
    pub async fn register(
        &self,
        config: &AssemblyConfig,
        name: String,
        framework: String,
    ) -> Result<String, SdkClientError> {
        let endpoint = config.resolve_gateway_endpoint();
        let request = build_register_request(config, name, framework);

        let mut client = GatewayRegistrationClient::connect(endpoint).await?;
        let response = client.register(request).await?;

        {
            let mut guard = self.credential_token.lock().map_err(|_| SdkClientError::LockPoisoned)?;
            *guard = Some(response.credential_token);
        }

        Ok(response.assigned_policy)
    }

    /// Return the stored gateway credential token, if registration has run.
    pub fn credential_token(&self) -> Option<String> {
        self.credential_token.lock().ok().and_then(|g| g.clone())
    }

    /// Enqueue an already-built event onto the IPC command channel.
    fn send(&self, event: aa_proto::assembly::audit::v1::AuditEvent) -> Result<(), SdkClientError> {
        let guard = self.inner.lock().map_err(|_| SdkClientError::LockPoisoned)?;
        let ipc = guard.as_ref().ok_or(SdkClientError::Shutdown)?;
        ipc.cmd_tx
            .blocking_send(IpcCommand::SendEvent(Box::new(event)))
            .map_err(|_| SdkClientError::ChannelClosed)
    }

    /// Report an audit event to the runtime.
    ///
    /// `details` passes through the advisory preflight before shipping; the
    /// runtime re-scans regardless.
    pub fn report_event(&self, event_type: String, details: String) -> Result<(), SdkClientError> {
        let safe_details = self.apply_preflight(details);

        let mut labels = HashMap::new();
        labels.insert("event_type".to_string(), event_type);
        labels.insert("details".to_string(), safe_details);

        let event = aa_proto::assembly::audit::v1::AuditEvent {
            event_id: unique_event_id(),
            labels,
            ..Default::default()
        };

        self.send(event)
    }

    /// Report an LLM call to the runtime with typed metadata.
    pub fn report_llm_call(
        &self,
        model: String,
        prompt_tokens: i32,
        completion_tokens: i32,
        latency_ms: i64,
        provider: &str,
    ) -> Result<(), SdkClientError> {
        use aa_proto::assembly::audit::v1::{audit_event, AuditEvent, LlmCallDetail};
        use aa_proto::assembly::common::v1::ActionType;

        let detail = LlmCallDetail {
            model,
            prompt_tokens,
            completion_tokens,
            latency_ms,
            provider: provider.to_string(),
            ..Default::default()
        };

        let event = AuditEvent {
            event_id: unique_event_id(),
            action_type: ActionType::LlmCall.into(),
            detail: Some(audit_event::Detail::LlmCall(detail)),
            ..Default::default()
        };

        self.send(event)
    }

    /// Report a directed topology edge between two agents.
    pub fn report_edge(
        &self,
        source_agent_id: String,
        target_agent_id: String,
        edge_type: String,
        metadata_json: Option<String>,
    ) -> Result<(), SdkClientError> {
        let mut labels = HashMap::new();
        labels.insert("__aa_edge_source__".to_string(), source_agent_id);
        labels.insert("__aa_edge_target__".to_string(), target_agent_id);
        labels.insert("__aa_edge_type__".to_string(), edge_type);
        if let Some(m) = metadata_json {
            labels.insert("__aa_edge_metadata__".to_string(), m);
        }

        let event = aa_proto::assembly::audit::v1::AuditEvent {
            event_id: unique_event_id(),
            labels,
            ..Default::default()
        };

        self.send(event)
    }

    /// Synchronously query the runtime for a policy decision on an action.
    ///
    /// Sends a `CheckActionRequest` to `aa-runtime` over the IPC connection and
    /// blocks (up to [`QUERY_TIMEOUT`]) for the `CheckActionResponse`. Returns
    /// [`SdkClientError::QueryFailed`] when the runtime does not answer in time
    /// or the connection closes — callers must treat that as *fail-open* (the
    /// SDK is advisory; the runtime/proxy/eBPF layers are authoritative).
    ///
    /// FFI shims that hold a language-runtime lock (e.g. Python's GIL) should
    /// release it around this call, since it blocks the calling thread.
    pub fn query_policy(
        &self,
        request: aa_proto::assembly::policy::v1::CheckActionRequest,
    ) -> Result<aa_proto::assembly::policy::v1::CheckActionResponse, SdkClientError> {
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();

        // Enqueue under the lock, then release it before blocking on the
        // response so a slow runtime cannot stall shutdown or other calls.
        {
            let guard = self.inner.lock().map_err(|_| SdkClientError::LockPoisoned)?;
            let ipc = guard.as_ref().ok_or(SdkClientError::Shutdown)?;
            ipc.cmd_tx
                .blocking_send(IpcCommand::QueryPolicy {
                    request: Box::new(request),
                    resp: resp_tx,
                })
                .map_err(|_| SdkClientError::ChannelClosed)?;
        }

        resp_rx
            .recv_timeout(QUERY_TIMEOUT)
            .map_err(|_| SdkClientError::QueryFailed)
    }

    /// Shut down the IPC connection and join the background thread.
    ///
    /// Safe to call multiple times — subsequent calls are no-ops. FFI shims
    /// that hold a runtime lock (e.g. Python's GIL) should release it around
    /// this call, since it blocks on the background thread join.
    pub fn shutdown(&self) -> Result<(), SdkClientError> {
        let mut guard = self.inner.lock().map_err(|_| SdkClientError::LockPoisoned)?;

        if let Some(mut ipc) = guard.take() {
            // Best-effort shutdown signal — the channel may already be closed.
            let _ = ipc.cmd_tx.blocking_send(IpcCommand::Shutdown);

            if let Some(thread) = ipc.thread.take() {
                let _ = thread.join();
            }
        }

        Ok(())
    }

    /// Returns the list of detected AI frameworks.
    pub fn detected_frameworks(&self) -> Vec<String> {
        self.detected_frameworks.clone()
    }
}

/// Generate a unique event ID string.
fn unique_event_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{:016x}-{:08x}-{:04x}", nanos, pid, seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    /// Build an `AssemblyClient` backed by a test mpsc channel (no real socket).
    fn test_client(frameworks: Vec<String>) -> (AssemblyClient, mpsc::Receiver<IpcCommand>) {
        let (tx, rx) = mpsc::channel(16);
        let ipc = IpcHandle {
            cmd_tx: tx,
            thread: None,
        };
        (AssemblyClient::new(ipc, frameworks), rx)
    }

    #[test]
    fn unique_event_id_is_nonempty() {
        assert!(!unique_event_id().is_empty());
    }

    #[test]
    fn unique_event_id_unique() {
        assert_ne!(unique_event_id(), unique_event_id());
    }

    #[test]
    fn detected_frameworks_are_returned() {
        let (client, _rx) = test_client(vec!["openai".to_string()]);
        assert_eq!(client.detected_frameworks(), vec!["openai".to_string()]);
    }

    #[test]
    fn report_llm_call_sends_event_with_llm_detail() {
        use aa_proto::assembly::audit::v1::audit_event;

        let (client, mut rx) = test_client(vec![]);
        client
            .report_llm_call("gpt-4o".to_string(), 100, 50, 1234, "openai")
            .unwrap();

        match rx.try_recv().expect("should have received a command") {
            IpcCommand::SendEvent(event) => {
                assert!(!event.event_id.is_empty());
                assert_eq!(
                    event.action_type,
                    i32::from(aa_proto::assembly::common::v1::ActionType::LlmCall)
                );
                match event.detail {
                    Some(audit_event::Detail::LlmCall(ref d)) => {
                        assert_eq!(d.model, "gpt-4o");
                        assert_eq!(d.prompt_tokens, 100);
                        assert_eq!(d.completion_tokens, 50);
                        assert_eq!(d.latency_ms, 1234);
                        assert_eq!(d.provider, "openai");
                    }
                    other => panic!("expected LlmCall detail, got {:?}", other),
                }
            }
            other => panic!("expected SendEvent, got {:?}", other),
        }
    }

    #[test]
    fn report_on_shutdown_client_returns_error() {
        let (client, _rx) = test_client(vec![]);
        client.shutdown().unwrap();
        let err = client
            .report_llm_call("gpt-4o".to_string(), 0, 0, 0, "openai")
            .expect_err("should error on a shut-down client");
        assert!(matches!(err, SdkClientError::Shutdown));
    }

    #[test]
    fn report_edge_sets_edge_labels() {
        let (client, mut rx) = test_client(vec![]);
        client
            .report_edge("a".into(), "b".into(), "delegates_to".into(), None)
            .unwrap();

        match rx.try_recv().expect("should receive command") {
            IpcCommand::SendEvent(event) => {
                assert_eq!(event.labels.get("__aa_edge_source__").unwrap(), "a");
                assert_eq!(event.labels.get("__aa_edge_target__").unwrap(), "b");
                assert_eq!(event.labels.get("__aa_edge_type__").unwrap(), "delegates_to");
            }
            other => panic!("expected SendEvent, got {other:?}"),
        }
    }

    #[cfg(feature = "preflight")]
    #[test]
    fn report_event_redacts_credentials_in_details() {
        let (client, mut rx) = test_client(vec![]);
        let secret = "sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab";

        client
            .report_event("llm_call".into(), format!("called openai with key {secret}"))
            .unwrap();

        match rx.try_recv().expect("should receive command") {
            IpcCommand::SendEvent(event) => {
                let labels_str = format!("{:?}", event.labels);
                assert!(
                    !labels_str.contains("sk-proj-"),
                    "details label must not contain raw credential, got: {labels_str}"
                );
                assert!(
                    labels_str.contains("[REDACTED:"),
                    "details label should contain redaction marker"
                );
            }
            other => panic!("expected SendEvent, got {other:?}"),
        }
    }

    #[test]
    fn report_event_passes_clean_details_unchanged() {
        let (client, mut rx) = test_client(vec![]);
        client
            .report_event("tool_call".into(), "searched for cats".into())
            .unwrap();

        match rx.try_recv().expect("should receive command") {
            IpcCommand::SendEvent(event) => {
                assert_eq!(event.labels.get("details").unwrap(), "searched for cats");
            }
            other => panic!("expected SendEvent, got {other:?}"),
        }
    }

    #[cfg(feature = "preflight")]
    #[test]
    fn report_event_with_preflight_disabled_passes_details_through() {
        let (tx, mut rx) = mpsc::channel(16);
        let ipc = IpcHandle {
            cmd_tx: tx,
            thread: None,
        };
        let client = AssemblyClient::with_preflight(ipc, vec![], None);
        let secret = "sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab";
        let details = format!("key is {secret}");

        client.report_event("llm_call".into(), details.clone()).unwrap();

        match rx.try_recv().expect("should receive command") {
            IpcCommand::SendEvent(event) => {
                // Preflight disabled — raw credential passes through locally; the
                // runtime still redacts it authoritatively.
                assert_eq!(event.labels.get("details").unwrap(), &details);
            }
            other => panic!("expected SendEvent, got {other:?}"),
        }
    }
}
