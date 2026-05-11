//! Python-facing `AssemblyHandle` — the return type of `init_assembly()`.
//!
//! Manages the lifecycle of the IPC connection to `aa-runtime`. Supports
//! the Python context manager protocol (`with init_assembly() as handle:`).

use std::sync::Mutex;

use pyo3::prelude::*;

use aa_core::CredentialScanner;

use crate::ipc::{IpcCommand, IpcHandle};

/// Handle to an active Agent Assembly session.
///
/// Returned by `init_assembly()`. Provides methods to report events to the
/// runtime and to shut down the connection. Supports the Python context
/// manager protocol.
///
/// ```python
/// with init_assembly(agent_id="my-agent") as handle:
///     handle.report_event("tool_call", {"tool": "search"})
/// # connection is cleaned up automatically
/// ```
#[pyclass]
pub struct AssemblyHandle {
    inner: Mutex<Option<IpcHandle>>,
    detected_frameworks: Vec<String>,
    scanner: Option<CredentialScanner>,
}

impl AssemblyHandle {
    /// Create a new handle with default credential scanning enabled.
    pub fn new(ipc_handle: IpcHandle, detected_frameworks: Vec<String>) -> Self {
        Self::with_scanner(ipc_handle, detected_frameworks, Some(CredentialScanner::new()))
    }

    /// Create a new handle with an explicit scanner configuration.
    ///
    /// Pass `None` to disable credential scanning, or `Some(scanner)` to use
    /// a custom-configured [`CredentialScanner`].
    pub fn with_scanner(
        ipc_handle: IpcHandle,
        detected_frameworks: Vec<String>,
        scanner: Option<CredentialScanner>,
    ) -> Self {
        Self {
            inner: Mutex::new(Some(ipc_handle)),
            detected_frameworks,
            scanner,
        }
    }
}

#[pymethods]
impl AssemblyHandle {
    /// Report an audit event to the runtime.
    ///
    /// Args:
    ///     event_type: The type of event (e.g., "tool_call", "llm_response").
    ///     details: Human-readable description of the event.
    pub fn report_event(&self, event_type: String, details: String) -> PyResult<()> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}")))?;

        let ipc = guard.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("AssemblyHandle is shut down; cannot report events")
        })?;

        // Redact any credentials from user-supplied details before they enter
        // the audit pipeline.
        let safe_details = if let Some(scanner) = &self.scanner {
            let scan_result = scanner.scan(&details);
            if scan_result.is_clean() {
                details
            } else {
                tracing::warn!(
                    findings = scan_result.findings.len(),
                    "credentials detected in report_event details, redacting"
                );
                scan_result.redact(&details)
            }
        } else {
            details
        };

        let mut labels = std::collections::HashMap::new();
        labels.insert("event_type".to_string(), event_type);
        labels.insert("details".to_string(), safe_details);

        let event = aa_proto::assembly::audit::v1::AuditEvent {
            event_id: unique_event_id(),
            labels,
            ..Default::default()
        };

        ipc.cmd_tx
            .blocking_send(IpcCommand::SendEvent(Box::new(event)))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("failed to enqueue event: {e}")))?;

        Ok(())
    }

    /// Report an LLM call to the runtime with typed metadata.
    ///
    /// Builds an `AuditEvent` with `LlmCallDetail` and sends it through the
    /// IPC command channel. Used by Python hook modules (e.g. `aa_hooks.openai`)
    /// to report intercepted LLM API calls.
    ///
    /// Args:
    ///     model: Model identifier (e.g. "gpt-4o", "claude-3-5-sonnet").
    ///     prompt_tokens: Token count in the prompt (from usage metadata).
    ///     completion_tokens: Token count in the completion (from usage metadata).
    ///     latency_ms: End-to-end call latency in milliseconds.
    ///     provider: Inference provider name (e.g. "openai", "anthropic").
    #[pyo3(signature = (model, prompt_tokens=0, completion_tokens=0, latency_ms=0, provider="unknown"))]
    pub fn report_llm_call(
        &self,
        model: String,
        prompt_tokens: i32,
        completion_tokens: i32,
        latency_ms: i64,
        provider: &str,
    ) -> PyResult<()> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}")))?;

        let ipc = guard.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("AssemblyHandle is shut down; cannot report events")
        })?;

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

        ipc.cmd_tx
            .blocking_send(IpcCommand::SendEvent(Box::new(event)))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("failed to enqueue event: {e}")))?;

        Ok(())
    }

    /// Report a directed topology edge between two agents.
    ///
    /// Called by framework adapter hooks (LangGraph, OpenAI Agents, MCP) when
    /// they detect inter-agent interactions. The edge is encoded into an
    /// `AuditEvent` with structured labels and forwarded to the audit pipeline;
    /// the gateway extracts and persists it into the edge store.
    ///
    /// Args:
    ///     source_agent_id: Hex-encoded ID of the originating agent.
    ///     target_agent_id: Hex-encoded ID of the target agent.
    ///     edge_type:       Relationship kind — one of `delegates_to`, `calls`,
    ///                      `reads`, `writes`, `approves`, `messages`.
    ///     metadata_json:   Optional JSON string with extra context.
    #[pyo3(signature = (source_agent_id, target_agent_id, edge_type, metadata_json=None))]
    pub fn report_edge(
        &self,
        source_agent_id: String,
        target_agent_id: String,
        edge_type: String,
        metadata_json: Option<String>,
    ) -> PyResult<()> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}")))?;

        let ipc = guard.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("AssemblyHandle is shut down; cannot report events")
        })?;

        let mut labels = std::collections::HashMap::new();
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

        ipc.cmd_tx
            .blocking_send(IpcCommand::SendEvent(Box::new(event)))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("failed to enqueue event: {e}")))?;

        Ok(())
    }

    /// Shut down the IPC connection and join the background thread.
    ///
    /// Safe to call multiple times — subsequent calls are no-ops.
    pub fn shutdown(&self, py: Python<'_>) -> PyResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}")))?;

        if let Some(mut ipc) = guard.take() {
            // Send shutdown command (best-effort — channel may be closed).
            let _ = ipc.cmd_tx.blocking_send(IpcCommand::Shutdown);

            // Join the background thread, releasing the GIL to avoid deadlock.
            if let Some(thread) = ipc.thread.take() {
                py.detach(|| {
                    let _ = thread.join();
                });
            }
        }

        Ok(())
    }

    /// Returns the list of detected AI frameworks.
    pub fn detected_frameworks(&self) -> Vec<String> {
        self.detected_frameworks.clone()
    }

    /// Context manager entry — returns `self`.
    pub fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context manager exit — calls `shutdown()`.
    pub fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.shutdown(py)?;
        Ok(false) // Do not suppress exceptions.
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
    use crate::ipc::{IpcCommand, IpcHandle};
    use tokio::sync::mpsc;

    /// Create an `AssemblyHandle` backed by a test mpsc channel (no real socket).
    fn make_test_handle() -> (AssemblyHandle, mpsc::Receiver<IpcCommand>) {
        let (tx, rx) = mpsc::channel(16);
        let ipc = IpcHandle {
            cmd_tx: tx,
            thread: None,
        };
        (AssemblyHandle::new(ipc, vec![]), rx)
    }

    /// Create a test handle backed by a real mpsc channel (no socket).
    /// Returns `(handle, receiver)` so tests can inspect sent commands.
    fn test_handle() -> (AssemblyHandle, tokio::sync::mpsc::Receiver<IpcCommand>) {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let ipc = IpcHandle {
            cmd_tx: tx,
            thread: None,
        };
        let handle = AssemblyHandle::new(ipc, vec!["openai".to_string()]);
        (handle, rx)
    }

    #[test]
    fn unique_event_id_is_nonempty() {
        let id = unique_event_id();
        assert!(!id.is_empty());
    }

    #[test]
    fn unique_event_id_unique() {
        let a = unique_event_id();
        let b = unique_event_id();
        // Not strictly guaranteed but extremely likely with nanos.
        assert_ne!(a, b);
    }

    #[test]
    fn report_llm_call_sends_event_with_llm_detail() {
        use aa_proto::assembly::audit::v1::audit_event;

        let (handle, mut rx) = test_handle();

        handle
            .report_llm_call("gpt-4o".to_string(), 100, 50, 1234, "openai")
            .unwrap();

        let cmd = rx.try_recv().expect("should have received a command");
        match cmd {
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
    fn report_llm_call_on_shutdown_handle_returns_error() {
        pyo3::Python::initialize();
        let (handle, _rx) = test_handle();

        // Shut down the handle first.
        Python::attach(|py| handle.shutdown(py).unwrap());

        // Now report_llm_call should fail.
        let result = handle.report_llm_call("gpt-4o".to_string(), 0, 0, 0, "openai");
        let err = result.expect_err("should error on shutdown handle");
        assert!(err.to_string().contains("shut down"));
    }

    #[test]
    fn report_llm_call_defaults_are_applied() {
        use aa_proto::assembly::audit::v1::audit_event;

        let (handle, mut rx) = test_handle();

        // Call with only model — other args use defaults.
        handle
            .report_llm_call("claude-3".to_string(), 0, 0, 0, "unknown")
            .unwrap();

        let cmd = rx.try_recv().expect("should have received a command");
        match cmd {
            IpcCommand::SendEvent(event) => {
                if let Some(audit_event::Detail::LlmCall(ref d)) = event.detail {
                    assert_eq!(d.model, "claude-3");
                    assert_eq!(d.prompt_tokens, 0);
                    assert_eq!(d.completion_tokens, 0);
                    assert_eq!(d.latency_ms, 0);
                    assert_eq!(d.provider, "unknown");
                } else {
                    panic!("expected LlmCall detail");
                }
            }
            other => panic!("expected SendEvent, got {:?}", other),
        }
    }

    #[test]
    fn report_event_redacts_credentials_in_details() {
        let (handle, mut rx) = make_test_handle();
        let secret = "sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab";
        let details = format!("called openai with key {secret}");

        handle.report_event("llm_call".into(), details).unwrap();

        let cmd = rx.try_recv().expect("should receive command");
        match cmd {
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
        let (handle, mut rx) = make_test_handle();

        handle
            .report_event("tool_call".into(), "searched for cats".into())
            .unwrap();

        let cmd = rx.try_recv().expect("should receive command");
        match cmd {
            IpcCommand::SendEvent(event) => {
                assert_eq!(event.labels.get("details").unwrap(), "searched for cats");
            }
            other => panic!("expected SendEvent, got {other:?}"),
        }
    }

    #[test]
    fn report_event_with_scanner_disabled_passes_details_through() {
        let (tx, mut rx) = mpsc::channel(16);
        let ipc = IpcHandle {
            cmd_tx: tx,
            thread: None,
        };
        let handle = AssemblyHandle::with_scanner(ipc, vec![], None);
        let secret = "sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab";
        let details = format!("key is {secret}");

        handle.report_event("llm_call".into(), details.clone()).unwrap();

        let cmd = rx.try_recv().expect("should receive command");
        match cmd {
            IpcCommand::SendEvent(event) => {
                // Scanner is disabled — raw credential passes through.
                assert_eq!(event.labels.get("details").unwrap(), &details);
            }
            other => panic!("expected SendEvent, got {other:?}"),
        }
    }
}
