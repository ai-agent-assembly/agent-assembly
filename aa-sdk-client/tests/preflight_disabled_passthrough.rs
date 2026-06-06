//! AAASM-2570 acceptance: preflight is advisory and optional. Disabling it lets
//! raw text pass through locally (the runtime still scans authoritatively) and
//! even then no trust marker is added to the event.
#![cfg(feature = "preflight")]

use aa_sdk_client::ipc::{IpcCommand, IpcHandle};
use aa_sdk_client::AssemblyClient;
use tokio::sync::mpsc;

#[test]
fn preflight_disabled_passes_text_through_without_marker() {
    let (tx, mut rx) = mpsc::channel(8);
    let client = AssemblyClient::with_preflight(
        IpcHandle {
            cmd_tx: tx,
            thread: None,
        },
        vec![],
        None,
    );
    let secret = "sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab";
    let details = format!("key is {secret}");

    client.report_event("llm_call".into(), details.clone()).unwrap();

    match rx.try_recv().expect("event should have been enqueued") {
        IpcCommand::SendEvent(event) => {
            // Local preflight off ⇒ raw text passes through unchanged here; the
            // runtime is responsible for the authoritative scan/redact.
            assert_eq!(event.labels.get("details").unwrap(), &details);
            // Still no trust marker added.
            assert_eq!(event.labels.len(), 2, "unexpected extra labels: {:?}", event.labels);
        }
        other => panic!("expected SendEvent, got {other:?}"),
    }
}
