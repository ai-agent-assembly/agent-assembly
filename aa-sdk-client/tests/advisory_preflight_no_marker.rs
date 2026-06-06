//! AAASM-2570 acceptance: the advisory preflight redacts credentials locally,
//! but **never** emits a trust marker on the wire. The runtime re-scans every
//! event unconditionally; nothing the SDK does may shorten that work.
#![cfg(feature = "preflight")]

use aa_sdk_client::ipc::{IpcCommand, IpcHandle};
use aa_sdk_client::AssemblyClient;
use tokio::sync::mpsc;

#[test]
fn advisory_preflight_redacts_and_emits_no_trust_marker() {
    let (tx, mut rx) = mpsc::channel(8);
    let client = AssemblyClient::new(
        IpcHandle {
            cmd_tx: tx,
            thread: None,
        },
        vec![],
    );
    let secret = "sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab";

    client
        .report_event("llm_call".into(), format!("called openai with key {secret}"))
        .unwrap();

    match rx.try_recv().expect("event should have been enqueued") {
        IpcCommand::SendEvent(event) => {
            // Advisory redaction happened locally.
            let details = event.labels.get("details").expect("details label present");
            assert!(!details.contains("sk-proj-"), "raw credential leaked: {details}");
            assert!(details.contains("[REDACTED:"), "expected redaction marker in details");

            // No `clean` / `already_scanned` / pre-scanned signal is ever placed
            // on the wire.
            for marker in [
                "clean",
                "scanned",
                "already_scanned",
                "preflight",
                "__aa_scanned__",
                "__aa_clean__",
            ] {
                assert!(
                    !event.labels.contains_key(marker),
                    "unexpected SDK trust marker on the wire: {marker}"
                );
            }

            // Only the two expected labels exist — no extra metadata smuggled in.
            assert_eq!(event.labels.len(), 2, "unexpected extra labels: {:?}", event.labels);
        }
        other => panic!("expected SendEvent, got {other:?}"),
    }
}
