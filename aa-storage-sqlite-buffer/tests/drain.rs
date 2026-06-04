//! Enqueue/drain behaviour tests for the SQLite event buffer.

mod common;

use aa_storage_sqlite_buffer::EventBuffer;
use common::{sample_entry, CollectingSink, FlakySink};
use tempfile::tempdir;

#[tokio::test]
async fn enqueues_and_drains_in_fifo_order() {
    let dir = tempdir().unwrap();
    let buffer = EventBuffer::new(dir.path().join("buffer.db"), 100).unwrap();

    let inputs: Vec<_> = (0..5).map(|i| sample_entry(i, &format!("event-{i}"))).collect();
    for entry in &inputs {
        buffer.enqueue(entry).unwrap();
    }
    assert_eq!(buffer.len().unwrap(), 5);

    let sink = CollectingSink::default();
    let flushed = buffer.drain_and_send(&sink).await.unwrap();

    assert_eq!(flushed, 5);
    assert!(buffer.is_empty().unwrap());
    assert_eq!(sink.entries(), inputs, "events must replay in insertion order");
}

#[tokio::test]
async fn drain_stops_at_first_sink_failure_and_resumes_later() {
    let dir = tempdir().unwrap();
    let buffer = EventBuffer::new(dir.path().join("buffer.db"), 100).unwrap();

    let inputs: Vec<_> = (0..5).map(|i| sample_entry(i, &format!("event-{i}"))).collect();
    for entry in &inputs {
        buffer.enqueue(entry).unwrap();
    }

    // The upstream accepts two events, then goes unreachable.
    let flaky = FlakySink::new(2);
    let flushed = buffer.drain_and_send(&flaky).await.unwrap();
    assert_eq!(flushed, 2);
    assert_eq!(flaky.entries(), inputs[..2].to_vec());
    assert_eq!(buffer.len().unwrap(), 3, "unacked events stay buffered");

    // The upstream recovers; the remaining events replay in FIFO order.
    let sink = CollectingSink::default();
    let flushed = buffer.drain_and_send(&sink).await.unwrap();
    assert_eq!(flushed, 3);
    assert!(buffer.is_empty().unwrap());
    assert_eq!(sink.entries(), inputs[2..].to_vec());
}
