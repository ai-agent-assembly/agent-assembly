//! Enqueue/drain behaviour tests for the SQLite event buffer.

mod common;

use aa_storage_sqlite_buffer::EventBuffer;
use common::{sample_entry, CollectingSink};
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
