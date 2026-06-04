//! Cap-enforcement (oldest-eviction) tests.

mod common;

use aa_storage_sqlite_buffer::EventBuffer;
use common::{sample_entry, CollectingSink};
use tempfile::tempdir;

#[tokio::test]
async fn cap_evicts_oldest_and_retains_newest_in_order() {
    let dir = tempdir().unwrap();
    let buffer = EventBuffer::new(dir.path().join("buffer.db"), 10).unwrap();

    // Enqueue 15 events into a cap-10 buffer; the 5 oldest are dropped.
    let inputs: Vec<_> = (0..15).map(|i| sample_entry(i, &format!("event-{i}"))).collect();
    for entry in &inputs {
        buffer.enqueue(entry).unwrap();
    }

    assert_eq!(buffer.len().unwrap(), 10, "buffer never exceeds its cap");

    // The retained events are the 10 most recent, still in FIFO order.
    let sink = CollectingSink::default();
    let flushed = buffer.drain_and_send(&sink).await.unwrap();
    assert_eq!(flushed, 10);
    assert_eq!(
        sink.entries(),
        inputs[5..].to_vec(),
        "the oldest five events were evicted, newest ten retained in order"
    );
}
