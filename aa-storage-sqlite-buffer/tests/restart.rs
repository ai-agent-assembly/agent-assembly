//! Restart-safety test: buffered events survive dropping and reopening the
//! buffer (the in-process analogue of a process restart) and replay in order.

mod common;

use aa_storage_sqlite_buffer::EventBuffer;
use common::{sample_entry, CollectingSink};
use tempfile::tempdir;

#[tokio::test]
async fn buffered_events_survive_restart_and_replay_in_order() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("buffer.db");

    let inputs: Vec<_> = (0..5).map(|i| sample_entry(i, &format!("event-{i}"))).collect();

    // First "process": enqueue events, then drop the buffer to close the DB.
    {
        let buffer = EventBuffer::new(&path, 100).unwrap();
        for entry in &inputs {
            buffer.enqueue(entry).unwrap();
        }
        assert_eq!(buffer.len().unwrap(), 5);
    } // buffer (and its SQLite connection) dropped here

    // Second "process": reopen the same file and prove the events are still
    // there, then flush them in insertion order.
    let buffer = EventBuffer::new(&path, 100).unwrap();
    assert_eq!(buffer.len().unwrap(), 5, "events persisted across restart");

    let sink = CollectingSink::default();
    let flushed = buffer.drain_and_send(&sink).await.unwrap();
    assert_eq!(flushed, 5);
    assert!(buffer.is_empty().unwrap());
    assert_eq!(sink.entries(), inputs, "events replay in FIFO order after restart");
}
