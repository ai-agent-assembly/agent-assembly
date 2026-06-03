//! Verifies cap eviction is metered: the `aa_events_dropped_total` counter
//! reflects the exact number of evicted events, alongside the buffered and
//! flushed counters.

mod common;

use std::collections::HashMap;

use aa_storage_sqlite_buffer::{EventBuffer, METRIC_EVENTS_BUFFERED, METRIC_EVENTS_DROPPED, METRIC_EVENTS_FLUSHED};
use common::{sample_entry, CollectingSink};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use tempfile::tempdir;

/// Snapshot every emitted counter into a `name -> value` map.
fn counters(snapshotter: &Snapshotter) -> HashMap<String, u64> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _unit, _desc, value)| match value {
            DebugValue::Counter(v) => Some((key.key().name().to_string(), v)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn cap_eviction_is_metered() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("install debugging recorder");

    let dir = tempdir().unwrap();
    let buffer = EventBuffer::new(dir.path().join("buffer.db"), 10).unwrap();

    // 15 enqueues into a cap-10 buffer evicts the 5 oldest.
    for i in 0..15 {
        buffer.enqueue(&sample_entry(i, &format!("event-{i}"))).unwrap();
    }

    let snap = counters(&snapshotter);
    assert_eq!(snap.get(METRIC_EVENTS_BUFFERED).copied(), Some(15));
    assert_eq!(snap.get(METRIC_EVENTS_DROPPED).copied(), Some(5));
    assert_eq!(buffer.len().unwrap(), 10);

    // Draining the retained 10 bumps the flushed counter by exactly 10.
    let sink = CollectingSink::default();
    let flushed = buffer.drain_and_send(&sink).await.unwrap();
    assert_eq!(flushed, 10);

    let snap = counters(&snapshotter);
    assert_eq!(snap.get(METRIC_EVENTS_FLUSHED).copied(), Some(10));
}
