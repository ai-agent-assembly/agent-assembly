//! SIGKILL restart test (AAASM-2375): a child process enqueues events and is
//! killed with `kill -9` (no graceful shutdown); the parent reopens the same
//! buffer file and proves the events replay in FIFO order.

mod common;

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aa_storage_sqlite_buffer::EventBuffer;
use common::{sample_entry, CollectingSink};
use tempfile::tempdir;

/// Env var carrying the buffer path to the child role.
const CHILD_DB_ENV: &str = "AA_SQLITE_BUFFER_KILL_CHILD_DB";

const EVENT_COUNT: u64 = 5;

/// Child role: enqueue events, signal readiness, then block until SIGKILLed.
///
/// A no-op when `CHILD_DB_ENV` is unset, so it stays harmless in a normal run.
#[test]
fn child_enqueue_then_block() {
    let Ok(db) = std::env::var(CHILD_DB_ENV) else {
        return;
    };
    let buffer = EventBuffer::new(&db, 100).expect("child: open buffer");
    for i in 0..EVENT_COUNT {
        buffer
            .enqueue(&sample_entry(i, &format!("event-{i}")))
            .expect("child: enqueue");
    }
    // Tell the parent the events are durably written.
    std::fs::write(format!("{db}.ready"), b"ready").expect("child: write ready file");
    // Block until the parent kills us; sleeping avoids a busy spin.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

#[tokio::test]
async fn survives_sigkill_and_replays_in_order() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("buffer.db");
    let db_str = db.to_str().unwrap().to_string();
    let ready = format!("{db_str}.ready");

    // Re-invoke this same test binary, running only the child role.
    let exe = std::env::current_exe().expect("locate test binary");
    let mut child = Command::new(exe)
        .args(["--exact", "child_enqueue_then_block"])
        .env(CHILD_DB_ENV, &db_str)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child");

    // Wait for the child to finish enqueuing.
    let start = Instant::now();
    while !Path::new(&ready).exists() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "child never signalled readiness"
        );
        if let Ok(Some(status)) = child.try_wait() {
            panic!("child exited early with {status}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // kill -9: terminate the child with no chance to close the DB gracefully.
    child.kill().expect("SIGKILL child");
    let _ = child.wait();

    // Restart: reopen the file and prove the buffered events survived the kill
    // and replay in insertion order.
    let buffer = EventBuffer::new(&db, 100).unwrap();
    assert_eq!(buffer.len().unwrap(), EVENT_COUNT as usize);

    let sink = CollectingSink::default();
    let flushed = buffer.drain_and_send(&sink).await.unwrap();
    assert_eq!(flushed, EVENT_COUNT as usize);

    let expected: Vec<_> = (0..EVENT_COUNT)
        .map(|i| sample_entry(i, &format!("event-{i}")))
        .collect();
    assert_eq!(sink.entries(), expected, "events replay in FIFO order after kill -9");
}
