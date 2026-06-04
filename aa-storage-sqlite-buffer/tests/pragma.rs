//! Durability-pragma tests: the buffer opens in WAL with `synchronous = NORMAL`.

use aa_storage_sqlite_buffer::EventBuffer;
use tempfile::tempdir;

#[test]
fn opens_in_wal_mode_with_synchronous_normal() {
    let dir = tempdir().unwrap();
    let buffer = EventBuffer::new(dir.path().join("buffer.db"), 100).unwrap();

    assert_eq!(buffer.journal_mode().unwrap().to_lowercase(), "wal");
    assert_eq!(buffer.synchronous().unwrap(), 1, "1 == synchronous NORMAL");
}
