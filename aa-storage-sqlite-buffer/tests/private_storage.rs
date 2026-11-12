//! AAASM-6460: the buffer must live in storage only the runtime's uid can reach.
//! Unix only — modes and ownership are the property under test.
#![cfg(unix)]

mod common;

use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aa_storage_sqlite_buffer::{EventBuffer, StorageError};
use common::sample_entry;
use tempfile::tempdir;

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

fn chmod(p: &Path, m: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}

fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut n = db.as_os_str().to_os_string();
    n.push(suffix);
    PathBuf::from(n)
}

fn refusal(r: Result<EventBuffer, StorageError>) -> String {
    match r {
        Err(StorageError::Backend(msg)) => msg,
        Err(other) => panic!("expected a Backend refusal, got {other:?}"),
        Ok(_) => panic!("expected the buffer to refuse this location"),
    }
}

/// A fresh private directory. `tempfile` follows the umask (0755 under 022),
/// so tighten it explicitly rather than rely on its default.
fn private_dir() -> tempfile::TempDir {
    let d = tempdir().unwrap();
    chmod(d.path(), 0o700);
    d
}

#[test]
fn created_directory_is_0700_and_database_wal_and_shm_are_0600() {
    let root = private_dir();
    let db = root.path().join("nested/buf/buffer.db");

    let buffer = EventBuffer::new(&db, 100).unwrap();
    buffer.enqueue(&sample_entry(1, "x")).unwrap();
    // Checkpoint-free: while the connection is open the sidecars exist.
    let (wal, shm) = (sidecar(&db, "-wal"), sidecar(&db, "-shm"));
    let modes = (
        mode(db.parent().unwrap()),
        mode(db.parent().unwrap().parent().unwrap()),
        mode(&db),
        wal.exists().then(|| mode(&wal)),
        shm.exists().then(|| mode(&shm)),
    );

    assert_eq!(modes.0, 0o700, "created leaf directory");
    assert_eq!(modes.1, 0o700, "created intermediate directory");
    assert_eq!(modes.2, 0o600, "database file");
    assert_eq!(modes.3, Some(0o600), "-wal must exist and be 0600 (Linux inheritance)");
    assert_eq!(modes.4, Some(0o600), "-shm must exist and be 0600 (Linux inheritance)");
}

#[test]
fn clean_existing_private_database_is_accepted_and_replays() {
    let root = private_dir();
    let db = root.path().join("buffer.db");
    {
        let b = EventBuffer::new(&db, 100).unwrap();
        b.enqueue(&sample_entry(1, "kept")).unwrap();
    }
    assert_eq!(mode(&db), 0o600);
    let b = EventBuffer::new(&db, 100).unwrap();
    assert_eq!(b.len().unwrap(), 1);
}

#[test]
fn symlinked_database_is_refused() {
    let root = private_dir();
    let real = root.path().join("real.db");
    std::fs::write(&real, b"").unwrap();
    chmod(&real, 0o600);
    let link = root.path().join("buffer.db");
    symlink(&real, &link).unwrap();
    let msg = refusal(EventBuffer::new(&link, 10));
    assert!(msg.contains("not a regular file"), "{msg}");
}

#[test]
fn dangling_symlinked_database_is_refused_and_target_not_created() {
    let root = private_dir();
    let target = root.path().join("victim.db");
    let link = root.path().join("buffer.db");
    symlink(&target, &link).unwrap();
    refusal(EventBuffer::new(&link, 10));
    assert!(!target.exists());
}

#[test]
fn parent_directory_writable_by_group_or_other_is_refused() {
    for m in [0o777, 0o770, 0o707, 0o757] {
        let root = private_dir();
        let dir = root.path().join("shared");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, m);
        let db = dir.join("buffer.db");
        let msg = refusal(EventBuffer::new(&db, 10));
        assert!(msg.contains("writable by group/other"), "mode {m:o}: {msg}");
        assert!(!db.exists(), "mode {m:o}: must not create the database");
    }
}

#[test]
fn private_parent_below_a_replaceable_ancestor_is_refused() {
    let root = private_dir();
    let anc = root.path().join("anc");
    let parent = anc.join("p");
    std::fs::create_dir_all(&parent).unwrap();
    chmod(&parent, 0o700);
    chmod(&anc, 0o777);
    let db = parent.join("buffer.db");
    let msg = refusal(EventBuffer::new(&db, 10));
    assert!(msg.contains("ancestor") && msg.contains("sticky"), "{msg}");
    assert!(!db.exists(), "must not create the database");
}

#[test]
fn symlinked_parent_directory_is_refused() {
    let root = private_dir();
    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = root.path().join("link");
    symlink(&real, &link).unwrap();
    let msg = refusal(EventBuffer::new(link.join("buffer.db"), 10));
    assert!(msg.contains("not a real directory"), "{msg}");
}

#[test]
fn preexisting_wal_that_is_a_symlink_is_refused() {
    let root = private_dir();
    let db = root.path().join("buffer.db");
    drop(EventBuffer::new(&db, 10).unwrap());
    let wal = sidecar(&db, "-wal");
    let _ = std::fs::remove_file(&wal);
    symlink(root.path().join("elsewhere"), &wal).unwrap();
    let msg = refusal(EventBuffer::new(&db, 10));
    assert!(msg.contains("-wal") && msg.contains("not a regular file"), "{msg}");
}

#[test]
fn preexisting_sidecars_with_loose_mode_are_refused() {
    for suffix in ["-wal", "-shm", "-journal"] {
        let root = private_dir();
        let db = root.path().join("buffer.db");
        drop(EventBuffer::new(&db, 10).unwrap());
        let side = sidecar(&db, suffix);
        std::fs::write(&side, b"").unwrap();
        chmod(&side, 0o666);
        let msg = refusal(EventBuffer::new(&db, 10));
        assert!(msg.contains(suffix) && msg.contains("group/other"), "{suffix}: {msg}");
    }
}

#[test]
fn loose_database_outside_a_default_dir_is_refused_not_modified() {
    let root = private_dir();
    let db = root.path().join("buffer.db");
    drop(EventBuffer::new(&db, 10).unwrap());
    chmod(&db, 0o644);
    let msg = refusal(EventBuffer::new(&db, 10));
    assert!(msg.contains("group/other"), "{msg}");
    assert_eq!(mode(&db), 0o644, "an operator-chosen location is never re-moded");
}

#[test]
fn hardlinked_database_is_refused() {
    let root = private_dir();
    let db = root.path().join("buffer.db");
    drop(EventBuffer::new(&db, 10).unwrap());
    std::fs::hard_link(&db, root.path().join("alias.db")).unwrap();
    assert!(std::fs::metadata(&db).unwrap().nlink() > 1);
    let msg = refusal(EventBuffer::new(&db, 10));
    assert!(msg.contains("hard links"), "{msg}");
}

#[test]
fn world_writable_sticky_temp_dir_is_refused() {
    // The old default location. /tmp is 1777 on Linux and macOS.
    // /tmp is a symlink on macOS; resolve it so the *directory* itself is judged.
    let Ok(tmp) = std::fs::canonicalize("/tmp") else {
        return;
    };
    let db = tmp.join(format!("aa-6460-sticky-{}.db", std::process::id()));
    let msg = refusal(EventBuffer::new(&db, 10));
    // Root-owned and 1777: refused on ownership first, writability second.
    assert!(
        msg.contains("owned by uid") || msg.contains("writable by group/other"),
        "{msg}"
    );
    assert!(!db.exists());
}
