//! Filesystem watcher that hot-reloads policy into an ArcSwap slot.
//!
//! Two flavours: [`start_watcher`] hot-reloads a single policy *file*;
//! [`start_cascade_watcher`] (AAASM-3497) hot-reloads a multi-document policy
//! *directory* — the Global/Org/Team/Agent cascade — by re-reading the whole
//! directory and atomically swapping the rebuilt scope index + compiled
//! patterns into the live slot whenever a `*.yaml` is added, removed, or
//! modified.

use arc_swap::ArcSwap;
use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use crate::engine::{CascadeState, PolicyEngine};
use crate::policy::{PolicyDocument, PolicyValidator};

/// Start a background filesystem watcher on `path`.
///
/// On [`EventKind::Modify`] events: re-parse the file. If valid, atomically
/// swap into `slot`. Invalid parses are silently ignored — the current policy
/// stays active.
///
/// Returns the watcher handle; drop it to stop watching.
#[allow(dead_code)]
pub(crate) fn start_watcher(
    path: &Path,
    slot: Arc<ArcSwap<PolicyDocument>>,
) -> notify::Result<notify::RecommendedWatcher> {
    let path_buf = path.to_path_buf();
    let mut watcher = recommended_watcher(move |res: notify::Result<notify::Event>| {
        handle_fs_event(res, &path_buf, &slot);
    })?;
    watcher.watch(path, RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

/// Process one filesystem event: on a `Modify`, re-parse the policy file and
/// atomically swap a valid document into `slot`. Empty or invalid content is
/// ignored so the active policy stays in place.
fn handle_fs_event(res: notify::Result<notify::Event>, path: &Path, slot: &Arc<ArcSwap<PolicyDocument>>) {
    let Ok(event) = res else {
        return;
    };
    if !matches!(event.kind, EventKind::Modify(_)) {
        return;
    }
    let Ok(yaml) = std::fs::read_to_string(path) else {
        return;
    };
    // Skip events fired while the file is mid-truncation (0 bytes).
    // On Linux (inotify), a truncate+write sequence emits a Modify
    // event for the truncated (empty) file before the new content
    // arrives. An empty file is not a valid policy, so skip it to
    // avoid replacing the active policy with an empty document.
    if yaml.trim().is_empty() {
        return;
    }
    if let Ok(output) = PolicyValidator::from_yaml(&yaml) {
        slot.store(Arc::new(output.document));
    }
}

/// Start a background watcher on the policy *directory* `dir` (AAASM-3497).
///
/// On any create / modify / remove event affecting a `*.yaml` entry, the whole
/// directory is re-read and re-assembled (via
/// [`PolicyEngine::rebuild_cascade_state`]) and the rebuilt primary document +
/// cascade state are atomically swapped into `policy_slot` / `cascade_slot`.
/// `policy_epoch` is then bumped so the decision cache drops stale entries —
/// the same invalidation mechanism `apply_yaml` uses.
///
/// Fail-safe semantics (mirroring [`start_watcher`]): if the re-read fails to
/// read or parse — a mid-edit truncation, a syntactically invalid file, a file
/// removed mid-scan — the current cascade is left untouched. A broken edit
/// never degrades the running gateway to an empty allow-all cascade.
///
/// The watch is non-recursive: the cascade loader reads only the directory's
/// own `*.yaml` entries (see `read_cascade_dir`), so nested directories are
/// deliberately ignored to keep watch and load semantics identical.
///
/// Returns the watcher handle; drop it to stop watching.
pub(crate) fn start_cascade_watcher(
    dir: &Path,
    policy_slot: Arc<ArcSwap<PolicyDocument>>,
    cascade_slot: Arc<ArcSwap<CascadeState>>,
    policy_epoch: Arc<AtomicU64>,
) -> notify::Result<notify::RecommendedWatcher> {
    let dir_buf = dir.to_path_buf();
    let mut watcher = recommended_watcher(move |res: notify::Result<notify::Event>| {
        handle_cascade_event(res, &dir_buf, &policy_slot, &cascade_slot, &policy_epoch);
    })?;
    watcher.watch(dir, RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

/// Process one directory event: if it touches a `*.yaml` and is a
/// create / modify / remove, re-read the whole directory and swap the rebuilt
/// cascade in. A read or parse failure preserves the current cascade.
fn handle_cascade_event(
    res: notify::Result<notify::Event>,
    dir: &Path,
    policy_slot: &Arc<ArcSwap<PolicyDocument>>,
    cascade_slot: &Arc<ArcSwap<CascadeState>>,
    policy_epoch: &Arc<AtomicU64>,
) {
    let Ok(event) = res else {
        return;
    };
    // Only act on add / remove / change events; access-only events (reads,
    // metadata) don't alter the cascade and would cause pointless rebuilds.
    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) {
        return;
    }
    // Ignore events whose paths are all non-`*.yaml` (e.g. an editor's swap
    // file). An event with no paths (some backends) is treated as "directory
    // changed" and triggers a rebuild — the re-read is the source of truth.
    if !event.paths.is_empty() && !event.paths.iter().any(|p| is_yaml_path(p)) {
        return;
    }

    // Re-read the directory as the source of truth. On any read/parse error
    // (mid-truncation, invalid YAML, a file vanishing mid-scan) keep the
    // current cascade — never swap in a degraded one.
    match PolicyEngine::rebuild_cascade_state(dir) {
        Ok((primary, cascade)) => {
            policy_slot.store(primary);
            cascade_slot.store(Arc::new(cascade));
            // Bump the epoch so the cascade decision cache treats every prior
            // entry as stale — same mechanism `apply_yaml` relies on.
            policy_epoch.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {
            // Fail-safe: leave the live cascade in place.
        }
    }
}

/// Whether `path` is a `*.yaml` file the cascade loader would read.
fn is_yaml_path(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()) == Some("yaml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use notify::event::{DataChange, ModifyKind};
    use std::{io::Write, sync::Arc, time::Duration};
    use tempfile::NamedTempFile;

    const ALLOW_YAML: &str = "version: \"1\"\ntools:\n  search:\n    allow: true\n";
    const DENY_YAML: &str = "version: \"1\"\ntools:\n  search:\n    allow: false\n";

    /// Overall bound on observing a hot-reload, and *not* a latency assertion
    /// (AAASM-5367).
    ///
    /// Filesystem notification delivery is a property of the platform backend,
    /// not of this watcher, and the two platforms are nothing alike. On Linux
    /// (inotify — what CI runs) this test completes in **0.014 s**. On macOS
    /// (FSEvents) the same unchanged watcher takes a median of **0.7 s**, a p90
    /// of **5.7 s** and a worst case of **8.7 s** over 80 measured trials, and
    /// up to **17 s** when a second workspace build shares the machine. Any
    /// fixed deadline short enough to be interesting is therefore a coin flip on
    /// macOS — the old one-second sleep lost that flip on ~2 runs in 3 here.
    ///
    /// So this is a backstop, not a deadline: it is only reached when the
    /// watcher has stopped storing anything at all. The trade-off it carries,
    /// which is real and worth stating: a *broken* watcher now costs 60 s per
    /// attempt — with `retries = 2` in `.config/nextest.toml`, ~180 s and a
    /// `SLOW` marker before the suite reports it. That is the deliberate price
    /// of never failing a healthy watcher, and a healthy run pays none of it
    /// because [`wait_for_swap`] returns the moment a store lands.
    const WATCH_LIVENESS_BOUND: Duration = Duration::from_secs(60);

    /// How long to wait for one application of the stimulus before re-applying
    /// it.
    ///
    /// Re-writing is the *normal* path, not an exception: 55% of 80 measured
    /// macOS runs needed more than one round (median 2, max 18). That is the
    /// mechanism working as intended, not a symptom — see [`wait_for_swap`] for
    /// why one write is not enough.
    const STIMULUS_ROUND: Duration = Duration::from_millis(500);

    fn parse_doc(yaml: &str) -> PolicyDocument {
        PolicyValidator::from_yaml(yaml).unwrap().document
    }

    /// Drive `stimulus` until `slot` holds something other than `previous`,
    /// returning whatever was swapped in.
    ///
    /// Two things make this deterministic where a fixed sleep was not. It polls
    /// instead of sleeping a fixed interval, so it returns as soon as the
    /// watcher has acted rather than always paying a fixed wait. And it
    /// re-applies the stimulus each round, because on macOS a single write is
    /// not guaranteed to yield a notification at all.
    ///
    /// That second point was challenged in review and re-measured properly, as
    /// 80 interleaved trials of one-write-only against this re-applying loop on
    /// the same machine:
    ///
    /// | | one write | re-applied |
    /// |---|---|---|
    /// | never observed | **5 / 80 (6.25%)** | **0 / 80** |
    /// | median latency | 0.85 s | 0.69 s |
    /// | mean latency | 1.88 s | 1.84 s |
    ///
    /// Re-applying is what removes the misses, and it is not slower doing it —
    /// the two latency distributions are indistinguishable. (A short run can
    /// easily see 8/8 clean with one write; at a 6.25% miss rate that happens
    /// 60% of the time, which is why the sample size matters here.)
    ///
    /// The limit of what this proves, stated so nobody over-reads it: because
    /// the stimulus repeats, a *lossy* watcher still passes. A mutant dropping
    /// 49 of every 50 notifications is not caught — it merely takes ~24 s. The
    /// test therefore proves hot-reload works, not that it works promptly, and
    /// it cannot distinguish a healthy watcher from a badly degraded one. That
    /// is the deliberate cost of tolerating a platform which loses ~6% of
    /// notifications on its own; a test that failed on loss would flake.
    ///
    /// This does not weaken the property under test. The caller still asserts
    /// what landed in the slot; only "how promptly the OS reported the write"
    /// stops being part of the assertion.
    fn wait_for_swap(
        slot: &ArcSwap<PolicyDocument>,
        previous: &Arc<PolicyDocument>,
        mut stimulus: impl FnMut(),
    ) -> Arc<PolicyDocument> {
        let start = std::time::Instant::now();
        while start.elapsed() < WATCH_LIVENESS_BOUND {
            stimulus();
            let round = std::time::Instant::now();
            while round.elapsed() < STIMULUS_ROUND {
                let current = slot.load_full();
                // Compare *identity*, not value. The handler allocates a fresh
                // Arc for every store, so this observes the store itself rather
                // than the store's effect. A value comparison would be blind to
                // a watcher that swaps in a document equal to the live one —
                // the natural shape of a "reload read stale content" bug — and
                // would then time out and blame a watcher that is in fact
                // firing constantly. The caller checks the content.
                if !Arc::ptr_eq(&current, previous) {
                    return current;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        panic!(
            "watcher stored nothing into the policy slot within \
             {WATCH_LIVENESS_BOUND:?}, despite the policy file being rewritten \
             every {STIMULUS_ROUND:?} — the watcher is not firing at all, or is \
             firing but rejecting the content it reads"
        );
    }

    #[test]
    fn hot_reload_swaps_in_the_new_policy() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{}", ALLOW_YAML).unwrap();
        tmp.flush().unwrap();

        let initial = Arc::new(parse_doc(ALLOW_YAML));
        let slot = Arc::new(ArcSwap::new(initial.clone()));

        let _watcher = start_watcher(tmp.path(), slot.clone()).unwrap();

        // Overwrite the file with the DENY policy until the watcher reports it.
        let path = tmp.path().to_path_buf();
        let current_doc = wait_for_swap(&slot, &initial, || {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            write!(f, "{}", DENY_YAML).unwrap();
            f.flush().unwrap();
        });

        // Assert on *what* was swapped in: a swap to the wrong document fails
        // here immediately rather than being waited out.
        assert!(
            !current_doc.tools["search"].allow,
            "search.allow should be false after hot-reload"
        );
    }

    /// A content-change `Modify` event for `path`, shaped as the notify
    /// backends report one.
    fn modify_event(path: &Path) -> notify::Result<notify::Event> {
        Ok(notify::Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Content))).add_path(path.to_path_buf()))
    }

    fn write_file(path: &Path, contents: &str) {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        write!(f, "{}", contents).unwrap();
        f.flush().unwrap();
    }

    /// A truncated policy file must not clobber the live policy (AAASM-3561).
    ///
    /// `handle_fs_event` skips zero-byte reads because a truncate-then-write
    /// edit fires a Modify event for the empty file first. Without that guard an
    /// empty document parses as a Global allow-all and would replace a deny
    /// policy for the width of the write — a fail-*open* window. The guard had
    /// no test of its own: deleting it left every other test in this module
    /// green. The cascade watcher's equivalent is covered by
    /// `cascade_hot_reload_invalid_yaml_preserves_cascade`; this is the
    /// single-file twin.
    #[test]
    fn truncated_file_keeps_previous_policy() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();

        let initial_doc = parse_doc(DENY_YAML);
        let slot = Arc::new(ArcSwap::new(Arc::new(initial_doc.clone())));

        // Whitespace-only stands in for the mid-truncation read: it is what the
        // watcher sees between the truncate and the new bytes landing.
        write_file(path, "   \n");
        handle_fs_event(modify_event(path), path, &slot);
        assert_eq!(
            *slot.load_full(),
            initial_doc,
            "a truncated file must not clobber the live policy with an allow-all"
        );

        write_file(path, ALLOW_YAML);
        handle_fs_event(modify_event(path), path, &slot);
        assert!(
            slot.load_full().tools["search"].allow,
            "control: the same event over valid YAML must reach the parse step \
             and swap, otherwise the assertion above proves nothing"
        );
    }

    /// Drives [`handle_fs_event`] directly rather than through a real watcher
    /// (AAASM-5367).
    ///
    /// This asserts a *negative* — that nothing is swapped in — so waiting a
    /// fixed second for a notification made it pass for the wrong reason
    /// whenever the notification simply hadn't arrived yet, which measurement
    /// showed is the common case. Feeding the handler the event removes the
    /// notification path from the test entirely: the ignore-invalid-content
    /// decision is exercised on every run, deterministically and instantly.
    ///
    /// The valid-content half is the control that keeps the negative honest —
    /// it proves this event actually reaches the parse step, so the first
    /// assertion cannot pass merely because the handler discarded the event.
    #[test]
    fn invalid_yaml_keeps_previous_policy() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();

        let initial_doc = parse_doc(ALLOW_YAML);
        let slot = Arc::new(ArcSwap::new(Arc::new(initial_doc.clone())));

        write_file(path, "invalid: yaml: [[[");
        handle_fs_event(modify_event(path), path, &slot);
        assert_eq!(
            *slot.load_full(),
            initial_doc,
            "slot should still hold the original policy after an invalid parse"
        );

        write_file(path, DENY_YAML);
        handle_fs_event(modify_event(path), path, &slot);
        assert!(
            !slot.load_full().tools["search"].allow,
            "control: the same event over valid YAML must reach the parse step \
             and swap, otherwise the assertion above proves nothing"
        );
    }
}
