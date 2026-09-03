//! Filesystem watcher that hot-reloads policy into an ArcSwap slot.
//!
//! Two flavours: [`start_watcher`] hot-reloads a single policy *file*;
//! [`start_cascade_watcher`] (AAASM-3497) hot-reloads a multi-document policy
//! *directory* — the Global/Org/Team/Agent cascade — by re-reading the whole
//! directory and atomically swapping the rebuilt scope index + compiled
//! patterns into the live slot whenever a `*.yaml` is added, removed, or
//! modified.
//!
//! # Delivery guarantee (AAASM-5382)
//!
//! The OS filesystem notification each watcher above uses is a **latency
//! optimization, not the correctness mechanism**. Every loading path also
//! starts a [`start_reconciler`]/[`start_cascade_reconciler`] poll, and it is
//! that poll — not the OS watcher — that provides the actual guarantee:
//! **every change to the watched path is picked up within
//! [`RECONCILE_INTERVAL`] (5s), even when the OS delivers nothing.**
//!
//! This guarantee exists because neither platform's push path is sound on
//! its own, in different ways, both measured directly against this module's
//! actual watch shapes:
//!
//! - **macOS (FSEvents):** ~6% of single-write notifications are dropped
//!   outright — not late, absent. Measured over 80 trials; see
//!   `WATCH_LIVENESS_BOUND`'s doc in this module's tests for the full table.
//! - **Linux (inotify), single-file watch (`start_watcher`):** the watch is
//!   on the file's **inode**, not its path. A rename-based save — vim, most
//!   IDE atomic-saves, `sed -i`, Ansible's `copy` module, a Kubernetes
//!   ConfigMap symlink swap — delivers `ATTRIB` (so the *first* rename-save
//!   still works) → `DELETE_SELF` → `IGNORED`, which removes the watch from
//!   the kernel with **no re-arm path**. Every subsequent save — rename-based
//!   *or* in-place — is then silently lost, permanently, until process
//!   restart.
//! - **Linux (inotify), directory watch (`start_cascade_watcher`):** watches
//!   the directory's own inode, which a rename *inside* it never replaces —
//!   measured immune to the single-file failure mode above.
//!
//! **The asymmetry this leaves, stated so the guarantee above is not
//! over-read:** the reconciler *masks* a dead single-file inotify watch, it
//! does not repair it. On Linux, after the first rename-based save to a
//! single watched file, that path is permanently poll-only (bounded by
//! [`RECONCILE_INTERVAL`]) rather than push (sub-second) for the life of the
//! process. The cascade (directory) watch is not affected by this.

use arc_swap::ArcSwap;
use notify::{recommended_watcher, Config, EventKind, PollWatcher, RecursiveMode, Watcher};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::engine::{CascadeState, PolicyEngine};
use crate::policy::{PolicyDocument, PolicyValidator};

/// How often the reconciliation poll re-reads the watched path (AAASM-5382).
///
/// Bounds the staleness window for both platform-specific delivery failures
/// this module's tests measure: macOS/FSEvents drops ~6% of single-write
/// notifications outright (see `WATCH_LIVENESS_BOUND`'s doc below), and
/// Linux/inotify's single-file watch dies permanently after one rename-based
/// save (an `ATTRIB` → `DELETE_SELF` → `IGNORED` sequence with no re-arm
/// path — vim, most IDE atomic saves, `sed -i`, and k8s ConfigMap updates all
/// save this way). 5s is chosen to *improve* on the OS path's own measured
/// tail on macOS (p90 5.7s, worst case 8.7s) rather than merely bound it, and
/// is well inside what an operator would consider "policy took effect
/// promptly" for a governance control.
pub(crate) const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// Start a background filesystem watcher on `path`.
///
/// On [`EventKind::Create`] or [`EventKind::Modify`] events: re-parse the
/// file. If valid, atomically swap into `slot`. Invalid parses are silently
/// ignored — the current policy stays active.
///
/// This is a latency optimization, not the correctness mechanism — see this
/// module's `//!` doc and [`start_reconciler`] for the delivery guarantee
/// this watcher alone does not provide.
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

/// Start a reconciliation poll on `path`, backing up [`start_watcher`]
/// (AAASM-5382).
///
/// The OS watcher above is a latency optimization, not the correctness
/// mechanism — it can silently drop a notification (macOS) or die
/// permanently after one rename-based save (Linux; see [`RECONCILE_INTERVAL`]'s
/// doc). This function re-stats `path` every `interval` and, when its
/// content differs from what it last saw, drives the same
/// [`handle_fs_event`] the OS watcher does — so a missed push notification
/// is recovered within `interval`, and no second swap path is introduced.
///
/// Uses [`notify::PollWatcher`] with content comparison (not mtime alone):
/// mtime-only comparison misses a write that preserves or predates the old
/// mtime (`cp -p`, `rsync --times`, a restored backup) — exactly the
/// silent-miss class this function exists to catch. A poll tick that finds
/// no change emits no event, so a healthy OS watcher's swaps are not
/// duplicated and `slot`/downstream caches see no spurious churn.
///
/// Returns the poll handle; drop it to stop reconciling.
pub(crate) fn start_reconciler(
    path: &Path,
    slot: Arc<ArcSwap<PolicyDocument>>,
    interval: Duration,
) -> notify::Result<PollWatcher> {
    let path_buf = path.to_path_buf();
    let mut watcher = PollWatcher::new(
        move |res: notify::Result<notify::Event>| {
            handle_fs_event(res, &path_buf, &slot);
        },
        Config::default()
            .with_poll_interval(interval)
            .with_compare_contents(true),
    )?;
    watcher.watch(path, RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

/// Process one filesystem event: on a `Create` or `Modify`, re-parse the
/// policy file and atomically swap a valid document into `slot`. Empty or
/// invalid content is ignored so the active policy stays in place.
///
/// `Create` is accepted, not just `Modify` (AAASM-5382): the reconciliation
/// poll's `compare_to_event` emits `Create(CreateKind::Any)` when a poll tick
/// finds content where its baseline saw none — a delete-then-recreate save
/// whose absent window straddles a tick. Dropping that event would resync
/// the reconciler's baseline to absent and only recover on the *next* change,
/// silently reintroducing the staleness window this function exists to bound.
fn handle_fs_event(res: notify::Result<notify::Event>, path: &Path, slot: &Arc<ArcSwap<PolicyDocument>>) {
    let Ok(event) = res else {
        return;
    };
    if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
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

/// Start a reconciliation poll on directory `dir`, backing up
/// [`start_cascade_watcher`] (AAASM-5382). See [`start_reconciler`]'s doc for
/// why a poll backstop is needed and how content comparison avoids spurious
/// rebuilds; this is its cascade-directory twin, driving
/// [`handle_cascade_event`] on each tick that finds a change.
///
/// The directory's own inode is what is watched (see
/// [`start_cascade_watcher`]'s doc on why that inode survives a rename
/// *inside* the directory), so this reconciler exists purely to bound the
/// macOS drop rate — the Linux permanent-death failure mode measured for
/// [`start_reconciler`] does not apply to the directory watch. It is added
/// anyway for the same bounded-staleness guarantee and because a future
/// platform backend change should not silently regress this cascade path's
/// coverage without a test noticing.
///
/// Returns the poll handle; drop it to stop reconciling.
pub(crate) fn start_cascade_reconciler(
    dir: &Path,
    policy_slot: Arc<ArcSwap<PolicyDocument>>,
    cascade_slot: Arc<ArcSwap<CascadeState>>,
    policy_epoch: Arc<AtomicU64>,
    interval: Duration,
) -> notify::Result<PollWatcher> {
    let dir_buf = dir.to_path_buf();
    let mut watcher = PollWatcher::new(
        move |res: notify::Result<notify::Event>| {
            handle_cascade_event(res, &dir_buf, &policy_slot, &cascade_slot, &policy_epoch);
        },
        Config::default()
            .with_poll_interval(interval)
            .with_compare_contents(true),
    )?;
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

    /// The reconciliation poll recovers a write the OS watcher never reports
    /// at all — the actual guarantee this module's `//!` doc states
    /// (AAASM-5382).
    ///
    /// [`start_watcher`] is deliberately absent from this test: the push path
    /// is not mocked or stubbed, it simply does not exist here, so a swap can
    /// only be explained by [`start_reconciler`]. And the file is written
    /// exactly **once** — not through [`wait_for_swap`]'s re-applying
    /// stimulus, which is precisely what makes the other tests in this
    /// module unable to distinguish "the push path recovered" from "the poll
    /// recovered": both would pass either way.
    ///
    /// Mutation proof: delete the `.watch(...)` call or the closure body in
    /// [`start_reconciler`] and this test fails while every other test in
    /// this module — none of which exercise the reconciler — stays green.
    #[test]
    fn reconciler_recovers_a_write_the_watcher_never_reported() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{}", ALLOW_YAML).unwrap();
        tmp.flush().unwrap();

        let initial = Arc::new(parse_doc(ALLOW_YAML));
        let slot = Arc::new(ArcSwap::new(initial.clone()));

        let _reconciler = start_reconciler(tmp.path(), slot.clone(), Duration::from_millis(100)).unwrap();

        write_file(tmp.path(), DENY_YAML);

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let current = loop {
            let current = slot.load_full();
            if !Arc::ptr_eq(&current, &initial) {
                break current;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "reconciler did not recover a single unreplayed write within 10s \
                 (10 poll intervals at 100ms) — the reconciliation poll is not \
                 working, or is not actually reaching handle_fs_event"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            !current.tools["search"].allow,
            "search.allow should be false after the reconciler picks up the write"
        );
    }

    /// A poll tick that finds no content change must not swap or otherwise
    /// touch downstream state — asserted on the artifact that actually
    /// decides staleness (`policy_epoch`), not on an absence of log lines or
    /// similar proxy (AAASM-5382).
    ///
    /// Uses the cascade reconciler because `policy_epoch` is its externally
    /// observable "did anything happen" signal; the single-file reconciler
    /// has no equivalent counter to assert against.
    ///
    /// The control (writing changed content and asserting the epoch *does*
    /// move) is required: without it, an epoch that stayed at 0 could mean
    /// "correctly did nothing" or merely "the reconciler is dead" — the two
    /// look identical unless something proves the reconciler is alive.
    #[test]
    fn reconciler_does_not_swap_when_content_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("global.yaml"), ALLOW_YAML).unwrap();

        let policy_slot = Arc::new(ArcSwap::new(Arc::new(parse_doc(ALLOW_YAML))));
        let cascade_slot = Arc::new(ArcSwap::new(Arc::new(CascadeState::default())));
        let policy_epoch = Arc::new(AtomicU64::new(0));

        let _reconciler = start_cascade_reconciler(
            dir.path(),
            policy_slot,
            cascade_slot,
            policy_epoch.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Five idle intervals with no writes: if the poll swapped on every
        // tick regardless of content, this would already have moved.
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            policy_epoch.load(Ordering::Relaxed),
            0,
            "an idle reconciliation poll must not bump policy_epoch — that would \
             needlessly invalidate the cascade decision cache on every tick"
        );

        // Control: prove the reconciler is alive and actually driving
        // handle_cascade_event, so the assertion above means "correctly
        // idle" and not "the reconciler never ran".
        std::fs::write(dir.path().join("global.yaml"), DENY_YAML).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while policy_epoch.load(Ordering::Relaxed) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "control failed: policy_epoch never moved after a real content \
                 change, so the idle assertion above proves nothing about a live \
                 reconciler"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
