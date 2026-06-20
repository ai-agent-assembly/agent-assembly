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
    use std::{io::Write, sync::Arc, time::Duration};
    use tempfile::NamedTempFile;

    const ALLOW_YAML: &str = "version: \"1\"\ntools:\n  search:\n    allow: true\n";
    const DENY_YAML: &str = "version: \"1\"\ntools:\n  search:\n    allow: false\n";

    fn parse_doc(yaml: &str) -> PolicyDocument {
        PolicyValidator::from_yaml(yaml).unwrap().document
    }

    #[test]
    fn hot_reload_reflects_new_policy_within_one_second() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{}", ALLOW_YAML).unwrap();
        tmp.flush().unwrap();

        let initial_doc = parse_doc(ALLOW_YAML);
        let slot = Arc::new(ArcSwap::new(Arc::new(initial_doc.clone())));

        let _watcher = start_watcher(tmp.path(), slot.clone()).unwrap();

        // Overwrite file with DENY policy.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tmp.path())
            .unwrap();
        write!(f, "{}", DENY_YAML).unwrap();
        f.flush().unwrap();
        drop(f);

        std::thread::sleep(Duration::from_secs(1));

        let loaded = slot.load();
        let current_doc: &PolicyDocument = &loaded;
        assert_ne!(
            current_doc, &initial_doc,
            "slot should have been swapped to the new policy"
        );
        assert!(
            !current_doc.tools["search"].allow,
            "search.allow should be false after hot-reload"
        );
    }

    #[test]
    fn invalid_yaml_keeps_previous_policy() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{}", ALLOW_YAML).unwrap();
        tmp.flush().unwrap();

        let initial_doc = parse_doc(ALLOW_YAML);
        let slot = Arc::new(ArcSwap::new(Arc::new(initial_doc.clone())));

        let _watcher = start_watcher(tmp.path(), slot.clone()).unwrap();

        // Overwrite file with invalid YAML.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tmp.path())
            .unwrap();
        write!(f, "invalid: yaml: [[[").unwrap();
        f.flush().unwrap();
        drop(f);

        std::thread::sleep(Duration::from_secs(1));

        let loaded = slot.load();
        let current_doc: &PolicyDocument = &loaded;
        assert_eq!(
            current_doc, &initial_doc,
            "slot should still hold the original policy after an invalid parse"
        );
    }
}
