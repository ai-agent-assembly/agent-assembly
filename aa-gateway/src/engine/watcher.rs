//! Filesystem watcher that hot-reloads the policy file into an ArcSwap slot.

use arc_swap::ArcSwap;
use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
use std::{path::Path, sync::Arc};

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
