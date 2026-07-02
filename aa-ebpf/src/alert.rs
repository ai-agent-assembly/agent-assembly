//! Sensitive path detection for userspace event processing.
//!
//! While the BPF probes perform in-kernel blocklist checks (flags bit 0),
//! the [`SensitivePathDetector`] provides a userspace-side check for
//! additional flexibility (e.g., prefix matching, regex patterns).

use crate::events::FileIoEvent;

/// Lexically canonicalize a filesystem path for **alert matching** (AAASM-3921a).
///
/// Collapses repeated `/`, drops `.` segments, and resolves `..` segments
/// against earlier components without touching the filesystem. This defeats the
/// trivial non-canonical evasions the in-kernel exact-match blocklist cannot
/// see (`/etc//shadow`, `/etc/./shadow`, `/etc/../etc/shadow`, trailing-dot
/// forms).
///
/// This is a **lexical** normalization only: it does NOT resolve symlinks or
/// the process's mount namespace / CWD, so a symlink pointing at a sensitive
/// file still evades detection. True path resolution requires an in-kernel
/// `d_path` / dentry walk, which is deferred (it cannot be written or validated
/// without a Linux kernel target) — see the AAASM-3921a notes in
/// `aa-ebpf-probes/src/maps.rs`.
///
/// A leading `/` (absolute) and a single trailing `/` (a directory-prefix
/// boundary, e.g. `/root/.ssh/`) are preserved so boundary-aware prefix rules
/// keep their semantics (`/home/` must not match `/homestead`).
#[must_use]
pub fn canonicalize_lexical(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let had_trailing_slash = path.len() > 1 && path.ends_with('/');

    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => match stack.last() {
                // Pop a real parent component.
                Some(&last) if last != ".." => {
                    stack.pop();
                }
                // At root (absolute) a `..` is ignored; for a relative path we
                // must preserve leading `..` segments.
                _ => {
                    if !is_absolute {
                        stack.push("..");
                    }
                }
            },
            other => stack.push(other),
        }
    }

    let mut out = String::with_capacity(path.len());
    if is_absolute {
        out.push('/');
    }
    out.push_str(&stack.join("/"));
    // Restore a directory-boundary trailing slash, but never for the bare root
    // (already `/`).
    if had_trailing_slash && !stack.is_empty() {
        out.push('/');
    }
    out
}

/// Detects whether a file I/O event targets a sensitive path.
///
/// Maintains a list of path prefixes. Any event whose path starts with
/// one of these prefixes is classified as a sensitive access.
#[derive(Debug, Clone)]
pub struct SensitivePathDetector {
    prefixes: Vec<String>,
}

impl SensitivePathDetector {
    /// Create a detector with the given path prefixes.
    ///
    /// Prefixes are stored in lexically-canonical form (see
    /// [`canonicalize_lexical`]) so they match canonicalized event paths
    /// regardless of how the rule was written.
    pub fn new(prefixes: Vec<String>) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(|p| canonicalize_lexical(&p)).collect(),
        }
    }

    /// Create a detector with default sensitive paths.
    pub fn with_defaults() -> Self {
        Self::new(vec![
            "/etc/shadow".into(),
            "/etc/passwd".into(),
            "/etc/sudoers".into(),
            "/root/.ssh/".into(),
            "/home/".into(),
        ])
    }

    /// Check whether the given event targets a sensitive path.
    ///
    /// The event path is lexically canonicalized before matching so trivial
    /// non-canonical evasions (`/etc//shadow`, `/etc/../etc/shadow`, …) are
    /// still caught (AAASM-3921a).
    pub fn is_sensitive(&self, event: &FileIoEvent) -> bool {
        let canonical = canonicalize_lexical(&event.path);
        self.prefixes.iter().any(|p| canonical.starts_with(p))
    }

    /// Add a path prefix to the detector. The prefix is stored in
    /// lexically-canonical form (see [`canonicalize_lexical`]).
    pub fn add_prefix(&mut self, prefix: String) {
        self.prefixes.push(canonicalize_lexical(&prefix));
    }

    /// Return the current list of sensitive path prefixes.
    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::SyscallKind;

    fn make_event(path: &str) -> FileIoEvent {
        FileIoEvent {
            pid: 1,
            tid: 1,
            timestamp_ns: 0,
            syscall: SyscallKind::Openat,
            path: path.into(),
            flags: 0,
            return_code: 0,
            is_sensitive: false,
            duration_ns: 0,
        }
    }

    #[test]
    fn detects_sensitive_path() {
        let detector = SensitivePathDetector::with_defaults();
        assert!(detector.is_sensitive(&make_event("/etc/shadow")));
        assert!(detector.is_sensitive(&make_event("/etc/passwd")));
        assert!(detector.is_sensitive(&make_event("/root/.ssh/id_rsa")));
    }

    #[test]
    fn allows_normal_path() {
        let detector = SensitivePathDetector::with_defaults();
        assert!(!detector.is_sensitive(&make_event("/tmp/workfile")));
        assert!(!detector.is_sensitive(&make_event("/var/log/syslog")));
    }

    #[test]
    fn custom_prefix() {
        let mut detector = SensitivePathDetector::new(vec![]);
        detector.add_prefix("/opt/secrets/".into());
        assert!(detector.is_sensitive(&make_event("/opt/secrets/key.pem")));
        assert!(!detector.is_sensitive(&make_event("/opt/app/config")));
    }

    #[test]
    fn detects_noncanonical_sensitive_path() {
        let detector = SensitivePathDetector::with_defaults();
        // Evasions that the in-kernel exact-match blocklist would miss but the
        // canonicalizing userspace detector catches (AAASM-3921a).
        assert!(detector.is_sensitive(&make_event("/etc//shadow")));
        assert!(detector.is_sensitive(&make_event("/etc/./shadow")));
        assert!(detector.is_sensitive(&make_event("/etc/../etc/shadow")));
        assert!(detector.is_sensitive(&make_event("/root/.ssh/../.ssh/id_rsa")));
    }

    #[test]
    fn directory_prefix_boundary_is_respected() {
        let detector = SensitivePathDetector::with_defaults();
        // `/home/` must match files under it but not a sibling like `/homestead`.
        assert!(detector.is_sensitive(&make_event("/home//user/.bashrc")));
        assert!(!detector.is_sensitive(&make_event("/homestead/config")));
    }

    #[test]
    fn collapse_slashes_in_added_prefix() {
        let mut detector = SensitivePathDetector::new(vec![]);
        detector.add_prefix("/opt//secrets/".into());
        assert_eq!(detector.prefixes(), ["/opt/secrets/"]);
        assert!(detector.is_sensitive(&make_event("/opt/secrets/key.pem")));
    }

    #[test]
    fn canonicalize_collapses_repeated_slashes() {
        assert_eq!(canonicalize_lexical("/etc//shadow"), "/etc/shadow");
        assert_eq!(canonicalize_lexical("/etc///foo//bar"), "/etc/foo/bar");
    }

    #[test]
    fn canonicalize_drops_dot_segments() {
        assert_eq!(canonicalize_lexical("/etc/./shadow"), "/etc/shadow");
        assert_eq!(canonicalize_lexical("/./etc/shadow"), "/etc/shadow");
    }

    #[test]
    fn canonicalize_resolves_dotdot_segments() {
        assert_eq!(canonicalize_lexical("/etc/../etc/shadow"), "/etc/shadow");
        assert_eq!(canonicalize_lexical("/a/b/../c"), "/a/c");
    }

    #[test]
    fn canonicalize_dotdot_cannot_escape_root() {
        assert_eq!(canonicalize_lexical("/etc/../../shadow"), "/shadow");
        assert_eq!(canonicalize_lexical("/../../x"), "/x");
    }

    #[test]
    fn canonicalize_preserves_root_and_directory_trailing_slash() {
        assert_eq!(canonicalize_lexical("/"), "/");
        assert_eq!(canonicalize_lexical("/root/.ssh/"), "/root/.ssh/");
        assert_eq!(canonicalize_lexical("/home//"), "/home/");
    }

    #[test]
    fn canonicalize_keeps_relative_leading_dotdot() {
        assert_eq!(canonicalize_lexical("../etc/shadow"), "../etc/shadow");
        assert_eq!(canonicalize_lexical("a/./b/../c"), "a/c");
        assert_eq!(canonicalize_lexical(""), "");
    }
}
