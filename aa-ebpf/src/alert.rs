//! Sensitive path detection for userspace event processing.
//!
//! While the BPF probes perform in-kernel blocklist checks (flags bit 0),
//! the [`SensitivePathDetector`] provides a userspace-side check for
//! additional flexibility (e.g., prefix matching, regex patterns).

use crate::events::FileIoEvent;

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
    pub fn new(prefixes: Vec<String>) -> Self {
        Self { prefixes }
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
    pub fn is_sensitive(&self, event: &FileIoEvent) -> bool {
        self.prefixes.iter().any(|p| event.path.starts_with(p))
    }

    /// Add a path prefix to the detector.
    pub fn add_prefix(&mut self, prefix: String) {
        self.prefixes.push(prefix);
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
}
