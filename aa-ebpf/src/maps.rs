//! BPF map types and constants for path filtering.

/// Maximum number of path patterns in the BPF hash map.
pub const MAX_PATH_PATTERNS: u32 = 256;

/// Maximum byte length of a single path pattern stored in a BPF map entry.
pub const MAX_PATH_LEN: usize = 256;

/// Whether matching a path pattern should allow or deny the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PathVerdict {
    /// The path is allowed — no policy violation.
    Allow = 0,
    /// The path is blocked — triggers a policy violation event.
    Deny = 1,
}

/// A path pattern entry stored in a BPF hash map.
///
/// Userspace writes these entries to configure which file paths the kprobes
/// should flag. The map is updatable at runtime without reloading the eBPF
/// programs.
///
/// **Match contract (AAASM-3921a/b).** In-kernel matching is **exact,
/// NUL-padded full-path equality** only — it is NOT prefix matching despite the
/// historical "prefix" wording. A directory rule like `/etc/` therefore never
/// fires in-kernel; express directory/prefix and non-canonical rules through
/// the userspace [`SensitivePathDetector`](crate::alert::SensitivePathDetector),
/// which canonicalizes and does boundary-aware prefix matching. The file layer
/// is OBSERVE-ONLY, so this split degrades alert coverage, not enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    /// The **exact** path to match (e.g., `/etc/shadow`). Matched byte-for-byte
    /// in-kernel; use the userspace detector for prefix/canonical rules.
    pub pattern: String,
    /// Whether matching this pattern should allow or deny the operation.
    pub verdict: PathVerdict,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_pattern_construction() {
        let pattern = PathPattern {
            pattern: "/etc/shadow".into(),
            verdict: PathVerdict::Deny,
        };
        assert_eq!(pattern.pattern, "/etc/shadow");
        assert_eq!(pattern.verdict, PathVerdict::Deny);
    }

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(MAX_PATH_PATTERNS, 256);
        assert_eq!(MAX_PATH_LEN, 256);
    }
}
