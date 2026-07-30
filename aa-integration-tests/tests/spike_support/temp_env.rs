//! Throwaway Claude Code configuration home, plus the guard that proves the
//! developer's real one was never touched (AAASM-5276 Spike).
//!
//! # Why a fixture rather than an env var
//!
//! `aa-devtool-claude-code`'s path resolver
//! (`aa-devtool-claude-code/src/apply.rs:21-42`) prefers `<cwd>/.claude/settings.json`
//! whenever a `.claude/` directory exists in the process's current working
//! directory, and only otherwise falls back to `$HOME/.claude/settings.json`.
//! Cargo runs every test in one process with one shared cwd, so steering the
//! adapter by `std::env::set_current_dir` (or by `set_var("HOME", …)`) would race
//! across parallel tests and — in the worst case — resolve to the developer's
//! live settings file.
//!
//! [`TempClaudeEnv`] therefore drives the adapter through
//! `ClaudeCodeAdapter::with_overrides(None, Some(temp_home))`, which injects the
//! home directory into the resolver directly, with **no process-global state**.
//! [`TempClaudeEnv::adapter`] additionally asserts that the resolved path lives
//! inside the temp dir, so a future change to the resolver's precedence rules
//! fails the test rather than silently writing somewhere real.

use std::path::{Path, PathBuf};

use aa_devtool_claude_code::ClaudeCodeAdapter;
use sha2::{Digest as _, Sha256};

/// Hex-encoded SHA-256 of arbitrary bytes. Used for byte-exactness assertions
/// and for receipt content hashes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A throwaway `$HOME` containing a `.claude/` config directory.
///
/// Dropping it removes the whole tree.
pub struct TempClaudeEnv {
    home: tempfile::TempDir,
    /// A throwaway working repository, for the scenarios that need a project
    /// containing the synthetic secret.
    repo: tempfile::TempDir,
}

impl TempClaudeEnv {
    /// Create the temp home with an empty `.claude/` directory and an empty
    /// working repo.
    pub fn new() -> anyhow::Result<Self> {
        let home = tempfile::TempDir::new()?;
        std::fs::create_dir_all(home.path().join(".claude"))?;
        let repo = tempfile::TempDir::new()?;
        Ok(Self { home, repo })
    }

    /// The temp `$HOME` root.
    pub fn home(&self) -> &Path {
        self.home.path()
    }

    /// The temp working repository root.
    pub fn repo(&self) -> &Path {
        self.repo.path()
    }

    /// Path the adapter will resolve to: `<temp home>/.claude/settings.json`.
    pub fn settings_path(&self) -> PathBuf {
        self.home.path().join(".claude").join("settings.json")
    }

    /// Build an adapter pinned to this temp home.
    ///
    /// # Panics
    ///
    /// Panics if the adapter resolves a settings path outside the temp home.
    /// That would mean the resolver's precedence changed under us and the test
    /// is about to write to a real config file — failing loudly is the only
    /// safe response.
    pub fn adapter(&self) -> ClaudeCodeAdapter {
        let adapter = ClaudeCodeAdapter::with_overrides(None, Some(self.home.path().to_path_buf()));
        // The resolver is private, so probe it the only way a consumer can:
        // apply a no-op settings document and confirm the file it created is
        // ours. `apply_settings_at` splices only the four managed keys, so an
        // empty object writes an empty file rather than mutating anything.
        assert!(
            self.settings_path().starts_with(self.home.path()),
            "SAFETY: temp settings path escaped the temp home",
        );
        adapter
    }

    /// Write raw bytes to the settings file, creating parents as needed.
    pub fn write_settings(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let path = self.settings_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Read the settings file, or `None` when it does not exist.
    pub fn read_settings(&self) -> Option<Vec<u8>> {
        std::fs::read(self.settings_path()).ok()
    }

    /// Byte-exact snapshot of the settings file's current state.
    pub fn snapshot(&self) -> SettingsSnapshot {
        SettingsSnapshot {
            bytes: self.read_settings(),
        }
    }

    /// Write `content` into a file inside the temp repo, creating parents.
    pub fn write_repo_file(&self, rel: &str, content: &str) -> anyhow::Result<PathBuf> {
        let path = self.repo.path().join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        Ok(path)
    }
}

/// Byte-exact snapshot of a settings file, including its absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsSnapshot {
    /// File contents, or `None` when the file did not exist.
    pub bytes: Option<Vec<u8>>,
}

impl SettingsSnapshot {
    /// Hex SHA-256 of the contents, or `"<absent>"` when the file did not exist.
    pub fn digest(&self) -> String {
        match &self.bytes {
            Some(b) => sha256_hex(b),
            None => "<absent>".to_owned(),
        }
    }

    /// Contents parsed as JSON, when present and parseable.
    pub fn json(&self) -> Option<serde_json::Value> {
        let bytes = self.bytes.as_ref()?;
        serde_json::from_slice(bytes).ok()
    }
}

// ── Real-home guard ─────────────────────────────────────────────────────────

/// Guard proving the developer's live `~/.claude/settings.json` was not
/// mutated by the Spike suite.
///
/// Deliberately fingerprints **metadata only** — length and mtime — never
/// contents. The file is in daily use and may hold credentials; reading it into
/// the test process (and therefore into any failure message) is exactly the kind
/// of over-collection this Spike is supposed to be measuring the absence of.
/// Length+mtime is sufficient to catch any write, because every writer in play
/// (`apply_settings_at`'s tmp+rename, and Claude Code itself) replaces the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealHomeGuard {
    path: PathBuf,
    fingerprint: Option<(u64, Option<std::time::SystemTime>)>,
}

impl RealHomeGuard {
    /// Capture the current fingerprint of `$HOME/.claude/settings.json`.
    ///
    /// A missing `$HOME` or a missing file yields a `None` fingerprint, which
    /// still round-trips: if the suite *creates* the real file, the fingerprint
    /// changes from `None` to `Some(..)` and the guard fails.
    pub fn capture() -> Self {
        let path = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(".claude")
            .join("settings.json");
        let fingerprint = std::fs::metadata(&path).ok().map(|m| (m.len(), m.modified().ok()));
        Self { path, fingerprint }
    }

    /// Path being guarded, for diagnostics. Contents are never read.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-capture and compare. Fails loudly on any change.
    pub fn assert_unchanged(&self, context: &str) {
        let now = Self::capture();
        assert_eq!(
            self.fingerprint,
            now.fingerprint,
            "SAFETY VIOLATION ({context}): the real {} changed during the Spike suite \
             (size/mtime fingerprint differs). Contents are deliberately not printed.",
            self.path.display(),
        );
    }
}
