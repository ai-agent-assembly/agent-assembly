//! Configuration for the policy history store.

use std::ffi::OsString;
use std::path::PathBuf;

use super::error::PolicyHistoryError;

/// Default maximum number of retained policy versions.
const DEFAULT_MAX_VERSIONS: usize = 50;

/// Default history subdirectory name under the data root.
const HISTORY_DIR_NAME: &str = "policy-history";

/// Configuration for the policy version history store.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryConfig {
    /// Directory where versioned policy snapshots are stored.
    pub history_dir: PathBuf,
    /// Maximum number of versions to retain before pruning.
    pub max_versions: usize,
}

impl HistoryConfig {
    /// Build a default configuration.
    ///
    /// The history directory resolves in this order:
    /// 1. `$AA_DATA_DIR/policy-history/` if `AA_DATA_DIR` is set and non-empty
    /// 2. `~/.aa/policy-history/` otherwise
    ///
    /// # Errors
    ///
    /// [`PolicyHistoryError::UnresolvableHistoryDir`] when neither yields a
    /// directory, rather than guessing one relative to the working directory.
    pub fn default_config() -> Result<Self, PolicyHistoryError> {
        let base = history_base_from(non_empty_var("AA_DATA_DIR"), dirs::home_dir())
            .ok_or(PolicyHistoryError::UnresolvableHistoryDir)?;

        Ok(Self {
            history_dir: base.join(HISTORY_DIR_NAME),
            max_versions: DEFAULT_MAX_VERSIONS,
        })
    }
}

/// Screen an override value, treating empty as absent.
///
/// # Why this is separate from [`non_empty_var`]
///
/// This screen is the *only* thing standing between an empty `AA_DATA_DIR` and a
/// bare relative `policy-history`: [`history_base_from`] takes whatever override
/// it is handed, so `Some("")` reaches `base.join(HISTORY_DIR_NAME)` and yields a
/// cwd-relative path — AAASM-5959 by a second route. A screen that reads the
/// variable itself cannot be asserted without a test mutating a process-global,
/// which is the same reason the resolution rules below take their environment as
/// arguments rather than reading it.
fn non_empty(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn non_empty_var(name: &str) -> Option<PathBuf> {
    non_empty(std::env::var_os(name))
}

/// The resolution rule for the history root, with the environment passed in.
///
/// # Why there is no `.` fallback
///
/// This used to end in `dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))`,
/// so a host where no home directory is resolvable kept the policy version
/// history in `./.aa/policy-history` — relative to whatever directory the process
/// happened to start in. Policy history is the record of what governance was in
/// force when; a run that resolves a different working directory then reads an
/// empty history and writes a second, unrelated one, and nothing in the output
/// distinguishes that from a genuinely empty history (AAASM-5959).
///
/// Nothing legitimate is lost. `AA_DATA_DIR` or a home directory is available for
/// every ordinary invocation, and `dirs::home_dir()` already falls back to the
/// passwd database on Unix, so reaching `None` here takes a substantially more
/// degraded environment than a merely unset variable.
///
/// # Why an empty `AA_DATA_DIR` is treated as unset
///
/// It previously took the override branch, so `"".join("policy-history")` yielded
/// the bare relative `policy-history` — the same defect by a second route, and
/// the one an operator is most likely to hit by exporting the variable from an
/// unset shell parameter. `default_audit_dir` in `aa-gateway` already screened
/// empty out; this now matches it.
///
/// # Why the environment is an argument
///
/// A function not given the environment cannot resolve against the process
/// working directory, so the removed fallback cannot return by accident — and the
/// rule stays assertable without any test mutating process-global state.
fn history_base_from(override_dir: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    match override_dir {
        Some(dir) => Some(dir),
        None => Some(home?.join(".aa")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_versions_is_50() {
        let cfg = HistoryConfig {
            history_dir: PathBuf::from("/tmp/test"),
            max_versions: DEFAULT_MAX_VERSIONS,
        };
        assert_eq!(cfg.max_versions, 50);
    }

    #[test]
    fn custom_construction() {
        let cfg = HistoryConfig {
            history_dir: PathBuf::from("/custom/path"),
            max_versions: 100,
        };
        assert_eq!(cfg.history_dir, PathBuf::from("/custom/path"));
        assert_eq!(cfg.max_versions, 100);
    }

    #[test]
    fn default_config_ends_with_policy_history() {
        // Resolvable on any host CI or a developer runs this on: `AA_DATA_DIR` or
        // a home directory is always available. `expect` rather than `unwrap` so a
        // host where it is not says why.
        let cfg = HistoryConfig::default_config().expect("a history directory must be resolvable");
        assert!(cfg.history_dir.ends_with("policy-history"));
        assert_eq!(cfg.max_versions, 50);
    }

    /// The history root rule may not invent a root when it has none (AAASM-5959).
    ///
    /// Reverting `history_base_from` to
    /// `home.unwrap_or_else(|| PathBuf::from("."))` reddens exactly this test.
    #[test]
    fn the_history_root_rule_synthesises_nothing_when_nothing_is_set() {
        assert_eq!(
            history_base_from(None, None),
            None,
            "an unset AA_DATA_DIR and no home directory must yield no root, not ./.aa"
        );
    }

    /// The refusal names the variable an operator can act on (AC 2).
    ///
    /// Asserted on the error itself rather than on `is_err()`, so a refusal that
    /// stopped being actionable would fail here (AC 5).
    #[test]
    fn the_refusal_names_the_variable_an_operator_can_set() {
        let message = PolicyHistoryError::UnresolvableHistoryDir.to_string();
        assert!(
            message.contains("AA_DATA_DIR"),
            "the refusal must name AA_DATA_DIR so it is actionable, got: {message}"
        );
        assert!(std::error::Error::source(&PolicyHistoryError::UnresolvableHistoryDir).is_none());
    }

    /// Resolution order and results are unchanged whenever anything is set, which
    /// is every ordinary invocation including CI (AC 6).
    #[test]
    fn the_history_root_rule_is_unchanged_when_an_override_or_home_is_set() {
        let over = PathBuf::from("/o");
        let home = PathBuf::from("/h");

        // The override wins over the home directory.
        assert_eq!(
            history_base_from(Some(over.clone()), Some(home.clone())),
            Some(over.clone())
        );
        // A home directory alone gives the documented `~/.aa` layout.
        assert_eq!(history_base_from(None, Some(home)), Some(PathBuf::from("/h/.aa")));
        // An override alone works with no home directory at all.
        assert_eq!(history_base_from(Some(over.clone()), None), Some(over));
    }

    /// An empty `AA_DATA_DIR` is screened out before it can produce a bare
    /// relative `policy-history`, which is the same defect by a second route.
    ///
    /// The screen is the only guard against that route: `history_base_from` uses
    /// whatever override it is handed, so `Some("")` would reach
    /// `base.join(HISTORY_DIR_NAME)` and yield the relative `policy-history`. The
    /// assertion below is therefore on a *real* empty value, which is what
    /// `non_empty` exists to make possible — an earlier version of this test passed
    /// a deliberately unset variable name instead, so `var_os` returned `None`
    /// before the filter was consulted and deleting the filter left it green.
    ///
    /// Removing `.filter(|v| !v.is_empty())` from `non_empty` reddens exactly the
    /// first assertion.
    #[test]
    fn an_empty_override_is_not_treated_as_a_root() {
        assert_eq!(
            non_empty(Some(OsString::new())),
            None,
            "an empty override must be screened out, not returned as a root — it would join to \
             the relative \"policy-history\""
        );

        // The two halves that make that refusal safe: a set value is still
        // honoured, and an absent one is still absent.
        assert_eq!(non_empty(Some(OsString::from("/o"))), Some(PathBuf::from("/o")));
        assert_eq!(non_empty(None), None);

        // And with the empty override screened out, the rule falls through to the
        // home directory rather than joining onto "".
        assert_eq!(
            history_base_from(non_empty(Some(OsString::new())), Some(PathBuf::from("/h"))),
            Some(PathBuf::from("/h/.aa")),
            "an empty override must fall through, not yield the relative \"policy-history\""
        );
    }
}
