//! Policy rule types loaded from the policy volume mount.

use serde::Deserialize;

fn default_approval_timeout_secs() -> u32 {
    300
}

/// A single policy rule: a named set of action strings that are blocked or require approval.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    /// Human-readable rule name (used in violation log messages).
    pub name: String,
    /// Action strings that this rule blocks outright.
    /// Matched against the action type string during pipeline evaluation.
    pub blocked_actions: Vec<String>,
    /// Action strings that require human approval before proceeding.
    /// When matched, the pipeline responds with `Decision::PENDING` and
    /// submits the request to the [`crate::approval::ApprovalQueue`].
    #[serde(default)]
    pub requires_approval_actions: Vec<String>,
    /// Seconds before an approval request times out and the fallback policy applies.
    /// Defaults to 300 (5 minutes) when absent from the policy file.
    #[serde(default = "default_approval_timeout_secs")]
    pub approval_timeout_secs: u32,
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            blocked_actions: Vec::new(),
            requires_approval_actions: Vec::new(),
            approval_timeout_secs: 300,
        }
    }
}

/// The full set of policy rules loaded at runtime startup.
///
/// An empty `PolicyRules` (zero rules) means no enforcement — all events pass through normally.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyRules {
    /// The list of rules to evaluate against each event.
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

impl PolicyRules {
    /// Returns `true` if no rules are loaded (policy enforcement is disabled).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Errors that can occur when loading the policy file.
#[derive(Debug)]
pub enum PolicyLoadError {
    /// I/O error reading the file (other than file-not-found).
    Io(std::io::Error),
    /// The file exists but could not be parsed as valid TOML policy.
    Parse(toml::de::Error),
}

impl std::fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "policy file I/O error: {e}"),
            Self::Parse(e) => write!(f, "policy file parse error: {e}"),
        }
    }
}

impl std::error::Error for PolicyLoadError {}

/// Load policy rules from a TOML file at `path`.
///
/// - If the file does not exist, logs a warning and returns empty `PolicyRules` (no enforcement).
/// - If the file exists but cannot be parsed, returns `Err(PolicyLoadError::Parse)`.
/// - Any other I/O error returns `Err(PolicyLoadError::Io)`.
pub fn load_policy(path: &std::path::Path) -> Result<PolicyRules, PolicyLoadError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents).map_err(PolicyLoadError::Parse),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(path = %path.display(), "policy file not found — starting without enforcement");
            Ok(PolicyRules::default())
        }
        Err(e) => Err(PolicyLoadError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_rules_is_empty() {
        let rules = PolicyRules::default();
        assert!(rules.is_empty());
        assert_eq!(rules.rules.len(), 0);
    }

    #[test]
    fn policy_rules_is_empty_false_when_rules_present() {
        let rules = PolicyRules {
            rules: vec![PolicyRule {
                name: "test-rule".to_string(),
                blocked_actions: vec!["dangerous_action".to_string()],
                ..Default::default()
            }],
        };
        assert!(!rules.is_empty());
    }

    #[test]
    fn policy_rule_fields_are_accessible() {
        let rule = PolicyRule {
            name: "block-exfil".to_string(),
            blocked_actions: vec!["send_email".to_string(), "upload_file".to_string()],
            ..Default::default()
        };
        assert_eq!(rule.name, "block-exfil");
        assert_eq!(rule.blocked_actions.len(), 2);
    }

    #[test]
    fn policy_rule_requires_approval_defaults_empty() {
        let rule = PolicyRule {
            name: "approval-rule".to_string(),
            requires_approval_actions: vec!["TOOL_CALL".to_string()],
            ..Default::default()
        };
        assert_eq!(rule.requires_approval_actions, vec!["TOOL_CALL"]);
        assert_eq!(rule.approval_timeout_secs, 300);
    }

    #[test]
    fn load_policy_returns_empty_when_file_absent() {
        let result = load_policy(std::path::Path::new("/nonexistent/path/policy.toml"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn load_policy_parses_valid_toml() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "[[rules]]").unwrap();
        writeln!(tmp, r#"name = "block-exfil""#).unwrap();
        writeln!(tmp, r#"blocked_actions = ["send_email"]"#).unwrap();
        tmp.flush().unwrap();
        let result = load_policy(tmp.path()).expect("should parse");
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].name, "block-exfil");
        assert_eq!(result.rules[0].blocked_actions, vec!["send_email"]);
        assert!(result.rules[0].requires_approval_actions.is_empty());
        assert_eq!(result.rules[0].approval_timeout_secs, 300);
    }

    #[test]
    fn load_policy_returns_io_error_for_non_notfound_failure() {
        // Pointing at a directory makes read_to_string fail with a non-NotFound
        // I/O error, which must surface as PolicyLoadError::Io (not be swallowed
        // as "absent → no enforcement").
        let dir = tempfile::tempdir().expect("tempdir");
        let result = load_policy(dir.path());
        assert!(matches!(result, Err(PolicyLoadError::Io(_))));
    }

    #[test]
    fn policy_load_error_display_renders_both_variants() {
        let io = PolicyLoadError::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope"));
        assert!(io.to_string().contains("I/O error"), "got: {io}");

        let parse_err = toml::from_str::<PolicyRules>("rules = 5").expect_err("type mismatch is a parse error");
        let parse = PolicyLoadError::Parse(parse_err);
        assert!(parse.to_string().contains("parse error"), "got: {parse}");
    }

    #[test]
    fn load_policy_errors_on_malformed_toml() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "[[rules]]\nname = unterminated_string_literal").unwrap();
        tmp.flush().unwrap();
        let result = load_policy(tmp.path());
        assert!(matches!(result, Err(PolicyLoadError::Parse(_))));
    }
}
