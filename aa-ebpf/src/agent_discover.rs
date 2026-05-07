//! Unknown-agent discovery via exec-event classification (L0 / discover mode).
//!
//! In L0 mode the gateway is purely observational — it does not enforce policy
//! but tries to detect AI dev tools that were *not* registered through the SDK
//! or a managed adapter.  This module provides [`AgentDiscoveryClassifier`], a
//! cross-platform component that inspects process-exec filenames and classifies
//! them as a known [`DevToolKind`] (or [`Unknown`][DevToolKind::Custom] with the
//! raw binary name).
//!
//! ## Usage
//!
//! ```rust
//! use aa_ebpf::agent_discover::AgentDiscoveryClassifier;
//!
//! let clf = AgentDiscoveryClassifier::default();
//! if let Some(kind_str) = clf.classify("/home/user/.nvm/bin/claude") {
//!     println!("detected unregistered agent: {kind_str}");
//! }
//! ```
//!
//! ## Integration with the exec tracepoint
//!
//! On Linux the caller feeds exec filenames from [`TracepointManager`] events
//! directly into [`AgentDiscoveryClassifier::classify`].  The returned string
//! can then be forwarded to the gateway for opportunistic registration or
//! alerting.
//!
//! On non-Linux platforms this module is still fully functional (no aya
//! dependency) and is exercised by unit tests in CI.
//!
//! [`TracepointManager`]: crate::tracepoint::TracepointManager

/// An entry in the binary-pattern catalogue.
pub(crate) struct Pattern {
    /// Executable basename to match (case-sensitive, exact).
    pub(crate) basename: &'static str,
    /// Human-readable tool name returned on match.
    pub(crate) tool_name: &'static str,
}

/// Classifies process-exec filenames against a catalogue of known AI dev tool
/// binary names.
///
/// Pattern matching is basename-only (the directory portion of the path is
/// stripped before comparison) and exact (no glob or regex).
///
/// Construct with [`AgentDiscoveryClassifier::default`] to get the built-in
/// catalogue, or build a custom catalogue with
/// [`AgentDiscoveryClassifier::with_patterns`].
pub struct AgentDiscoveryClassifier {
    patterns: Vec<Pattern>,
}

impl Default for AgentDiscoveryClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentDiscoveryClassifier {
    /// Create a classifier loaded with the built-in AI dev tool patterns.
    ///
    /// Covers the four tools tracked by the detection adapters in `aa-devtool`:
    /// Claude Code, Codex, GitHub Copilot (agent mode), and Windsurf Cascade.
    pub fn new() -> Self {
        Self::with_patterns(vec![
            // Claude Code CLI — installed by `npm i -g @anthropic-ai/claude-code`.
            Pattern {
                basename: "claude",
                tool_name: "ClaudeCode",
            },
            // OpenAI Codex CLI — installed by `npm i -g @openai/codex`.
            Pattern {
                basename: "codex",
                tool_name: "Codex",
            },
            // GitHub Copilot agent-mode shim (VS Code extension spawns this).
            Pattern {
                basename: "copilot",
                tool_name: "GitHubCopilot",
            },
            // Windsurf Cascade IDE agent binary.
            Pattern {
                basename: "windsurf",
                tool_name: "WindsurfCascade",
            },
            // Alternative Windsurf executable name on some distros.
            Pattern {
                basename: "cascade",
                tool_name: "WindsurfCascade",
            },
        ])
    }

    /// Create a classifier with a caller-supplied pattern list.
    ///
    /// Primarily intended for testing or out-of-tree extension.
    pub(crate) fn with_patterns(patterns: Vec<Pattern>) -> Self {
        Self { patterns }
    }

    /// Classify an executable path.
    ///
    /// Strips the directory component and performs an exact basename match
    /// against the built-in catalogue.
    ///
    /// Returns `Some(&str)` with the tool name on a match, or `None` if the
    /// binary is not recognised as a known AI dev tool.
    pub fn classify<'a>(&'a self, path: &'a str) -> Option<&'a str> {
        let basename = path.rsplit('/').next().unwrap_or(path);
        self.patterns
            .iter()
            .find(|p| p.basename == basename)
            .map(|p| p.tool_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_claude_by_basename() {
        let clf = AgentDiscoveryClassifier::new();
        assert_eq!(clf.classify("/usr/local/bin/claude"), Some("ClaudeCode"));
    }

    #[test]
    fn classify_codex_bare_name() {
        let clf = AgentDiscoveryClassifier::new();
        assert_eq!(clf.classify("codex"), Some("Codex"));
    }

    #[test]
    fn classify_windsurf_returns_tool_name() {
        let clf = AgentDiscoveryClassifier::new();
        assert_eq!(clf.classify("/opt/windsurf/windsurf"), Some("WindsurfCascade"));
    }

    #[test]
    fn classify_cascade_alias_returns_windsurf_cascade() {
        let clf = AgentDiscoveryClassifier::new();
        assert_eq!(clf.classify("/usr/bin/cascade"), Some("WindsurfCascade"));
    }

    #[test]
    fn classify_unknown_binary_returns_none() {
        let clf = AgentDiscoveryClassifier::new();
        assert_eq!(clf.classify("/usr/bin/ls"), None);
        assert_eq!(clf.classify("/usr/bin/python3"), None);
    }

    #[test]
    fn classify_empty_path_returns_none() {
        let clf = AgentDiscoveryClassifier::new();
        assert_eq!(clf.classify(""), None);
    }

    #[test]
    fn custom_pattern_is_matched() {
        let clf = AgentDiscoveryClassifier::with_patterns(vec![Pattern {
            basename: "my-agent",
            tool_name: "MyCustomTool",
        }]);
        assert_eq!(clf.classify("/opt/my-agent"), Some("MyCustomTool"));
        assert_eq!(clf.classify("/usr/bin/claude"), None);
    }
}
