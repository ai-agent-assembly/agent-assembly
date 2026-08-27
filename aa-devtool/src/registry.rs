//! Built-in dev-tool adapter registry — the **single source of truth** for
//! which [`DevToolAdapter`] implementation backs each supported tool.
//!
//! # Why this module exists (AAASM-5274)
//!
//! Before this module, two consumers picked adapters independently:
//! `DiscoveryService::new()` constructed detection-only stubs that lived in
//! `aa-devtool/src/adapters/`, while `aasm run`'s `resolve_adapter()` hard-coded
//! a *different* mix of dedicated-crate adapters and local placeholders. The two
//! paths therefore reported different governance levels for the same tool
//! (`aasm tools list` claimed Claude Code was `L3Native`; `aasm run claude` used
//! a stub declaring `L0Discover` that could not launch anything at all).
//!
//! Every consumer now resolves through this one table, so a tool's adapter —
//! and therefore its governance level, MCP support and launch behaviour — can no
//! longer differ between discovery and launch. The dedicated `aa-devtool-*`
//! crates are the authoritative implementations; `aa-devtool` is the registry /
//! discovery / orchestration layer above them and is no longer a second
//! implementation source.
//!
//! Adding a tool is a single edit here plus its dedicated crate — both consumers
//! pick it up automatically.

use aa_devtool_contract::{DevToolAdapter, DevToolKind};

/// CLI tool tokens for every built-in adapter, in the order
/// [`built_in_adapters`] returns them.
///
/// These are the **canonical** tool tokens. Changing one is a user-visible CLI
/// break: they are what `aasm run <tool>` has always accepted, and what every
/// per-tool lookup in this module is keyed by.
///
/// They are no longer the *only* strings `aasm run` accepts. Since AAASM-5503 it
/// also accepts each tool's Developer-Integration id — the longer spelling
/// `aasm integrations list` prints in its `TOOL` column (`claude-code` for
/// `claude`, and so on) — so an id copied off the discovery surface works on the
/// execution surface. That alias resolution lives in `aasm run`, which is the
/// only place that can see both vocabularies; this list stays the canonical one.
pub const SUPPORTED_TOOLS: [&str; 4] = ["claude", "codex", "copilot", "windsurf"];

/// Construct the authoritative adapter for a CLI tool token.
///
/// Returns `None` for tokens outside [`SUPPORTED_TOOLS`] — callers decide
/// whether that is a user error (`aasm run`) or simply an unsupported tool.
///
/// Each arm returns the adapter from the tool's **dedicated crate**. There is
/// deliberately no fallback stub: a tool either has a real implementation or is
/// not registered, so no consumer can silently end up with a non-functional
/// adapter (AAASM-5274).
pub fn adapter_for(tool: &str) -> Option<Box<dyn DevToolAdapter>> {
    match tool {
        "claude" => Some(Box::new(aa_devtool_claude_code::ClaudeCodeAdapter::new())),
        "codex" => Some(Box::new(aa_devtool_codex::CodexAdapter::default())),
        "copilot" => Some(Box::new(aa_devtool_copilot::CopilotAdapter::new())),
        "windsurf" => {
            aa_devtool_windsurf::WindsurfCascadeAdapter::new().map(|a| Box::new(a) as Box<dyn DevToolAdapter>)
        }
        _ => None,
    }
}

/// The [`DevToolKind`] a registered tool token identifies.
///
/// Declared here rather than derived from [`DevToolAdapter::detect`] because
/// `detect()` returns `None` when the tool is not installed, and callers
/// (registration payloads, tests, docs) need the kind regardless of whether the
/// host happens to have the tool.
pub fn kind_for(tool: &str) -> Option<DevToolKind> {
    match tool {
        "claude" => Some(DevToolKind::ClaudeCode),
        "codex" => Some(DevToolKind::Codex),
        "copilot" => Some(DevToolKind::GitHubCopilot),
        "windsurf" => Some(DevToolKind::WindsurfCascade),
        _ => None,
    }
}

/// Bypass conditions a launch's own arguments would create, in words a user can
/// act on.
///
/// Agent Assembly never strips these flags — its interception sits below the
/// tool's own permission enforcement, so removing them would change the user's
/// session without changing what is protected. What it can do is refuse to be
/// silent: a session started with `--dangerously-skip-permissions` is not
/// getting the tool-action governance its receipt describes, and the honest
/// place to say so is the moment it starts.
///
/// Resolved here rather than in `aasm run` for the same reason adapters are: the
/// CLI should not learn which flags matter to which tool.
pub fn launch_warnings(tool: &str, tool_args: &[String]) -> Vec<String> {
    match tool {
        "claude" => aa_devtool_claude_code::bypass::launch_flag_bypasses(tool_args)
            .into_iter()
            .map(|finding| format!("{} — {}", finding.summary, finding.remediation))
            .collect(),
        _ => Vec::new(),
    }
}

/// Construct one adapter per [`SUPPORTED_TOOLS`] entry that could be built in
/// this environment, in that order.
///
/// This is what `DiscoveryService::new()` runs, and it returns the same adapter
/// instances `aasm run` resolves — that shared origin is what the
/// discovery/launch parity regression test in `aa-cli` pins.
///
/// A [`SUPPORTED_TOOLS`] entry is silently omitted, not panicked on, when
/// [`adapter_for`] returns `None` for it (AAASM-5976): since that adapter's
/// own construction can legitimately fail at runtime (e.g. Windsurf's
/// `$HOME`-derived paths being unresolvable), `adapter_for`'s `None` no
/// longer means only "programming error — no match arm for this token".
/// Conflating the two here would mean an unset `$HOME` takes down discovery
/// for every other tool along with it, and the whole process at boot for any
/// consumer that calls this during startup (`aa-api`'s `AppState`) — a
/// materially worse failure than the misgoverned-Windsurf bug this ticket
/// fixes. A genuine `SUPPORTED_TOOLS`/`adapter_for` arm mismatch is still
/// caught, just by `every_supported_tool_resolves_to_an_adapter_and_a_kind`
/// below rather than by a panic here.
pub fn built_in_adapters() -> Vec<Box<dyn DevToolAdapter>> {
    SUPPORTED_TOOLS.iter().filter_map(|tool| adapter_for(tool)).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn every_supported_tool_resolves_to_an_adapter_and_a_kind() {
        for tool in SUPPORTED_TOOLS {
            assert!(adapter_for(tool).is_some(), "no adapter registered for {tool}");
            assert!(kind_for(tool).is_some(), "no kind registered for {tool}");
        }
    }

    #[test]
    fn built_in_adapters_covers_every_supported_tool() {
        assert_eq!(built_in_adapters().len(), SUPPORTED_TOOLS.len());
    }

    /// AAASM-5976 regression: an environment where one tool's adapter cannot
    /// be constructed (Windsurf's `$HOME`-derived paths, here) must not take
    /// discovery for the *other* tools down with it — `built_in_adapters()`
    /// used to `.expect()` on every `adapter_for` call, so this would have
    /// panicked (and, transitively, taken `aa-api`'s `AppState` construction
    /// down at boot) before `built_in_adapters` switched to `filter_map`.
    #[test]
    fn an_unavailable_adapter_is_omitted_not_a_panic() {
        static HOME_LOCK: Mutex<()> = Mutex::new(());
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("HOME");
        // SAFETY: serialized by HOME_LOCK; no other test in this binary
        // mutates HOME.
        unsafe { std::env::set_var("HOME", "") };

        assert!(adapter_for("windsurf").is_none());
        let adapters = built_in_adapters();
        assert_eq!(
            adapters.len(),
            SUPPORTED_TOOLS.len() - 1,
            "every other tool must still discover with HOME unresolvable"
        );

        // SAFETY: same reasoning as above.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn a_permission_bypass_flag_is_reported_but_never_stripped() {
        let args = vec!["--dangerously-skip-permissions".to_string(), "-p".to_string()];
        let warnings = launch_warnings("claude", &args);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("--dangerously-skip-permissions"), "{warnings:?}");
        assert!(launch_warnings("claude", &["-p".to_string()]).is_empty());
        // A tool with no bypass vocabulary of its own says nothing rather than
        // borrowing Claude Code's.
        assert!(launch_warnings("codex", &args).is_empty());
    }

    #[test]
    fn unknown_tool_is_not_registered() {
        assert!(adapter_for("notathing").is_none());
        assert!(kind_for("notathing").is_none());
    }

    #[test]
    fn registered_kinds_are_distinct() {
        let kinds: Vec<DevToolKind> = SUPPORTED_TOOLS.iter().filter_map(|t| kind_for(t)).collect();
        for (i, a) in kinds.iter().enumerate() {
            for b in kinds.iter().skip(i + 1) {
                assert_ne!(a, b, "two tool tokens map to the same DevToolKind");
            }
        }
    }

    /// The registry is only useful if it hands back *real* adapters — a stub
    /// declaring `L0Discover` is exactly the drift this module removes.
    #[test]
    fn no_registered_adapter_is_a_discovery_only_stub() {
        use aa_devtool_contract::GovernanceLevel;
        for tool in SUPPORTED_TOOLS {
            let adapter = adapter_for(tool).expect("registered");
            assert_ne!(
                adapter.governance_level(),
                GovernanceLevel::L0Discover,
                "{tool} resolved to an adapter that cannot govern anything"
            );
        }
    }
}
