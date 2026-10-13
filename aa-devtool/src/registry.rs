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

pub use aa_devtool_codex::boundary::LaunchDecision;

/// What verifying a launch's effective boundary concluded (AAASM-6331).
#[derive(Debug, PartialEq, Eq)]
pub struct BoundaryCheck {
    /// Whether the launch may go ahead.
    pub decision: LaunchDecision,
    /// One machine-readable line per fact, for the launch report. Empty when the
    /// tool has no verification (the launch is then simply not verified).
    pub report: String,
}

/// Verifies, before launch, the boundary the tool will ACTUALLY run under —
/// not the one a written config file claims. Only Codex is verified today; for
/// every other tool this returns `None` and the caller must not claim a
/// verified boundary.
///
/// `command` is the fully bound launch command (program, argv, working
/// directory and environment changes), so the probes see the same
/// configuration the launch will. `enforce` is true under Enforce mode, where
/// anything short of a verified boundary refuses the launch.
pub fn verify_launch_boundary(
    tool: &str,
    command: &std::process::Command,
    policy: &aa_devtool_contract::PolicyDocument,
    enforce: bool,
) -> Option<BoundaryCheck> {
    use aa_devtool_codex::boundary::{launch_decision, required_floor, verify, CommandRunner, Verdict};
    if tool != "codex" {
        return None;
    }
    let argv: Vec<String> = command.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let runner = CommandRunner {
        program: command.get_program().into(),
        cwd: command.get_current_dir().map(std::path::Path::to_path_buf),
        env: command
            .get_envs()
            .map(|(k, v)| (k.to_owned(), v.map(std::ffi::OsStr::to_owned)))
            .collect(),
        timeout: aa_devtool_codex::boundary::DEFAULT_PROBE_TIMEOUT,
    };
    let mut verdict = verify(&runner, &argv, required_floor(policy));
    // Allow rules the prompt-input probe does not list still run unsandboxed.
    if let Verdict::Checked(r) = &verdict {
        if r.allows_launch() {
            let from_env = |k: &str| {
                command
                    .get_envs()
                    .find(|(name, _)| *name == std::ffi::OsStr::new(k))
                    .map(|(_, v)| v.map(std::path::PathBuf::from))
                    .unwrap_or_else(|| std::env::var_os(k).map(std::path::PathBuf::from))
                    .filter(|p| !p.as_os_str().is_empty())
            };
            // A relative path is resolved by the OS against the process cwd at
            // spawn, and (for CODEX_HOME) by Codex against its own cwd, so both
            // spellings are candidates; the scan is a superset on purpose.
            let process_cwd = std::env::current_dir().ok();
            let absolutise = |p: &std::path::Path| -> Vec<std::path::PathBuf> {
                if p.is_absolute() {
                    vec![p.to_path_buf()]
                } else {
                    process_cwd.iter().map(|c| c.join(p)).collect()
                }
            };
            let mut bases: Vec<std::path::PathBuf> = match command.get_current_dir() {
                Some(d) => absolutise(d),
                None => process_cwd.iter().cloned().collect(),
            };
            if let Ok(aa_devtool_codex::boundary::Invocation::AgentRun { cd: Some(cd), .. }) =
                aa_devtool_codex::boundary::parse_invocation(&argv)
            {
                let joined: Vec<_> = bases.iter().map(|b| b.join(&cd)).collect();
                bases.extend(joined);
            }
            let mut homes: Vec<std::path::PathBuf> = Vec::new();
            match (from_env("CODEX_HOME"), from_env("HOME")) {
                (Some(h), _) if h.is_absolute() => homes.push(h),
                (Some(h), _) => {
                    homes.extend(bases.iter().map(|b| b.join(&h)));
                    homes.extend(absolutise(&h));
                }
                (None, Some(h)) => {
                    // A relative HOME is resolved by Codex against the launch
                    // directory, like a relative CODEX_HOME (review F1).
                    homes.extend(bases.iter().map(|b| b.join(&h).join(".codex")));
                    homes.extend(absolutise(&h.join(".codex")));
                }
                (None, None) => {}
            }
            let rules = if homes.is_empty() {
                // Neither CODEX_HOME nor HOME resolves: the user rules cannot be
                // located, so the boundary cannot be called verified.
                vec![std::path::PathBuf::from("<CODEX_HOME not locatable>")]
            } else {
                aa_devtool_codex::boundary::execpolicy_rule_files(&homes, &bases)
            };
            if !rules.is_empty() {
                verdict = Verdict::Checked(aa_devtool_codex::boundary::BoundaryReport::below(format!(
                    "{} execpolicy rule file(s) can run commands outside the sandbox (e.g. {})",
                    rules.len(),
                    rules
                        .iter()
                        .take(3)
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
    }
    let report = match &verdict {
        Verdict::NotApplicable => "codex_boundary=not_applicable\ncodex_boundary_scope=sandbox_approval_network_only".to_string(),
        Verdict::Refused(why) => format!(
            "codex_boundary=unverifiable\ncodex_boundary_scope=sandbox_approval_network_only\ncodex_boundary_reason={why:?}"
        ),
        Verdict::Checked(r) => format!(
            "codex_boundary={}\ncodex_boundary_scope=sandbox_approval_network_only\ncodex_boundary_filesystem={:?}\ncodex_boundary_network={:?}\ncodex_boundary_approval={:?}",
            if r.allows_launch() { "verified" } else { "not_met" },
            r.filesystem,
            r.network,
            r.approval
        ),
    };
    Some(BoundaryCheck {
        decision: launch_decision(&verdict, enforce),
        report,
    })
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
    // ---- AAASM-6331: verify_launch_boundary against fake `codex` scripts ----

    fn fake_codex(dir: &std::path::Path, prompt: &str, doctor: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(dir.join("prompt.json"), prompt).unwrap();
        std::fs::write(dir.join("doctor.json"), doctor).unwrap();
        let path = dir.join("codex");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n doctor) cat '{d}/doctor.json';;\n debug) cat '{d}/prompt.json';;\nesac\n",
                d = dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Hand-written JSON (no serde_json dev-dependency, so this crate's manifest
    /// and the lockfile stay untouched).
    fn read_only_prompt() -> String {
        r#"[
  {"role":"developer","content":[{"text":"<permissions instructions>\n`sandbox_mode` is `read-only`: x. Network access is restricted.\n"}]},
  {"role":"user","content":[{"text":"<environment_context>\n<cwd>/w</cwd><filesystem><workspace_roots><root>/w</root></workspace_roots><permission_profile type=\"managed\"><file_system type=\"restricted\"><entry access=\"read\"><special>:root</special></entry></file_system></permission_profile></filesystem>\n</environment_context>"}]}
]"#
        .to_string()
    }

    fn doctor_json(fs: &str) -> String {
        format!(
            r#"{{"codexVersion":"{}","checks":{{"config.load":{{"status":"ok"}},"sandbox.helpers":{{"details":{{"approval policy":"OnRequest","filesystem sandbox":"{fs}","network sandbox":"restricted"}}}}}}}}"#,
            aa_devtool_codex::boundary::MEASURED_CODEX_VERSION
        )
    }

    fn deny_policy() -> aa_devtool_contract::PolicyDocument {
        aa_devtool_contract::PolicyDocument {
            version: 1,
            name: "deny".into(),
            enforcement_mode: aa_devtool_contract::EnforcementMode::default(),
            rules: vec![aa_devtool_contract::PolicyRule {
                action_pattern: "fs:write".into(),
                decision: aa_devtool_contract::PolicyDecision::Deny,
            }],
        }
    }

    fn command_for(program: &std::path::Path, args: &[&str]) -> std::process::Command {
        let mut c = std::process::Command::new(program);
        c.args(args);
        // Hermetic: never read the developer's real ~/.codex/rules, and never
        // walk up from the repository checkout (which lives under $HOME).
        c.env("CODEX_HOME", program.parent().unwrap());
        c.current_dir(program.parent().unwrap());
        c
    }

    #[test]
    fn only_codex_has_a_boundary_verdict() {
        let cmd = std::process::Command::new("true");
        assert!(verify_launch_boundary("claude", &cmd, &deny_policy(), true).is_none());
        assert!(verify_launch_boundary("copilot", &cmd, &deny_policy(), true).is_none());
    }

    #[test]
    fn a_verified_boundary_proceeds_and_reports_its_scope() {
        let dir = tempfile::tempdir().unwrap();
        let prog = fake_codex(dir.path(), &read_only_prompt(), &doctor_json("restricted"));
        let check = verify_launch_boundary("codex", &command_for(&prog, &["exec", "do it"]), &deny_policy(), true)
            .expect("codex is verified");
        assert_eq!(check.decision, LaunchDecision::Proceed, "{}", check.report);
        assert!(check.report.contains("codex_boundary=verified"));
        assert!(check
            .report
            .contains("codex_boundary_scope=sandbox_approval_network_only"));
    }

    #[test]
    fn an_unmet_boundary_is_refused_under_enforce_and_degraded_under_observe() {
        let dir = tempfile::tempdir().unwrap();
        // doctor says unrestricted while the prompt says read-only: disagreement.
        let prog = fake_codex(dir.path(), &read_only_prompt(), &doctor_json("unrestricted"));
        let cmd = command_for(&prog, &["exec", "do it"]);
        let enforce = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert!(matches!(enforce.decision, LaunchDecision::Refuse(_)), "{enforce:?}");
        assert!(enforce.report.contains("codex_boundary=not_met"));
        let observe = verify_launch_boundary("codex", &cmd, &deny_policy(), false).unwrap();
        assert!(
            matches!(observe.decision, LaunchDecision::ProceedDegraded(_)),
            "{observe:?}"
        );
    }

    #[test]
    fn an_execpolicy_rules_file_blocks_a_verified_claim() {
        let dir = tempfile::tempdir().unwrap();
        let prog = fake_codex(dir.path(), &read_only_prompt(), &doctor_json("restricted"));
        let home = tempfile::tempdir().unwrap();
        let mut cmd = command_for(&prog, &["exec", "do it"]);
        cmd.env("CODEX_HOME", home.path());
        // Control: no rules file, same probes -> verified.
        let ok = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert_eq!(ok.decision, LaunchDecision::Proceed);
        std::fs::create_dir_all(home.path().join("rules")).unwrap();
        std::fs::write(
            home.path().join("rules/default.rules"),
            "prefix_rule(pattern=[\"bash\"], decision=\"allow\")",
        )
        .unwrap();
        let bad = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert!(matches!(bad.decision, LaunchDecision::Refuse(_)), "{:?}", bad.decision);
        assert!(bad.report.contains("codex_boundary=not_met"), "{}", bad.report);
    }

    /// AAASM-6331 final review: with `approval_policy=never` Codex lists no allow
    /// rules, so project rules found only by the directory scan must still void
    /// the claim - from an ancestor of the launch dir and from a `-C` target.
    #[test]
    fn project_rules_void_the_claim_from_an_ancestor_and_from_a_cd_target() {
        let dir = tempfile::tempdir().unwrap();
        let prog = fake_codex(dir.path(), &read_only_prompt(), &doctor_json("restricted"));
        let proj = tempfile::tempdir().unwrap();
        let sub = proj.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(proj.path().join(".git")).unwrap();

        let from_sub = || {
            let mut c = command_for(&prog, &["exec", "x"]);
            c.current_dir(&sub);
            c
        };
        let via_cd = || command_for(&prog, &["-C", sub.to_str().unwrap(), "exec", "x"]);
        // Controls: no rules file yet -> both launches verify.
        for cmd in [from_sub(), via_cd()] {
            let ok = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
            assert_eq!(ok.decision, LaunchDecision::Proceed, "{}", ok.report);
        }
        std::fs::create_dir_all(proj.path().join(".codex/rules")).unwrap();
        std::fs::write(
            proj.path().join(".codex/rules/a.rules"),
            "prefix_rule(pattern=[\"env\"], decision=\"allow\")",
        )
        .unwrap();
        for cmd in [from_sub(), via_cd()] {
            let bad = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
            assert!(matches!(bad.decision, LaunchDecision::Refuse(_)), "{:?}", bad.decision);
        }
    }

    /// AAASM-6331 final review F4: a relative CODEX_HOME is resolved by Codex
    /// against the launch directory, not the aasm process's.
    #[test]
    fn a_relative_codex_home_is_resolved_against_the_launch_directory() {
        let dir = tempfile::tempdir().unwrap();
        let prog = fake_codex(dir.path(), &read_only_prompt(), &doctor_json("restricted"));
        let lab = tempfile::tempdir().unwrap();
        let mut cmd = command_for(&prog, &["exec", "x"]);
        cmd.current_dir(lab.path()).env("CODEX_HOME", "home");
        // Control: no rules under lab/home -> verified.
        let ok = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert_eq!(ok.decision, LaunchDecision::Proceed, "{}", ok.report);
        std::fs::create_dir_all(lab.path().join("home/rules")).unwrap();
        std::fs::write(
            lab.path().join("home/rules/u.rules"),
            "prefix_rule(pattern=[\"env\"], decision=\"allow\")",
        )
        .unwrap();
        let bad = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert!(matches!(bad.decision, LaunchDecision::Refuse(_)), "{:?}", bad.decision);
    }

    /// Final-delta review F1: a relative HOME (no CODEX_HOME) is resolved by
    /// Codex against the launch directory.
    #[test]
    fn a_relative_home_is_resolved_against_the_launch_directory() {
        let dir = tempfile::tempdir().unwrap();
        let prog = fake_codex(dir.path(), &read_only_prompt(), &doctor_json("restricted"));
        let lab = tempfile::tempdir().unwrap();
        let mut cmd = command_for(&prog, &["exec", "x"]);
        cmd.current_dir(lab.path()).env_remove("CODEX_HOME").env("HOME", "hh");
        let ok = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert_eq!(ok.decision, LaunchDecision::Proceed, "{}", ok.report);
        std::fs::create_dir_all(lab.path().join("hh/.codex/rules")).unwrap();
        std::fs::write(
            lab.path().join("hh/.codex/rules/a.rules"),
            "prefix_rule(pattern=[\"env\"], decision=\"allow\")",
        )
        .unwrap();
        let bad = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert!(matches!(bad.decision, LaunchDecision::Refuse(_)), "{:?}", bad.decision);
    }

    /// With neither CODEX_HOME nor HOME the user rules cannot be located, so the
    /// claim is withheld rather than assumed clean.
    #[test]
    fn an_unlocatable_codex_home_is_not_a_verified_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let prog = fake_codex(dir.path(), &read_only_prompt(), &doctor_json("restricted"));
        let mut cmd = command_for(&prog, &["exec", "x"]);
        cmd.env_remove("CODEX_HOME").env_remove("HOME");
        let r = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert!(matches!(r.decision, LaunchDecision::Refuse(_)), "{:?}", r.decision);
        assert!(r.report.contains("codex_boundary=not_met"), "{}", r.report);
    }

    #[test]
    fn unverifiable_arguments_never_reach_codex() {
        let dir = tempfile::tempdir().unwrap();
        let prog = fake_codex(dir.path(), "not even json", "not even json");
        let cmd = command_for(&prog, &["--dangerously-bypass-approvals-and-sandbox"]);
        let check = verify_launch_boundary("codex", &cmd, &deny_policy(), true).unwrap();
        assert!(matches!(check.decision, LaunchDecision::Refuse(_)));
        assert!(check.report.contains("codex_boundary=unverifiable"));
    }

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
