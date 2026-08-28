//! Conditions under which Claude Code stops being governed by what Agent
//! Assembly installed.
//!
//! # Why these are reported rather than blocked
//!
//! Host-level bypass prevention is a non-goal, and the AAASM-5276 spike is
//! explicit that ten of the known bypasses were never demonstrated. What the
//! product *can* honestly do is look at the surfaces it already reads — the
//! settings documents it manages and the environment a launch would inherit —
//! and say which known bypasses are **currently true**. A bypass that is
//! detected and named lowers the reported protection level and appears in
//! `status`; a bypass that is merely known appears in the plan's warnings.
//!
//! # Why a detected bypass becomes `Absent` evidence
//!
//! [`EvidenceKind::Absent`](aa_devtool_contract::EvidenceKind::Absent) is the
//! reading for "a check could not be made", and that is exactly the situation:
//! with `defaultMode: "bypassPermissions"` in effect, Agent Assembly's
//! permission rules are still written and still read back — but nothing can be
//! concluded from them about what the tool will actually do. Absent readings
//! only ever lower a state, which is the behaviour this needs.
//!
//! # Environment bypasses are caller-stated, never daemon-read (AAASM-5993)
//!
//! [`environment_bypasses`] takes a
//! [`CallerEnvironment`](aa_devtool_contract::CallerEnvironment) rather than
//! reading the process environment itself. The lifecycle service this runs inside is a
//! long-lived daemon shared by every client on the host; its own process
//! environment describes the daemon, not whichever caller's launch is being
//! asked about. Reading it directly produced both directions of wrong answer —
//! a bypassed caller with a clean daemon read as fully protected, and a clean
//! caller with a daemon carrying one of the watched variables read as
//! bypassed. A caller that states nothing produces
//! [`EnvironmentBypassReport::unexamined`], never a clean bill of health: an
//! absence of findings must never be confused with an absence of bypasses.

use aa_devtool_contract::{CallerEnvironment, EnvVarState};

/// One known bypass, either observed on this host or documented as
/// undemonstrable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassFinding {
    /// Stable identifier, so a report can be diffed between runs.
    pub id: &'static str,
    /// Where it was observed, in words a user recognises.
    pub source: String,
    /// What it means for the protection claim.
    pub summary: String,
    /// What to do about it.
    pub remediation: String,
}

impl BypassFinding {
    /// One line combining the summary and the source, for evidence detail.
    pub fn detail(&self) -> String {
        format!("{} ({})", self.summary, self.source)
    }
}

/// Environment variables whose presence changes whether Claude Code is
/// governed. Only names are read; a value is never echoed into a report.
///
/// Re-exports `aa_core`'s copy (via `aa_devtool_contract`, this crate's usual
/// path to `aa-core` types) rather than declaring its own — see that
/// constant's doc comment for why the canonical list lives in `aa-core`
/// (AAASM-5993: the DI-API client that states a caller's environment links
/// `aa-core`, not this adapter crate).
pub use aa_devtool_contract::KNOWN_LAUNCH_BYPASS_ENV_VARS as BYPASS_ENV_VARS;

/// Command-line flags that switch Claude Code's own permission enforcement off.
///
/// Agent Assembly passes them through unchanged — its enforcement sits below
/// them — but a session launched with one is not getting the tool-action
/// governance the managed settings describe, and saying so is the point.
const BYPASS_LAUNCH_FLAGS: [&str; 3] = [
    "--dangerously-skip-permissions",
    "--allow-dangerously-skip-permissions",
    "--bare",
];

/// Inspect one settings document for bypass conditions.
///
/// `label` names the document for the report (a path, or a scope name).
/// Unparseable JSON yields no findings — that is a drift/observability problem
/// reported elsewhere, and inventing a bypass finding for it would be a guess.
pub fn settings_bypasses(label: &str, raw: &str) -> Vec<BypassFinding> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let mut found = Vec::new();

    let default_mode = doc
        .get("permissions")
        .and_then(|p| p.get("defaultMode"))
        .and_then(|m| m.as_str());
    let permission_mode = doc.get("permissionMode").and_then(|m| m.as_str());
    if [default_mode, permission_mode]
        .iter()
        .flatten()
        .any(|m| *m == BYPASS_MODE)
    {
        found.push(BypassFinding {
            id: "settings.bypass-permissions-mode",
            source: label.to_string(),
            summary: format!(
                "the permission mode is {BYPASS_MODE:?}, so Claude Code applies no permission \
                 rule at all — including the ones Agent Assembly wrote"
            ),
            remediation: format!(
                "remove the {BYPASS_MODE:?} permission mode from {label}, then run \
                 `aasm integrations repair claude-code`"
            ),
        });
    }

    if let Some(env) = doc.get("env").and_then(|e| e.as_object()) {
        for name in ["ANTHROPIC_BASE_URL", "CLAUDE_CODE_API_BASE_URL"] {
            if env.contains_key(name) {
                found.push(base_url_finding(label.to_string(), name));
            }
        }
        if env.contains_key("NODE_TLS_REJECT_UNAUTHORIZED") {
            found.push(tls_finding(label.to_string()));
        }
    }

    found
}

/// The permission mode that switches Claude Code's own rule evaluation off.
const BYPASS_MODE: &str = "bypassPermissions";

/// What inspecting a caller-stated launch environment produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentBypassReport {
    /// Bypasses the caller's statement showed to be true.
    pub findings: Vec<BypassFinding>,
    /// Names from [`BYPASS_ENV_VARS`] the caller said nothing about, so no
    /// conclusion — clean or bypassed — is available for them.
    pub unexamined: Vec<&'static str>,
}

/// Inspect what the caller stated about its launch environment for bypass
/// conditions.
///
/// `None` means the caller stated nothing at all: every watched variable is
/// [`unexamined`](EnvironmentBypassReport::unexamined) and `findings` is
/// empty — never read as "clean", because nothing was actually looked at.
pub fn environment_bypasses(env: Option<&CallerEnvironment>) -> EnvironmentBypassReport {
    let Some(env) = env else {
        return EnvironmentBypassReport {
            findings: Vec::new(),
            unexamined: BYPASS_ENV_VARS.to_vec(),
        };
    };

    let mut findings = Vec::new();
    let mut unexamined = Vec::new();

    for &name in &BYPASS_ENV_VARS {
        match env.state_of(name) {
            EnvVarState::Set => findings.push(finding_for(name)),
            EnvVarState::Unset => {}
            EnvVarState::NotStated => unexamined.push(name),
        }
    }

    EnvironmentBypassReport { findings, unexamined }
}

/// The finding for one [`BYPASS_ENV_VARS`] name known to be set.
fn finding_for(name: &str) -> BypassFinding {
    match name {
        "ANTHROPIC_BASE_URL" | "CLAUDE_CODE_API_BASE_URL" => {
            base_url_finding("the launching client's environment".to_string(), name)
        }
        "NODE_TLS_REJECT_UNAUTHORIZED" => tls_finding("the launching client's environment".to_string()),
        // "CLAUDE_CODE_USE_BEDROCK" | "CLAUDE_CODE_USE_VERTEX", and anything
        // else added to BYPASS_ENV_VARS later.
        _ => BypassFinding {
            id: "environment.alternate-provider",
            source: "the launching client's environment".to_string(),
            summary: format!(
                "{name} is set, so Claude Code talks to an alternate provider endpoint that \
                 this integration does not intercept, and skips its server-managed settings fetch"
            ),
            remediation: format!("unset {name} before launching through `aasm run claude`"),
        },
    }
}

/// Bypass flags present in the arguments a launch would pass through.
pub fn launch_flag_bypasses(tool_args: &[String]) -> Vec<BypassFinding> {
    BYPASS_LAUNCH_FLAGS
        .iter()
        .filter(|flag| tool_args.iter().any(|a| a == *flag))
        .map(|flag| BypassFinding {
            id: "launch.permission-bypass-flag",
            source: format!("the launch argument {flag}"),
            summary: format!(
                "{flag} switches Claude Code's own permission enforcement off; Agent Assembly's \
                 in-path interception is unaffected, but the tool-action governance in the managed \
                 settings is not applied for this session"
            ),
            remediation: format!("drop {flag} to get the tool-action governance the receipt describes"),
        })
        .collect()
}

fn base_url_finding(source: String, name: &str) -> BypassFinding {
    BypassFinding {
        id: "base-url-redirection",
        source,
        summary: format!(
            "{name} redirects Claude Code's model endpoint. AAASM-5276 measured this delivering a \
             synthetic secret to the provider with no Agent Assembly component anywhere in the path; \
             it is routing, not protection, and when it is set in the shell it additionally \
             suppresses Claude Code's server-managed settings fetch"
        ),
        remediation: format!("unset {name} so model traffic goes through the intercepting proxy"),
    }
}

fn tls_finding(source: String) -> BypassFinding {
    BypassFinding {
        id: "tls-verification-disabled",
        source,
        summary: "NODE_TLS_REJECT_UNAUTHORIZED is set, which disables TLS certificate verification \
                  for every host the tool talks to. Agent Assembly never sets it: a TLS failure is a \
                  finding, not something to suppress"
            .to_string(),
        remediation: "unset NODE_TLS_REJECT_UNAUTHORIZED; if interception needs a trusted CA, the \
                      integration supplies one through NODE_EXTRA_CA_CERTS"
            .to_string(),
    }
}

/// Known bypasses this integration cannot observe, stated so `status` and the
/// plan never imply the absence of a finding is the absence of a bypass.
///
/// Wording tracks the AAASM-5276 "inferred, not demonstrated" list.
pub const UNOBSERVABLE_BYPASSES: &str =
    "launching `claude` outside `aasm run` (no proxy or CA is injected), repointing \
     CLAUDE_CONFIG_DIR, symlinking .claude, editing the settings file directly, replacing the \
     binary, or calling the Anthropic API from another program with the developer's own key";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_permissions_is_detected_in_either_key() {
        let nested = r#"{"permissions":{"defaultMode":"bypassPermissions","allow":[]}}"#;
        let found = settings_bypasses("~/.claude/settings.json", nested);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "settings.bypass-permissions-mode");
        assert!(found[0].detail().contains("~/.claude/settings.json"), "{:?}", found[0]);

        let top_level = r#"{"permissionMode":"bypassPermissions"}"#;
        assert_eq!(settings_bypasses("s", top_level).len(), 1);

        let benign = r#"{"permissions":{"defaultMode":"default"},"permissionMode":"plan"}"#;
        assert!(settings_bypasses("s", benign).is_empty());
    }

    #[test]
    fn a_settings_env_block_can_redirect_the_model_endpoint() {
        let doc = r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:9"}}"#;
        let found = settings_bypasses("s", doc);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "base-url-redirection");
        assert!(found[0].summary.contains("routing, not protection"), "{found:?}");
    }

    #[test]
    fn environment_bypasses_are_detected_without_reading_values() {
        let env = CallerEnvironment::stating(BYPASS_ENV_VARS)
            .present("ANTHROPIC_BASE_URL")
            .present("CLAUDE_CODE_USE_BEDROCK")
            .present("NODE_TLS_REJECT_UNAUTHORIZED");
        let report = environment_bypasses(Some(&env));
        assert!(report.unexamined.is_empty(), "{report:?}");
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"base-url-redirection"), "{ids:?}");
        assert!(ids.contains(&"environment.alternate-provider"), "{ids:?}");
        assert!(ids.contains(&"tls-verification-disabled"), "{ids:?}");
        // Only the variable's name is ever carried — `CallerEnvironment` has no
        // way to carry a value in the first place.
        for finding in &report.findings {
            assert!(
                !finding.summary.contains("http://") && !finding.detail().contains("http://"),
                "a bypass report echoed something value-shaped: {finding:?}"
            );
        }
    }

    #[test]
    fn a_caller_that_states_nothing_gets_no_findings_and_every_name_unexamined() {
        let report = environment_bypasses(None);
        assert!(report.findings.is_empty(), "{report:?}");
        assert_eq!(report.unexamined, BYPASS_ENV_VARS.to_vec());
    }

    #[test]
    fn a_name_the_caller_examined_and_found_unset_produces_no_finding_and_is_not_unexamined() {
        let env = CallerEnvironment::stating(BYPASS_ENV_VARS);
        let report = environment_bypasses(Some(&env));
        assert!(report.findings.is_empty(), "{report:?}");
        assert!(report.unexamined.is_empty(), "{report:?}");
    }

    #[test]
    fn launch_flags_are_reported_without_being_stripped() {
        let args = vec!["--dangerously-skip-permissions".to_string(), "-p".to_string()];
        let found = launch_flag_bypasses(&args);
        assert_eq!(found.len(), 1);
        assert!(
            found[0].summary.contains("in-path interception is unaffected"),
            "{found:?}"
        );
        assert!(launch_flag_bypasses(&["-p".to_string()]).is_empty());
    }

    #[test]
    fn unparseable_settings_produce_no_invented_finding() {
        assert!(settings_bypasses("s", "not json at all").is_empty());
    }
}
