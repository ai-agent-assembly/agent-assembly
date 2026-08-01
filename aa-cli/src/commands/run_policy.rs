//! Effective-policy resolution for `aasm run` (AAASM-5349).
//!
//! # Why absence of configuration is not permission
//!
//! `aasm run` used to hand its adapter a hard-coded `PolicyDocument` with an
//! empty rule list. That is not a neutral placeholder. The Claude Code adapter
//! maps an empty rule list to `permissions: {allow: [], deny: []}` and
//! `permissionMode: "acceptEdits"` — so the session it produced was not merely
//! ungoverned, it was *more* permissive than the tool's own default, and it
//! reported itself as a successfully governed launch while being so.
//!
//! The rule this module exists to enforce is that an empty effective policy is
//! a statement about the **operator**, not about the agent: it means nobody has
//! said what this agent may do. "Nobody has said" is not "everything is
//! allowed". A governed launch therefore refuses, and the refusal names the
//! remedy — because a fail-closed default that an operator cannot act on gets
//! worked around, and a workaround is how the empty policy got here.
//!
//! Permissive execution remains available, but it has to be *said*: an operator
//! who wants an agent with no restrictions writes an allow-all artifact (see
//! [`ALLOW_ALL_TEMPLATE`]) and selects it. The difference between "I chose to
//! restrict nothing" and "I never chose anything" is the entire point, and it
//! is why [`PolicyResolution`] has four variants rather than an `Option`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use aa_core::{PolicyDecision, PolicyDocument, PolicyRule};

/// A minimal policy artifact that permits everything.
///
/// This is the *whole* shape of an explicit allow-all: a policy whose tool
/// ruleset is exactly the wildcard, allowed, and which restricts nothing on any
/// other dimension. There is no dedicated `permissive: true` switch, because a
/// switch is easy to set without reading what it turns off — writing the
/// wildcard out is the smallest thing that is unambiguously deliberate, and it
/// validates through the same [`aa_gateway::policy::PolicyValidator`] as every
/// other policy rather than through a bypass.
pub const ALLOW_ALL_TEMPLATE: &str = r#"apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: allow-all
spec:
  tools:
    "*":
      allow: true
"#;

/// Environment variable carrying the resolved policy state into the child.
///
/// Exported so anything downstream of the launch — an SDK inside the tool, a
/// log scraper joining child output to a session — can tell an enforced session
/// from a deliberately permissive one without re-deriving it. The two refusing
/// states never reach a child, but they do reach `--dry-run`, which is where an
/// operator checks what a live run would do.
pub const POLICY_STATE_ENV: &str = "AA_POLICY_STATE";

/// Environment variable carrying the path the policy was resolved from.
pub const POLICY_SOURCE_ENV: &str = "AA_POLICY_SOURCE";

/// The outcome of resolving an effective policy for a launch.
///
/// # Why four variants and not `Option<PolicyDocument>`
///
/// Each variant is a different fact about the operator's configuration, and
/// each one obliges a different response:
///
/// * [`Enforced`](Self::Enforced) — rules exist and will be applied. Launch.
/// * [`Permissive`](Self::Permissive) — the operator wrote down that nothing is
///   restricted. Launch, but say so loudly: a reader of the audit trail must
///   not mistake this for the case above.
/// * [`Unconfigured`](Self::Unconfigured) — no effective policy resolved.
///   Refuse, and explain how to supply one.
/// * [`LoadFailed`](Self::LoadFailed) — an artifact was selected and is broken.
///   Refuse, and explain how to fix *that file*.
///
/// The last two must not collapse into each other. An operator whose YAML has a
/// typo has already made a decision about governance and needs to be sent to
/// their file; an operator with no policy at all needs to be sent to the
/// concept. Merging them produces a message that is wrong for both, and — worse
/// — makes a broken policy indistinguishable from an absent one in the audit
/// trail, which is precisely the confusion an attacker who corrupts a policy
/// file would want.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyResolution {
    /// An effective policy resolved and carries at least one enforceable rule.
    Enforced {
        /// The artifact it was read from.
        source: PathBuf,
        /// The projection handed to the dev-tool adapter.
        document: PolicyDocument,
    },
    /// The operator explicitly selected an allow-all artifact.
    Permissive {
        /// The artifact it was read from.
        source: PathBuf,
        /// The projection handed to the dev-tool adapter.
        document: PolicyDocument,
    },
    /// No effective policy resolved.
    Unconfigured(Unconfigured),
    /// An artifact was selected but could not be turned into a policy.
    LoadFailed {
        /// The artifact that could not be loaded.
        source: PathBuf,
        /// Why it could not be loaded, for the operator to act on.
        detail: String,
    },
}

/// Why no effective policy resolved.
///
/// Both are [`PolicyResolution::Unconfigured`] — contract point 1 is that an
/// empty effective policy *is* the unconfigured state — but the remedy differs,
/// so the refusal text does too.
#[derive(Debug, Clone, PartialEq)]
pub enum Unconfigured {
    /// Nothing existed at any searched location.
    NoSource {
        /// Human-readable locations that were searched, in order.
        searched: Vec<String>,
    },
    /// An artifact parsed cleanly but declares no tool rule, so it governs
    /// nothing. Distinct from `NoSource` only in the remedy: the operator has a
    /// file and needs to put rules in it.
    EmptyDocument {
        /// The artifact that turned out to be empty.
        source: PathBuf,
    },
}

impl PolicyResolution {
    /// Stable machine-readable token for this state.
    ///
    /// Stable on purpose: it lands in [`POLICY_STATE_ENV`], in the dry-run
    /// preview and in the launch banner, and audit tooling matches on it.
    pub fn state_token(&self) -> &'static str {
        match self {
            Self::Enforced { .. } => "enforced",
            Self::Permissive { .. } => "permissive",
            Self::Unconfigured(_) => "unconfigured",
            Self::LoadFailed { .. } => "load_failed",
        }
    }

    /// The artifact this resolution came from, when there was one.
    pub fn source(&self) -> Option<&Path> {
        match self {
            Self::Enforced { source, .. }
            | Self::Permissive { source, .. }
            | Self::LoadFailed { source, .. }
            | Self::Unconfigured(Unconfigured::EmptyDocument { source }) => Some(source),
            Self::Unconfigured(Unconfigured::NoSource { .. }) => None,
        }
    }

    /// One-line operator-facing summary, distinct per state.
    ///
    /// Every state names itself, so the four are told apart by reading the line
    /// rather than by inferring from what is missing from it.
    pub fn summary(&self) -> String {
        match self {
            Self::Enforced { source, document } => {
                format!("enforced — {} rule(s) from {}", document.rules.len(), source.display())
            }
            Self::Permissive { source, .. } => format!(
                "permissive — explicit allow-all artifact at {} (nothing is restricted)",
                source.display()
            ),
            Self::Unconfigured(Unconfigured::NoSource { .. }) => {
                "unconfigured — no policy artifact found; a governed launch is refused".to_string()
            }
            Self::Unconfigured(Unconfigured::EmptyDocument { source }) => format!(
                "unconfigured — {} declares no tool rule; a governed launch is refused",
                source.display()
            ),
            Self::LoadFailed { source, detail } => {
                format!("load_failed — {} could not be loaded: {detail}", source.display())
            }
        }
    }

    /// Record this state in the child environment.
    ///
    /// Deliberately a mutation of an already-built map rather than a parameter
    /// of `build_child_env`: the policy state is orthogonal to the identity and
    /// proxy wiring that function exists to assemble.
    pub fn annotate_env(&self, env: &mut HashMap<String, String>) {
        env.insert(POLICY_STATE_ENV.into(), self.state_token().into());
        match self.source() {
            Some(source) => {
                env.insert(POLICY_SOURCE_ENV.into(), source.display().to_string());
            }
            None => {
                env.remove(POLICY_SOURCE_ENV);
            }
        }
    }

    /// Consume this resolution into the policy a launch may proceed under, or
    /// refuse with an explanation the operator can act on.
    ///
    /// The two refusing states produce different text on purpose — see the type
    /// docs. Both refuse *before* anything is launched, because a tool that has
    /// already started under no policy cannot be retroactively governed.
    pub fn into_enforceable(self) -> Result<PolicyDocument> {
        match self {
            Self::Enforced { document, .. } | Self::Permissive { document, .. } => Ok(document),
            Self::Unconfigured(Unconfigured::NoSource { searched }) => Err(anyhow::anyhow!(
                "refusing to launch ungoverned: no effective policy is configured, so this session \
                 would run under no rules at all. An absent policy is not permission.\n\
                 \n\
                 Searched, in order: {}\n\
                 \n\
                 Supply a policy, then re-run:\n\
                 \x20 aasm run --policy <FILE> <tool>\n\
                 \x20 AA_POLICY=<FILE> aasm run <tool>\n\
                 \x20 install one at ~/.aasm/policy.yaml (or /etc/aasm/policy.yaml)\n\
                 Check it first with: aasm policy validate <FILE>\n\
                 \n\
                 If you intend this agent to be unrestricted, say so explicitly with an \
                 allow-all artifact:\n\
                 {}",
                searched.join(", "),
                indent(ALLOW_ALL_TEMPLATE),
            )),
            Self::Unconfigured(Unconfigured::EmptyDocument { source }) => Err(anyhow::anyhow!(
                "refusing to launch ungoverned: the policy at {} parsed cleanly but declares no \
                 tool rule, so it would govern nothing. An empty policy is unconfigured, not \
                 allow-all.\n\
                 \n\
                 Add the tool rules this agent should run under, then re-run.\n\
                 Check the file with: aasm policy validate {}\n\
                 \n\
                 If you intend this agent to be unrestricted, say so explicitly — an empty \
                 `tools:` section does not mean that, this does:\n\
                 {}",
                source.display(),
                source.display(),
                indent(ALLOW_ALL_TEMPLATE),
            )),
            Self::LoadFailed { source, detail } => Err(anyhow::anyhow!(
                "refusing to launch: the policy at {} could not be loaded — {detail}\n\
                 \n\
                 This is a broken policy artifact, not an absent one: the file was selected as \
                 this session's policy, so guessing what it meant is not safe.\n\
                 Fix it, then re-check with: aasm policy validate {}\n\
                 \x20 or select a different one with: aasm run --policy <FILE> <tool>",
                source.display(),
                source.display(),
            )),
        }
    }
}

/// Indent a block so it reads as a quoted artifact inside an error message.
fn indent(block: &str) -> String {
    block.lines().map(|l| format!("    {l}\n")).collect()
}

/// The locations `aasm run` looks in, in order.
///
/// Deliberately the same order `aasm gateway start` uses, so the two commands
/// agree about where an operator's policy lives. Diverging here would let a
/// host be governed by one document and previewed against another.
fn search_path(explicit: Option<&Path>) -> Vec<(String, PathBuf)> {
    // An explicitly named artifact is the whole search: naming a file that does
    // not exist is an operator error worth reporting, not a cue to fall back to
    // an ambient policy they did not ask for.
    if let Some(path) = explicit {
        return vec![("--policy".to_string(), path.to_path_buf())];
    }

    let mut out = Vec::new();
    if let Ok(env_path) = std::env::var("AA_POLICY") {
        if !env_path.is_empty() {
            out.push(("$AA_POLICY".to_string(), PathBuf::from(env_path)));
        }
    }
    if let Some(home) = dirs::home_dir() {
        out.push((
            "~/.aasm/policy.yaml".to_string(),
            home.join(".aasm").join("policy.yaml"),
        ));
        out.push(("~/.aasm/policies/".to_string(), home.join(".aasm").join("policies")));
    }
    out.push((
        "/etc/aasm/policy.yaml".to_string(),
        PathBuf::from("/etc/aasm/policy.yaml"),
    ));
    out.push(("/etc/aasm/policies/".to_string(), PathBuf::from("/etc/aasm/policies")));
    out
}

/// Resolve the effective policy for this launch.
///
/// Never returns an "empty but fine" policy: every path out of here is one of
/// the four states, and two of them refuse.
pub fn resolve(explicit: Option<&Path>) -> PolicyResolution {
    let candidates = search_path(explicit);
    for (_, path) in &candidates {
        if path.exists() {
            return load(path);
        }
    }
    PolicyResolution::Unconfigured(Unconfigured::NoSource {
        searched: candidates.into_iter().map(|(label, _)| label).collect(),
    })
}

/// Load and classify a single policy artifact.
pub fn load(source: &Path) -> PolicyResolution {
    // A directory is the gateway's multi-document cascade. `aasm run` renders
    // one tool's managed settings and has no cascade merger, so it says so
    // rather than picking a file out of the directory and calling that the
    // effective policy.
    if source.is_dir() {
        return PolicyResolution::LoadFailed {
            source: source.to_path_buf(),
            detail: "it is a directory. `aasm run` resolves a single effective policy document \
                     and does not merge the multi-document cascade that `aasm gateway start` \
                     accepts; point --policy at one file"
                .to_string(),
        };
    }

    let yaml = match std::fs::read_to_string(source) {
        Ok(yaml) => yaml,
        Err(e) => {
            return PolicyResolution::LoadFailed {
                source: source.to_path_buf(),
                detail: e.to_string(),
            }
        }
    };
    classify(source, &yaml)
}

/// Parse `yaml` and place it in one of the four states.
///
/// Split out from [`load`] so classification is testable without a filesystem.
pub fn classify(source: &Path, yaml: &str) -> PolicyResolution {
    let validated = match aa_gateway::policy::PolicyValidator::from_yaml(yaml) {
        Ok(output) => output.document,
        Err(errors) => {
            return PolicyResolution::LoadFailed {
                source: source.to_path_buf(),
                detail: errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "),
            }
        }
    };

    let document = project_rules(&validated);
    if document.rules.is_empty() {
        return PolicyResolution::Unconfigured(Unconfigured::EmptyDocument {
            source: source.to_path_buf(),
        });
    }
    if is_explicit_allow_all(&validated) {
        return PolicyResolution::Permissive {
            source: source.to_path_buf(),
            document,
        };
    }
    PolicyResolution::Enforced {
        source: source.to_path_buf(),
        document,
    }
}

/// True when this artifact restricts nothing at all.
///
/// Both halves matter. A wildcard-allow `tools:` section alongside a network
/// allowlist or a capability denial is *not* permissive — something is still
/// enforced — and labelling it permissive would understate the governance in
/// place. The check is therefore conservative in the safe direction: it says
/// "permissive" only when there is genuinely nothing left to enforce.
fn is_explicit_allow_all(doc: &aa_gateway::policy::PolicyDocument) -> bool {
    let tools_are_wildcard_allow = doc.tools.len() == 1
        && doc
            .tools
            .get("*")
            .is_some_and(|t| t.allow && t.requires_approval_if.is_none() && t.limit_per_hour.is_none());

    tools_are_wildcard_allow
        && doc.network.is_none()
        && doc.schedule.is_none()
        && doc.budget.is_none()
        && doc.capabilities.is_none()
        && doc.data.as_ref().map_or(true, |d| d.sensitive_patterns.is_empty())
}

/// Project the gateway's validated document onto the rule list the dev-tool
/// adapter consumes.
///
/// Only the `tools:` dimension crosses over: a dev-tool adapter writes tool
/// permissions into the tool's own settings file and has nowhere to put a spend
/// cap or an egress allowlist — those are enforced by the gateway and the proxy.
/// Rules are sorted so the rendered settings are byte-stable across runs; the
/// source is a `HashMap` and would otherwise reorder on every launch.
fn project_rules(doc: &aa_gateway::policy::PolicyDocument) -> PolicyDocument {
    let mut rules: Vec<PolicyRule> = doc
        .tools
        .iter()
        .map(|(name, tool)| PolicyRule {
            action_pattern: name.clone(),
            decision: match (tool.allow, tool.requires_approval_if.is_some()) {
                (true, true) => PolicyDecision::RequireApproval,
                (true, false) => PolicyDecision::Allow,
                (false, _) => PolicyDecision::Deny,
            },
        })
        .collect();
    rules.sort_by(|a, b| a.action_pattern.cmp(&b.action_pattern));

    PolicyDocument {
        version: 1,
        name: doc.name.clone().unwrap_or_else(|| "policy".to_string()),
        rules,
        enforcement_mode: aa_core::EnforcementMode::default(),
    }
}
