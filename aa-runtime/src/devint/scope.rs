//! What a DI-API capability token is allowed to do (ADR 0030 §5.3).
//!
//! OS-level identity says "the developer's UID"; it cannot distinguish the
//! VS Code extension from a trojaned npm postinstall script running as the same
//! user. The scope is what draws that distinction, and it is what bounds the
//! blast radius of a *stolen* token: a token enrolled for the Claude Code
//! integration cannot plan, apply, repair or remove the Codex integration, and
//! a read-only status client cannot mutate anything.
//!
//! A scope is a pair of allowlists — never a denylist, and never a wildcard
//! that a caller can supply. Both halves must admit the request:
//!
//! * [`ToolScope`] — which tool ids the token may act on;
//! * the verb set — which members of the closed [`DiVerb`] space it may invoke.
//!
//! An empty verb set or an empty tool set grants nothing. That is the
//! fail-closed direction on purpose: a malformed or half-written enrolment
//! record must deny, never widen.

use std::collections::BTreeSet;

use super::verb::DiVerb;

/// Which tools a token may act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolScope {
    /// A fixed set of tool ids. The only variant an enrolment may produce for a
    /// per-tool client.
    Tools(BTreeSet<String>),
    /// Every tool. Reserved for the operator's own `aasm` enrolment, which the
    /// user performs deliberately and interactively — never granted implicitly
    /// and never the default for a plugin.
    AllTools,
}

impl ToolScope {
    /// Build a tool scope from an iterator of tool ids.
    pub fn tools<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ToolScope::Tools(ids.into_iter().map(Into::into).collect())
    }

    /// Whether `tool_id` is inside this scope.
    pub fn permits_tool(&self, tool_id: &str) -> bool {
        match self {
            ToolScope::Tools(ids) => ids.contains(tool_id),
            ToolScope::AllTools => true,
        }
    }

    /// The tool ids, for display and audit. `None` for [`ToolScope::AllTools`].
    pub fn tool_ids(&self) -> Option<impl Iterator<Item = &str>> {
        match self {
            ToolScope::Tools(ids) => Some(ids.iter().map(String::as_str)),
            ToolScope::AllTools => None,
        }
    }
}

/// The capability a token carries: a set of tools and a set of verbs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenScope {
    tools: ToolScope,
    verbs: BTreeSet<DiVerb>,
}

impl TokenScope {
    /// Build a scope from an explicit tool scope and verb set.
    pub fn new<I>(tools: ToolScope, verbs: I) -> Self
    where
        I: IntoIterator<Item = DiVerb>,
    {
        Self {
            tools,
            verbs: verbs.into_iter().collect(),
        }
    }

    /// The read-only scope a status/dashboard client needs: it can see what
    /// exists and what state it is in, and can change none of it.
    pub fn read_only(tools: ToolScope) -> Self {
        Self::new(
            tools,
            [DiVerb::ListTools, DiVerb::Status, DiVerb::ScopedEvents, DiVerb::Verify],
        )
    }

    /// The full lifecycle scope for one tool's integration client.
    ///
    /// Named rather than assembled at each call site so "what an integration
    /// client gets" is one reviewable definition instead of N drifting ones.
    pub fn full_lifecycle(tools: ToolScope) -> Self {
        Self::new(tools, DiVerb::ALL)
    }

    /// Whether this scope admits `verb` against `tool_id`.
    ///
    /// [`DiVerb::ListTools`] names no tool, so only its verb membership is
    /// checked; every other verb must satisfy **both** halves.
    pub fn permits(&self, verb: DiVerb, tool_id: &str) -> bool {
        if !self.verbs.contains(&verb) {
            return false;
        }
        if !verb.is_tool_scoped() {
            return true;
        }
        self.tools.permits_tool(tool_id)
    }

    /// The tool half of the scope.
    pub fn tool_scope(&self) -> &ToolScope {
        &self.tools
    }

    /// The verbs in this scope, in a stable order, for display and audit.
    pub fn verbs(&self) -> impl Iterator<Item = DiVerb> + '_ {
        self.verbs.iter().copied()
    }

    /// A stable, human-readable rendering for audit records: verbs and tools,
    /// never anything derived from the token secret.
    pub fn describe(&self) -> String {
        let verbs: Vec<&str> = self.verbs.iter().map(|v| v.as_str()).collect();
        let tools = match &self.tools {
            ToolScope::AllTools => "*".to_string(),
            ToolScope::Tools(ids) => ids.iter().cloned().collect::<Vec<_>>().join(","),
        };
        format!("tools=[{tools}] verbs=[{}]", verbs.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claude_only() -> TokenScope {
        TokenScope::full_lifecycle(ToolScope::tools(["claude-code"]))
    }

    #[test]
    fn a_tool_scoped_token_cannot_act_on_another_tool() {
        let scope = claude_only();
        for verb in DiVerb::ALL.into_iter().filter(|v| v.is_tool_scoped()) {
            assert!(scope.permits(verb, "claude-code"), "{verb} on its own tool");
            assert!(!scope.permits(verb, "codex"), "{verb} must not cross to another tool");
        }
    }

    #[test]
    fn list_tools_needs_no_tool_membership() {
        let scope = claude_only();
        assert!(scope.permits(DiVerb::ListTools, "codex"));
    }

    #[test]
    fn a_read_only_scope_grants_no_mutation() {
        let scope = TokenScope::read_only(ToolScope::AllTools);
        for verb in DiVerb::ALL.into_iter().filter(|v| v.is_mutation()) {
            assert!(!scope.permits(verb, "claude-code"), "{verb} must be denied");
        }
        assert!(scope.permits(DiVerb::Status, "claude-code"));
    }

    #[test]
    fn an_empty_scope_grants_nothing() {
        let scope = TokenScope::new(ToolScope::tools(Vec::<String>::new()), []);
        for verb in DiVerb::ALL {
            assert!(!scope.permits(verb, "claude-code"));
        }
    }

    #[test]
    fn all_tools_still_respects_the_verb_set() {
        let scope = TokenScope::new(ToolScope::AllTools, [DiVerb::Status]);
        assert!(scope.permits(DiVerb::Status, "anything"));
        assert!(!scope.permits(DiVerb::Apply, "anything"));
    }

    #[test]
    fn describe_names_only_scope_facts() {
        let scope = claude_only();
        let rendered = scope.describe();
        assert!(rendered.contains("claude-code"));
        assert!(rendered.contains("apply"));
    }
}
