//! Mini boolean expression parser for `requires_approval_if` conditions.
//!
//! Public surface: [`evaluate`].
//!
//! Grammar (flat, no parentheses in v1):
//! ```text
//! expr       := clause (combinator clause)*
//! clause     := field op literal
//! combinator := "AND" | "OR"
//! field      := "tool" | "path" | "url" | "method" | "command"
//! op         := "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains" | "starts_with"
//! literal    := quoted_string | integer | float
//! ```
//!
//! **Fail-safe**: any parse/tokenization error returns `true`
//! (triggers RequiresApproval — the safe default).

// The private helpers below are only consumed via `evaluate` which is
// `pub(crate)`.  Until a caller in this crate wires up the evaluator,
// rustc sees them as dead code.  The allow is intentional and temporary.
#![allow(dead_code)]

use aa_core::{GovernanceAction, GovernanceLevel};

use crate::policy::context::PolicyContext;

use strsim;

/// All variable names that the expression evaluator recognises.
///
/// Used by load-time validation to catch typos before a policy is ever
/// evaluated.  Any identifier in a `requires_approval_if` expression that is
/// not in this list and is not a combinator, operator, governance-level literal,
/// or numeric literal will be rejected with
/// [`PolicyParseError::UnknownVariable`](crate::policy::error::PolicyParseError::UnknownVariable).
pub(crate) const KNOWN_VARIABLES: &[&str] = &[
    "tool",
    "path",
    "url",
    "method",
    "command",
    "governance_level",
    "agent.depth",
    "agent.risk_tier",
    "team.active_agents",
    "team.budget_remaining",
    "child.tool",
    "child.risk_tier",
    "parent.risk_tier",
    "source.team_id",
    "target.team_id",
    "target.channel_id",
];

// ---------------------------------------------------------------------------
// Internal token types
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum FieldRef {
    Tool,
    Path,
    Url,
    Method,
    Command,
    GovernanceLevel,
    AgentDepth,
    TeamActiveAgents,
    TeamBudgetRemaining,
    ChildTool,
    ChildRiskTier,
    AgentRiskTier,
    ParentRiskTier,
    SourceTeamId,
    TargetTeamId,
    TargetChannelId,
}

#[derive(Debug, PartialEq)]
enum OpKind {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    StartsWith,
}

#[derive(Debug, PartialEq)]
enum LiteralVal {
    Str(String),
    Num(f64),
    Level(GovernanceLevel),
    Tier(aa_core::RiskTier),
}

#[derive(Debug, PartialEq)]
enum Token {
    Field(FieldRef),
    Op(OpKind),
    Literal(LiteralVal),
    And,
    Or,
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

fn tokenize(expr: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = expr.chars().peekable();

    while let Some(&ch) = chars.peek() {
        // Skip whitespace
        if ch.is_whitespace() {
            chars.next();
            continue;
        }

        // Quoted string literal
        if ch == '"' {
            chars.next(); // consume opening quote
            let mut s = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => {
                        // basic escape: \" and \\
                        match chars.next() {
                            Some('"') => s.push('"'),
                            Some('\\') => s.push('\\'),
                            Some(c) => {
                                s.push('\\');
                                s.push(c);
                            }
                            None => return None, // unterminated escape
                        }
                    }
                    Some(c) => s.push(c),
                    None => return None, // unterminated string
                }
            }
            tokens.push(Token::Literal(LiteralVal::Str(s)));
            continue;
        }

        // Operator tokens that start with '<', '>', '=', '!'
        if ch == '<' || ch == '>' || ch == '=' || ch == '!' {
            chars.next();
            let op = if chars.peek() == Some(&'=') {
                chars.next();
                match ch {
                    '<' => OpKind::Lte,
                    '>' => OpKind::Gte,
                    '=' => OpKind::Eq,
                    '!' => OpKind::Ne,
                    _ => return None,
                }
            } else {
                match ch {
                    '<' => OpKind::Lt,
                    '>' => OpKind::Gt,
                    _ => return None, // bare '=' or '!' without '=' is invalid
                }
            };
            tokens.push(Token::Op(op));
            continue;
        }

        // Word tokens: keywords, field names, operators, numeric literals
        if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    word.push(c);
                    chars.next();
                } else {
                    break;
                }
            }

            let token = match word.as_str() {
                "AND" => Token::And,
                "OR" => Token::Or,
                "tool" => Token::Field(FieldRef::Tool),
                "path" => Token::Field(FieldRef::Path),
                "url" => Token::Field(FieldRef::Url),
                "method" => Token::Field(FieldRef::Method),
                "command" => Token::Field(FieldRef::Command),
                "governance_level" => Token::Field(FieldRef::GovernanceLevel),
                "agent.depth" => Token::Field(FieldRef::AgentDepth),
                "team.active_agents" => Token::Field(FieldRef::TeamActiveAgents),
                "team.budget_remaining" => Token::Field(FieldRef::TeamBudgetRemaining),
                "child.tool" => Token::Field(FieldRef::ChildTool),
                "child.risk_tier" => Token::Field(FieldRef::ChildRiskTier),
                "agent.risk_tier" => Token::Field(FieldRef::AgentRiskTier),
                "parent.risk_tier" => Token::Field(FieldRef::ParentRiskTier),
                "source.team_id" => Token::Field(FieldRef::SourceTeamId),
                "target.team_id" => Token::Field(FieldRef::TargetTeamId),
                "target.channel_id" => Token::Field(FieldRef::TargetChannelId),
                "L0" => Token::Literal(LiteralVal::Level(GovernanceLevel::L0Discover)),
                "L1" => Token::Literal(LiteralVal::Level(GovernanceLevel::L1Observe)),
                "L2" => Token::Literal(LiteralVal::Level(GovernanceLevel::L2Enforce)),
                "L3" => Token::Literal(LiteralVal::Level(GovernanceLevel::L3Native)),
                "Low" => Token::Literal(LiteralVal::Tier(aa_core::RiskTier::Low)),
                "Medium" => Token::Literal(LiteralVal::Tier(aa_core::RiskTier::Medium)),
                "High" => Token::Literal(LiteralVal::Tier(aa_core::RiskTier::High)),
                "Critical" => Token::Literal(LiteralVal::Tier(aa_core::RiskTier::Critical)),
                "contains" => Token::Op(OpKind::Contains),
                "starts_with" => Token::Op(OpKind::StartsWith),
                other => {
                    // Try to parse as a number
                    if let Ok(n) = other.parse::<f64>() {
                        Token::Literal(LiteralVal::Num(n))
                    } else {
                        return None; // unknown word
                    }
                }
            };
            tokens.push(token);
            continue;
        }

        // Unknown character
        return None;
    }

    Some(tokens)
}

// ---------------------------------------------------------------------------
// Field value extraction
// ---------------------------------------------------------------------------

fn field_value<'a>(field: &FieldRef, action: &'a GovernanceAction) -> &'a str {
    match (field, action) {
        (FieldRef::Tool, GovernanceAction::ToolCall { name, .. }) => name.as_str(),
        (FieldRef::Path, GovernanceAction::FileAccess { path, .. }) => path.as_str(),
        (FieldRef::Url, GovernanceAction::NetworkRequest { url, .. }) => url.as_str(),
        (FieldRef::Method, GovernanceAction::NetworkRequest { method, .. }) => method.as_str(),
        (FieldRef::Command, GovernanceAction::ProcessExec { command }) => command.as_str(),
        // Field does not match the action variant, or governance_level is
        // handled out-of-band in `eval_clause_safe` → treat as empty string.
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// Clause evaluation
// ---------------------------------------------------------------------------

fn eval_clause_safe(
    field: &FieldRef,
    op: &OpKind,
    literal: &LiteralVal,
    action: &GovernanceAction,
    agent_level: Option<GovernanceLevel>,
    policy_ctx: Option<&dyn PolicyContext>,
) -> bool {
    // agent.depth — numeric comparison against the current agent's delegation depth.
    // Returns false (null-safe no-match) when no context is available.
    if let FieldRef::AgentDepth = field {
        let lhs = match policy_ctx.and_then(|c| c.agent_depth()) {
            Some(d) => d as f64,
            None => return false,
        };
        let rhs = match numeric_literal(literal) {
            Some(r) => r,
            None => return false,
        };
        return match op {
            OpKind::Eq => lhs == rhs,
            OpKind::Ne => lhs != rhs,
            OpKind::Gt => lhs > rhs,
            OpKind::Gte => lhs >= rhs,
            OpKind::Lt => lhs < rhs,
            OpKind::Lte => lhs <= rhs,
            OpKind::Contains | OpKind::StartsWith => false,
        };
    }

    // team.active_agents — numeric comparison against the count of agents in the
    // current agent's team. Returns false when the agent has no team (null-safe).
    if let FieldRef::TeamActiveAgents = field {
        let lhs = match policy_ctx.and_then(|c| c.team_active_agents()) {
            Some(n) => n as f64,
            None => return false,
        };
        let rhs = match numeric_literal(literal) {
            Some(r) => r,
            None => return false,
        };
        return match op {
            OpKind::Eq => lhs == rhs,
            OpKind::Ne => lhs != rhs,
            OpKind::Gt => lhs > rhs,
            OpKind::Gte => lhs >= rhs,
            OpKind::Lt => lhs < rhs,
            OpKind::Lte => lhs <= rhs,
            OpKind::Contains | OpKind::StartsWith => false,
        };
    }

    // team.budget_remaining — numeric comparison against the remaining monthly
    // budget for the current agent's team. Returns false when no budget entry or
    // no monthly limit is configured (null-safe).
    if let FieldRef::TeamBudgetRemaining = field {
        let lhs = match policy_ctx.and_then(|c| c.team_budget_remaining()) {
            Some(r) => r,
            None => return false,
        };
        let rhs = match numeric_literal(literal) {
            Some(r) => r,
            None => return false,
        };
        return match op {
            OpKind::Eq => lhs == rhs,
            OpKind::Ne => lhs != rhs,
            OpKind::Gt => lhs > rhs,
            OpKind::Gte => lhs >= rhs,
            OpKind::Lt => lhs < rhs,
            OpKind::Lte => lhs <= rhs,
            OpKind::Contains | OpKind::StartsWith => false,
        };
    }

    // child.tool — string comparison against the union of tool_names across all
    // direct children of the current agent. Returns false when context is absent.
    if let FieldRef::ChildTool = field {
        let tools = match policy_ctx {
            Some(c) => c.child_tools(),
            None => return false,
        };
        let rhs = match literal {
            LiteralVal::Str(s) => s.as_str(),
            _ => return false,
        };
        return match op {
            OpKind::Eq => tools.iter().any(|t| t == rhs),
            OpKind::Ne => tools.iter().all(|t| t != rhs),
            OpKind::Contains => tools.iter().any(|t| t.contains(rhs)),
            OpKind::StartsWith => tools.iter().any(|t| t.starts_with(rhs)),
            _ => false,
        };
    }

    // agent.risk_tier — ordinal comparison against the current agent's risk tier.
    // Returns false (null-safe no-match) when context or registry lookup is absent.
    if let FieldRef::AgentRiskTier = field {
        let lhs = match policy_ctx.and_then(|c| c.agent_risk_tier()) {
            Some(t) => t,
            None => return false,
        };
        let rhs = match literal {
            LiteralVal::Tier(t) => *t,
            _ => return false,
        };
        return match op {
            OpKind::Eq => lhs == rhs,
            OpKind::Ne => lhs != rhs,
            OpKind::Gt => lhs > rhs,
            OpKind::Gte => lhs >= rhs,
            OpKind::Lt => lhs < rhs,
            OpKind::Lte => lhs <= rhs,
            OpKind::Contains | OpKind::StartsWith => false,
        };
    }

    // parent.risk_tier — ordinal comparison against the parent agent's risk tier.
    // Returns false when context is absent, agent has no parent, or parent not in registry.
    if let FieldRef::ParentRiskTier = field {
        let lhs = match policy_ctx.and_then(|c| c.parent_risk_tier()) {
            Some(t) => t,
            None => return false,
        };
        let rhs = match literal {
            LiteralVal::Tier(t) => *t,
            _ => return false,
        };
        return match op {
            OpKind::Eq => lhs == rhs,
            OpKind::Ne => lhs != rhs,
            OpKind::Gt => lhs > rhs,
            OpKind::Gte => lhs >= rhs,
            OpKind::Lt => lhs < rhs,
            OpKind::Lte => lhs <= rhs,
            OpKind::Contains | OpKind::StartsWith => false,
        };
    }

    // child.risk_tier — ordinal comparison against the proposed risk tier of the
    // child agent being spawned. Returns false when no spawn context is supplied.
    if let FieldRef::ChildRiskTier = field {
        let lhs = match policy_ctx.and_then(|c| c.child_risk_tier()) {
            Some(t) => t,
            None => return false,
        };
        let rhs = match literal {
            LiteralVal::Tier(t) => *t,
            _ => return false,
        };
        return match op {
            OpKind::Eq => lhs == rhs,
            OpKind::Ne => lhs != rhs,
            OpKind::Gt => lhs > rhs,
            OpKind::Gte => lhs >= rhs,
            OpKind::Lt => lhs < rhs,
            OpKind::Lte => lhs <= rhs,
            OpKind::Contains | OpKind::StartsWith => false,
        };
    }

    // governance_level is the only field whose value type is not a string;
    // route it through an Ord-based comparison and return early.
    if let FieldRef::GovernanceLevel = field {
        let rhs = match literal {
            LiteralVal::Level(l) => *l,
            // Mismatched literal kind (e.g. `governance_level == "L2"`) cannot
            // match — treat as no-fire rather than fail-safe approval, since
            // the validator should have rejected it before evaluation.
            _ => return false,
        };
        let lhs = match agent_level {
            Some(l) => l,
            // No agent level supplied → cannot compare; treat as no-match.
            None => return false,
        };
        return match op {
            OpKind::Eq => lhs == rhs,
            OpKind::Ne => lhs != rhs,
            OpKind::Gt => lhs > rhs,
            OpKind::Gte => lhs >= rhs,
            OpKind::Lt => lhs < rhs,
            OpKind::Lte => lhs <= rhs,
            // String operators do not apply to governance_level.
            OpKind::Contains | OpKind::StartsWith => false,
        };
    }

    let lhs = field_value(field, action);

    match op {
        OpKind::Contains => {
            if let LiteralVal::Str(rhs) = literal {
                lhs.contains(rhs.as_str())
            } else {
                false
            }
        }
        OpKind::StartsWith => {
            if let LiteralVal::Str(rhs) = literal {
                lhs.starts_with(rhs.as_str())
            } else {
                false
            }
        }
        OpKind::Eq => match literal {
            LiteralVal::Num(rhs) => {
                if let Ok(lhs_num) = lhs.parse::<f64>() {
                    lhs_num == *rhs
                } else {
                    false
                }
            }
            LiteralVal::Str(rhs) => lhs == rhs.as_str(),
            // A level/tier literal against a non-level/tier field cannot match.
            LiteralVal::Level(_) | LiteralVal::Tier(_) => false,
        },
        OpKind::Ne => match literal {
            LiteralVal::Num(rhs) => {
                if let Ok(lhs_num) = lhs.parse::<f64>() {
                    lhs_num != *rhs
                } else {
                    true // can't parse as number, so not equal numerically
                }
            }
            LiteralVal::Str(rhs) => lhs != rhs.as_str(),
            // A level/tier literal against a non-level/tier field is unconditionally
            // not-equal — matches the symmetric `Eq` handling above.
            LiteralVal::Level(_) | LiteralVal::Tier(_) => true,
        },
        OpKind::Gt => {
            let rhs = numeric_literal(literal);
            let lhs_n = lhs.parse::<f64>().ok();
            match (lhs_n, rhs) {
                (Some(l), Some(r)) => l > r,
                _ => false,
            }
        }
        OpKind::Gte => {
            let rhs = numeric_literal(literal);
            let lhs_n = lhs.parse::<f64>().ok();
            match (lhs_n, rhs) {
                (Some(l), Some(r)) => l >= r,
                _ => false,
            }
        }
        OpKind::Lt => {
            let rhs = numeric_literal(literal);
            let lhs_n = lhs.parse::<f64>().ok();
            match (lhs_n, rhs) {
                (Some(l), Some(r)) => l < r,
                _ => false,
            }
        }
        OpKind::Lte => {
            let rhs = numeric_literal(literal);
            let lhs_n = lhs.parse::<f64>().ok();
            match (lhs_n, rhs) {
                (Some(l), Some(r)) => l <= r,
                _ => false,
            }
        }
    }
}

fn numeric_literal(lit: &LiteralVal) -> Option<f64> {
    match lit {
        LiteralVal::Num(n) => Some(*n),
        LiteralVal::Str(s) => s.parse::<f64>().ok(),
        // Level and tier literals never participate in numeric comparisons.
        LiteralVal::Level(_) | LiteralVal::Tier(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Token evaluation  (AND binds tighter than OR)
// ---------------------------------------------------------------------------

/// A single parsed clause: `field op literal`.
struct Clause<'t> {
    field: &'t FieldRef,
    op: &'t OpKind,
    literal: &'t LiteralVal,
}

fn eval_tokens(
    tokens: &[Token],
    action: &GovernanceAction,
    agent_level: Option<GovernanceLevel>,
    policy_ctx: Option<&dyn PolicyContext>,
) -> bool {
    // Parse tokens into a sequence of clauses separated by AND/OR.
    // Strategy: split into OR-groups where each group is a slice of
    // AND-connected clauses.  Result = any OR-group where all clauses are true.

    // First, extract clauses and combinators in order.
    // Expected pattern: Clause (AND|OR Clause)*
    // A "Clause" is three consecutive tokens: Field, Op, Literal.

    let mut or_groups: Vec<Vec<Clause>> = vec![Vec::new()];

    let mut i = 0;
    while i < tokens.len() {
        // Expect: Field Op Literal
        match (&tokens[i], tokens.get(i + 1), tokens.get(i + 2)) {
            (Token::Field(f), Some(Token::Op(op)), Some(Token::Literal(lit))) => {
                let clause = Clause {
                    field: f,
                    op,
                    literal: lit,
                };
                or_groups.last_mut().unwrap().push(clause);
                i += 3;

                // Now expect AND | OR | end
                match tokens.get(i) {
                    None => break,
                    Some(Token::And) => {
                        i += 1; // continue in the same OR group
                    }
                    Some(Token::Or) => {
                        i += 1;
                        or_groups.push(Vec::new()); // start a new OR group
                    }
                    _ => return true, // unexpected token → fail-safe
                }
            }
            _ => return true, // unexpected structure → fail-safe
        }
    }

    // If nothing was parsed, that's a fail-safe trigger (empty expr)
    if or_groups.is_empty() || or_groups.iter().all(|g| g.is_empty()) {
        return true;
    }

    // Evaluate: OR across groups, AND within each group
    or_groups.iter().any(|group| {
        group
            .iter()
            .all(|c| eval_clause_safe(c.field, c.op, c.literal, action, agent_level, policy_ctx))
    })
}

// ---------------------------------------------------------------------------
// Variable extraction for load-time validation
// ---------------------------------------------------------------------------

/// Extract every identifier-like word from `expr` that could be a field
/// reference (skipping quoted strings, numeric literals, and combinators).
///
/// Used by [`validate_variables`] to find unknown variable names without
/// running the full tokenizer.
pub(crate) fn extract_field_names(expr: &str) -> Vec<String> {
    const SKIP_WORDS: &[&str] = &[
        "AND",
        "OR",
        "true",
        "false",
        "contains",
        "starts_with",
        "L0",
        "L1",
        "L2",
        "L3",
        "Low",
        "Medium",
        "High",
        "Critical",
    ];

    let mut names = Vec::new();
    let mut chars = expr.chars().peekable();

    while let Some(&ch) = chars.peek() {
        // Skip whitespace and operator chars
        if ch.is_whitespace() || matches!(ch, '<' | '>' | '=' | '!') {
            chars.next();
            continue;
        }

        // Skip quoted string literals
        if ch == '"' {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') | None => break,
                    Some('\\') => {
                        chars.next();
                    }
                    _ => {}
                }
            }
            continue;
        }

        // Collect word token (letters, digits, underscore, hyphen, dot)
        if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    word.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            // Skip combinators, boolean keywords, and numeric literals
            if SKIP_WORDS.contains(&word.as_str()) || word.parse::<f64>().is_ok() {
                continue;
            }
            names.push(word);
            continue;
        }

        chars.next();
    }

    names
}

/// Return the closest entry in `KNOWN_VARIABLES` to `name` when the edit
/// distance is at most 2, or `None` when no candidate is close enough.
fn suggest_variable(name: &str) -> Option<&'static str> {
    KNOWN_VARIABLES
        .iter()
        .copied()
        .filter(|&v| strsim::levenshtein(name, v) <= 2)
        .min_by_key(|&v| strsim::levenshtein(name, v))
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Validate that every identifier in `expr` is a member of [`KNOWN_VARIABLES`].
///
/// Returns [`PolicyParseError::UnknownVariable`] on the first unknown name
/// found, with a typo suggestion when the Levenshtein distance to the closest
/// known variable is ≤ 2.
pub(crate) fn validate_variables(expr: &str) -> Result<(), crate::policy::error::PolicyParseError> {
    for name in extract_field_names(expr) {
        if !KNOWN_VARIABLES.contains(&name.as_str()) {
            let suggestion = suggest_variable(&name).map(str::to_owned);
            let available = KNOWN_VARIABLES.iter().map(|s| s.to_string()).collect();
            return Err(crate::policy::error::PolicyParseError::UnknownVariable {
                name,
                suggestion,
                available,
            });
        }
    }
    Ok(())
}

/// Validate that every `governance_level` literal in `expr` is one of the
/// four known levels (L0..L3).
///
/// Returns the spec-mandated error message
/// `unknown governance level: <value>; valid values: L0, L1, L2, L3` when the
/// expression mentions an unknown level (e.g. `L4` or `LX`). Other shapes are
/// not rejected here — the runtime evaluator is fail-safe for everything else.
pub(crate) fn validate_governance_levels(expr: &str) -> Result<(), String> {
    let mut chars = expr.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch == 'L' {
            // Collect the identifier-like word starting with 'L'.
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' {
                    word.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            // Only reject `L<digit>+` shapes — these are clearly intended as
            // level literals. Anything else (`Logger`, `Limit`, …) is left
            // for the runtime tokenizer to handle.
            let rest = &word[1..];
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                match word.as_str() {
                    "L0" | "L1" | "L2" | "L3" => {}
                    _ => {
                        return Err(format!(
                            "unknown governance level: {word}; valid values: L0, L1, L2, L3"
                        ));
                    }
                }
            }
            continue;
        }
        chars.next();
    }
    Ok(())
}

/// Evaluate a flat boolean expression against a [`GovernanceAction`] and the
/// governing agent's [`GovernanceLevel`].
///
/// `agent_level` is consulted only by clauses referencing the
/// `governance_level` field; pass `None` when the caller does not know the
/// agent's level (e.g. legacy code paths) — clauses that depend on the
/// level are then treated as unknown comparisons (no-match).
///
/// Returns `true` if the expression matches (approval required).
/// Returns `true` on ANY parse/tokenization error (fail-safe).
pub(crate) fn evaluate(
    expr: &str,
    action: &GovernanceAction,
    agent_level: Option<GovernanceLevel>,
    policy_ctx: Option<&dyn PolicyContext>,
) -> bool {
    let tokens = match tokenize(expr) {
        Some(t) if !t.is_empty() => t,
        _ => return true, // fail-safe
    };
    eval_tokens(&tokens, action, agent_level, policy_ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::{FileMode, GovernanceAction};

    fn tool(name: &str) -> GovernanceAction {
        GovernanceAction::ToolCall {
            name: name.to_string(),
            args: String::new(),
        }
    }

    fn file(path: &str) -> GovernanceAction {
        GovernanceAction::FileAccess {
            path: path.to_string(),
            mode: FileMode::Read,
        }
    }

    fn network(url: &str, method: &str) -> GovernanceAction {
        GovernanceAction::NetworkRequest {
            url: url.to_string(),
            method: method.to_string(),
        }
    }

    fn process(command: &str) -> GovernanceAction {
        GovernanceAction::ProcessExec {
            command: command.to_string(),
        }
    }

    #[test]
    fn eq_operator_matches_tool_name() {
        assert!(evaluate(r#"tool == "search""#, &tool("search"), None, None));
    }

    #[test]
    fn ne_operator_false_when_equal() {
        assert!(!evaluate(r#"tool != "search""#, &tool("search"), None, None));
    }

    #[test]
    fn contains_operator_on_url() {
        assert!(evaluate(
            r#"url contains "evil""#,
            &network("https://evil.com", "GET"),
            None,
            None,
        ));
    }

    #[test]
    fn starts_with_operator_on_path() {
        assert!(evaluate(r#"path starts_with "/etc""#, &file("/etc/passwd"), None, None));
    }

    #[test]
    fn and_combinator_all_true() {
        assert!(evaluate(
            r#"tool == "search" AND tool == "search""#,
            &tool("search"),
            None,
            None,
        ));
    }

    #[test]
    fn and_combinator_short_circuits() {
        assert!(!evaluate(
            r#"tool == "search" AND tool == "other""#,
            &tool("search"),
            None,
            None,
        ));
    }

    #[test]
    fn or_combinator_first_true() {
        assert!(evaluate(
            r#"tool == "x" OR tool == "search""#,
            &tool("search"),
            None,
            None
        ));
    }

    #[test]
    fn fail_safe_on_bad_expr() {
        assert!(evaluate("not valid @@@ expr", &tool("anything"), None, None));
    }

    #[test]
    fn field_absent_for_action_variant_returns_false() {
        // `tool` field is "" for ProcessExec → should NOT match "foo"
        assert!(!evaluate(r#"tool == "foo""#, &process("ls"), None, None));
    }

    #[test]
    fn rule_with_ge_l2_fires_for_l2_agent() {
        // An L2 agent satisfies `governance_level >= L2`.
        assert!(evaluate(
            "governance_level >= L2",
            &tool("any"),
            Some(GovernanceLevel::L2Enforce),
            None,
        ));
    }

    #[test]
    fn rule_with_ge_l2_does_not_fire_for_l1_agent() {
        // An L1 agent does not satisfy `governance_level >= L2`.
        assert!(!evaluate(
            "governance_level >= L2",
            &tool("any"),
            Some(GovernanceLevel::L1Observe),
            None,
        ));
    }

    #[test]
    fn rule_without_level_condition_fires_for_all_levels() {
        // Backward compat: a condition that does not mention
        // `governance_level` evaluates the same way at every level.
        for level in [
            GovernanceLevel::L0Discover,
            GovernanceLevel::L1Observe,
            GovernanceLevel::L2Enforce,
            GovernanceLevel::L3Native,
        ] {
            assert!(
                evaluate(r#"tool == "search""#, &tool("search"), Some(level), None),
                "tool-only condition unexpectedly skipped for {level:?}"
            );
        }
    }

    fn fake_ctx(depth: Option<u32>) -> crate::policy::context::FakePolicyContext {
        crate::policy::context::FakePolicyContext {
            depth,
            team_active: None,
            team_budget: None,
            child_tools: vec![],
            agent_risk_tier: None,
            parent_risk_tier: None,
            child_risk_tier: None,
        }
    }

    #[test]
    fn agent_depth_gt_matches_when_deeper() {
        let ctx = fake_ctx(Some(3));
        assert!(evaluate("agent.depth > 2", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn agent_depth_gt_no_match_when_shallower() {
        let ctx = fake_ctx(Some(1));
        assert!(!evaluate("agent.depth > 2", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn agent_depth_eq_matches_exact() {
        let ctx = fake_ctx(Some(0));
        assert!(evaluate("agent.depth == 0", &tool("any"), None, Some(&ctx)));
    }

    fn fake_team_ctx(active: Option<u64>) -> crate::policy::context::FakePolicyContext {
        crate::policy::context::FakePolicyContext {
            depth: None,
            team_active: active,
            team_budget: None,
            child_tools: vec![],
            agent_risk_tier: None,
            parent_risk_tier: None,
            child_risk_tier: None,
        }
    }

    #[test]
    fn team_active_agents_gt_matches() {
        let ctx = fake_team_ctx(Some(6));
        assert!(evaluate("team.active_agents > 5", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn team_active_agents_gt_no_match() {
        let ctx = fake_team_ctx(Some(3));
        assert!(!evaluate("team.active_agents > 5", &tool("any"), None, Some(&ctx)));
    }

    fn fake_budget_ctx(remaining: Option<f64>) -> crate::policy::context::FakePolicyContext {
        crate::policy::context::FakePolicyContext {
            depth: None,
            team_active: None,
            team_budget: remaining,
            child_tools: vec![],
            agent_risk_tier: None,
            parent_risk_tier: None,
            child_risk_tier: None,
        }
    }

    #[test]
    fn team_budget_remaining_lt_matches_when_low() {
        let ctx = fake_budget_ctx(Some(50.0));
        assert!(evaluate("team.budget_remaining < 100", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn team_budget_remaining_lt_no_match_when_sufficient() {
        let ctx = fake_budget_ctx(Some(200.0));
        assert!(!evaluate("team.budget_remaining < 100", &tool("any"), None, Some(&ctx)));
    }

    fn fake_child_ctx(tools: Vec<&str>) -> crate::policy::context::FakePolicyContext {
        crate::policy::context::FakePolicyContext {
            depth: None,
            team_active: None,
            team_budget: None,
            child_tools: tools.into_iter().map(String::from).collect(),
            agent_risk_tier: None,
            parent_risk_tier: None,
            child_risk_tier: None,
        }
    }

    #[test]
    fn child_tool_eq_matches_when_present() {
        let ctx = fake_child_ctx(vec!["bash", "search"]);
        assert!(evaluate(r#"child.tool == "bash""#, &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn child_tool_eq_no_match_when_absent() {
        let ctx = fake_child_ctx(vec!["search"]);
        assert!(!evaluate(r#"child.tool == "bash""#, &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn child_tool_ne_true_when_all_differ() {
        let ctx = fake_child_ctx(vec!["search"]);
        assert!(evaluate(r#"child.tool != "bash""#, &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn null_safety_team_active_returns_false_when_no_team() {
        // team_active = None means the agent has no team; condition must not fire.
        let ctx = crate::policy::context::FakePolicyContext {
            depth: None,
            team_active: None,
            team_budget: None,
            child_tools: vec![],
            agent_risk_tier: None,
            parent_risk_tier: None,
            child_risk_tier: None,
        };
        assert!(!evaluate("team.active_agents > 0", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn null_safety_returns_false_when_no_context() {
        // No context at all: graph-aware field must not fire (fail-closed → no-match).
        assert!(!evaluate("agent.depth > 0", &tool("any"), None, None));
    }

    // ── risk tier tests ──────────────────────────────────────────────────

    fn fake_tier_ctx(
        agent: Option<aa_core::RiskTier>,
        parent: Option<aa_core::RiskTier>,
    ) -> crate::policy::context::FakePolicyContext {
        crate::policy::context::FakePolicyContext {
            depth: None,
            team_active: None,
            team_budget: None,
            child_tools: vec![],
            agent_risk_tier: agent,
            parent_risk_tier: parent,
            child_risk_tier: None,
        }
    }

    #[test]
    fn agent_risk_tier_eq_matches_same_tier() {
        let ctx = fake_tier_ctx(Some(aa_core::RiskTier::Medium), None);
        assert!(evaluate("agent.risk_tier == Medium", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn agent_risk_tier_eq_no_match_different_tier() {
        let ctx = fake_tier_ctx(Some(aa_core::RiskTier::Low), None);
        assert!(!evaluate("agent.risk_tier == Medium", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn agent_risk_tier_gt_detects_escalation() {
        let ctx = fake_tier_ctx(Some(aa_core::RiskTier::High), Some(aa_core::RiskTier::Medium));
        // agent is High, parent is Medium → child tier > parent tier
        assert!(evaluate("agent.risk_tier > Medium", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn parent_risk_tier_eq_matches() {
        let ctx = fake_tier_ctx(Some(aa_core::RiskTier::High), Some(aa_core::RiskTier::Medium));
        assert!(evaluate("parent.risk_tier == Medium", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn parent_risk_tier_returns_false_when_no_parent() {
        let ctx = fake_tier_ctx(Some(aa_core::RiskTier::Low), None);
        assert!(!evaluate("parent.risk_tier == Low", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn risk_tier_null_safe_no_context() {
        assert!(!evaluate("agent.risk_tier == High", &tool("any"), None, None));
    }

    // ── child.risk_tier tests ────────────────────────────────────────────────

    fn fake_child_tier_ctx(child: Option<aa_core::RiskTier>) -> crate::policy::context::FakePolicyContext {
        crate::policy::context::FakePolicyContext {
            depth: None,
            team_active: None,
            team_budget: None,
            child_tools: vec![],
            agent_risk_tier: None,
            parent_risk_tier: None,
            child_risk_tier: child,
        }
    }

    #[test]
    fn child_risk_tier_gt_denies_escalation() {
        // Spawn proposes High; parent is Medium → child.risk_tier > Medium fires.
        let ctx = fake_child_tier_ctx(Some(aa_core::RiskTier::High));
        assert!(evaluate("child.risk_tier > Medium", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn child_risk_tier_same_tier_does_not_fire() {
        // Spawn proposes Medium; parent is Medium → child.risk_tier > Medium does not fire.
        let ctx = fake_child_tier_ctx(Some(aa_core::RiskTier::Medium));
        assert!(!evaluate("child.risk_tier > Medium", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn child_risk_tier_eq_matches_exact() {
        let ctx = fake_child_tier_ctx(Some(aa_core::RiskTier::Critical));
        assert!(evaluate("child.risk_tier == Critical", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn child_risk_tier_null_safe_when_no_spawn_context() {
        // No spawn context supplied → condition does not fire (null-safe no-match).
        let ctx = fake_child_tier_ctx(None);
        assert!(!evaluate("child.risk_tier > Low", &tool("any"), None, Some(&ctx)));
    }

    #[test]
    fn child_risk_tier_null_safe_no_context_at_all() {
        assert!(!evaluate("child.risk_tier == High", &tool("any"), None, None));
    }

    // ── validate_variables tests ──────────────────────────────────────────

    #[test]
    fn validate_variables_accepts_known_variable() {
        assert!(validate_variables("agent.depth > 2").is_ok());
        assert!(validate_variables("team.active_agents == 5").is_ok());
        assert!(validate_variables("child.tool == \"bash\"").is_ok());
        assert!(validate_variables("child.risk_tier > Medium").is_ok());
        assert!(validate_variables("child.risk_tier == Critical").is_ok());
    }

    #[test]
    fn validate_variables_rejects_unknown_variable() {
        let err = validate_variables("agent.xyz > 0").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("agent.xyz"), "message should name the unknown var: {msg}");
        assert!(msg.contains("agent.depth"), "message should list known vars: {msg}");
    }

    #[test]
    fn validate_variables_suggests_typo_correction() {
        let err = validate_variables("agent.depht > 0").unwrap_err();
        match err {
            crate::policy::error::PolicyParseError::UnknownVariable { name, suggestion, .. } => {
                assert_eq!(name, "agent.depht");
                assert_eq!(suggestion.as_deref(), Some("agent.depth"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn validate_variables_no_suggestion_when_too_different() {
        let err = validate_variables("completely_unknown > 0").unwrap_err();
        match err {
            crate::policy::error::PolicyParseError::UnknownVariable { suggestion, .. } => {
                assert!(
                    suggestion.is_none(),
                    "should not suggest a match for a very different name"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parser_accepts_l0_through_l3() {
        // Each named level parses and compares equal against an agent of the
        // same level — covering all four members of the `GovernanceLevel`
        // enum in a single test.
        for (literal, level) in [
            ("L0", GovernanceLevel::L0Discover),
            ("L1", GovernanceLevel::L1Observe),
            ("L2", GovernanceLevel::L2Enforce),
            ("L3", GovernanceLevel::L3Native),
        ] {
            let expr = format!("governance_level == {literal}");
            assert!(
                evaluate(&expr, &tool("any"), Some(level), None),
                "{literal} did not parse / compare equal for matching agent level"
            );
        }
    }
}
