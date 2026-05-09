//! Approval-related domain types shared across crates.

use alloc::string::String;

/// The category of action that triggered an approval request.
///
/// Used as an optional filter key in team routing configuration so different
/// action types can be routed to different approver lists within the same team.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ApprovalKind {
    /// An agent attempted to spawn a child agent.
    Spawn,
    /// An agent invoked a tool that requires approval.
    ToolUse,
    /// An agent requested a budget increase.
    BudgetIncrease,
    /// A caller-defined approval category.
    Custom(String),
}

impl ApprovalKind {
    /// Returns the canonical string key stored in the database.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Spawn => "spawn",
            Self::ToolUse => "tool_use",
            Self::BudgetIncrease => "budget_increase",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl core::fmt::Display for ApprovalKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for ApprovalKind {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "spawn" => Self::Spawn,
            "tool_use" => Self::ToolUse,
            "budget_increase" => Self::BudgetIncrease,
            other => Self::Custom(String::from(other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_kinds_round_trip_via_as_str_and_from_str() {
        for kind in [ApprovalKind::Spawn, ApprovalKind::ToolUse, ApprovalKind::BudgetIncrease] {
            let s = kind.as_str();
            let parsed: ApprovalKind = s.parse().unwrap();
            assert_eq!(kind, parsed);
        }
    }

    #[test]
    fn custom_kind_preserves_string() {
        let k: ApprovalKind = "file_access".parse().unwrap();
        assert_eq!(k, ApprovalKind::Custom(String::from("file_access")));
        assert_eq!(k.as_str(), "file_access");
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(ApprovalKind::Spawn.to_string(), "spawn");
        assert_eq!(ApprovalKind::ToolUse.to_string(), "tool_use");
    }
}
