//! Risk tier classification for agents and policies.
//!
//! Mirrors the proto `RiskTier` enum defined in `proto/common.proto` so that
//! pure-Rust code can reason about risk without a proto dependency.
//!
//! | Tier     | Proto value | Meaning |
//! |----------|-------------|---------|
//! | `Low`    | 1           | Log-only enforcement; no blocking. |
//! | `Medium` | 2           | Block-and-optionally-approve enforcement. |
//! | `High`   | 3           | Always block; human review mandatory. |
//! | `Critical`| 4          | Immediate kill + incident escalation. |
//!
//! **Null-safe policy semantics**: when a registry lookup cannot resolve a
//! risk tier (agent not registered yet, or `risk_tier = 0` / unspecified),
//! the condition evaluates to `false` — no-match, not fail-safe trigger.

/// Risk tier assigned to an agent or policy, in ascending severity order.
///
/// `PartialOrd` / `Ord` reflect severity: `Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "PascalCase"))]
pub enum RiskTier {
    /// Log-only enforcement; no blocking.
    #[default]
    Low,
    /// Block-and-optionally-approve enforcement.
    Medium,
    /// Always block; human review mandatory.
    High,
    /// Immediate kill + incident escalation.
    Critical,
}

impl RiskTier {
    /// Convert from the proto integer value (1=Low … 4=Critical).
    /// Returns `None` for 0 (UNSPECIFIED) and any out-of-range value.
    pub fn from_proto_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(Self::Low),
            2 => Some(Self::Medium),
            3 => Some(Self::High),
            4 => Some(Self::Critical),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_reflects_severity() {
        assert!(RiskTier::Low < RiskTier::Medium);
        assert!(RiskTier::Medium < RiskTier::High);
        assert!(RiskTier::High < RiskTier::Critical);
    }

    #[test]
    fn default_is_low() {
        assert_eq!(RiskTier::default(), RiskTier::Low);
    }

    #[test]
    fn from_proto_i32_round_trips() {
        assert_eq!(RiskTier::from_proto_i32(1), Some(RiskTier::Low));
        assert_eq!(RiskTier::from_proto_i32(2), Some(RiskTier::Medium));
        assert_eq!(RiskTier::from_proto_i32(3), Some(RiskTier::High));
        assert_eq!(RiskTier::from_proto_i32(4), Some(RiskTier::Critical));
        assert_eq!(RiskTier::from_proto_i32(0), None);
        assert_eq!(RiskTier::from_proto_i32(99), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip() {
        for tier in [RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: RiskTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }
}
