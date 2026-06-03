//! Versioned governance policy as persisted by storage drivers.

use alloc::string::String;
use alloc::vec::Vec;

/// A single allow/deny statement inside a [`Policy`].
///
/// # Wire format
///
/// ```json
/// { "capability": "net.http", "resource": "api.example.com/*" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct Rule {
    /// Capability this statement governs, e.g. `"net.http"`.
    pub capability: String,
    /// Resource pattern the capability applies to, e.g. `"api.example.com/*"`.
    pub resource: String,
}

/// A versioned governance policy.
///
/// `policy_version` is mandatory and monotonic: the L1 cache compares it to
/// detect drift between a cached policy and the authoritative store. `deny`
/// statements are evaluated after `allow`.
///
/// # Wire format
///
/// ```json
/// {
///   "policy_version": 7,
///   "allow": [{ "capability": "net.http", "resource": "api.example.com/*" }],
///   "deny": [{ "capability": "fs.write", "resource": "/etc/*" }]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct Policy {
    /// Monotonic version used by the L1 cache to detect drift.
    pub policy_version: u64,
    /// Statements that grant capabilities.
    pub allow: Vec<Rule>,
    /// Statements that revoke capabilities (evaluated after `allow`).
    pub deny: Vec<Rule>,
}

#[cfg(all(test, feature = "serde"))]
mod serde_round_trip {
    use super::{Policy, Rule};
    use proptest::prelude::*;

    fn rule_strategy() -> impl Strategy<Value = Rule> {
        ("[a-z.]{1,12}", "[a-z0-9.*/_-]{1,20}").prop_map(|(capability, resource)| Rule { capability, resource })
    }

    proptest! {
        #[test]
        fn policy_round_trips(
            policy_version in any::<u64>(),
            allow in prop::collection::vec(rule_strategy(), 0..4),
            deny in prop::collection::vec(rule_strategy(), 0..4),
        ) {
            let original = Policy { policy_version, allow, deny };
            let json = serde_json::to_string(&original).unwrap();
            let restored: Policy = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(original, restored);
        }
    }
}
