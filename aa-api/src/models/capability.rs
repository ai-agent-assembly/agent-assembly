//! Capability matrix data model — agent × resource × verb × decision view
//! consumed by the dashboard Capability Matrix page (AAASM-1280).
//!
//! Field names use `serde(rename_all = "camelCase")` on response structs so
//! the wire shape matches the dashboard's TypeScript types in
//! `dashboard/src/api/capability.ts`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Verb a capability cell scopes its decision to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Verb {
    Read,
    Write,
    Delete,
    Exec,
}

/// Decision recorded for a single (agent, resource, verb) tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Narrow,
    Approval,
    Deny,
    Na,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Verb::Read).unwrap(), r#""read""#);
        assert_eq!(serde_json::to_string(&Verb::Write).unwrap(), r#""write""#);
        assert_eq!(serde_json::to_string(&Verb::Delete).unwrap(), r#""delete""#);
        assert_eq!(serde_json::to_string(&Verb::Exec).unwrap(), r#""exec""#);
    }

    #[test]
    fn decision_serializes_lowercase_including_na() {
        assert_eq!(serde_json::to_string(&Decision::Allow).unwrap(), r#""allow""#);
        assert_eq!(serde_json::to_string(&Decision::Narrow).unwrap(), r#""narrow""#);
        assert_eq!(serde_json::to_string(&Decision::Approval).unwrap(), r#""approval""#);
        assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), r#""deny""#);
        assert_eq!(serde_json::to_string(&Decision::Na).unwrap(), r#""na""#);
    }

    #[test]
    fn verb_deserializes_lowercase() {
        let v: Verb = serde_json::from_str(r#""exec""#).unwrap();
        assert_eq!(v, Verb::Exec);
    }
}
