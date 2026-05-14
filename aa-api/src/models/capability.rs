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

/// Coarse group a resource belongs to, used for matrix column headings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ResourceGroup {
    Comm,
    Files,
    Data,
    Infra,
    Code,
}

/// A resource that an agent may interact with — one column family in the
/// dashboard Capability Matrix.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Resource {
    /// Stable identifier (e.g. `"gmail"`, `"pg"`, `"shell"`).
    pub id: String,
    /// Human-readable display name (e.g. `"Postgres"`).
    pub name: String,
    /// Coarse group this resource belongs to.
    pub group: ResourceGroup,
    /// Globbed paths covered by this resource (e.g. `["pg.public.*"]`).
    pub paths: Vec<String>,
}

/// One cell in the (agent × resource) matrix: a decision per verb, plus an
/// optional `flag` marker the UI uses to highlight over-permissioned cells.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CapCell {
    pub read: Decision,
    pub write: Decision,
    pub delete: Decision,
    pub exec: Decision,
    /// Marks this cell for UI attention (e.g. over-permissioned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag: Option<bool>,
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

    #[test]
    fn resource_group_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&ResourceGroup::Comm).unwrap(), r#""comm""#);
        assert_eq!(serde_json::to_string(&ResourceGroup::Files).unwrap(), r#""files""#);
        assert_eq!(serde_json::to_string(&ResourceGroup::Infra).unwrap(), r#""infra""#);
    }

    #[test]
    fn resource_serializes_fields_in_order() {
        let r = Resource {
            id: "pg".to_string(),
            name: "Postgres".to_string(),
            group: ResourceGroup::Data,
            paths: vec!["pg.public.*".to_string(), "pg.public.users".to_string()],
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["id"], "pg");
        assert_eq!(json["name"], "Postgres");
        assert_eq!(json["group"], "data");
        assert_eq!(json["paths"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn cap_cell_omits_flag_when_none() {
        let cell = CapCell {
            read: Decision::Allow,
            write: Decision::Narrow,
            delete: Decision::Deny,
            exec: Decision::Na,
            flag: None,
        };
        let json = serde_json::to_value(&cell).unwrap();
        assert_eq!(json["read"], "allow");
        assert_eq!(json["write"], "narrow");
        assert_eq!(json["delete"], "deny");
        assert_eq!(json["exec"], "na");
        assert!(json.get("flag").is_none(), "flag should be omitted when None");
    }

    #[test]
    fn cap_cell_includes_flag_when_set() {
        let cell = CapCell {
            read: Decision::Allow,
            write: Decision::Allow,
            delete: Decision::Allow,
            exec: Decision::Na,
            flag: Some(true),
        };
        let json = serde_json::to_value(&cell).unwrap();
        assert_eq!(json["flag"], true);
    }
}
