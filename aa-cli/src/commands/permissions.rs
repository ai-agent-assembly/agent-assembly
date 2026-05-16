//! Shared client-side types and renderer for effective agent permissions
//! (AAASM-1049, F100).
//!
//! Consumed by both `aasm policy show <agent_id> --show-permissions` and
//! `aasm topology lineage <agent_id> --show-permissions`. The wire schema
//! matches `aa_api::routes::agents::EffectivePermissionsResponse`.

use std::collections::BTreeSet;

use comfy_table::{ContentArrangement, Table};
use serde::Deserialize;

use crate::client;
use crate::config::ResolvedContext;
use crate::error::CliError;
use crate::output::OutputFormat;

/// Per-scope contribution mirroring `aa_api::routes::agents::PermissionSourceResponse`.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionSource {
    pub scope: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Effective permissions for one agent (text/JSON renderable).
#[derive(Debug, Clone, Deserialize)]
pub struct EffectivePermissions {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub sources: Vec<PermissionSource>,
}

/// Fetch `/api/v1/agents/{id}/capabilities` for the given agent.
pub async fn fetch_effective_permissions(
    ctx: &ResolvedContext,
    agent_id: &str,
) -> Result<EffectivePermissions, CliError> {
    let path = format!("/api/v1/agents/{agent_id}/capabilities");
    client::get_json(ctx, &path).await
}

/// Render an `EffectivePermissions` payload to stdout in the requested format.
///
/// Text format (default): a `comfy-table` with one row per capability appearing
/// anywhere in the cascade. Columns are `Capability` / `Effective` (Allow /
/// Deny / —) / `Granted by` (scopes whose `allow` lists the capability) /
/// `Denied by` (scopes whose `deny` lists it). JSON and YAML formats serialise
/// the raw response payload.
pub fn render(perms: &EffectivePermissions, output: OutputFormat) {
    match output {
        OutputFormat::Json => render_json(perms),
        OutputFormat::Yaml => render_yaml(perms),
        OutputFormat::Table => render_text(perms),
    }
}

fn as_serde_value(perms: &EffectivePermissions) -> serde_json::Value {
    // Read-side types do not derive Serialize, so build the wire shape inline.
    serde_json::json!({
        "allow": perms.allow,
        "deny": perms.deny,
        "sources": perms.sources.iter().map(|s| {
            serde_json::json!({
                "scope": s.scope,
                "allow": s.allow,
                "deny": s.deny,
            })
        }).collect::<Vec<_>>(),
    })
}

fn render_json(perms: &EffectivePermissions) {
    let value = as_serde_value(perms);
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("serialize permissions")
    );
}

fn render_yaml(perms: &EffectivePermissions) {
    let value = as_serde_value(perms);
    print!(
        "{}",
        serde_yaml::to_string(&value).expect("serialize permissions to yaml")
    );
}

/// Effective verdict for a single capability after merging the cascade.
///
/// The merge contract is parent-deny-wins; capabilities can also be filtered
/// out of `merged.allow` when scopes intersect non-empty allow-lists. `Open`
/// is used when no `allow` list applies (i.e. `merged.allow.is_empty()` and
/// the capability is not explicitly denied): no restriction is in force.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Effective {
    Allow,
    Deny,
    /// Capability appears in some scope's allow but is filtered out by
    /// `most-restrictive-wins` intersection with another scope's allow.
    Filtered,
    /// No allow-list constrains this capability and no deny lists it.
    Open,
}

impl Effective {
    fn label(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
            Self::Filtered => "—",
            Self::Open => "(open)",
        }
    }
}

fn effective_for(cap: &str, perms: &EffectivePermissions) -> Effective {
    if perms.deny.iter().any(|c| c == cap) {
        Effective::Deny
    } else if perms.allow.iter().any(|c| c == cap) {
        Effective::Allow
    } else if perms.allow.is_empty() && perms.sources.iter().all(|s| s.allow.is_empty()) {
        // No source ever constrained the allow-list — every cap is open.
        Effective::Open
    } else {
        Effective::Filtered
    }
}

fn render_text(perms: &EffectivePermissions) {
    if perms.sources.is_empty() {
        println!("No policy in this agent's cascade declares a capabilities block.");
        println!("Effective: no allow-list restriction, no denies.");
        return;
    }

    // Union every capability mentioned anywhere in the cascade. BTreeSet keeps
    // output deterministic (lexicographic by capability identifier).
    let mut all_caps: BTreeSet<&str> = BTreeSet::new();
    for src in &perms.sources {
        for c in &src.allow {
            all_caps.insert(c.as_str());
        }
        for c in &src.deny {
            all_caps.insert(c.as_str());
        }
    }
    for c in &perms.allow {
        all_caps.insert(c.as_str());
    }
    for c in &perms.deny {
        all_caps.insert(c.as_str());
    }

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Capability", "Effective", "Granted by", "Denied by"]);

    for cap in &all_caps {
        let granted_by: Vec<&str> = perms
            .sources
            .iter()
            .filter(|s| s.allow.iter().any(|c| c == cap))
            .map(|s| s.scope.as_str())
            .collect();
        let denied_by: Vec<&str> = perms
            .sources
            .iter()
            .filter(|s| s.deny.iter().any(|c| c == cap))
            .map(|s| s.scope.as_str())
            .collect();
        let effective = effective_for(cap, perms);
        table.add_row(vec![
            cap.to_string(),
            effective.label().to_string(),
            granted_by.join(", "),
            denied_by.join(", "),
        ]);
    }

    println!("{table}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EffectivePermissions {
        EffectivePermissions {
            allow: vec!["file_read".to_string()],
            deny: vec!["network_outbound".to_string()],
            sources: vec![
                PermissionSource {
                    scope: "global".to_string(),
                    allow: vec!["file_read".to_string(), "file_write".to_string()],
                    deny: vec![],
                },
                PermissionSource {
                    scope: "team:platform".to_string(),
                    allow: vec!["file_read".to_string()],
                    deny: vec!["network_outbound".to_string()],
                },
            ],
        }
    }

    #[test]
    fn deserialize_response_shape() {
        let json = serde_json::json!({
            "allow": ["file_read"],
            "deny": [],
            "sources": [
                {"scope": "global", "allow": ["file_read"], "deny": []}
            ]
        });
        let parsed: EffectivePermissions = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.allow, vec!["file_read"]);
        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.sources[0].scope, "global");
    }

    #[test]
    fn empty_sources_renders_explicit_no_restriction_message() {
        let perms = EffectivePermissions {
            allow: vec![],
            deny: vec![],
            sources: vec![],
        };
        // Smoke: render_text should not panic on the no-policy edge case.
        render_text(&perms);
    }

    #[test]
    fn sample_renders_each_source_and_effective_section() {
        // Smoke: render every format without panic.
        render_text(&sample());
        render_json(&sample());
        render_yaml(&sample());
    }

    #[test]
    fn effective_for_classifies_each_case() {
        let perms = sample();
        // file_read is in merged.allow → Allow
        assert_eq!(effective_for("file_read", &perms), Effective::Allow);
        // network_outbound is in merged.deny → Deny
        assert_eq!(effective_for("network_outbound", &perms), Effective::Deny);
        // file_write appears in a source allow but was filtered out by the
        // most-restrictive intersection with team:platform's narrower allow.
        assert_eq!(effective_for("file_write", &perms), Effective::Filtered);
    }

    #[test]
    fn effective_for_returns_open_when_no_source_constrains_allow() {
        let perms = EffectivePermissions {
            allow: vec![],
            deny: vec![],
            sources: vec![PermissionSource {
                scope: "global".to_string(),
                allow: vec![],
                deny: vec![],
            }],
        };
        assert_eq!(effective_for("anything", &perms), Effective::Open);
    }
}
