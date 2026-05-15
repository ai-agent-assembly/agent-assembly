//! Shared client-side types and renderer for effective agent permissions
//! (AAASM-1049, F100).
//!
//! Consumed by both `aasm policy show <agent_id> --show-permissions` and
//! `aasm topology lineage <agent_id> --show-permissions`. The wire schema
//! matches `aa_api::routes::agents::EffectivePermissionsResponse`.

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
/// Text format: per-scope sections (broadest → narrowest) followed by an
/// `Effective` summary. Capabilities are bullet-listed under `Allow:` /
/// `Deny:` headers and sorted lexicographically by the API. JSON format
/// pretty-prints the payload as-is.
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

fn render_text(perms: &EffectivePermissions) {
    if perms.sources.is_empty() {
        println!("No policy in this agent's cascade declares a capabilities block.");
        println!("Effective: (no allow-list restriction, no denies)");
        return;
    }

    for src in &perms.sources {
        println!("Source: {}", src.scope);
        print_list("  Allow", &src.allow);
        print_list("  Deny", &src.deny);
        println!();
    }

    println!("Effective (most-restrictive-wins merge):");
    print_list("  Allow", &perms.allow);
    print_list("  Deny", &perms.deny);
}

fn print_list(label: &str, items: &[String]) {
    if items.is_empty() {
        println!("{label}: (none)");
    } else {
        println!("{label}:");
        for item in items {
            println!("    - {item}");
        }
    }
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
        // Smoke: render_text should not panic. Captured-stdout coverage is
        // exercised by integration tests under tests/.
        render_text(&perms);
    }

    #[test]
    fn sample_renders_each_source_and_effective_section() {
        // Smoke: render both formats without panic.
        render_text(&sample());
        render_json(&sample());
    }
}
