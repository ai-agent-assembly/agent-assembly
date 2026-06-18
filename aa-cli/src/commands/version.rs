//! `aasm version` — display CLI and runtime version information.

use std::process::ExitCode;

use comfy_table::Table;
use serde::{Deserialize, Serialize};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Subset of the configured REST API `/api/v1/health` response used for
/// version extraction.
///
/// The REST API health endpoint reports both `version` and `api_version`.
/// `api_version` stays optional so the same struct also parses a gateway
/// `/healthz` body (which omits it), falling back to the served REST API
/// major version.
#[derive(Debug, Deserialize)]
struct HealthInfo {
    version: String,
    #[serde(default)]
    api_version: Option<String>,
}

/// A single row in the version output.
#[derive(Debug, Serialize)]
struct VersionRow {
    component: String,
    version: String,
    status: String,
}

/// Build version rows by probing the gateway health endpoint.
fn build_rows(ctx: &ResolvedContext) -> Vec<VersionRow> {
    let cli_row = VersionRow {
        component: "cli".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "-".to_string(),
    };

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let (gateway_row, api_row) = rt.block_on(async {
        let client = reqwest::Client::new();
        // Probe the configured `--api-url`'s own health endpoint. The REST
        // API serves `GET /api/v1/health` (carrying `version`/`api_version`);
        // the gateway-daemon-only `/healthz` is NOT mounted by the REST API,
        // so probing it reported a reachable api-url as "unreachable".
        let url = format!("{}/api/v1/health", ctx.api_url);

        let mut req = client.get(&url);
        if let Some(ref key) = ctx.api_key {
            req = req.bearer_auth(key);
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<HealthInfo>().await {
                Ok(info) => (
                    VersionRow {
                        component: "gateway".to_string(),
                        version: info.version,
                        status: "reachable".to_string(),
                    },
                    VersionRow {
                        component: "api".to_string(),
                        version: info.api_version.unwrap_or_else(|| "v1".to_string()),
                        status: "reachable".to_string(),
                    },
                ),
                Err(_) => unreachable_rows(),
            },
            _ => unreachable_rows(),
        }
    });

    vec![cli_row, gateway_row, api_row]
}

/// Produce gateway and api rows for the unreachable case.
fn unreachable_rows() -> (VersionRow, VersionRow) {
    (
        VersionRow {
            component: "gateway".to_string(),
            version: "-".to_string(),
            status: "unreachable".to_string(),
        },
        VersionRow {
            component: "api".to_string(),
            version: "-".to_string(),
            status: "unreachable".to_string(),
        },
    )
}

/// Render version rows as a comfy-table.
fn render_table(rows: &[VersionRow]) {
    let mut table = Table::new();
    table.set_header(vec!["COMPONENT", "VERSION", "STATUS"]);
    for r in rows {
        table.add_row(vec![&r.component, &r.version, &r.status]);
    }
    println!("{table}");
}

/// Run the `aasm version` command.
pub fn run(ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rows = build_rows(ctx);

    match output {
        OutputFormat::Table => render_table(&rows),
        OutputFormat::Json => match serde_json::to_string_pretty(&rows) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("error serializing JSON: {e}"),
        },
        OutputFormat::Yaml => match serde_yaml::to_string(&rows) {
            Ok(yaml) => print!("{yaml}"),
            Err(e) => eprintln!("error serializing YAML: {e}"),
        },
    }

    // `version` degrades gracefully: an unreachable gateway/api is reported as
    // "unreachable" rows but still exits 0, per the documented contract.
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reachable_rows() -> Vec<VersionRow> {
        vec![
            VersionRow {
                component: "cli".to_string(),
                version: "0.0.1".to_string(),
                status: "-".to_string(),
            },
            VersionRow {
                component: "gateway".to_string(),
                version: "0.3.2".to_string(),
                status: "reachable".to_string(),
            },
            VersionRow {
                component: "api".to_string(),
                version: "v1".to_string(),
                status: "reachable".to_string(),
            },
        ]
    }

    fn unreachable_version_rows() -> Vec<VersionRow> {
        let (gw, api) = unreachable_rows();
        vec![
            VersionRow {
                component: "cli".to_string(),
                version: "0.0.1".to_string(),
                status: "-".to_string(),
            },
            gw,
            api,
        ]
    }

    #[test]
    fn render_table_reachable_does_not_panic() {
        render_table(&reachable_rows());
    }

    #[test]
    fn render_table_unreachable_does_not_panic() {
        render_table(&unreachable_version_rows());
    }

    #[test]
    fn unreachable_rows_have_dash_versions() {
        let (gw, api) = unreachable_rows();
        assert_eq!(gw.version, "-");
        assert_eq!(gw.status, "unreachable");
        assert_eq!(api.version, "-");
        assert_eq!(api.status, "unreachable");
    }

    #[test]
    fn json_output_has_three_entries() {
        let rows = reachable_rows();
        let json = serde_json::to_string_pretty(&rows).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["component"], "cli");
        assert_eq!(arr[1]["component"], "gateway");
        assert_eq!(arr[1]["version"], "0.3.2");
        assert_eq!(arr[2]["component"], "api");
        assert_eq!(arr[2]["version"], "v1");
    }

    #[test]
    fn health_info_parses_api_health_body_with_api_version() {
        // The configured REST API `/api/v1/health` body carries both
        // `version` and `api_version`; deserialization must capture both.
        let body = r#"{"status":"ok","version":"0.0.1","api_version":"v1","uptime_secs":3,"active_connections":0,"pipeline_lag_ms":0,"checks":{}}"#;
        let info: HealthInfo = serde_json::from_str(body).expect("api health body must parse");
        assert_eq!(info.version, "0.0.1");
        assert_eq!(info.api_version.as_deref(), Some("v1"));
    }

    #[test]
    fn health_info_parses_healthz_body_without_api_version() {
        // A gateway `/healthz` body still parses (api_version absent) so a
        // gateway-targeted `--api-url` continues to work via fallback.
        let body = r#"{"mode":"local","version":"0.0.1","storage":"memory","uptime_secs":3}"#;
        let info: HealthInfo = serde_json::from_str(body).expect("healthz body must parse");
        assert_eq!(info.version, "0.0.1");
        assert_eq!(info.api_version, None);
    }

    #[test]
    fn json_output_unreachable_shows_dash() {
        let rows = unreachable_version_rows();
        let json = serde_json::to_string_pretty(&rows).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr[1]["version"], "-");
        assert_eq!(arr[1]["status"], "unreachable");
        assert_eq!(arr[2]["version"], "-");
        assert_eq!(arr[2]["status"], "unreachable");
    }
}
