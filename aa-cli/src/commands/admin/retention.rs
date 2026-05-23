//! `aasm admin run-retention` — manually trigger one retention pass
//! against the running gateway.
//!
//! Posts to `POST /api/v1/admin/retention-policy/run` and prints the
//! returned `RetentionRunStatsDto` to stdout. The transport landed in
//! Epic 18 Story S-I.5 (AAASM-1872) — the matching aa-api handler,
//! OpenAPI registration, and dashboard codegen were already in place
//! from sibling stories AAASM-1850 / AAASM-1856 / AAASM-1861.

use std::process::ExitCode;

use clap::Args;
use serde::{Deserialize, Serialize};

use crate::client::post_json;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Arguments for `aasm admin run-retention`.
#[derive(Debug, Args)]
pub struct RunRetentionArgs {
    /// Run in dry-run mode — log what would be retained/dropped without
    /// taking any action.
    #[arg(long)]
    pub dry_run: bool,
}

/// Request body sent to `POST /api/v1/admin/retention-policy/run`.
///
/// Mirrors `aa_api::models::retention::RunRetentionRequest`. Kept local
/// to aa-cli so the CLI does not depend on the aa-api crate, matching
/// the convention used elsewhere (e.g. `budget.rs`, `permissions.rs`).
#[derive(Debug, Serialize)]
struct RunRetentionRequest {
    dry_run: bool,
}

/// Response body returned by `POST /api/v1/admin/retention-policy/run`.
///
/// Mirrors `aa_api::models::retention::RetentionRunStatsDto`.
#[derive(Debug, Deserialize, Serialize)]
struct RetentionRunStatsDto {
    ran_at: String,
    hot_rows: u64,
    compressed_rows: u64,
    archived_rows: u64,
    dropped_rows: u64,
    freed_bytes: u64,
    dry_run: bool,
}

const ENDPOINT: &str = "/api/v1/admin/retention-policy/run";

/// Dispatch `aasm admin run-retention [--dry-run]`.
///
/// Honours `OutputFormat::Yaml` if selected; defaults to pretty JSON.
/// Exits with `ExitCode::SUCCESS` on a successful pass, or
/// `ExitCode::FAILURE` when the gateway is unreachable or returns a
/// non-2xx status — the reqwest / HTTP error chain is printed to
/// stderr so an operator running `aasm admin run-retention` can see
/// exactly why the call failed.
pub fn dispatch(args: RunRetentionArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let req = RunRetentionRequest { dry_run: args.dry_run };
    let stats: RetentionRunStatsDto = match rt.block_on(post_json(ctx, ENDPOINT, &req)) {
        Ok(stats) => stats,
        Err(err) => {
            eprintln!("aasm admin run-retention: {err}");
            return ExitCode::FAILURE;
        }
    };
    let rendered = match output {
        OutputFormat::Yaml => serde_yaml::to_string(&stats).expect("serialize stats as YAML"),
        // Table format on a single-record response is the same as JSON
        // pretty-print for now; the dashboard renders the same shape.
        OutputFormat::Table | OutputFormat::Json => {
            serde_json::to_string_pretty(&stats).expect("serialize stats as JSON")
        }
    };
    println!("{rendered}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the wire shape sent to `POST /api/v1/admin/retention-policy/run`.
    /// The OpenAPI spec + the aa-api `RunRetentionRequest` deserializer
    /// both expect a single field named exactly `dry_run`.
    #[test]
    fn request_serializes_dry_run_true() {
        let body = serde_json::to_value(RunRetentionRequest { dry_run: true }).expect("serialize");
        assert_eq!(body, serde_json::json!({"dry_run": true}));
    }

    /// Default flag → `dry_run: false` on the wire.
    #[test]
    fn request_serializes_dry_run_false() {
        let body = serde_json::to_value(RunRetentionRequest { dry_run: false }).expect("serialize");
        assert_eq!(body, serde_json::json!({"dry_run": false}));
    }

    /// Pins the response shape we deserialize from the gateway.
    /// Mirrors the aa-api `RetentionRunStatsDto` exactly so a future
    /// rename / field addition surfaces here.
    #[test]
    fn response_deserializes_full_stats() {
        let payload = serde_json::json!({
            "ran_at": "2026-05-23T12:34:56Z",
            "hot_rows": 100,
            "compressed_rows": 20,
            "archived_rows": 5,
            "dropped_rows": 3,
            "freed_bytes": 4096,
            "dry_run": false
        });
        let stats: RetentionRunStatsDto = serde_json::from_value(payload).expect("deserialize");
        assert_eq!(stats.ran_at, "2026-05-23T12:34:56Z");
        assert_eq!(stats.hot_rows, 100);
        assert_eq!(stats.compressed_rows, 20);
        assert_eq!(stats.archived_rows, 5);
        assert_eq!(stats.dropped_rows, 3);
        assert_eq!(stats.freed_bytes, 4096);
        assert!(!stats.dry_run);
    }

    /// The endpoint path the CLI POSTs to must match what the aa-api
    /// router mounts (`aa-api/src/routes/mod.rs`) and what
    /// `openapi/v1.yaml` advertises.
    #[test]
    fn endpoint_matches_openapi_path() {
        assert_eq!(ENDPOINT, "/api/v1/admin/retention-policy/run");
    }
}
