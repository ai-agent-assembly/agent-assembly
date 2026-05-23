//! `GET /api/v1/admin/status` — gateway admin status with storage health.
//!
//! Sibling of [`super::healthz`] that returns the deeper readiness signal:
//! backend type, database connection health and latency, hot-tier row
//! counts, and an optional TimescaleDB chunk + compression rollup. The
//! `aasm status` CLI consumes this endpoint to render the operator-facing
//! storage section delivered by AAASM-1591 / Epic 18 S-J.
//!
//! Unlike `/healthz`, this handler performs a backend round-trip per call
//! and is **not** intended for high-frequency load-balancer probes; mount
//! it behind admin-only access (Epic 17 S-G IAM gating, to land).

use serde::{Deserialize, Serialize};

/// Hot-tier row-count snapshot returned inside the storage health block.
///
/// Field names are stable wire contract — the `aasm status` CLI and the
/// dashboard's storage panel both parse this shape. Warm and cold tiers
/// are omitted from v1; the retention engine surfaces them in a follow-up
/// once the compressed-row count is cheap to compute on both backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowCountsBlock {
    /// Audit events in the hot tier (uncompressed, queryable).
    pub audit_events_hot: u64,
    /// Registered agents.
    pub agents: u64,
    /// Total policy versions across all policy names.
    pub policy_versions: u64,
}

/// TimescaleDB hypertable + compression rollup, populated only when the
/// PostgreSQL backend is connected to a cluster with the `timescaledb`
/// extension installed.
///
/// `enabled` is always `true` in the response — the field exists so a
/// future "extension installed but disabled" state can be distinguished
/// from "extension absent" (which is conveyed by omitting the whole
/// block via `Option`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimescaleDbBlock {
    /// `true` when the extension is active on the backing cluster.
    pub enabled: bool,
    /// Total number of chunks across the gateway's hypertables.
    pub total_chunks: u32,
    /// Subset of `total_chunks` already compressed by the auto-policy.
    pub compressed_chunks: u32,
    /// Aggregate `uncompressed_bytes / compressed_bytes` ratio as a
    /// human-friendly float (e.g. `11.4` = 11.4× size reduction). Sourced
    /// from `TimescaleStats.compression_ratio_tenths` divided by 10.
    pub compression_ratio: f32,
}

/// Replace the password segment of a database connection URL with `***`.
///
/// The server-side counterpart to the `aa-cli` deployment-overview
/// redactor. Per the AAASM-1591 acceptance criterion "Password in
/// database URL redacted in all output (API response, CLI output, logs)",
/// the gateway must never let a raw password leave the process — neither
/// in the API response body nor in any `tracing::*` macro that captures
/// the connection URL.
///
/// Behaviour mirrors the CLI helper at
/// `aa-cli::commands::status::models::redact_database_url`:
///
/// * `postgresql://user:secret@host:5432/db` → `postgresql://user:***@host:5432/db`
/// * `postgresql://user@host/db` (no password) → unchanged.
/// * `sqlite:///home/dev/.aasm/local.db` (no userinfo) → unchanged.
/// * `~/.aasm/local.db`, `not-a-url`, `""` → unchanged.
///
/// The split point between userinfo and host is the rightmost `@` inside
/// the authority — well-formed URLs percent-encode any `@` inside the
/// password, so this is safe.
pub fn redact_database_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map(|i| authority_start + i)
        .unwrap_or(url.len());
    let authority = &url[authority_start..authority_end];

    let Some(at_idx) = authority.rfind('@') else {
        return url.to_string();
    };
    let userinfo = &authority[..at_idx];
    let Some(colon_idx) = userinfo.find(':') else {
        return url.to_string();
    };

    let user = &userinfo[..colon_idx];
    let host_and_rest = &url[authority_start + at_idx..];
    format!("{}://{}:***{}", &url[..scheme_end], user, host_and_rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_replaces_postgres_password_with_stars() {
        let redacted = redact_database_url("postgresql://aasm:secret@db.internal:5432/aasm");
        assert_eq!(redacted, "postgresql://aasm:***@db.internal:5432/aasm");
    }

    #[test]
    fn redact_leaves_url_without_userinfo_unchanged() {
        let input = "postgresql://db.internal:5432/aasm";
        assert_eq!(redact_database_url(input), input);
    }

    #[test]
    fn redact_leaves_user_only_userinfo_unchanged() {
        let input = "postgresql://aasm@db.internal:5432/aasm";
        assert_eq!(redact_database_url(input), input);
    }

    #[test]
    fn redact_leaves_sqlite_url_unchanged() {
        let input = "sqlite:///home/dev/.aasm/local.db";
        assert_eq!(redact_database_url(input), input);
    }

    #[test]
    fn redact_leaves_non_url_inputs_unchanged() {
        for input in ["~/.aasm/local.db", "not-a-url", "://no-scheme", ""] {
            assert_eq!(redact_database_url(input), input, "input: {input:?}");
        }
    }

    #[test]
    fn redact_handles_at_inside_password_via_rightmost_at_split() {
        // Well-formed URLs percent-encode `@` inside the password as `%40`,
        // but if a misconfigured operator sneaks a literal `@` past the
        // parser the rightmost-@ rule must still leave a valid host.
        let redacted = redact_database_url("postgresql://aasm:p@ss@db.internal:5432/aasm");
        assert_eq!(redacted, "postgresql://aasm:***@db.internal:5432/aasm");
    }

    #[test]
    fn row_counts_block_serialises_with_documented_keys() {
        let counts = RowCountsBlock {
            audit_events_hot: 14_293,
            agents: 8,
            policy_versions: 3,
        };
        let json = serde_json::to_value(&counts).expect("RowCountsBlock must serialise");
        assert_eq!(json["audit_events_hot"], 14_293);
        assert_eq!(json["agents"], 8);
        assert_eq!(json["policy_versions"], 3);
    }

    #[test]
    fn timescaledb_block_serialises_with_documented_keys() {
        let block = TimescaleDbBlock {
            enabled: true,
            total_chunks: 12,
            compressed_chunks: 8,
            compression_ratio: 11.4,
        };
        let json = serde_json::to_value(&block).expect("TimescaleDbBlock must serialise");
        assert_eq!(json["enabled"], true);
        assert_eq!(json["total_chunks"], 12);
        assert_eq!(json["compressed_chunks"], 8);
        // serde_json represents f32 as the closest f64; assert via approx.
        let ratio = json["compression_ratio"].as_f64().expect("compression_ratio is number");
        assert!((ratio - 11.4).abs() < 0.05, "ratio drift > 0.05: got {ratio}");
    }
}
