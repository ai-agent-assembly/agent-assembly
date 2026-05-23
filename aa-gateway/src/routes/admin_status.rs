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

use std::sync::Arc;
use std::time::Instant;

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::storage::{HealthStatus, RowCounts, StorageBackend, StorageHealth};

/// Top-level wire body returned by `GET /api/v1/admin/status`.
///
/// Field names form a stable contract — the `aasm status` CLI parses this
/// shape, and the AAASM-1591 story description publishes it verbatim.
/// Do not rename without a coordinated client update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminStatusBody {
    /// Deployment mode label: `"local"` or `"remote"`.
    pub mode: String,
    /// Gateway crate version.
    pub version: String,
    /// Seconds elapsed since the gateway became ready to serve traffic.
    pub uptime_secs: u64,
    /// Storage health block (always present — `backend` discriminates
    /// between sqlite / postgres / memory).
    pub storage: StorageHealthBlock,
}

/// Axum `Extension` payload for the admin status handler.
///
/// Cloned on every request — keeping the storage handle behind an `Arc`
/// is the existing workspace convention (see [`crate::AppState`]).
#[derive(Clone)]
pub struct AdminStatusState {
    /// Deployment mode label propagated into [`AdminStatusBody::mode`].
    pub mode: &'static str,
    /// Gateway crate version propagated into [`AdminStatusBody::version`].
    pub version: &'static str,
    /// Instant the gateway became ready; drives `uptime_secs`.
    pub started_at: Instant,
    /// Local-mode SQLite file path, forwarded into the sqlite branch of
    /// [`StorageHealthBlock::from_health`].
    pub sqlite_path: Option<String>,
    /// PostgreSQL connection URL — passed unredacted; the handler
    /// redacts the password before serialising.
    pub database_url: Option<String>,
    /// Durable storage handle that backs the healthcheck probe.
    pub storage: Arc<dyn StorageBackend>,
}

impl AdminStatusState {
    /// Construct a state with `started_at = Instant::now()`. Used by
    /// the remote-mode and local-mode boot paths.
    pub fn new(
        mode: &'static str,
        storage: Arc<dyn StorageBackend>,
        sqlite_path: Option<String>,
        database_url: Option<String>,
    ) -> Self {
        Self {
            mode,
            version: env!("CARGO_PKG_VERSION"),
            started_at: Instant::now(),
            sqlite_path,
            database_url,
            storage,
        }
    }
}

/// `GET /api/v1/admin/status` — gateway admin status with storage health.
///
/// Always responds with HTTP `200 OK` so the `aasm status` CLI can parse
/// a structured body in both healthy and degraded cases. When the
/// backend probe fails (transport error, query failure), the storage
/// block carries `health = "unavailable"`, `latency_ms = 0`, and
/// zero-filled row counts; the CLI maps this to a non-zero exit code.
///
/// Returning a 5xx instead would force the CLI to distinguish transport
/// failures from logical health failures — splitting one signal into two
/// for no operator benefit.
pub async fn admin_status(Extension(state): Extension<AdminStatusState>) -> Json<AdminStatusBody> {
    let storage_block = match state.storage.healthcheck().await {
        Ok(health) => {
            StorageHealthBlock::from_health(&health, state.sqlite_path.as_deref(), state.database_url.as_deref())
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "storage healthcheck failed; reporting unavailable in admin status"
            );
            StorageHealthBlock::from_health(
                &StorageHealth {
                    status: HealthStatus::Unavailable,
                    // backend label is best-effort: prefer the type the
                    // operator configured (visible via sqlite_path /
                    // database_url) over the storage-trait label we
                    // could not retrieve.
                    backend: if state.sqlite_path.is_some() {
                        "sqlite"
                    } else if state.database_url.is_some() {
                        "postgres"
                    } else {
                        "unknown"
                    },
                    latency_ms: 0,
                    row_counts: RowCounts::default(),
                    timescale: None,
                },
                state.sqlite_path.as_deref(),
                state.database_url.as_deref(),
            )
        }
    };
    Json(AdminStatusBody {
        mode: state.mode.to_string(),
        version: state.version.to_string(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        storage: storage_block,
    })
}

/// Wire-contract storage health block returned under
/// `body.storage` in the admin status response.
///
/// Per-backend optional fields:
///
/// * `path` — populated on SQLite, omitted on PostgreSQL.
/// * `database_url` — populated on PostgreSQL (always already redacted by
///   [`redact_database_url`]), omitted on SQLite.
/// * `timescaledb` — populated only when the PostgreSQL backend is
///   connected to a cluster with the TimescaleDB extension installed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageHealthBlock {
    /// Static backend identifier — e.g. `"sqlite"`, `"postgres"`,
    /// `"memory"`.
    pub backend: String,
    /// Local-mode SQLite file path. Present only when `backend == "sqlite"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// PostgreSQL connection URL with the password segment replaced by
    /// `***`. Present only when `backend == "postgres"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_url: Option<String>,
    /// Coarse health label: `"ok"`, `"degraded"`, or `"unavailable"`.
    pub health: String,
    /// Latency of the healthcheck round-trip in milliseconds (time to
    /// execute the backend's `SELECT 1` equivalent).
    pub latency_ms: u32,
    /// Hot-tier row-count snapshot taken during the healthcheck.
    pub row_counts: RowCountsBlock,
    /// TimescaleDB rollup, present only when the extension is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timescaledb: Option<TimescaleDbBlock>,
}

impl StorageHealthBlock {
    /// Project a [`StorageHealth`] snapshot into the wire-contract shape.
    ///
    /// `sqlite_path` is propagated to the `path` field only when
    /// `health.backend == "sqlite"`; passing `Some(_)` for other backends
    /// is silently dropped, so callers can hand the same value in
    /// unconditionally.
    ///
    /// `database_url` is propagated to the `database_url` field only
    /// when `health.backend == "postgres"` and is redacted via
    /// [`redact_database_url`] before storage.
    pub fn from_health(health: &StorageHealth, sqlite_path: Option<&str>, database_url: Option<&str>) -> Self {
        let backend = health.backend.to_string();
        let path = (backend == "sqlite").then(|| sqlite_path.map(str::to_string)).flatten();
        let database_url = (backend == "postgres")
            .then(|| database_url.map(redact_database_url))
            .flatten();
        let timescaledb = health.timescale.as_ref().map(|stats| TimescaleDbBlock {
            enabled: true,
            total_chunks: stats.total_chunks,
            compressed_chunks: stats.compressed_chunks,
            compression_ratio: stats.compression_ratio_tenths as f32 / 10.0,
        });
        Self {
            backend,
            path,
            database_url,
            health: health_status_label(health.status).to_string(),
            latency_ms: health.latency_ms,
            row_counts: RowCountsBlock {
                audit_events_hot: health.row_counts.audit_events,
                agents: health.row_counts.agents,
                policy_versions: health.row_counts.policy_versions,
            },
            timescaledb,
        }
    }
}

/// Render the coarse [`HealthStatus`] as the lowercase string used in the
/// wire contract.
const fn health_status_label(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Ok => "ok",
        HealthStatus::Degraded => "degraded",
        HealthStatus::Unavailable => "unavailable",
    }
}

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
    use crate::storage::{HealthStatus, RowCounts, StorageHealth, TimescaleStats};

    fn sample_health(backend: &'static str, timescale: Option<TimescaleStats>) -> StorageHealth {
        StorageHealth {
            status: HealthStatus::Ok,
            backend,
            latency_ms: 3,
            row_counts: RowCounts {
                audit_events: 47,
                agents: 2,
                policy_versions: 1,
            },
            timescale,
        }
    }

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

    #[test]
    fn from_health_propagates_sqlite_path_and_drops_database_url() {
        let block = StorageHealthBlock::from_health(
            &sample_health("sqlite", None),
            Some("~/.aasm/local.db"),
            // Caller may pass database_url unconditionally; sqlite path drops it.
            Some("postgresql://u:p@h/db"),
        );
        assert_eq!(block.backend, "sqlite");
        assert_eq!(block.path.as_deref(), Some("~/.aasm/local.db"));
        assert!(block.database_url.is_none(), "database_url must be omitted on sqlite");
        assert!(block.timescaledb.is_none(), "no TimescaleStats → no timescaledb block");
        assert_eq!(block.health, "ok");
        assert_eq!(block.latency_ms, 3);
        assert_eq!(block.row_counts.audit_events_hot, 47);
    }

    #[test]
    fn from_health_redacts_postgres_database_url_and_drops_sqlite_path() {
        let block = StorageHealthBlock::from_health(
            &sample_health("postgres", None),
            // Caller passes sqlite path unconditionally; postgres branch drops it.
            Some("~/.aasm/local.db"),
            Some("postgresql://aasm:secret@db.internal:5432/aasm"),
        );
        assert_eq!(block.backend, "postgres");
        assert!(block.path.is_none(), "path must be omitted on postgres");
        assert_eq!(
            block.database_url.as_deref(),
            Some("postgresql://aasm:***@db.internal:5432/aasm")
        );
    }

    #[test]
    fn from_health_populates_timescaledb_block_when_stats_present() {
        let stats = TimescaleStats {
            total_chunks: 12,
            compressed_chunks: 8,
            // 114 tenths → 11.4× ratio.
            compression_ratio_tenths: 114,
            oldest_chunk_age_days: 45,
        };
        let block = StorageHealthBlock::from_health(
            &sample_health("postgres", Some(stats)),
            None,
            Some("postgresql://aasm:secret@db.internal:5432/aasm"),
        );
        let ts = block.timescaledb.expect("TimescaleStats → Some(TimescaleDbBlock)");
        assert!(ts.enabled);
        assert_eq!(ts.total_chunks, 12);
        assert_eq!(ts.compressed_chunks, 8);
        assert!((ts.compression_ratio - 11.4).abs() < 0.05);
    }

    #[test]
    fn storage_block_omits_optional_fields_when_none() {
        let block = StorageHealthBlock::from_health(&sample_health("sqlite", None), None, None);
        let json = serde_json::to_value(&block).expect("serialise");
        assert!(json.get("path").is_none(), "path None must be skipped");
        assert!(json.get("database_url").is_none(), "database_url None must be skipped");
        assert!(json.get("timescaledb").is_none(), "timescaledb None must be skipped");
    }

    #[test]
    fn from_health_renders_unavailable_status_label() {
        let mut health = sample_health("postgres", None);
        health.status = HealthStatus::Unavailable;
        let block = StorageHealthBlock::from_health(&health, None, Some("postgresql://u:p@h/db"));
        assert_eq!(block.health, "unavailable");
    }

    /// Bootstrap a real SQLite-backed StorageBackend pointed at a
    /// per-test tempdir. Returns the handle + the path string for
    /// assertions; the tempdir lives for the test's lifetime via the
    /// stored `TempDir`.
    async fn sqlite_state() -> (tempfile::TempDir, AdminStatusState) {
        use crate::storage::{SqliteBackend, SqliteConfig};

        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("local.db");
        let backend = SqliteBackend::open(&SqliteConfig { path: path.clone() })
            .await
            .expect("open sqlite backend");
        backend.migrate().await.expect("migrate");
        let state = AdminStatusState::new(
            "local",
            Arc::new(backend),
            Some(path.to_string_lossy().into_owned()),
            None,
        );
        (tmp, state)
    }

    #[tokio::test]
    async fn handler_returns_documented_body_against_sqlite_backend() {
        let (_tmp, state) = sqlite_state().await;
        let Json(body) = admin_status(Extension(state.clone())).await;
        assert_eq!(body.mode, "local");
        assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(body.storage.backend, "sqlite");
        assert_eq!(body.storage.health, "ok");
        assert!(body.storage.path.is_some(), "sqlite path must be reported");
        assert!(body.storage.database_url.is_none(), "no postgres URL on sqlite");
        assert!(body.storage.timescaledb.is_none(), "no timescaledb on sqlite");
    }

    #[tokio::test]
    async fn handler_uptime_reflects_started_at() {
        let (_tmp, mut state) = sqlite_state().await;
        // Back-date started_at so uptime_secs is non-zero without sleeping.
        state.started_at = Instant::now() - std::time::Duration::from_secs(5);
        let Json(body) = admin_status(Extension(state)).await;
        assert!(body.uptime_secs >= 5, "expected uptime ≥ 5s, got {}", body.uptime_secs);
    }

    #[test]
    fn admin_status_body_serialises_with_documented_top_level_keys() {
        let body = AdminStatusBody {
            mode: "remote".into(),
            version: "0.0.1".into(),
            uptime_secs: 86_400,
            storage: StorageHealthBlock::from_health(
                &sample_health("postgres", None),
                None,
                Some("postgresql://aasm:secret@db.internal:5432/aasm"),
            ),
        };
        let json = serde_json::to_value(&body).expect("AdminStatusBody must serialise");
        for key in ["mode", "version", "uptime_secs", "storage"] {
            assert!(json.get(key).is_some(), "missing top-level key {key:?}");
        }
        assert_eq!(json["mode"], "remote");
        assert_eq!(json["uptime_secs"], 86_400);
        assert_eq!(json["storage"]["backend"], "postgres");
        assert_eq!(
            json["storage"]["database_url"],
            "postgresql://aasm:***@db.internal:5432/aasm"
        );
    }
}
