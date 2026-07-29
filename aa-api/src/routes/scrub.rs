//! DLP / secret-scrub read endpoints (AAASM-5174).
//!
//! Exposes the real credential-scanner surface over HTTP so the dashboard
//! Scrub page can stop rendering static fixtures:
//!
//! * `GET /api/v1/scrub/patterns` — the **effective pattern catalogue**: the
//!   built-in [`CredentialKind`] detectors (their canonical kind label,
//!   `[REDACTED:<kind>]` replacement, coarse category, and fixed severity).
//! * `GET /api/v1/scrub/pattern-counts` — **per-pattern-kind hit counts** over a
//!   window, aggregated from the persisted `secret_detected` alerts (each
//!   carries the detected `CredentialKind` string). Bounded like the other
//!   aggregations.
//! * `GET /api/v1/scrub/posture` — a **leak-posture figure** over the window, or
//!   an explicit `computed: false` when a clean figure is not derivable rather
//!   than a fabricated one.
//!
//! Truthfulness (AAASM-5174, label `truthfulness-backend-gap`): every value
//! here is derived from real gateway state. Nothing is invented — where a value
//! is not computable it is surfaced as explicitly absent, never as a synthetic
//! posture or count.
//!
//! The catalogue is a static, non-tenant-specific surface (the detector set is
//! the same for every caller) and needs only the read scope enforced by the
//! `require_authentication` gate. The count/posture aggregations additionally
//! confine the underlying alerts to the caller's tenant, mirroring
//! [`crate::routes::alerts::list_alerts`] and [`crate::routes::analytics`].

use std::collections::BTreeMap;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_security::CredentialKind;

use crate::alerts::{AlertCategory, StoredAlert};
use crate::auth::scope::{RequireRead, Scope};
use crate::auth::AuthenticatedCaller;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

/// Query parameters for the windowed scrub aggregations
/// (`/scrub/pattern-counts`, `/scrub/posture`).
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ScrubWindowParams {
    /// Time range preset (`24h`, `7d`, `30d`, `90d`) or custom
    /// `YYYY-MM-DD..YYYY-MM-DD`. Defaults to `7d`. Matches the analytics
    /// routes' range grammar.
    pub range: Option<String>,
}

// ---------------------------------------------------------------------------
// Response types — catalogue
// ---------------------------------------------------------------------------

/// One entry in the effective pattern catalogue.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScrubPattern {
    /// Canonical detector kind label, e.g. `"AwsAccessKey"`. Stable identifier
    /// and the value that appears in the `[REDACTED:<kind>]` replacement.
    pub kind: String,
    /// The exact replacement string this detector emits when it redacts a
    /// match, e.g. `"[REDACTED:AwsAccessKey]"`.
    pub redaction_label: String,
    /// Coarse detector family: `api_key` | `cloud_credential` | `auth_token` |
    /// `database_url` | `private_key` | `pii` | `generic`.
    pub category: String,
    /// Fixed leak severity: `critical` | `high` | `medium` | `low`.
    pub severity: String,
    /// Whether this is a built-in detector (always `true` here — custom
    /// policy-defined patterns are not yet exposed through this endpoint; see
    /// the AAASM-5174 follow-up notes).
    pub builtin: bool,
}

/// Response for `GET /api/v1/scrub/patterns`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScrubCatalogueResponse {
    /// Every built-in detector, in the scanner's stable declaration order.
    pub patterns: Vec<ScrubPattern>,
    /// Total number of built-in detectors (equals `patterns.len()`).
    pub total: usize,
}

// ---------------------------------------------------------------------------
// Response types — per-pattern counts
// ---------------------------------------------------------------------------

/// A per-kind hit count within the queried window.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PatternCount {
    /// Detected credential kind, e.g. `"AwsAccessKey"`. This is the
    /// `detected_pattern_type` recorded on each `secret_detected` alert.
    pub kind: String,
    /// Number of `secret_detected` alerts of this kind in the window.
    pub hits: u64,
}

/// Response for `GET /api/v1/scrub/pattern-counts`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PatternCountsResponse {
    /// Per-kind counts, ordered by kind. Only kinds that fired at least once in
    /// the window appear (an idle window yields an empty list — no fabricated
    /// activity).
    pub counts: Vec<PatternCount>,
    /// Total `secret_detected` alerts counted across all kinds in the window.
    pub total_hits: u64,
    /// Length of the aggregation window in seconds.
    pub window_seconds: u64,
}

// ---------------------------------------------------------------------------
// Response types — posture
// ---------------------------------------------------------------------------

/// Response for `GET /api/v1/scrub/posture`.
///
/// The v1 leak-posture figure is the count of distinct outbound payloads that
/// the gateway's credential scanner **caught and redacted** in the window —
/// i.e. the number of `secret_detected` alerts. This is a real, defensible
/// "leaks intercepted" figure derived entirely from persisted alerts.
///
/// A *leak-rate* (leaks caught ÷ payloads scanned) is deliberately **not**
/// reported: the alert store persists only the detections, not the denominator
/// of total payloads scanned, so a rate could not be computed without inventing
/// the denominator. When that denominator is unavailable the rate fields are
/// surfaced as explicitly absent (`leak_rate: null`, `rate_computed: false`)
/// rather than fabricated.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PostureResponse {
    /// Number of outbound payloads that were caught and redacted in the window
    /// (count of `secret_detected` alerts). Always a real figure.
    pub leaks_intercepted: u64,
    /// Number of distinct credential kinds observed leaking in the window.
    pub distinct_kinds: u64,
    /// Fraction of scanned payloads that contained a leak, or `null` when it is
    /// not computable from the available state (see the type doc). Never
    /// fabricated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leak_rate: Option<f64>,
    /// Whether [`leak_rate`](Self::leak_rate) was computable. `false` today
    /// because the total-payloads-scanned denominator is not persisted.
    pub rate_computed: bool,
    /// Length of the posture window in seconds.
    pub window_seconds: u64,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Resolve a dashboard range filter to a window length in seconds.
///
/// Accepts the presets `24h` / `7d` / `30d` / `90d` and custom
/// `YYYY-MM-DD..YYYY-MM-DD` ranges (inclusive of both endpoints), matching the
/// analytics routes' grammar. Any unrecognised or absent value falls back to
/// the `7d` default.
fn window_secs_from_range(range: Option<&str>) -> u64 {
    const DAY: u64 = 86_400;
    match range {
        Some("24h") => DAY,
        Some("7d") => 7 * DAY,
        Some("30d") => 30 * DAY,
        Some("90d") => 90 * DAY,
        Some(custom) if custom.contains("..") => parse_custom_range(custom).unwrap_or(7 * DAY),
        _ => 7 * DAY,
    }
}

/// Parse a `YYYY-MM-DD..YYYY-MM-DD` custom range into an inclusive window in
/// seconds. Returns `None` for malformed input or an inverted range.
fn parse_custom_range(s: &str) -> Option<u64> {
    let (start, end) = s.split_once("..")?;
    let start = chrono::NaiveDate::parse_from_str(start.trim(), "%Y-%m-%d").ok()?;
    let end = chrono::NaiveDate::parse_from_str(end.trim(), "%Y-%m-%d").ok()?;
    let days = (end - start).num_days();
    if days < 0 {
        return None;
    }
    Some((days as u64 + 1) * 86_400)
}

/// Upper bound on the number of alerts a single scrub aggregation pulls from the
/// store, mirroring [`crate::routes::analytics`]'s bounded-read policy
/// (AAASM-4145). The in-memory store is a capacity-bounded ring buffer, but
/// this fixed ceiling keeps a single request's work bounded regardless of the
/// backing store's size.
const MAX_SCRUB_ALERTS: usize = 100_000;

/// Fetch the tenant-visible `secret_detected` alerts whose timestamp falls
/// inside the window `[now - window, now]`.
///
/// Tenant confinement mirrors [`crate::routes::alerts::list_alerts`]: an admin
/// sees every team's alerts; a team-scoped caller sees only its own team;
/// untagged alerts are admin-only; a caller with neither admin nor a team scope
/// sees nothing.
fn windowed_secret_alerts(caller: &AuthenticatedCaller, state: &AppState, window_secs: u64) -> Vec<StoredAlert> {
    let is_admin = caller.scopes.contains(&Scope::Admin);
    let (all, _total) = state.alert_store.list(MAX_SCRUB_ALERTS, 0);

    let now = chrono::Utc::now();
    let since = now - chrono::Duration::seconds(window_secs as i64);

    all.into_iter()
        .filter(|a| matches!(a.category, AlertCategory::SecretDetected))
        .filter(|a| match a.team_id.as_deref() {
            Some(team) => caller.can_access_team(team),
            None => is_admin,
        })
        .filter(|a| within_window(&a.timestamp, since, now))
        .collect()
}

/// Whether an ISO-8601 alert timestamp falls in the inclusive window
/// `[since, now]`. A timestamp that fails to parse is treated as out of window
/// (excluded) rather than silently counted.
fn within_window(ts: &str, since: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> bool {
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(t) => {
            let t = t.with_timezone(&chrono::Utc);
            t >= since && t <= now
        }
        Err(_) => false,
    }
}

/// Tally secret alerts by their `detected_pattern_type`, dropping any without a
/// kind. The single grouping both `get_pattern_counts` and its test rely on, so
/// the count semantics are defined in exactly one place.
fn tally_by_kind(alerts: &[StoredAlert]) -> BTreeMap<String, u64> {
    let mut by_kind: BTreeMap<String, u64> = BTreeMap::new();
    for a in alerts {
        if let Some(kind) = a.detected_pattern_type.as_deref() {
            *by_kind.entry(kind.to_string()).or_insert(0) += 1;
        }
    }
    by_kind
}

/// The number of distinct pattern kinds present across the alerts — the
/// `distinct_kinds` posture figure, defined once for handler and test.
fn distinct_kinds(alerts: &[StoredAlert]) -> u64 {
    alerts
        .iter()
        .filter_map(|a| a.detected_pattern_type.as_deref())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u64
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/scrub/patterns` — the effective built-in pattern catalogue.
///
/// Returns every built-in [`CredentialKind`] detector with its canonical kind
/// label, `[REDACTED:<kind>]` replacement string, coarse category, and fixed
/// severity. This is the real detector set the gateway scanner enforces — the
/// dashboard Scrub page can render it directly instead of the static fixtures
/// it used before AAASM-5174.
///
/// Custom policy-defined patterns (`data.sensitive_patterns`) are intentionally
/// **not** listed here: they are per-policy, not built-in, and exposing/managing
/// them is scoped as an AAASM-5174 follow-up. `builtin` is therefore always
/// `true` on the current response.
#[utoipa::path(
    get,
    path = "/api/v1/scrub/patterns",
    responses(
        (status = 200, description = "Effective built-in pattern catalogue", body = ScrubCatalogueResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    security(("bearer_auth" = [])),
    tag = "scrub"
)]
pub async fn get_patterns(RequireRead(_caller): RequireRead) -> (StatusCode, Json<ScrubCatalogueResponse>) {
    let patterns: Vec<ScrubPattern> = CredentialKind::ALL
        .iter()
        .map(|k| ScrubPattern {
            kind: k.as_str().to_string(),
            redaction_label: format!("[REDACTED:{}]", k.as_str()),
            category: k.category().to_string(),
            severity: k.severity().to_string(),
            builtin: true,
        })
        .collect();

    let total = patterns.len();
    (StatusCode::OK, Json(ScrubCatalogueResponse { patterns, total }))
}

/// `GET /api/v1/scrub/pattern-counts` — per-kind detection counts over a window.
///
/// Aggregates the persisted `secret_detected` alerts by their recorded
/// `detected_pattern_type` (the [`CredentialKind`] string) over the requested
/// window. Only kinds that actually fired appear, so an idle window returns an
/// empty list rather than zero-filled fabricated rows. The alert read is
/// bounded by [`MAX_SCRUB_ALERTS`] and confined to the caller's tenant.
#[utoipa::path(
    get,
    path = "/api/v1/scrub/pattern-counts",
    params(ScrubWindowParams),
    responses(
        (status = 200, description = "Per-pattern-kind detection counts over the window", body = PatternCountsResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    security(("bearer_auth" = [])),
    tag = "scrub"
)]
pub async fn get_pattern_counts(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<ScrubWindowParams>,
) -> (StatusCode, Json<PatternCountsResponse>) {
    let window_seconds = window_secs_from_range(params.range.as_deref());
    let alerts = windowed_secret_alerts(&caller, &state, window_seconds);

    let by_kind = tally_by_kind(&alerts);
    let total_hits: u64 = by_kind.values().sum();
    let counts: Vec<PatternCount> = by_kind
        .into_iter()
        .map(|(kind, hits)| PatternCount { kind, hits })
        .collect();

    (
        StatusCode::OK,
        Json(PatternCountsResponse {
            counts,
            total_hits,
            window_seconds,
        }),
    )
}

/// `GET /api/v1/scrub/posture` — leak posture over a window.
///
/// Reports `leaks_intercepted` (the count of `secret_detected` alerts in the
/// window) and `distinct_kinds`. A leak *rate* is not derivable — the store
/// does not persist the total-payloads-scanned denominator — so `leak_rate` is
/// surfaced as explicitly absent with `rate_computed: false` rather than
/// fabricated (AAASM-5174 truthfulness requirement). Confined to the caller's
/// tenant and bounded by [`MAX_SCRUB_ALERTS`].
#[utoipa::path(
    get,
    path = "/api/v1/scrub/posture",
    params(ScrubWindowParams),
    responses(
        (status = 200, description = "Leak posture over the window (leak rate absent when not derivable)", body = PostureResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    security(("bearer_auth" = [])),
    tag = "scrub"
)]
pub async fn get_posture(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<ScrubWindowParams>,
) -> (StatusCode, Json<PostureResponse>) {
    let window_seconds = window_secs_from_range(params.range.as_deref());
    let alerts = windowed_secret_alerts(&caller, &state, window_seconds);

    let leaks_intercepted = alerts.len() as u64;
    let distinct_kinds = distinct_kinds(&alerts);

    (
        StatusCode::OK,
        Json(PostureResponse {
            leaks_intercepted,
            distinct_kinds,
            // No total-payloads-scanned denominator is persisted, so a leak
            // rate is not computable — report absent, never fabricated.
            leak_rate: None,
            rate_computed: false,
            window_seconds,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tenant;

    fn admin_caller() -> AuthenticatedCaller {
        AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes: vec![Scope::Admin],
            tenant: Tenant {
                team_id: None,
                org_id: None,
            },
        }
    }

    #[test]
    fn catalogue_lists_all_builtin_kinds() {
        // The catalogue must expose exactly the built-in scanner kinds.
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let (_status, Json(resp)) = rt.block_on(get_patterns(RequireRead(admin_caller())));
        assert_eq!(resp.total, CredentialKind::ALL.len());
        assert_eq!(resp.patterns.len(), CredentialKind::ALL.len());
        // Every entry carries a REDACTED label matching its kind and a
        // non-empty category + a known severity.
        for p in &resp.patterns {
            assert_eq!(p.redaction_label, format!("[REDACTED:{}]", p.kind));
            assert!(p.builtin);
            assert!(!p.category.is_empty());
            assert!(["critical", "high", "medium", "low"].contains(&p.severity.as_str()));
        }
        // Spot-check a couple of well-known kinds are present.
        let kinds: Vec<&str> = resp.patterns.iter().map(|p| p.kind.as_str()).collect();
        assert!(kinds.contains(&"AwsAccessKey"));
        assert!(kinds.contains(&"AnthropicKey"));
        assert!(kinds.contains(&"SsnPattern"));
        // Custom is policy-defined, not a built-in, so it must not appear.
        assert!(!kinds.contains(&"Custom"));
    }

    #[test]
    fn window_presets_and_custom_ranges_resolve() {
        assert_eq!(window_secs_from_range(Some("24h")), 86_400);
        assert_eq!(window_secs_from_range(Some("7d")), 604_800);
        assert_eq!(window_secs_from_range(Some("30d")), 2_592_000);
        assert_eq!(window_secs_from_range(None), 604_800);
        assert_eq!(window_secs_from_range(Some("bogus")), 604_800);
        assert_eq!(window_secs_from_range(Some("2026-01-01..2026-01-07")), 7 * 86_400);
        // Inverted / malformed custom range falls back to the 7d default.
        assert_eq!(window_secs_from_range(Some("2026-01-07..2026-01-01")), 604_800);
    }

    #[test]
    fn within_window_includes_in_range_excludes_out_and_unparseable() {
        let now = chrono::Utc::now();
        let since = now - chrono::Duration::seconds(3600);
        let in_range = (now - chrono::Duration::seconds(10)).to_rfc3339();
        let too_old = (now - chrono::Duration::seconds(7200)).to_rfc3339();
        assert!(within_window(&in_range, since, now));
        assert!(!within_window(&too_old, since, now));
        assert!(
            !within_window("not-a-timestamp", since, now),
            "unparseable ts is excluded, not counted"
        );
    }

    #[test]
    fn counts_and_posture_aggregate_real_secret_alerts_only() {
        // Seed the in-memory store with real secret-detection alerts via the
        // public record path, plus a non-secret budget alert that must be
        // ignored, then assert the aggregations reflect only the secret alerts.
        use aa_gateway::alerts::SecretAlert;
        use aa_gateway::budget::types::BudgetAlert;

        let state = AppState::local_in_memory().expect("state builds");

        // Two AwsAccessKey detections and one OpenAiKey detection.
        for kinds in [
            vec![CredentialKind::AwsAccessKey],
            vec![CredentialKind::AwsAccessKey],
            vec![CredentialKind::OpenAiKey],
        ] {
            let finding_count = kinds.len();
            let alert = SecretAlert {
                agent_id: aa_core::AgentId::from_bytes([0x11; 16]),
                team_id: None,
                kinds,
                finding_count,
            };
            state.alert_store.record_secret(&alert);
        }

        // A budget alert that must NOT be counted as a scrub detection.
        state.alert_store.record(&BudgetAlert {
            agent_id: aa_core::AgentId::from_bytes([0x22; 16]),
            team_id: None,
            threshold_pct: 90,
            spent_usd: 9.0,
            limit_usd: 10.0,
        });

        let caller = admin_caller();

        // Only the three secret alerts are in scope; the budget alert is excluded.
        let secret_alerts = windowed_secret_alerts(&caller, &state, 7 * 86_400);
        assert_eq!(secret_alerts.len(), 3, "only the three secret alerts are counted");

        // pattern-counts: two kinds — AwsAccessKey x2, OpenAiKey x1.
        let counts = tally_by_kind(&secret_alerts);
        assert_eq!(counts.get("AwsAccessKey"), Some(&2));
        assert_eq!(counts.get("OpenAiKey"), Some(&1));

        // posture: 3 intercepted, 2 distinct kinds.
        assert_eq!(secret_alerts.len() as u64, 3);
        assert_eq!(distinct_kinds(&secret_alerts), 2);
    }
}
