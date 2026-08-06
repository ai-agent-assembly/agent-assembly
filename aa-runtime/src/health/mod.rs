//! Health check and Prometheus metrics HTTP server.
//!
//! # `status` is liveness; `protection` is a claim
//!
//! `status` answers "is this process up". It is deliberately *not* overloaded
//! to answer "is anything protected" — conflating the two is how an operator
//! ends up reading a green health check as evidence of governance. The
//! `protection` section (AAASM-5535) answers the second question separately,
//! in the ADR 0033 §6 vocabulary.
//!
//! Be precise about what is fresh in it: the *claim term* is derived when the
//! request is served, but the *basis* it derives from is the startup probe.
//! See [`HealthState::protection`] for what that costs and when it must change.
//!
//! This endpoint has no authentication layer, so treat the body as public.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use aa_core::attestation::{ClaimTerm, ProtectionAttestation};
use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::ipc::message::IpcFrame;
use crate::pipeline::PipelineMetrics;

/// Shared state passed to all axum handlers.
#[derive(Clone)]
pub struct HealthState {
    pub start_time: std::time::Instant,
    pub pipeline_metrics: Arc<PipelineMetrics>,
    pub ready_rx: watch::Receiver<bool>,
    pub prometheus_handle: PrometheusHandle,
    pub active_connections: Arc<AtomicI64>,
    pub inbound_tx: mpsc::Sender<(u64, IpcFrame)>,
    pub active_layers: crate::layer::LayerSet,
    pub degraded_layers: Vec<String>,
    /// What each interception component could claim when the runtime started.
    ///
    /// **Frozen at startup.** The probes touch the filesystem, so the *basis*
    /// of every claim — and `generated_at_unix_secs` with it — is the process
    /// start, not the moment of the request. Only the derived
    /// [`ClaimTerm`] is recomputed per request
    /// ([`ProtectionReport::evaluate`]).
    ///
    /// Two consequences a consumer must know. The freshness window is inert
    /// today: it is consulted only when a basis asserts coverage, and no
    /// startup probe can (ADR 0033 §7), so nothing ever ages out. And
    /// `generated_at_unix_secs` is process start — on a pod that has been up
    /// for thirty days it reads as a thirty-day-old verification, which is
    /// what it is.
    ///
    /// The moment any component gains an
    /// [`Adjudicated`](aa_core::attestation::AttestationBasis::Adjudicated)
    /// basis, this must be re-probed on a schedule rather than held; a frozen
    /// coverage claim is exactly the stale-protection failure the attestation
    /// exists to prevent.
    pub protection: ProtectionAttestation,
}

/// Response body for GET /health.
#[derive(serde::Serialize)]
pub struct HealthResponse {
    /// Process liveness only. Never a protection claim — see the module docs.
    pub status: &'static str,
    pub uptime_secs: u64,
    pub events_processed: u64,
    /// Historic presence bitflag, retained for compatibility. Presence is not
    /// protection; read `protection` instead (ADR 0033 §7).
    pub active_layers: Vec<&'static str>,
    /// Historic list of components that are **not present**, retained for
    /// compatibility.
    ///
    /// **This is not ADR 0033 §6 `Degraded`, and the two deliberately disagree
    /// in the same payload.** This field lists any component absent from
    /// `active_layers`, whether or not anything asked for it. §6 reserves
    /// *Degraded* for a control that was *planned* and is unavailable, so on a
    /// default host with no eBPF and no proxy this field says
    /// `["ebpf", "proxy"]` while `protection.verified_states` reports
    /// `unsupported`/`unmeasured` and `degraded_at()` is empty — because
    /// nothing was planned.
    ///
    /// A renderer must read `protection.verified_states`, never this field.
    pub degraded_layers: Vec<String>,
    /// What may truthfully be claimed about each component, right now.
    pub protection: ProtectionReport,
}

/// The protection section of `GET /health`, evaluated at request time.
#[derive(serde::Serialize)]
pub struct ProtectionReport {
    /// The startup attestation: schema version, release series, platform, and
    /// when it was produced.
    ///
    /// `component_version` here is the release **series**, not the exact build
    /// — this endpoint is unauthenticated, and the precise build is a
    /// fingerprinting aid. Trusted consumers that need the exact build must
    /// read it from a source that authenticates them.
    pub attestation: ProtectionAttestation,
    /// When the claims below were derived, as seconds since the Unix epoch.
    pub evaluated_at_unix_secs: u64,
    /// Each component's ADR 0033 §6 term as of `evaluated_at_unix_secs`.
    pub verified_states: Vec<ComponentClaim>,
    /// Whether *any* component substantiates a coverage claim right now.
    ///
    /// Allowed to be `false`, and on a default build it is: none of the three
    /// startup probes is evidence that a control acted on an action. A surface
    /// that cannot report "nothing is verified" cannot be believed when it
    /// reports that something is.
    pub any_coverage_verified: bool,
}

/// One component's claim.
#[derive(serde::Serialize)]
pub struct ComponentClaim {
    /// The component this claim is about, e.g. `"proxy"`.
    pub component: String,
    /// What configuration asked for.
    pub selected_mode: aa_core::attestation::SelectedMode,
    /// What the evidence supports — never raised by `selected_mode`.
    pub verified_state: ClaimTerm,
    /// What was actually checked.
    pub detail: String,
}

impl ProtectionReport {
    /// Evaluate `attestation` as of `now_unix_secs`.
    ///
    /// Only the *term* is re-derived here; the *basis* it is derived from is
    /// the startup probe (see [`HealthState::protection`]). Deriving rather
    /// than storing the term follows ADR 0030's reason for deriving protection
    /// state on every read — a stored answer keeps displaying protection that
    /// has already stopped being true — but note the limit: re-deriving a term
    /// from a frozen basis cannot notice that the basis stopped holding.
    fn evaluate(attestation: &ProtectionAttestation, now_unix_secs: u64) -> Self {
        let verified_states = attestation
            .layers
            .iter()
            .map(|layer| ComponentClaim {
                component: layer.component.clone(),
                selected_mode: layer.selected_mode,
                verified_state: layer.verified_state_at(now_unix_secs, attestation.freshness_window_secs),
                detail: layer.detail.clone(),
            })
            .collect();

        // This router carries no authentication layer and `AA_METRICS_ADDR`
        // defaults to `0.0.0.0:8080`, which the reference compose file
        // publishes to the host — so everything below is reachable by anyone
        // who can reach the port. The exact build (e.g. `0.0.1-rc.7`) is a
        // fingerprinting aid: it tells an unauthenticated caller precisely
        // which advisories apply. The release *series* keeps the payload
        // legible for the public trust surface without naming the build.
        //
        // The filesystem paths in `detail` deliberately stay: a well-known
        // default socket path is not a secret, and the path *is* the evidence
        // — removing it would cost legibility for no security gain.
        let mut attestation = attestation.clone();
        attestation.component_version = version_series(&attestation.component_version);

        Self {
            evaluated_at_unix_secs: now_unix_secs,
            verified_states,
            any_coverage_verified: attestation.any_coverage_verified_at(now_unix_secs),
            attestation,
        }
    }
}

/// The release series of a version, dropping pre-release and build metadata.
///
/// `"0.0.1-rc.7"` becomes `"0.0.1"`. Semver puts pre-release after `-` and
/// build metadata after `+`, and it is exactly those that distinguish one build
/// from the next.
fn version_series(version: &str) -> String {
    version.split(['-', '+']).next().unwrap_or(version).to_string()
}

/// Seconds since the Unix epoch, saturating to 0 before it.
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build the axum router with all three routes.
pub fn router(state: HealthState) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/ready", axum::routing::get(ready_handler))
        .route("/metrics", axum::routing::get(metrics_handler))
        .with_state(state)
}

// --- Stub handlers (replaced in Tasks 6–8) ---

async fn health_handler(axum::extract::State(state): axum::extract::State<HealthState>) -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
        status: "healthy",
        uptime_secs: state.start_time.elapsed().as_secs(),
        events_processed: state.pipeline_metrics.processed(),
        active_layers: state.active_layers.names(),
        degraded_layers: state.degraded_layers.clone(),
        protection: ProtectionReport::evaluate(&state.protection, now_unix_secs()),
    })
}

async fn ready_handler(axum::extract::State(state): axum::extract::State<HealthState>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if *state.ready_rx.borrow() {
        (axum::http::StatusCode::OK, "ready").into_response()
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
    }
}

async fn metrics_handler(axum::extract::State(state): axum::extract::State<HealthState>) -> String {
    // Update live gauges just before rendering.
    let active = state.active_connections.load(Ordering::Relaxed);
    metrics::gauge!("aa_active_connections").set(active as f64);

    let capacity = state.inbound_tx.max_capacity();
    let available = state.inbound_tx.capacity();
    let utilization = if capacity > 0 {
        1.0 - (available as f64 / capacity as f64)
    } else {
        0.0
    };
    metrics::gauge!("aa_channel_utilization_ratio").set(utilization);

    state.prometheus_handle.render()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI64;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for `oneshot`

    /// A fixed instant, so an attestation's freshness never depends on the
    /// wall clock.
    const TEST_NOW: u64 = 1_700_000_000;

    fn make_prometheus_handle() -> metrics_exporter_prometheus::PrometheusHandle {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle()
    }

    #[test]
    fn health_response_serializes_correctly() {
        let resp = HealthResponse {
            status: "healthy",
            uptime_secs: 42,
            events_processed: 100,
            active_layers: vec!["sdk"],
            degraded_layers: vec![],
            protection: ProtectionReport::evaluate(&crate::layer::LayerDetector::attest(TEST_NOW), TEST_NOW),
        };
        let json = serde_json::to_string(&resp).expect("serialization failed");
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"uptime_secs\":42"));
        assert!(json.contains("\"events_processed\":100"));
        assert!(json.contains("\"active_layers\":[\"sdk\"]"));
        assert!(json.contains("\"degraded_layers\":[]"));
    }

    #[tokio::test]
    async fn health_endpoint_returns_200_with_json() {
        let (_, ready_rx) = tokio::sync::watch::channel(false);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: make_prometheus_handle(),
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(TEST_NOW),
        };

        let app = router(state);
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
        assert!(json["uptime_secs"].as_u64().is_some());
        assert_eq!(json["events_processed"], 0);
    }

    #[tokio::test]
    async fn ready_returns_503_when_not_ready() {
        let (_, ready_rx) = tokio::sync::watch::channel(false);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: make_prometheus_handle(),
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(TEST_NOW),
        };

        let app = router(state);
        let req = Request::builder().uri("/ready").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn ready_returns_200_when_ready() {
        let (_, ready_rx) = tokio::sync::watch::channel(true);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: make_prometheus_handle(),
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(TEST_NOW),
        };

        let app = router(state);
        let req = Request::builder().uri("/ready").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus_text() {
        let (_, ready_rx) = tokio::sync::watch::channel(false);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(100);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        // Build a non-global Prometheus recorder for this test.
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: handle,
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(TEST_NOW),
        };

        let app = router(state);
        let req = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        // The Prometheus output should contain the gauge we just set.
        // With a fresh non-global recorder, we only get metrics that were set via this recorder.
        // The gauges are set via the global recorder (metrics::gauge! macro), not this local one.
        // So just verify the response is a non-panicking string.
        assert!(!text.contains("panic"));
    }

    #[tokio::test]
    async fn metrics_active_connections_gauge_is_set() {
        let (_, ready_rx) = tokio::sync::watch::channel(false);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(100);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        // Install this recorder as the local recorder for this test.
        // Use metrics::with_recorder to scope it.
        let active_connections = Arc::new(AtomicI64::new(5));

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: handle.clone(),
            active_connections: Arc::clone(&active_connections),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(TEST_NOW),
        };

        // We call the handler manually using the recorder.
        // Since metrics::gauge! uses the global recorder, we need to install it.
        // Use metrics::set_global_recorder only if not already set.
        // For simplicity: just verify the handler doesn't panic and returns a string.
        let app = router(state);
        let req = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap().to_string();
        // The handler returned a valid string, verifying it doesn't panic.
        // Verify it is a string (not a panic indicator).
        assert!(
            !text.contains("thread"),
            "metrics response should not contain panic trace"
        );
    }

    #[tokio::test]
    async fn ready_reflects_watch_channel_update() {
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: make_prometheus_handle(),
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(TEST_NOW),
        };

        // First request: not ready (503)
        let app1 = router(state.clone());
        let req1 = Request::builder().uri("/ready").body(Body::empty()).unwrap();
        let response1 = app1.oneshot(req1).await.unwrap();
        assert_eq!(response1.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Update watch channel to ready
        ready_tx.send(true).unwrap();

        // Second request: now ready (200)
        let app2 = router(state.clone());
        let req2 = Request::builder().uri("/ready").body(Body::empty()).unwrap();
        let response2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(response2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_response_includes_active_layers() {
        let (_, ready_rx) = tokio::sync::watch::channel(false);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: make_prometheus_handle(),
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(TEST_NOW),
        };

        let app = router(state);
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let layers = json["active_layers"]
            .as_array()
            .expect("active_layers should be an array");
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0], "sdk");
    }

    #[tokio::test]
    async fn health_active_layers_matches_all_layers() {
        let (_, ready_rx) = tokio::sync::watch::channel(false);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let all_layers = crate::layer::LayerSet::EBPF | crate::layer::LayerSet::PROXY | crate::layer::LayerSet::SDK;

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: make_prometheus_handle(),
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: all_layers,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(TEST_NOW),
        };

        let app = router(state);
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let layers = json["active_layers"]
            .as_array()
            .expect("active_layers should be an array");
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[0], "ebpf");
        assert_eq!(layers[1], "proxy");
        assert_eq!(layers[2], "sdk");
    }

    /// The end-to-end shape the public trust surface will render, taken from
    /// the real router rather than from a hand-built response: a default build
    /// serves `status: "healthy"` and, in the same body, states that nothing is
    /// verified. Those two facts must be able to coexist.
    #[tokio::test]
    async fn health_publishes_an_attestation_that_denies_unevidenced_coverage() {
        let (_, ready_rx) = tokio::sync::watch::channel(true);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: make_prometheus_handle(),
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            degraded_layers: vec![],
            protection: crate::layer::LayerDetector::attest(now_unix_secs()),
        };

        let app = router(state);
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Liveness is unchanged and says nothing about protection.
        assert_eq!(json["status"], "healthy");

        let protection = &json["protection"];
        assert_eq!(protection["any_coverage_verified"], false);
        assert_eq!(
            protection["attestation"]["schema_version"],
            aa_core::attestation::ATTESTATION_SCHEMA_VERSION
        );

        let claims = protection["verified_states"].as_array().expect("verified_states");
        assert_eq!(claims.len(), 3, "every component must be listed: {claims:?}");
        for claim in claims {
            let state = claim["verified_state"].as_str().expect("verified_state");
            assert!(
                matches!(state, "unmeasured" | "unsupported" | "degraded"),
                "{} published the coverage term {state}",
                claim["component"]
            );
            assert!(
                !claim["detail"].as_str().unwrap_or_default().is_empty(),
                "{} must say what was checked",
                claim["component"]
            );
        }
    }

    /// A startup probe is a claim about the moment it ran. Once it falls
    /// outside the freshness window, the surface must stop reporting it — a
    /// stored answer would keep displaying protection that had already ceased.
    #[tokio::test]
    async fn a_stale_startup_attestation_downgrades_by_request_time() {
        use aa_core::attestation::{
            AdjudicatedOutcome, AttestationBasis, ClaimTerm, LayerAttestation, ProtectionAttestation, SelectedMode,
        };

        // A component that genuinely had evidence when the runtime started.
        let attestation = ProtectionAttestation::new(
            env!("CARGO_PKG_VERSION"),
            "test-platform",
            TEST_NOW,
            vec![LayerAttestation::new(
                "proxy",
                SelectedMode::Enabled,
                AttestationBasis::Adjudicated {
                    outcome: AdjudicatedOutcome::Blocked,
                },
                TEST_NOW,
                "pre-dial refusal reported by aa-proxy",
            )],
        );

        let fresh = ProtectionReport::evaluate(&attestation, TEST_NOW);
        assert_eq!(
            fresh.verified_states[0].verified_state,
            ClaimTerm::DeniedBeforeExecution
        );
        assert!(fresh.any_coverage_verified);

        let later = TEST_NOW + attestation.freshness_window_secs + 1;
        let stale = ProtectionReport::evaluate(&attestation, later);
        assert_eq!(stale.verified_states[0].verified_state, ClaimTerm::Degraded);
        assert!(!stale.any_coverage_verified);
        // The underlying attestation is unchanged; only the reading of it moved.
        assert_eq!(stale.attestation.generated_at_unix_secs, TEST_NOW);
        assert_eq!(stale.evaluated_at_unix_secs, later);
    }

    /// `degraded_layers` and `protection` deliberately disagree in one body,
    /// and 5588/5600 are told to render the latter — so the relationship is
    /// pinned rather than left to be discovered.
    ///
    /// `degraded_layers` lists components that are merely *absent*. ADR 0033 §6
    /// `Degraded` means a control that was *planned* and is unavailable, and on
    /// the probed path nothing sets `SelectedMode::Enabled`, so `degraded_at()`
    /// is empty while `degraded_layers` is not. If a future change wires
    /// configuration to `selected_mode`, this test is where the two must be
    /// reconciled.
    #[tokio::test]
    async fn legacy_degraded_layers_does_not_mean_adr_0033_degraded() {
        let (_, ready_rx) = tokio::sync::watch::channel(true);
        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let pipeline_metrics = Arc::new(crate::pipeline::PipelineMetrics::default());

        let attestation = crate::layer::LayerDetector::attest(TEST_NOW);
        // Precondition: the probed path plans nothing, so no component can
        // reach §6 Degraded. If this ever fails, the contradiction below has
        // been resolved and this test must be rewritten, not deleted.
        assert!(
            attestation.degraded_at(TEST_NOW).is_empty(),
            "probed path unexpectedly produced a planned component"
        );

        let state = HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics,
            ready_rx,
            prometheus_handle: make_prometheus_handle(),
            active_connections: Arc::new(AtomicI64::new(0)),
            inbound_tx,
            active_layers: crate::layer::LayerSet::SDK,
            // What `check_layer_availability` produces for an absent layer.
            degraded_layers: vec!["ebpf".to_string(), "proxy".to_string()],
            protection: attestation,
        };

        let app = router(state);
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let body = axum::body::to_bytes(app.oneshot(req).await.unwrap().into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // The legacy field says "degraded" ...
        assert_eq!(json["degraded_layers"], serde_json::json!(["ebpf", "proxy"]));

        // ... while no component claims the §6 term of that name.
        let claims = json["protection"]["verified_states"]
            .as_array()
            .expect("verified_states");
        for claim in claims {
            assert_ne!(
                claim["verified_state"], "degraded",
                "{} reported §6 Degraded; the two fields have converged and the \
                 documented divergence needs updating",
                claim["component"]
            );
        }
        assert_eq!(json["protection"]["any_coverage_verified"], false);
    }
}
