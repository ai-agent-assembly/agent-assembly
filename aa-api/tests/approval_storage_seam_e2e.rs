//! AAASM-5657: the REST surface reads a pending approval it never saw
//! submitted in-process, and can decide it — proving `local_hardened_at`'s
//! approval queue is actually backed by the shared durable file, not just
//! that a unit test can call the trait directly (see `aa-gateway`'s own
//! cross-process test in `storage/approval.rs` for that half).

use aa_api::{AppState, LocalAuth};
use aa_core::storage::{ApprovalRecord, ApprovalStore};
use aa_gateway::storage::{SqliteBackend, SqliteConfig};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn the_rest_surface_sees_and_can_decide_a_row_it_never_saw_submitted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let registry_db_path = tmp.path().join("local.db");

    // Seed a pending row directly into the shared file, out-of-band — as if
    // aa-gateway (or another process) had submitted it. The row must exist
    // *before* the state is built, so `local_hardened_at`'s own rehydrate
    // step is what's actually being exercised, not a subsequent poll tick.
    let seed_id = uuid::Uuid::new_v4();
    {
        let backend = SqliteBackend::open(&SqliteConfig {
            path: registry_db_path.clone(),
        })
        .await
        .expect("open should succeed");
        use aa_gateway::storage::StorageBackend as _;
        backend.migrate().await.expect("migrate should succeed");
        backend
            .insert_pending(&ApprovalRecord {
                request_id: seed_id.to_string(),
                agent_id: "seeded-agent".to_string(),
                action: "read_file /etc/passwd".to_string(),
                condition_triggered: "sensitive-file-access".to_string(),
                submitted_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                timeout_secs: 600,
                team_id: None,
                fallback_json: serde_json::to_string(&aa_core::PolicyResult::Deny {
                    reason: "timed out".to_string(),
                })
                .unwrap(),
            })
            .await
            .expect("seed insert should succeed");
    }

    let state = AppState::local_hardened_at(LocalAuth::Off, registry_db_path.clone())
        .await
        .expect("local_hardened_at should build");
    let app = aa_api::server::build_app(state);

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/api/v1/approvals").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    assert_eq!(json["total"], 1, "the seeded row must be visible: {json}");
    assert_eq!(json["items"][0]["id"], seed_id.to_string());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/approvals/{seed_id}/approve"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by":"operator"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "approving a row this process never submitted must still succeed"
    );

    // The 200 alone proves the endpoint accepted the request, not that
    // decide_persisted actually wrote anything — verify through a third,
    // independent connection to the same file that the decision is really
    // durable, not just applied to the in-process queue.
    let verify = SqliteBackend::open(&SqliteConfig { path: registry_db_path })
        .await
        .expect("reopen the shared file");
    let rows = verify
        .list_resolved_for(&[seed_id.to_string()])
        .await
        .expect("list_resolved_for should succeed");
    assert_eq!(rows.len(), 1, "the decision must be durable in the shared file");
    assert_eq!(rows[0].status, "approved");
    assert_eq!(rows[0].decided_by, "operator");

    let still_pending = verify.list_pending().await.expect("list_pending should succeed");
    assert!(
        still_pending.is_empty(),
        "the resolved row must no longer read back as pending"
    );
}
