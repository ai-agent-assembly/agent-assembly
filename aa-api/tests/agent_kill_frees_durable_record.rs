//! AAASM-6416 — `DELETE /api/v1/agents/:id` (what `aasm agent kill` calls) must
//! delete the agent's durable row, not just its in-memory record.
//!
//! The registry is rehydrated from `local.db` at every boot, so a row that
//! survives the delete re-occupies the id after the next restart and the
//! gateway then refuses that agent's re-registration forever.

use std::collections::{BTreeMap, VecDeque};

use aa_api::state::{AppState, LocalAuth, LocalDurablePaths};
use aa_gateway::registry::{AgentRecord, AgentStatus};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn agent(id: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: id,
        name: "aaasm-6416-agent".to_string(),
        framework: "test".to_string(),
        version: "0".to_string(),
        risk_tier: 1,
        tool_names: Vec::new(),
        public_key: String::new(),
        credential_token: String::new(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        active_sessions: Vec::new(),
        recent_events: VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some(id),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
        org_id: None,
    }
}

async fn boot(paths: &LocalDurablePaths) -> AppState {
    AppState::local_hardened_at(LocalAuth::Off, paths.clone())
        .await
        .expect("local_hardened_at")
}

#[tokio::test]
async fn kill_removes_the_durable_row_so_the_id_can_register_again_after_restart() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = LocalDurablePaths {
        registry_db: tmp.path().join("local.db"),
        audit_jsonl_dir: tmp.path().join("audit-jsonl"),
        audit_db: tmp.path().join("audit.db"),
    };
    let id = [0xE7u8; 16];

    let state1 = boot(&paths).await;
    state1
        .agent_registry
        .register_persisted(agent(id))
        .await
        .expect("register");

    let response = aa_api::server::build_app(state1.clone())
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/agents/{}", hex::encode(id)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    drop(state1);

    // Restart: the registry is rebuilt from the durable file.
    let state2 = boot(&paths).await;
    assert!(
        state2.agent_registry.get(&id).is_none(),
        "a killed agent must not be rehydrated from the durable store"
    );
    state2
        .agent_registry
        .register(agent(id))
        .expect("the freed id must be registrable again");
}

#[tokio::test]
async fn a_failed_durable_delete_is_a_500_and_the_kill_can_be_retried() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = LocalDurablePaths {
        registry_db: tmp.path().join("local.db"),
        audit_jsonl_dir: tmp.path().join("audit-jsonl"),
        audit_db: tmp.path().join("audit.db"),
    };
    let id = [0xD4u8; 16];
    let uri = format!("/api/v1/agents/{}", hex::encode(id));
    let delete = |app: axum::Router| {
        let uri = uri.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8_lossy(&body).into_owned())
        }
    };

    let state = boot(&paths).await;
    state
        .agent_registry
        .register_persisted(agent(id))
        .await
        .expect("register");

    // A second connection makes every DELETE on the registry table fail.
    let side = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rw", paths.registry_db.display()))
        .await
        .expect("side connection");
    sqlx::query(
        "CREATE TRIGGER block_delete BEFORE DELETE ON agent_registry BEGIN SELECT RAISE(ABORT, 'blocked'); END",
    )
    .execute(&side)
    .await
    .expect("install trigger");

    let app = aa_api::server::build_app(state.clone());
    let (status, body) = delete(app.clone()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        body.contains("not deregistered"),
        "body must say the agent was not deregistered: {body}"
    );
    assert!(body.contains("retry"), "body must tell the caller to retry: {body}");
    assert!(
        !body.contains("was deregistered"),
        "body must not claim the agent was deregistered: {body}"
    );
    assert!(
        state.agent_registry.get(&id).is_some(),
        "the agent must stay registered so the kill can be retried"
    );

    sqlx::query("DROP TRIGGER block_delete")
        .execute(&side)
        .await
        .expect("drop trigger");
    assert_eq!(delete(app).await.0, StatusCode::NO_CONTENT);
    assert!(state.agent_registry.get(&id).is_none());
}
