//! AAASM-6446 x AAASM-6444 — the agent/event filters on `GET /api/v1/logs` never
//! widen a caller's org pin, and the pin never turns a filter into an existence
//! oracle for another org's agents.

mod common;

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType, Lineage};
use aa_gateway::registry::{AgentRecord, AgentStatus};
use aa_gateway::service::convert::hash_to_16;
use aa_gateway::AuditReader;

const ACME_AGENT: &str = "acme-agent";
const GLOBEX_AGENT: &str = "globex-agent";
const GLOBEX_DID: &str = "did:key:z6MkGlobexGlobexGlobexGlobexGlobexGlobexGlobex";
const GLOBEX_KEY: [u8; 16] = [0xB2; 16];
const SHARED: &str = "shared-agent";

fn hex16(b: [u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn entry(
    seq: u64,
    ty: AuditEventType,
    id_key: [u8; 16],
    root: Option<[u8; 16]>,
    claimed: &str,
    org: &str,
) -> AuditEntry {
    AuditEntry::new_with_lineage(
        seq,
        1_000 + seq,
        ty,
        AgentId::from_bytes(id_key),
        SessionId::from_bytes([0xEE; 16]),
        serde_json::json!({ "agent_id_claimed": claimed }).to_string(),
        [0u8; 32],
        Lineage {
            org_id: Some(org.to_string()),
            root_agent_id: root.map(AgentId::from_bytes),
            ..Lineage::default()
        },
    )
}

fn record(name: &str, key: [u8; 16], org: &str) -> AgentRecord {
    AgentRecord {
        agent_id: key,
        name: name.to_string(),
        framework: "test".into(),
        version: "0".into(),
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
        root_agent_id: Some(key),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
        org_id: Some(org.to_string()),
    }
}

/// seq 0,1: acme's agent (deny by name, approval by name); seq 2,3: globex's agent (deny by
/// name, allow by did:key with the registry key as root); seq 4,5: the same name in both orgs.
fn app_with(extra: Vec<AuditEntry>) -> axum::Router {
    let dir = std::env::temp_dir().join(format!("aa-6446-pin-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut entries = vec![
        entry(
            0,
            AuditEventType::PolicyViolation,
            hash_to_16(ACME_AGENT),
            None,
            ACME_AGENT,
            "acme",
        ),
        entry(
            1,
            AuditEventType::ApprovalRequested,
            hash_to_16(ACME_AGENT),
            None,
            ACME_AGENT,
            "acme",
        ),
        entry(
            2,
            AuditEventType::PolicyViolation,
            hash_to_16(GLOBEX_AGENT),
            None,
            GLOBEX_AGENT,
            "globex",
        ),
        entry(
            3,
            AuditEventType::ToolCallIntercepted,
            hash_to_16(GLOBEX_DID),
            Some(GLOBEX_KEY),
            GLOBEX_DID,
            "globex",
        ),
        entry(
            4,
            AuditEventType::PolicyViolation,
            hash_to_16(SHARED),
            None,
            SHARED,
            "acme",
        ),
        entry(
            5,
            AuditEventType::PolicyViolation,
            hash_to_16(SHARED),
            None,
            SHARED,
            "globex",
        ),
    ];
    entries.extend(extra);
    let body: String = entries
        .iter()
        .map(|e| serde_json::to_string(e).unwrap() + "\n")
        .collect();
    std::fs::write(dir.join("audit.jsonl"), body).unwrap();

    let mut state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.audit_reader = Arc::new(AuditReader::new(dir));
    state
        .agent_registry
        .register(record(GLOBEX_AGENT, GLOBEX_KEY, "globex"))
        .unwrap();
    state
        .agent_registry
        .register(record(ACME_AGENT, [0xA1; 16], "acme"))
        .unwrap();
    aa_api::build_app(state)
}

fn app() -> axum::Router {
    app_with(Vec::new())
}

#[derive(Clone, Copy)]
enum Caller {
    AcmeReader,
    AcmeAdmin,
    UnboundAdmin,
    NoOrgReader,
}

fn token(c: Caller) -> String {
    match c {
        Caller::AcmeReader => common::generate_test_jwt_for_tenant("u", &[Scope::Read], None, Some("acme")),
        Caller::AcmeAdmin => common::generate_test_jwt_for_tenant("u", &[Scope::Admin], None, Some("acme")),
        Caller::UnboundAdmin => common::generate_test_jwt("u", &[Scope::Admin]),
        Caller::NoOrgReader => common::generate_test_jwt("u", &[Scope::Read]),
    }
}

async fn get(router: axum::Router, c: Caller, query: &str) -> (StatusCode, serde_json::Value) {
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/logs?{query}"))
                .header("authorization", format!("Bearer {}", token(c)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

fn seqs(body: &serde_json::Value) -> Vec<u64> {
    let mut v: Vec<u64> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    v.sort_unstable();
    v
}

/// (a) An org-bound caller, admin or not, filtering by another org's agent — by name, did:key or
/// 32-hex id — gets exactly what it gets for an agent that does not exist: no entry, and nothing in
/// the status or body that tells the two apart.
#[tokio::test]
async fn a_bound_caller_filtering_by_another_orgs_agent_learns_nothing() {
    let probes = [
        GLOBEX_AGENT.to_string(),
        GLOBEX_DID.to_string(),
        hex16(hash_to_16(GLOBEX_AGENT)),
    ];
    for caller in [Caller::AcmeReader, Caller::AcmeAdmin] {
        let unknown = get(app(), caller, "per_page=100&agent_id=no-such-agent").await;
        assert_eq!(unknown.0, StatusCode::OK);
        assert!(seqs(&unknown.1).is_empty());
        for probe in &probes {
            let got = get(app(), caller, &format!("per_page=100&agent_id={probe}")).await;
            assert_eq!(
                got, unknown,
                "agent_id={probe} answered differently from an unknown agent"
            );
        }
    }
    // Positive control: the same filters through an unbound admin do find the entries, so the
    // empty answers above are the pin and not a fixture that cannot match.
    for probe in &probes {
        let (_, body) = get(app(), Caller::UnboundAdmin, &format!("per_page=100&agent_id={probe}")).await;
        assert!(
            !seqs(&body).is_empty(),
            "unbound admin found nothing for agent_id={probe}"
        );
    }
}

/// (b) The same agent name in two orgs: a bound caller sees only its own org's entry.
#[tokio::test]
async fn a_shared_agent_name_is_scoped_to_the_callers_org() {
    for caller in [Caller::AcmeReader, Caller::AcmeAdmin] {
        let (_, body) = get(app(), caller, &format!("per_page=100&agent_id={SHARED}")).await;
        assert_eq!(seqs(&body), vec![4], "an acme caller must see only acme's {SHARED}");
    }
    let (_, both) = get(app(), Caller::UnboundAdmin, &format!("per_page=100&agent_id={SHARED}")).await;
    assert_eq!(seqs(&both), vec![4, 5]);
}

/// (c) With a filter, `total` counts only the caller's org's entries and paging stays inside them.
#[tokio::test]
async fn total_with_a_filter_counts_only_the_callers_org() {
    let name = "busy-agent";
    let mut extra = Vec::new();
    for i in 0..6 {
        extra.push(entry(
            10 + i,
            AuditEventType::PolicyViolation,
            hash_to_16(name),
            None,
            name,
            "acme",
        ));
    }
    for i in 0..4 {
        extra.push(entry(
            20 + i,
            AuditEventType::PolicyViolation,
            hash_to_16(name),
            None,
            name,
            "globex",
        ));
    }
    let (_, page1) = get(
        app_with(extra.clone()),
        Caller::AcmeReader,
        &format!("per_page=2&page=1&agent_id={name}"),
    )
    .await;
    assert_eq!(page1["total"], 6, "total must not include globex's four");
    assert_eq!(seqs(&page1).len(), 2);
    let (_, page3) = get(
        app_with(extra.clone()),
        Caller::AcmeReader,
        &format!("per_page=2&page=3&agent_id={name}"),
    )
    .await;
    assert_eq!(page3["total"], 6);
    assert!(
        seqs(&page3).iter().all(|s| (10..16).contains(s)),
        "paging left acme's entries: {:?}",
        seqs(&page3)
    );
    let (_, unbound) = get(
        app_with(extra),
        Caller::UnboundAdmin,
        &format!("per_page=2&agent_id={name}"),
    )
    .await;
    assert_eq!(unbound["total"], 10, "control: an unbound admin counts both orgs");
}

/// (d) A non-admin with no org scope gets the empty sentinel, filter or not.
#[tokio::test]
async fn a_non_admin_with_no_org_gets_nothing_with_or_without_a_filter() {
    for q in [
        "per_page=100",
        "per_page=100&agent_id=acme-agent",
        "per_page=100&event_type=violation",
    ] {
        let (status, body) = get(app(), Caller::NoOrgReader, q).await;
        assert_eq!(status, StatusCode::OK, "{q}");
        assert_eq!(body["total"], 0, "{q}");
        assert!(seqs(&body).is_empty(), "{q}");
    }
}

/// (e) event_type categories select, an unknown one selects nothing, a blank one selects nothing —
/// and the org pin still applies on top.
#[tokio::test]
async fn event_type_categories_select_unknown_and_blank_select_nothing() {
    let (_, violations) = get(app(), Caller::UnboundAdmin, "per_page=100&event_type=violation").await;
    assert_eq!(seqs(&violations), vec![0, 2, 4, 5]);
    let (_, approvals) = get(app(), Caller::UnboundAdmin, "per_page=100&event_type=approval").await;
    assert_eq!(seqs(&approvals), vec![1]);

    let (_, pinned) = get(app(), Caller::AcmeReader, "per_page=100&event_type=violation").await;
    assert_eq!(
        seqs(&pinned),
        vec![0, 4],
        "the category filter must not widen the org pin"
    );

    for q in [
        "event_type=NotAnEventType",
        "event_type=",
        "event_type=violation,nonsense",
    ] {
        let (status, body) = get(app(), Caller::UnboundAdmin, &format!("per_page=100&{q}")).await;
        assert_eq!(status, StatusCode::OK, "{q}");
        assert!(seqs(&body).is_empty(), "{q} returned {:?}", seqs(&body));
    }
}
