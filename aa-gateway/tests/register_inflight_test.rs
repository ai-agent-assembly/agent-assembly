//! AAASM-6447: a re-bind must never be handed a credential for a record whose durable
//! write has not completed, has failed, or was abandoned.
//!
//! `AgentRegistry::register_persisted` inserts into memory, then awaits the durable
//! write, and rolls the insert back if it fails. These tests drive that window with a
//! storage double whose `upsert_agent` blocks on a gate and can fail, calling the
//! service directly so a request can be cancelled deterministically.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aa_auth::api_key::{ApiKey, ApiKeyEntry, ApiKeyStore};
use aa_auth::scope::Scope;
use aa_core::identity::AgentId;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::org_binding::{OrgBinder, REGISTRATION_KEY_METADATA_KEY};
use aa_gateway::service::AgentLifecycleServiceImpl;
use aa_gateway::storage::{
    AgentFilter, AgentRecord, AgentScope, AuditEvent, AuditFilter, HealthStatus, Metric, MetricPoint, MetricQuery,
    PolicyDocument, PolicyMeta, PolicyVersion, RetentionPolicy, RetentionStats, RowCounts, StorageBackend,
    StorageError, StorageHealth, StorageResult,
};
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleService;
use aa_proto::assembly::agent::v1::{ChallengeRequest, RegisterRequest, RegisterResponse};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_sdk_client::AgentKeypair;
use async_trait::async_trait;
use chrono::Utc;
use tonic::{Code, Request, Status};

/// `upsert_agent` signals `entered`, then optionally waits on `gate`, then optionally fails.
struct GatedStorage {
    entered: tokio::sync::Notify,
    gate: tokio::sync::Semaphore,
    block: AtomicBool,
    fail: AtomicBool,
}

#[async_trait]
impl StorageBackend for GatedStorage {
    async fn append_audit_event(&self, _: &AuditEvent) -> StorageResult<()> {
        Ok(())
    }
    async fn query_audit_events(&self, _: AuditFilter) -> StorageResult<Vec<AuditEvent>> {
        Ok(vec![])
    }
    async fn count_audit_events(&self, _: AuditFilter) -> StorageResult<u64> {
        Ok(0)
    }
    async fn upsert_agent(&self, _: AgentRecord) -> StorageResult<()> {
        self.entered.notify_one();
        if self.block.load(Ordering::SeqCst) {
            self.gate.acquire().await.expect("gate open").forget();
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(StorageError::QueryFailed("injected durable-write failure".into()));
        }
        Ok(())
    }
    async fn get_agent(&self, _: &AgentScope, _: &AgentId) -> StorageResult<Option<AgentRecord>> {
        Ok(None)
    }
    async fn list_agents(&self, _: AgentFilter) -> StorageResult<Vec<AgentRecord>> {
        Ok(vec![])
    }
    async fn delete_agent(&self, _: &AgentScope, _: &AgentId) -> StorageResult<()> {
        Ok(())
    }
    async fn save_policy(&self, doc: PolicyDocument) -> StorageResult<PolicyVersion> {
        Ok(PolicyVersion {
            meta: PolicyMeta {
                name: doc.name.clone(),
                version: 1,
                created_at: Utc::now(),
                is_active: false,
            },
            document: doc,
        })
    }
    async fn get_active_policy(&self, _: &str) -> StorageResult<Option<PolicyDocument>> {
        Ok(None)
    }
    async fn list_policy_versions(&self, _: &str) -> StorageResult<Vec<PolicyMeta>> {
        Ok(vec![])
    }
    async fn rollback_policy(&self, _: &str, _: u32) -> StorageResult<()> {
        Ok(())
    }
    async fn record_metric(&self, _: Metric) -> StorageResult<()> {
        Ok(())
    }
    async fn query_metrics(&self, _: MetricQuery) -> StorageResult<Vec<MetricPoint>> {
        Ok(vec![])
    }
    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }
    async fn apply_retention(&self, _: &RetentionPolicy) -> StorageResult<RetentionStats> {
        Ok(RetentionStats {
            hot_rows: 0,
            compressed_rows: 0,
            archived_rows: 0,
            dropped_rows: 0,
            freed_bytes: 0,
            ran_at: Utc::now(),
        })
    }
    async fn healthcheck(&self) -> StorageResult<StorageHealth> {
        Ok(StorageHealth {
            status: HealthStatus::Ok,
            backend: "noop",
            latency_ms: 0,
            row_counts: RowCounts::default(),
            timescale: None,
        })
    }
}

struct Fixture {
    svc: Arc<AgentLifecycleServiceImpl>,
    registry: Arc<AgentRegistry>,
    storage: Arc<GatedStorage>,
    key: String,
    kp: Arc<AgentKeypair>,
    id: ProtoAgentId,
}

fn fixture(name: &str) -> Fixture {
    let key = ApiKey::generate();
    let entry = ApiKeyEntry {
        id: "inflight".into(),
        key_hash: key.hash().unwrap(),
        scopes: vec![Scope::Read],
        created_at: 0,
        expires_at: None,
        label: None,
        team_id: None,
        org_id: Some("acme".into()),
        key_lookup: Some(key.lookup()),
    };
    let storage = Arc::new(GatedStorage {
        entered: tokio::sync::Notify::new(),
        gate: tokio::sync::Semaphore::new(0),
        block: AtomicBool::new(true),
        fail: AtomicBool::new(true),
    });
    let registry = Arc::new(AgentRegistry::new().with_storage(storage.clone()));
    let svc = Arc::new(
        AgentLifecycleServiceImpl::new(Arc::clone(&registry))
            .with_org_binder(OrgBinder::new(Arc::new(ApiKeyStore::from_entries(vec![entry])))),
    );
    let kp = Arc::new(AgentKeypair::derive_transport_key(name));
    let id = ProtoAgentId {
        org_id: String::new(),
        team_id: "team-1".into(),
        agent_id: kp.did_key(),
    };
    Fixture {
        svc,
        registry,
        storage,
        key: key.as_str().to_owned(),
        kp,
        id,
    }
}

impl Fixture {
    fn registry_key(&self) -> [u8; 16] {
        proto_agent_id_to_key(&ProtoAgentId {
            org_id: "acme".into(),
            ..self.id.clone()
        })
    }

    /// Register under the org-bound key; a fresh challenge each call.
    fn register(&self) -> impl std::future::Future<Output = Result<RegisterResponse, Status>> + Send + 'static {
        let (svc, kp, id, key) = (
            Arc::clone(&self.svc),
            Arc::clone(&self.kp),
            self.id.clone(),
            self.key.clone(),
        );
        async move {
            let nonce = svc
                .request_challenge(Request::new(ChallengeRequest {
                    agent_id: Some(id.clone()),
                    public_key: kp.public_key_hex(),
                }))
                .await?
                .into_inner()
                .nonce;
            let mut req = Request::new(RegisterRequest {
                agent_id: Some(id),
                name: "agent".into(),
                framework: "custom".into(),
                version: "1".into(),
                public_key: kp.public_key_hex(),
                possession_proof: kp.sign(&nonce).to_vec(),
                registration_nonce: nonce,
                ..Default::default()
            });
            req.metadata_mut()
                .insert(REGISTRATION_KEY_METADATA_KEY, key.parse().unwrap());
            svc.register(req).await.map(|r| r.into_inner())
        }
    }
}

/// A first registration whose durable write blocks and then fails: while it is in
/// flight an authorized re-bind is refused (no credential for an uncommitted record);
/// after the failure the record is gone and a later registration succeeds and can then
/// be re-bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_rebind_during_a_failing_persist_gets_no_credential() {
    let f = fixture("inflight-fail");
    let first = tokio::spawn(f.register());
    f.storage.entered.notified().await;
    assert!(
        f.registry.get(&f.registry_key()).is_some(),
        "precondition: the record is in memory before its durable write finishes"
    );

    let err = f
        .register()
        .await
        .expect_err("an authorized re-bind of an uncommitted record");
    assert_eq!(err.code(), Code::AlreadyExists, "{err:?}");
    let leaked = f
        .registry
        .get(&f.registry_key())
        .map(|r| r.credential_token)
        .unwrap_or_default();
    assert!(
        !leaked.is_empty() && !err.message().contains(&leaked),
        "no credential in the refusal"
    );

    f.storage.gate.add_permits(1);
    let failed = first.await.unwrap().expect_err("the durable write failed");
    assert_eq!(failed.code(), Code::Internal, "{failed:?}");
    assert!(f.registry.get(&f.registry_key()).is_none(), "the record is rolled back");

    f.storage.block.store(false, Ordering::SeqCst);
    f.storage.fail.store(false, Ordering::SeqCst);
    let registered = f.register().await.expect("a later registration succeeds");
    let rebound = f.register().await.expect("and is then re-bindable");
    assert_eq!(rebound.credential_token, registered.credential_token);
}

/// tonic drops the handler future when the client goes away. Dropped between the
/// in-memory insert and the durable write, it must not leave a record that a later
/// authorized re-bind would return.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_registration_leaves_no_record_to_rebind() {
    let f = fixture("inflight-cancel");
    let first = tokio::spawn(f.register());
    f.storage.entered.notified().await;
    assert!(
        f.registry.get(&f.registry_key()).is_some(),
        "precondition: inserted, write outstanding"
    );

    first.abort();
    let _ = first.await;
    assert!(
        f.registry.get(&f.registry_key()).is_none(),
        "the abandoned registration's record must be removed"
    );

    f.storage.block.store(false, Ordering::SeqCst);
    f.storage.fail.store(false, Ordering::SeqCst);
    let again = f
        .register()
        .await
        .expect("a fresh registration after the cancelled one");
    assert_eq!(
        f.registry.get(&f.registry_key()).unwrap().credential_token,
        again.credential_token
    );
    assert_eq!(f.registry.list().len(), 1);
}
