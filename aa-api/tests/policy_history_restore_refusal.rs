//! AAASM-6430: start-up re-installs the newest policy history entry, and must
//! fail closed rather than run the broader bootstrap policy (or grant more
//! authority than the HTTP apply route would) when it cannot.

use aa_api::state::{AppState, LocalAuth, LocalDurablePaths, LocalStateError};
use aa_gateway::policy::history::{FsHistoryStore, HistoryConfig, PolicyHistoryStore};

fn policy(name: &str, scope_line: &str) -> String {
    format!(
        "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: {name}\n  version: \"1.0.0\"\n\
         spec:\n{scope_line}  budget:\n    daily_limit_usd: 10.0\n"
    )
}

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A tempdir wired as `AA_DATA_DIR`, with `AA_POLICY` cleared, and its history store.
struct Fixture {
    tmp: tempfile::TempDir,
    store: FsHistoryStore,
    paths: LocalDurablePaths,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("AA_DATA_DIR", tmp.path().join("data"));
    std::env::set_var("AA_AUDIT_DIR", tmp.path().join("audit-jsonl"));
    std::env::set_var("HOME", tmp.path());
    std::env::remove_var("AA_POLICY");
    let mut paths = LocalDurablePaths::resolve().expect("resolve");
    paths.registry_db = tmp.path().join("local.db");
    paths.audit_db = tmp.path().join("audit.db");
    let store = FsHistoryStore::new(HistoryConfig {
        history_dir: paths.policy_history_dir.clone(),
        max_versions: 50,
    });
    Fixture { tmp, store, paths }
}

#[tokio::test]
async fn a_scoped_document_in_history_is_refused_not_installed_globally() {
    let _g = ENV_LOCK.lock().await;
    let f = fixture();
    f.store
        .save(&policy("scoped", "  scope: team:team-alpha\n"), None)
        .await
        .expect("seed");

    let err = AppState::local_hardened_at(LocalAuth::Off, f.paths.clone())
        .await
        .err()
        .expect("a scoped document must not be installed at boot");
    let msg = err.to_string();
    assert!(matches!(err, LocalStateError::PolicyHistoryRestore { .. }), "{msg}");
    assert!(msg.contains("team:team-alpha"), "{msg}");
    assert!(msg.contains(&f.paths.policy_history_dir.display().to_string()), "{msg}");
}

#[tokio::test]
async fn a_corrupt_newest_entry_is_refused_and_named() {
    let _g = ENV_LOCK.lock().await;
    let f = fixture();
    f.store.save(&policy("good", ""), None).await.expect("seed");
    // A newer entry whose metadata is not valid JSON (names sort by timestamp).
    let bad = f
        .paths
        .policy_history_dir
        .join("9999-01-01T000000000Z-badbadbadbad.meta.json");
    std::fs::write(&bad, "{ not json").expect("write corrupt entry");

    let err = AppState::local_hardened_at(LocalAuth::Off, f.paths.clone())
        .await
        .err()
        .expect("a corrupt newest entry must refuse start-up");
    let msg = err.to_string();
    assert!(matches!(err, LocalStateError::PolicyHistoryRestore { .. }), "{msg}");
    assert!(msg.contains(&f.paths.policy_history_dir.display().to_string()), "{msg}");
    assert!(
        msg.contains("badbadbadbad.meta.json"),
        "names the offending file: {msg}"
    );
    assert!(
        !msg.contains("bootstrap policy: "),
        "not the misleading bootstrap wording: {msg}"
    );
}

#[tokio::test]
async fn aa_policy_stays_the_startup_policy_and_history_is_not_reinstalled() {
    let _g = ENV_LOCK.lock().await;
    let f = fixture();
    f.store.save(&policy("from-history", ""), None).await.expect("seed");
    let operator = f.tmp.path().join("operator.yaml");
    std::fs::write(&operator, policy("operator-policy", "")).expect("write operator policy");
    std::env::set_var("AA_POLICY", &operator);

    let state = AppState::local_hardened_at(LocalAuth::Off, f.paths.clone())
        .await
        .expect("boot");
    std::env::remove_var("AA_POLICY");
    assert_eq!(
        state.policy_engine.active_policy_info().name.as_deref(),
        Some("operator-policy"),
        "the operator-configured policy must remain the enforced one"
    );
}
