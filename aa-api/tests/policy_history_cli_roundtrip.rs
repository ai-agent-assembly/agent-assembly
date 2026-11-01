//! AAASM-6430: `aasm policy apply` -> `history` -> `rollback` against a real
//! in-process API server, with the CLI and the server sharing one
//! `AA_DATA_DIR`. Before the fix the CLI listed no history and rollback failed
//! with "version not found"; and a rollback that reached the store only wrote a
//! local snapshot, leaving the server's active policy unchanged.

use std::process::ExitCode;

use aa_api::state::{AppState, LocalAuth, LocalDurablePaths};
use aa_cli::commands::policy::history::{self, ApplyArgs, HistoryArgs, RollbackArgs};
use aa_gateway::policy::history::{FsHistoryStore, PolicyHistoryStore};
use sha2::{Digest, Sha256};

fn policy(name: &str, version: &str, limit: f64) -> String {
    format!(
        "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: {name}\n  version: \"{version}\"\n\
         spec:\n  budget:\n    daily_limit_usd: {limit}\n"
    )
}

/// The version string `aasm policy apply` prints: the first 12 hex chars of the
/// policy text's SHA-256.
fn printed_version(yaml: &str) -> String {
    hex::encode(Sha256::digest(yaml.as_bytes()))[..12].to_string()
}

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread")]
async fn rollback_by_printed_version_changes_the_active_policy() {
    let _g = ENV_LOCK.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("AA_DATA_DIR", tmp.path().join("data"));
    std::env::set_var("AA_AUDIT_DIR", tmp.path().join("audit-jsonl"));
    std::env::set_var("HOME", tmp.path());

    let mut paths = LocalDurablePaths::resolve().expect("resolve");
    paths.registry_db = tmp.path().join("local.db");
    paths.audit_db = tmp.path().join("audit.db");
    let state = AppState::local_hardened_at(LocalAuth::Off, paths).await.expect("state");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = aa_api::server::build_app(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let first = policy("first-policy", "1.0.0", 10.0);
    let second = policy("second-policy", "2.0.0", 20.0);
    let first_path = tmp.path().join("first.yaml");
    let second_path = tmp.path().join("second.yaml");
    std::fs::write(&first_path, &first).unwrap();
    std::fs::write(&second_path, &second).unwrap();
    let ctx = aa_cli::config::ResolvedContext {
        name: None,
        api_url: format!("http://{addr}"),
        api_key: None,
    };

    // The CLI functions own a tokio runtime, so they run off the test's runtime.
    let first_version = printed_version(&first);
    let ctx2 = ctx.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let apply = |file| history::run_apply(ApplyArgs { file, applied_by: None }, &ctx2);
        assert_eq!(apply(first_path), ExitCode::SUCCESS);
        // The history timestamp has millisecond resolution; keep the two applies
        // distinguishable so newest-first ordering is unambiguous.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(apply(second_path), ExitCode::SUCCESS);
        let listed = history::run_history(HistoryArgs { limit: 10 });
        let rolled = history::run_rollback(RollbackArgs { version: first_version }, &ctx2);
        (listed, rolled)
    })
    .await
    .unwrap();
    assert_eq!(outcome.0, ExitCode::SUCCESS);

    // What `aasm policy history` lists is the CLI-default store: it must hold both
    // applies plus the rollback's re-apply, newest first.
    let cli_store = FsHistoryStore::with_defaults().expect("cli store");
    let versions = cli_store.list(10).await.expect("list");
    assert_eq!(versions.len(), 3, "both applies and the rollback: {versions:?}");
    assert_eq!(versions[0].sha256[..12], printed_version(&first));
    assert_eq!(versions[1].sha256[..12], printed_version(&second));

    // The rollback is judged by the ACTIVE policy, not by its success message.
    assert_eq!(outcome.1, ExitCode::SUCCESS, "rollback of a stored version succeeds");
    assert_eq!(
        state.policy_engine.active_policy_info().name.as_deref(),
        Some("first-policy"),
        "the running server's active policy must be the rolled-back one"
    );
}
