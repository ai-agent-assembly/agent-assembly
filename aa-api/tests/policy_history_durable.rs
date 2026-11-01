//! AAASM-6430: the policy history `aasm policy apply` writes through the API
//! server lives where the CLI reads it, and survives a server restart.
//!
//! The server used to keep it under a per-process temp directory, so
//! `aasm policy history` (which reads `${AA_DATA_DIR:-~/.aa}/policy-history`)
//! never saw an apply, and every restart emptied it.

use aa_api::state::{AppState, LocalAuth, LocalDurablePaths};
use aa_gateway::policy::history::HistoryConfig;

const POLICY_YAML: &str = "apiVersion: agent-assembly/v1\n\
kind: Policy\n\
metadata:\n  name: durable-history\n  version: \"1.0.0\"\n\
spec:\n  budget:\n    daily_limit_usd: 10.0\n";

/// Env is process-global; `AA_DATA_DIR`, `AA_AUDIT_DIR` and `HOME` are set for the
/// whole test and the lock keeps `cargo test` (shared process) serial.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn server_history_is_at_the_cli_location_and_survives_restart() {
    let _g = ENV_LOCK.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("data");
    std::env::set_var("AA_DATA_DIR", &data_dir);
    std::env::set_var("AA_AUDIT_DIR", tmp.path().join("audit-jsonl"));
    std::env::set_var("HOME", tmp.path());

    // Production resolution, with only the unrelated SQLite files moved into the
    // tempdir so the test never touches a developer's `~/.aasm`.
    let mut paths = LocalDurablePaths::resolve().expect("resolve");
    paths.registry_db = tmp.path().join("local.db");
    paths.audit_db = tmp.path().join("audit.db");

    let cli_dir = HistoryConfig::default_config().expect("cli config").history_dir;
    assert_eq!(cli_dir, data_dir.join("policy-history"));
    assert_eq!(
        paths.policy_history_dir, cli_dir,
        "the server must keep history in the directory the CLI reads"
    );

    let state1 = AppState::local_hardened_at(LocalAuth::Off, paths.clone())
        .await
        .expect("first boot");
    state1
        .policy_engine
        .apply_yaml(POLICY_YAML, Some("api"), state1.policy_history.as_ref())
        .await
        .expect("apply");
    drop(state1);

    // Simulated restart: a brand-new AppState over the same paths.
    let state2 = AppState::local_hardened_at(LocalAuth::Off, paths)
        .await
        .expect("second boot");
    let versions = state2.policy_history.list(10).await.expect("list");
    assert_eq!(versions.len(), 1, "history must survive a restart: {versions:?}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cli_dir).expect("history dir").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "history directory must be owner-only");
    }
}
