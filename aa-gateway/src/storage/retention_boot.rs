//! Boot-time helper that spawns the durable retention engine.
//!
//! Epic 18 Story S-I.4 (AAASM-1870). The gateway opens a
//! [`StorageBackend`] before serving requests (Story S-I.1, AAASM-1859);
//! this module wires the [`RetentionEngine`] background task onto that
//! same backend so the configured hot / warm / cold lifecycle runs on
//! schedule for the lifetime of the gateway process.
//!
//! Cross-references:
//!
//! - **AAASM-1588 closeout follow-up #1** — "Background task starts on
//!   gateway boot." This module is the wire-up site that satisfies
//!   that follow-up bullet.
//! - **AAASM-1856** added the `aa_api::AppState.retention_engine`
//!   field as a future seam for the dashboard's admin REST API. This
//!   helper hands back the same `Arc<RetentionEngine>` so when the
//!   HTTP server entrypoint is wired in (AAASM-1592), it can be
//!   threaded onto `AppState.retention_engine`.

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use aa_core::config::{ColdAction as CoreColdAction, RetentionConfig as CoreRetentionConfig};

use super::retention::ColdAction as StorageColdAction;
use super::retention_config::{RetentionConfig as StorageRetentionConfig, RetentionConfigError};
use super::retention_engine::RetentionEngine;
use super::StorageBackend;

/// Translate the `aa_core::config` retention shape into the
/// `aa_gateway::storage` shape consumed by [`RetentionEngine::new`].
///
/// The two structs carry the same data; they live in different crates
/// because aa-core stays decoupled from storage internals. This is the
/// single seam.
fn core_to_storage_retention(cfg: &CoreRetentionConfig) -> StorageRetentionConfig {
    StorageRetentionConfig {
        schedule: cfg.schedule.clone(),
        hot_days: cfg.hot_days,
        warm_days: cfg.warm_days,
        cold_action: match cfg.cold_action {
            CoreColdAction::Drop => StorageColdAction::Drop,
            CoreColdAction::Archive => StorageColdAction::Archive,
        },
        archive_url: cfg.archive_url.clone(),
        dry_run: cfg.dry_run,
    }
}

/// Build a [`RetentionEngine`] from the gateway's storage handle plus
/// the operator-configured retention policy, then spawn its background
/// loop.
///
/// The returned `Arc<RetentionEngine>` lets later wire-up (e.g.
/// `aa_api::AppState.retention_engine` from AAASM-1856) share the
/// running engine for hot-reload / `run_once` admin RPCs. The
/// `JoinHandle` is held by the boot caller so a `shutdown.cancel()`
/// can `await` clean exit before tearing down storage.
///
/// # Errors
///
/// - [`RetentionConfigError::MissingArchiveUrl`] when
///   `cold_action == Archive` but no `archive_url` is configured.
/// - [`RetentionConfigError::InvalidSchedule`] when the configured
///   cron expression cannot be parsed. Fail-fast at startup is
///   preferred over a panic on the first tick.
pub fn spawn_retention_engine(
    storage: Arc<dyn StorageBackend>,
    retention: &CoreRetentionConfig,
    shutdown: CancellationToken,
) -> Result<(Arc<RetentionEngine>, JoinHandle<()>), RetentionConfigError> {
    let storage_cfg = core_to_storage_retention(retention);
    storage_cfg.validate()?;
    let engine = Arc::new(RetentionEngine::new(storage, storage_cfg));
    let handle = engine.clone().start(shutdown)?;
    Ok((engine, handle))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::storage::{open_sqlite_backend, StorageBackend};

    fn tmp_sqlite() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("retention-boot.db");
        (tmp, path)
    }

    /// Honors AAASM-1588 closeout follow-up #1: spawn returns immediately
    /// with a JoinHandle (no blocking), and a cancellation token resolves
    /// the loop cleanly.
    #[tokio::test]
    async fn spawn_returns_handle_and_token_drives_clean_shutdown() {
        let (_tmp, db_path) = tmp_sqlite();
        let storage: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("open backend");

        // The `cron` crate requires 6-field expressions (sec min hour
        // DoM month DoW); aa-core's default uses the looser 5-field
        // form, which AAASM-1588 documents as a known divergence the
        // retention_engine validator rejects. This Sub-task does not
        // own the aa-core default — see the PR body's "explicitly
        // defers" section for the upstream fix to AAASM-1582 / S-H.
        let cfg = CoreRetentionConfig {
            schedule: "0 0 3 * * *".to_string(),
            ..CoreRetentionConfig::default()
        };
        let token = CancellationToken::new();
        let (engine, handle) = match spawn_retention_engine(storage, &cfg, token.clone()) {
            Ok(pair) => pair,
            Err(e) => panic!("spawn_retention_engine should return Ok with default config: {e:?}"),
        };

        // The engine handle should not be dropped on first poll — the
        // loop is sleeping until the next scheduled tick.
        assert!(
            !handle.is_finished(),
            "engine loop must stay alive until shutdown is signalled"
        );

        // Cancellation must resolve the loop within 2 s. The task wakes
        // out of its tokio::select! and returns.
        token.cancel();
        let drained = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(drained.is_ok(), "engine loop must exit within 2 s of shutdown signal");

        // The Arc<RetentionEngine> stays usable post-shutdown — the
        // background task is gone but the handle is reusable for any
        // future hot-reload / run_once admin calls before final teardown.
        assert!(Arc::strong_count(&engine) >= 1);
    }

    /// Invalid cron expression must fail-fast at spawn time, not panic
    /// on the first tick.
    #[tokio::test]
    async fn invalid_schedule_returns_error_before_spawn() {
        let (_tmp, db_path) = tmp_sqlite();
        let storage: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("open backend");

        let cfg = CoreRetentionConfig {
            schedule: "not a cron expression".to_string(),
            ..CoreRetentionConfig::default()
        };
        match spawn_retention_engine(storage, &cfg, CancellationToken::new()) {
            Err(RetentionConfigError::InvalidSchedule { .. }) => {}
            Err(other) => panic!("expected InvalidSchedule, got {other:?}"),
            Ok(_) => panic!("invalid schedule must surface as Err"),
        }
    }

    /// Cold-action archive without an archive_url must fail validation
    /// at startup.
    #[tokio::test]
    async fn archive_action_without_url_returns_missing_archive_url() {
        let (_tmp, db_path) = tmp_sqlite();
        let storage: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("open backend");

        let cfg = CoreRetentionConfig {
            cold_action: CoreColdAction::Archive,
            archive_url: None,
            ..CoreRetentionConfig::default()
        };
        match spawn_retention_engine(storage, &cfg, CancellationToken::new()) {
            Err(RetentionConfigError::MissingArchiveUrl) => {}
            Err(other) => panic!("expected MissingArchiveUrl, got {other:?}"),
            Ok(_) => panic!("archive without url must surface as Err"),
        }
    }
}
