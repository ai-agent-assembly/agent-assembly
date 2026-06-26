//! Background tasks that capture broadcasted alerts into the store.

use std::sync::Arc;

use tokio::sync::broadcast;

use aa_gateway::alerts::SecretAlert;
use aa_gateway::anomaly::AnomalyEvent;
use aa_gateway::budget::types::BudgetAlert;

use super::AlertStore;

/// Spawn a background task that subscribes to the budget alert broadcast
/// channel and records each alert into the given store.
///
/// The task runs until the broadcast channel is closed (all senders dropped).
/// `RecvError::Lagged` is handled gracefully by logging and continuing.
pub fn spawn_alert_capture(
    mut rx: broadcast::Receiver<BudgetAlert>,
    store: Arc<dyn AlertStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(alert) => {
                    store.record(&alert);
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!(
                        count,
                        "alert capture task lagged behind broadcast, skipped {count} alerts"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("budget alert broadcast channel closed, stopping capture task");
                    break;
                }
            }
        }
    })
}

/// Spawn a background task that subscribes to the secret-detection alert
/// broadcast channel and records each alert into the given store
/// (AAASM-1545).
///
/// Same lifecycle and error handling as [`spawn_alert_capture`].
pub fn spawn_secret_alert_capture(
    mut rx: broadcast::Receiver<SecretAlert>,
    store: Arc<dyn AlertStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(alert) => {
                    store.record_secret(&alert);
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!(
                        count,
                        "secret-alert capture task lagged behind broadcast, skipped {count} alerts"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("secret-alert broadcast channel closed, stopping capture task");
                    break;
                }
            }
        }
    })
}

/// Spawn a background task that subscribes to the anomaly-detection event
/// broadcast and records each detection into the alert store (AAASM-3384).
///
/// The gateway's anomaly engine broadcasts an [`AnomalyEvent`] on every live
/// detection (AAASM-3378). This task mirrors [`spawn_secret_alert_capture`]:
/// it drains that broadcast into the store so anomalies surface via
/// `GET /api/v1/alerts`. Same lifecycle and error handling as the sibling
/// capture tasks.
pub fn spawn_anomaly_alert_capture(
    mut rx: broadcast::Receiver<AnomalyEvent>,
    store: Arc<dyn AlertStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    store.record_anomaly(&event);
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!(
                        count,
                        "anomaly-alert capture task lagged behind broadcast, skipped {count} alerts"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("anomaly broadcast channel closed, stopping capture task");
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::store::InMemoryAlertStore;
    use aa_core::identity::AgentId;
    use aa_gateway::anomaly::types::{AnomalyResponse, AnomalyType};
    use aa_security::scanner::CredentialKind;

    /// Wait until `store` reports at least `n` alerts, or the deadline passes.
    async fn await_count(store: &Arc<InMemoryAlertStore>, n: u64) -> u64 {
        for _ in 0..100 {
            let (_, total) = store.list(100, 0);
            if total >= n {
                return total;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        store.list(100, 0).1
    }

    #[tokio::test]
    async fn budget_capture_records_then_stops_on_close() {
        let (tx, rx) = broadcast::channel(8);
        let store = Arc::new(InMemoryAlertStore::new());
        let handle = spawn_alert_capture(rx, store.clone());

        tx.send(BudgetAlert {
            agent_id: AgentId::from_bytes([1u8; 16]),
            team_id: None,
            threshold_pct: 95,
            spent_usd: 95.0,
            limit_usd: 100.0,
        })
        .unwrap();

        assert_eq!(await_count(&store, 1).await, 1);

        // Dropping the only sender closes the channel → the task exits.
        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn secret_capture_records_then_stops_on_close() {
        let (tx, rx) = broadcast::channel(8);
        let store = Arc::new(InMemoryAlertStore::new());
        let handle = spawn_secret_alert_capture(rx, store.clone());

        tx.send(SecretAlert {
            agent_id: AgentId::from_bytes([2u8; 16]),
            team_id: Some("team-x".to_string()),
            kinds: vec![CredentialKind::AwsAccessKey],
            finding_count: 1,
        })
        .unwrap();

        assert_eq!(await_count(&store, 1).await, 1);
        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn anomaly_capture_records_then_stops_on_close() {
        let (tx, rx) = broadcast::channel(8);
        let store = Arc::new(InMemoryAlertStore::new());
        let handle = spawn_anomaly_alert_capture(rx, store.clone());

        tx.send(AnomalyEvent {
            anomaly_type: AnomalyType::BehaviorSpike,
            response: AnomalyResponse::Pause,
            agent_id: AgentId::from_bytes([3u8; 16]),
            description: "spike".to_string(),
            detected_at: chrono::Utc::now(),
        })
        .unwrap();

        assert_eq!(await_count(&store, 1).await, 1);
        drop(tx);
        handle.await.unwrap();
    }
}
