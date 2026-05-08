//! Background task that fires escalation when an approval request exceeds
//! the team's escalation timeout without a decision.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::broadcast;

use aa_runtime::approval::ApprovalRequestId;

// ---------------------------------------------------------------------------
// PersistedEscalation  (restart-safe state)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedEscalation {
    pub request_id: ApprovalRequestId,
    pub team_id: String,
    pub escalation_approvers: Vec<String>,
    /// Unix epoch (seconds) at which escalation should fire.
    pub escalate_at: u64,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct PersistedEscalations {
    pending: Vec<PersistedEscalation>,
}

// ---------------------------------------------------------------------------
// EscalationEvent  (broadcast notification)
// ---------------------------------------------------------------------------

/// Notification emitted when an escalation fires.
#[derive(Debug, Clone)]
pub struct EscalationEvent {
    pub request_id: ApprovalRequestId,
    pub team_id: String,
    pub escalation_approvers: Vec<String>,
}

// ---------------------------------------------------------------------------
// EscalationScheduler
// ---------------------------------------------------------------------------

/// Tracks pending escalations and fires them on schedule.
///
/// Call [`EscalationScheduler::register`] when a request is routed to a team.
/// The background task (started via [`EscalationScheduler::run`]) checks every
/// `poll_interval` and fires any overdue escalations.
pub struct EscalationScheduler {
    path: PathBuf,
    state: Arc<Mutex<HashMap<ApprovalRequestId, PersistedEscalation>>>,
    event_tx: broadcast::Sender<EscalationEvent>,
    poll_interval: Duration,
}

impl EscalationScheduler {
    /// Create a new scheduler, loading any restart-safe state from `path`.
    pub fn new(
        path: impl Into<PathBuf>,
        event_tx: broadcast::Sender<EscalationEvent>,
        poll_interval: Duration,
    ) -> Result<Self, EscalationError> {
        let path = path.into();
        let initial = load_escalations(&path)?;
        let state = Arc::new(Mutex::new(
            initial
                .into_iter()
                .map(|e| (e.request_id, e))
                .collect::<HashMap<_, _>>(),
        ));
        Ok(Self {
            path,
            state,
            event_tx,
            poll_interval,
        })
    }

    /// Subscribe to escalation events.
    pub fn subscribe(&self) -> broadcast::Receiver<EscalationEvent> {
        self.event_tx.subscribe()
    }

    /// Schedule an escalation for `request_id` to fire after `timeout_secs`.
    pub fn register(
        &self,
        request_id: ApprovalRequestId,
        team_id: String,
        escalation_approvers: Vec<String>,
        timeout_secs: u64,
    ) -> Result<(), EscalationError> {
        let now = current_epoch_secs();
        let entry = PersistedEscalation {
            request_id,
            team_id,
            escalation_approvers,
            escalate_at: now + timeout_secs,
        };
        {
            let mut state = self.state.lock().unwrap();
            state.insert(request_id, entry);
        }
        self.persist()
    }

    /// Remove the escalation for `request_id` (call when request is resolved).
    pub fn cancel(&self, request_id: ApprovalRequestId) -> Result<bool, EscalationError> {
        let removed = {
            let mut state = self.state.lock().unwrap();
            state.remove(&request_id).is_some()
        };
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Fire overdue escalations; called by the background loop.
    ///
    /// Exposed as `pub` so callers can force an immediate check in tests or
    /// administrative tooling without waiting for the polling interval.
    pub fn tick(&self) {
        let now = current_epoch_secs();
        let overdue: Vec<PersistedEscalation> = {
            let mut state = self.state.lock().unwrap();
            let overdue: Vec<_> = state.values().filter(|e| e.escalate_at <= now).cloned().collect();
            for e in &overdue {
                state.remove(&e.request_id);
            }
            overdue
        };
        if !overdue.is_empty() {
            let _ = self.persist();
        }
        for entry in overdue {
            tracing::info!(
                request_id = %entry.request_id,
                team_id = %entry.team_id,
                "approval escalation fired"
            );
            let _ = self.event_tx.send(EscalationEvent {
                request_id: entry.request_id,
                team_id: entry.team_id,
                escalation_approvers: entry.escalation_approvers,
            });
        }
    }

    /// Run the background polling loop until the Tokio runtime shuts down.
    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.poll_interval);
        loop {
            interval.tick().await;
            self.tick();
        }
    }

    /// Atomically persist the current escalation state to disk.
    fn persist(&self) -> Result<(), EscalationError> {
        let state = self.state.lock().unwrap();
        let persisted = PersistedEscalations {
            pending: state.values().cloned().collect(),
        };
        drop(state);
        save_escalations(&self.path, &persisted)
    }
}

// ---------------------------------------------------------------------------
// Disk I/O helpers
// ---------------------------------------------------------------------------

fn load_escalations(path: &Path) -> Result<Vec<PersistedEscalation>, EscalationError> {
    match std::fs::read_to_string(path) {
        Ok(json) => {
            let p: PersistedEscalations = serde_json::from_str(&json).map_err(EscalationError::Json)?;
            Ok(p.pending)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(EscalationError::Io(e)),
    }
}

fn save_escalations(path: &Path, state: &PersistedEscalations) -> Result<(), EscalationError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(EscalationError::Io)?;
    }
    let json = serde_json::to_string_pretty(state).map_err(EscalationError::Json)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).map_err(EscalationError::Io)?;
    std::fs::rename(&tmp, path).map_err(EscalationError::Io)?;
    Ok(())
}

fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum EscalationError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for EscalationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "escalation I/O error: {e}"),
            Self::Json(e) => write!(f, "escalation JSON error: {e}"),
        }
    }
}

impl std::error::Error for EscalationError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("escalation_test_{}.json", Uuid::new_v4()));
        p
    }

    fn make_scheduler() -> (Arc<EscalationScheduler>, broadcast::Receiver<EscalationEvent>) {
        let (tx, rx) = broadcast::channel(16);
        let s = Arc::new(EscalationScheduler::new(temp_path(), tx, Duration::from_millis(50)).unwrap());
        (s, rx)
    }

    #[test]
    fn register_then_cancel_returns_true() {
        let (s, _rx) = make_scheduler();
        let id = Uuid::new_v4();
        s.register(id, "team-a".to_string(), vec!["mgr".to_string()], 300)
            .unwrap();
        assert!(s.cancel(id).unwrap());
        assert!(!s.cancel(id).unwrap());
    }

    #[test]
    fn cancel_nonexistent_returns_false() {
        let (s, _rx) = make_scheduler();
        assert!(!s.cancel(Uuid::new_v4()).unwrap());
    }

    #[test]
    fn register_persists_to_disk() {
        let path = temp_path();
        let (tx, _rx) = broadcast::channel(4);
        let s = Arc::new(EscalationScheduler::new(&path, tx, Duration::from_millis(50)).unwrap());
        let id = Uuid::new_v4();
        s.register(id, "team-b".to_string(), vec![], 600).unwrap();

        let loaded = load_escalations(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].request_id, id);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn overdue_entry_fires_event() {
        let path = temp_path();
        let (tx, mut rx) = broadcast::channel(4);
        let s = Arc::new(EscalationScheduler::new(&path, tx, Duration::from_millis(50)).unwrap());
        let id = Uuid::new_v4();
        // timeout_secs = 0 → immediately overdue
        s.register(id, "team-c".to_string(), vec!["mgr".to_string()], 0)
            .unwrap();
        s.tick();
        let event = rx.try_recv().unwrap();
        assert_eq!(event.request_id, id);
        assert_eq!(event.team_id, "team-c");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn not_yet_overdue_does_not_fire() {
        let (s, mut rx) = make_scheduler();
        let id = Uuid::new_v4();
        // 1 hour in the future
        s.register(id, "team-d".to_string(), vec![], 3600).unwrap();
        s.tick();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn reload_restores_registered_entry() {
        let path = temp_path();
        let (tx, _rx) = broadcast::channel(4);
        let s = Arc::new(EscalationScheduler::new(&path, tx, Duration::from_millis(50)).unwrap());
        let id = Uuid::new_v4();
        s.register(id, "team-e".to_string(), vec![], 120).unwrap();
        drop(s);

        let (tx2, _rx2) = broadcast::channel(4);
        let s2 = Arc::new(EscalationScheduler::new(&path, tx2, Duration::from_millis(50)).unwrap());
        assert!(s2.cancel(id).unwrap());
        let _ = std::fs::remove_file(&path);
    }
}
