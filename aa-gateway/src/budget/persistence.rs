//! Atomic disk persistence for budget state.

use crate::budget::types::BudgetState;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedAgentEntry {
    pub agent_id_hex: String,
    pub state: BudgetState,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedBudget {
    pub per_agent: Vec<PersistedAgentEntry>,
    #[serde(default)]
    pub team_budgets: std::collections::HashMap<String, BudgetState>,
    pub global: BudgetState,
    #[serde(default = "default_timezone")]
    pub timezone: chrono_tz::Tz,
}

fn default_timezone() -> chrono_tz::Tz {
    chrono_tz::UTC
}

/// Error type for persistence I/O operations.
#[derive(Debug)]
pub enum PersistenceError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceError::Io(e) => write!(f, "budget I/O error: {e}"),
            PersistenceError::Json(e) => write!(f, "budget JSON error: {e}"),
        }
    }
}

impl std::error::Error for PersistenceError {}

/// Returns `~/.aa/budget.json` (uses `$HOME` env var; falls back to `.`).
pub fn default_budget_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".aa").join("budget.json")
}

/// Load persisted budget from disk. Returns an empty budget on `NotFound`.
pub fn load_from_disk(path: &std::path::Path) -> Result<PersistedBudget, PersistenceError> {
    match std::fs::read_to_string(path) {
        Ok(json) => serde_json::from_str(&json).map_err(PersistenceError::Json),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PersistedBudget {
            per_agent: vec![],
            team_budgets: Default::default(),
            global: crate::budget::types::BudgetState::new_today(),
            timezone: default_timezone(),
        }),
        Err(e) => Err(PersistenceError::Io(e)),
    }
}

/// Write budget to path atomically: write to `<path>.json.tmp`, then rename.
pub fn save_to_disk_atomic(path: &std::path::Path, budget: &PersistedBudget) -> Result<(), PersistenceError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(PersistenceError::Io)?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(budget).map_err(PersistenceError::Json)?;
    std::fs::write(&tmp, &json).map_err(PersistenceError::Io)?;
    std::fs::rename(&tmp, path).map_err(PersistenceError::Io)?;
    Ok(())
}

/// Spawn a tokio task that saves tracker state every 60 seconds.
pub fn start_background_writer(
    tracker: std::sync::Arc<crate::budget::tracker::BudgetTracker>,
    path: std::path::PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let snapshot = tracker.snapshot();
            if let Err(e) = save_to_disk_atomic(&path, &snapshot) {
                eprintln!("aa-gateway budget: persistence error: {e}");
            }
        }
    })
}

/// Encode an `AgentId` as a 32-char lowercase hex string.
pub fn agent_id_to_hex(id: &aa_core::AgentId) -> String {
    id.as_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a 32-char hex string back to an `AgentId`.
pub fn hex_to_agent_id(hex: &str) -> Result<aa_core::AgentId, PersistenceError> {
    if hex.len() != 32 {
        return Err(PersistenceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected 32 hex chars, got {}", hex.len()),
        )));
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(aa_core::AgentId::from_bytes(bytes))
}

fn hex_nibble(b: u8) -> Result<u8, PersistenceError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(PersistenceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid hex byte: {b}"),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::types::BudgetState;

    #[test]
    fn persisted_agent_entry_stores_hex_and_state() {
        let entry = PersistedAgentEntry {
            agent_id_hex: "aabbcc".to_string(),
            state: BudgetState::new_today(),
        };
        assert_eq!(entry.agent_id_hex, "aabbcc");
    }

    #[test]
    fn default_budget_path_ends_with_budget_json() {
        let p = default_budget_path();
        assert!(p.to_string_lossy().ends_with("budget.json"));
    }

    #[test]
    fn persistence_error_io_displays_message() {
        let e = PersistenceError::Io(std::io::Error::other("disk full"));
        assert!(e.to_string().contains("budget I/O error"));
    }

    #[test]
    fn load_from_disk_returns_empty_on_missing_file() {
        let p = std::path::Path::new("/nonexistent/budget.json");
        let b = load_from_disk(p).unwrap();
        assert!(b.per_agent.is_empty());
    }

    #[test]
    fn save_then_load_round_trips_decimal_precisely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.json");
        let budget = PersistedBudget {
            per_agent: vec![PersistedAgentEntry {
                agent_id_hex: "0102030405060708090a0b0c0d0e0f10".to_string(),
                state: {
                    let mut s = crate::budget::types::BudgetState::new_for_date(chrono::Utc::now().date_naive());
                    s.spent_usd = "12.345".parse().unwrap();
                    s
                },
            }],
            team_budgets: Default::default(),
            global: crate::budget::types::BudgetState::new_today(),
            timezone: chrono_tz::UTC,
        };
        save_to_disk_atomic(&path, &budget).unwrap();
        let loaded = load_from_disk(&path).unwrap();
        assert_eq!(loaded.per_agent[0].state.spent_usd, budget.per_agent[0].state.spent_usd);
    }

    #[test]
    fn save_to_disk_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.json");
        save_to_disk_atomic(
            &path,
            &PersistedBudget {
                per_agent: vec![],
                team_budgets: Default::default(),
                global: crate::budget::types::BudgetState::new_today(),
                timezone: chrono_tz::UTC,
            },
        )
        .unwrap();
        assert!(path.exists());
    }

    #[test]
    fn persisted_budget_holds_entries_and_global() {
        let budget = PersistedBudget {
            per_agent: vec![],
            team_budgets: Default::default(),
            global: BudgetState::new_today(),
            timezone: chrono_tz::UTC,
        };
        assert!(budget.per_agent.is_empty());
    }

    #[test]
    fn agent_id_hex_round_trip() {
        use aa_core::AgentId;
        let id = AgentId::from_bytes([0xABu8; 16]);
        let hex = agent_id_to_hex(&id);
        assert_eq!(hex.len(), 32);
        let restored = hex_to_agent_id(&hex).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn start_background_writer_returns_join_handle() {
        use crate::budget::{pricing::PricingTable, tracker::BudgetTracker};
        use std::sync::Arc;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let tracker = Arc::new(BudgetTracker::new(
                PricingTable::default_table(),
                None,
                None,
                chrono_tz::UTC,
            ));
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("budget.json");
            let handle = start_background_writer(tracker, path);
            handle.abort(); // immediately abort — just verifying it compiles and starts
        });
    }

    #[test]
    fn save_then_load_round_trips_timezone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.json");
        let budget = PersistedBudget {
            per_agent: vec![],
            team_budgets: Default::default(),
            global: crate::budget::types::BudgetState::new_today(),
            timezone: chrono_tz::Asia::Tokyo,
        };
        save_to_disk_atomic(&path, &budget).unwrap();
        let loaded = load_from_disk(&path).unwrap();
        assert_eq!(loaded.timezone, chrono_tz::Asia::Tokyo);
    }

    #[test]
    fn load_from_disk_defaults_timezone_to_utc_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.json");
        // Write JSON without a `timezone` field (simulates old budget.json)
        std::fs::write(
            &path,
            r#"{"per_agent":[],"global":{"spent_usd":"0","date":"2024-01-01"}}"#,
        )
        .unwrap();
        let loaded = load_from_disk(&path).unwrap();
        assert_eq!(loaded.timezone, chrono_tz::UTC);
    }

    #[test]
    fn save_then_load_round_trips_monthly_fields() {
        use rust_decimal::Decimal;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.json");
        let mut state = crate::budget::types::BudgetState::new_for_date(chrono::Utc::now().date_naive());
        state.spent_usd = "5.00".parse().unwrap();
        state.monthly_spent_usd = Some("42.50".parse().unwrap());
        let budget = PersistedBudget {
            per_agent: vec![PersistedAgentEntry {
                agent_id_hex: "0102030405060708090a0b0c0d0e0f10".to_string(),
                state,
            }],
            team_budgets: Default::default(),
            global: crate::budget::types::BudgetState::new_today(),
            timezone: chrono_tz::UTC,
        };
        save_to_disk_atomic(&path, &budget).unwrap();
        let loaded = load_from_disk(&path).unwrap();
        let loaded_state = &loaded.per_agent[0].state;
        assert_eq!(loaded_state.monthly_spent_usd, Some(Decimal::new(4250, 2)));
        assert!(loaded_state.month > 0);
    }

    #[test]
    fn load_from_disk_backward_compat_missing_monthly_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.json");
        // Simulate old format without month/monthly_spent_usd fields
        std::fs::write(
            &path,
            r#"{"per_agent":[{"agent_id_hex":"01020304050607080910111213141516","state":{"spent_usd":"10.00","date":"2024-06-15"}}],"global":{"spent_usd":"10.00","date":"2024-06-15"}}"#,
        )
        .unwrap();
        let loaded = load_from_disk(&path).unwrap();
        let state = &loaded.per_agent[0].state;
        assert_eq!(state.month, 0); // default from serde(default)
        assert!(state.monthly_spent_usd.is_none());
        assert_eq!(state.spent_usd, rust_decimal::Decimal::new(1000, 2));
    }
}
