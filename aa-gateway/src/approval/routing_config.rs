//! Team-level approval routing configuration and its JSON-backed store.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Routing configuration for a single team.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TeamRoutingConfig {
    /// Team identifier (matches `AgentContext.team_id`).
    pub team_id: String,
    /// Ordered list of approver identifiers (e.g. user IDs, role names).
    pub approvers: Vec<String>,
    /// Seconds to wait for this team's approvers before escalating.
    pub escalation_timeout_secs: u64,
    /// Approver identifiers to notify after escalation.
    pub escalation_approvers: Vec<String>,
}

/// Top-level container persisted to disk as JSON.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct PersistedRoutingConfig {
    teams: Vec<TeamRoutingConfig>,
}

// ---------------------------------------------------------------------------
// RoutingConfigStore
// ---------------------------------------------------------------------------

/// In-memory routing configuration store backed by a JSON file.
///
/// Load with [`RoutingConfigStore::load`]; mutate and persist with
/// [`RoutingConfigStore::upsert`] / [`RoutingConfigStore::remove`].
#[derive(Debug, Clone)]
pub struct RoutingConfigStore {
    path: PathBuf,
    configs: HashMap<String, TeamRoutingConfig>,
}

impl RoutingConfigStore {
    /// Load from `path`, creating an empty store if the file does not exist.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, RoutingConfigError> {
        let path = path.into();
        let configs = match std::fs::read_to_string(&path) {
            Ok(json) => {
                let persisted: PersistedRoutingConfig =
                    serde_json::from_str(&json).map_err(RoutingConfigError::Json)?;
                persisted
                    .teams
                    .into_iter()
                    .map(|c| (c.team_id.clone(), c))
                    .collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(RoutingConfigError::Io(e)),
        };
        Ok(Self { path, configs })
    }

    /// Look up the routing configuration for a team by ID.
    pub fn get(&self, team_id: &str) -> Option<&TeamRoutingConfig> {
        self.configs.get(team_id)
    }

    /// Insert or replace the configuration for a team, then atomically persist.
    pub fn upsert(&mut self, config: TeamRoutingConfig) -> Result<(), RoutingConfigError> {
        self.configs.insert(config.team_id.clone(), config);
        self.save()
    }

    /// Remove a team's configuration, then atomically persist.
    pub fn remove(&mut self, team_id: &str) -> Result<bool, RoutingConfigError> {
        let removed = self.configs.remove(team_id).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Returns an iterator over all team configurations.
    pub fn iter(&self) -> impl Iterator<Item = &TeamRoutingConfig> {
        self.configs.values()
    }

    /// Atomically write the current state to disk (write-to-temp + rename).
    fn save(&self) -> Result<(), RoutingConfigError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(RoutingConfigError::Io)?;
        }
        let persisted = PersistedRoutingConfig {
            teams: self.configs.values().cloned().collect(),
        };
        let json = serde_json::to_string_pretty(&persisted).map_err(RoutingConfigError::Json)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json).map_err(RoutingConfigError::Io)?;
        std::fs::rename(&tmp, &self.path).map_err(RoutingConfigError::Io)?;
        Ok(())
    }
}

/// Returns `~/.aa/approval_routing.json`.
pub fn default_routing_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".aa").join("approval_routing.json")
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RoutingConfigError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for RoutingConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "routing config I/O error: {e}"),
            Self::Json(e) => write!(f, "routing config JSON error: {e}"),
        }
    }
}

impl std::error::Error for RoutingConfigError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sample_config(team_id: &str) -> TeamRoutingConfig {
        TeamRoutingConfig {
            team_id: team_id.to_string(),
            approvers: vec!["alice".to_string(), "bob".to_string()],
            escalation_timeout_secs: 300,
            escalation_approvers: vec!["manager".to_string()],
        }
    }

    fn temp_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "approval_routing_test_{}.json",
            uuid::Uuid::new_v4()
        ));
        p
    }

    #[test]
    fn load_missing_file_returns_empty_store() {
        let path = temp_path();
        let store = RoutingConfigStore::load(&path).unwrap();
        assert_eq!(store.configs.len(), 0);
    }

    #[test]
    fn upsert_and_get_roundtrip() {
        let path = temp_path();
        let mut store = RoutingConfigStore::load(&path).unwrap();
        store.upsert(sample_config("team-a")).unwrap();

        let got = store.get("team-a").unwrap();
        assert_eq!(got.approvers, vec!["alice", "bob"]);
        assert_eq!(got.escalation_timeout_secs, 300);
    }

    #[test]
    fn upsert_persists_to_disk_and_reload_recovers() {
        let path = temp_path();
        {
            let mut store = RoutingConfigStore::load(&path).unwrap();
            store.upsert(sample_config("team-b")).unwrap();
        }
        let store2 = RoutingConfigStore::load(&path).unwrap();
        assert!(store2.get("team-b").is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_existing_entry_returns_true_and_persists() {
        let path = temp_path();
        let mut store = RoutingConfigStore::load(&path).unwrap();
        store.upsert(sample_config("team-c")).unwrap();
        let removed = store.remove("team-c").unwrap();
        assert!(removed);
        assert!(store.get("team-c").is_none());

        let store2 = RoutingConfigStore::load(&path).unwrap();
        assert!(store2.get("team-c").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_absent_entry_returns_false() {
        let path = temp_path();
        let mut store = RoutingConfigStore::load(&path).unwrap();
        let removed = store.remove("nonexistent").unwrap();
        assert!(!removed);
    }

    #[test]
    fn get_unknown_team_returns_none() {
        let path = temp_path();
        let store = RoutingConfigStore::load(&path).unwrap();
        assert!(store.get("ghost-team").is_none());
    }

    #[test]
    fn upsert_overwrites_previous_config() {
        let path = temp_path();
        let mut store = RoutingConfigStore::load(&path).unwrap();
        store.upsert(sample_config("team-d")).unwrap();
        let updated = TeamRoutingConfig {
            team_id: "team-d".to_string(),
            approvers: vec!["carol".to_string()],
            escalation_timeout_secs: 600,
            escalation_approvers: vec![],
        };
        store.upsert(updated).unwrap();
        let got = store.get("team-d").unwrap();
        assert_eq!(got.approvers, vec!["carol"]);
        assert_eq!(got.escalation_timeout_secs, 600);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_corrupt_json_returns_error() {
        let path = temp_path();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"not valid json").unwrap();
        assert!(RoutingConfigStore::load(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn iter_returns_all_configs() {
        let path = temp_path();
        let mut store = RoutingConfigStore::load(&path).unwrap();
        store.upsert(sample_config("t1")).unwrap();
        store.upsert(sample_config("t2")).unwrap();
        let mut ids: Vec<_> = store.iter().map(|c| c.team_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["t1", "t2"]);
        let _ = std::fs::remove_file(&path);
    }
}
