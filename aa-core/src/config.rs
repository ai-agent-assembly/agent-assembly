//! Gateway deployment-mode configuration types (Epic 17, AAASM-1568).
//!
//! Configuration is loaded once at startup and threaded through the
//! application. This module is the **foundation** of Epic 17 — every
//! other story in the Epic depends on these types to decide whether
//! the gateway should boot in local-dev or remote-control-plane mode.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Errors that can occur while loading or parsing a `GatewayConfig`.
///
/// All variants carry enough context to be surfaced verbatim to an
/// operator running `aasm start`; `Display` implementations come
/// from `thiserror` so they format cleanly into log lines and CLI
/// stderr.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read the YAML config file (permission denied, or
    /// other filesystem error other than "file not found").
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    /// The YAML payload could not be deserialised into a `GatewayConfig`.
    #[error("failed to parse config YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    /// `AA_MODE` was set to something other than `local` or `remote`.
    #[error("invalid AA_MODE value: '{raw}' (expected 'local' or 'remote')")]
    InvalidMode {
        /// The unrecognised value as read from the environment.
        raw: String,
    },
    /// `AAASM_GATEWAY_PORT` was not a valid `u16`.
    #[error("invalid AAASM_GATEWAY_PORT value: '{raw}' (expected u16)")]
    InvalidPort {
        /// The unrecognised value as read from the environment.
        raw: String,
    },
    /// `AAASM_STORAGE_BACKEND` was set to something other than `sqlite`
    /// or `postgres`.
    #[error("invalid AAASM_STORAGE_BACKEND value: '{raw}' (expected 'sqlite' or 'postgres')")]
    InvalidStorageBackend {
        /// The unrecognised value as read from the environment.
        raw: String,
    },
    /// `AAASM_RETENTION_COLD_ACTION` was set to something other than
    /// `drop` or `archive`.
    #[error("invalid AAASM_RETENTION_COLD_ACTION value: '{raw}' (expected 'drop' or 'archive')")]
    InvalidColdAction {
        /// The unrecognised value as read from the environment.
        raw: String,
    },
    /// A retention env var (`AAASM_RETENTION_HOT_DAYS`,
    /// `AAASM_RETENTION_WARM_DAYS`, …) was not a non-negative integer.
    #[error("invalid {var} value: '{raw}' (expected non-negative integer)")]
    InvalidUnsignedInt {
        /// The env-var name, surfaced verbatim in the message so an
        /// operator scanning startup logs can `grep` for the variable.
        var: &'static str,
        /// The unrecognised value as read from the environment.
        raw: String,
    },
}

/// Which deployment topology the gateway should boot into.
///
/// Selected at startup from a combination of YAML config, environment
/// variables, and CLI flags. See [Epic 17 spec][epic] for the full
/// precedence rules.
///
/// [epic]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1568
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum DeploymentMode {
    /// Lightweight in-process control plane on `localhost:7391`.
    ///
    /// Zero-config developer experience: SQLite storage, embedded
    /// dashboard, no network connectivity required.
    #[default]
    Local,
    /// Independently-deployed control plane reached over the network.
    ///
    /// Agents on multiple machines all register against one gateway.
    /// PostgreSQL storage, TLS required for production.
    Remote,
}

/// Configuration for the in-process **local-dev** control plane.
///
/// All fields default to the zero-config developer values documented
/// in the Epic 17 spec. `storage_path` is stored raw; `~` is expanded
/// later by `GatewayConfig::expand_paths()` (added in AAASM-1691).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct LocalModeConfig {
    /// TCP port the local gateway listens on. Default: `7391`.
    pub port: u16,
    /// Whether to serve the dashboard SPA at the same address. Default: `true`.
    pub dashboard: bool,
    /// SQLite database path. Default: `~/.aasm/local.db` (un-expanded).
    pub storage_path: PathBuf,
}

impl Default for LocalModeConfig {
    fn default() -> Self {
        Self {
            port: 7391,
            dashboard: true,
            storage_path: PathBuf::from("~/.aasm/local.db"),
        }
    }
}

/// TLS material for the remote control plane listener.
///
/// `None` on `RemoteModeConfig::tls` disables TLS (development only).
/// Production deployments must supply both files; paths are stored raw
/// and expanded by `GatewayConfig::expand_paths()` (AAASM-1691).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TlsConfig {
    /// PEM-encoded certificate chain.
    pub cert_file: PathBuf,
    /// PEM-encoded private key matching `cert_file`.
    pub key_file: PathBuf,
}

/// Configuration for the network-reachable **remote** control plane.
///
/// Defaults bind to `0.0.0.0:7391` with no TLS and no database —
/// production callers must explicitly configure `tls` and
/// `database_url` before serving real traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct RemoteModeConfig {
    /// Address the gateway binds to. Default: `0.0.0.0:7391`.
    pub listen_addr: SocketAddr,
    /// TLS cert / key paths. `None` disables TLS (development only).
    pub tls: Option<TlsConfig>,
    /// PostgreSQL connection URL. `None` falls back to in-memory storage.
    pub database_url: Option<String>,
    /// Optional Redis URL used by the rate-limit and pub/sub subsystems.
    pub redis_url: Option<String>,
}

impl Default for RemoteModeConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 7391)),
            tls: None,
            database_url: None,
            redis_url: None,
        }
    }
}

/// Agent-side connection settings (used by the SDK FFI shims, not the gateway).
///
/// `gateway_url` is the address the SDK calls into. `api_key` is the
/// optional bearer token surface for authenticated SaaS deployments;
/// in local mode it is typically `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct AgentConnectConfig {
    /// Where the SDK connects. Default: `http://localhost:7391`.
    pub gateway_url: String,
    /// Optional API key for authenticated control planes.
    pub api_key: Option<String>,
}

impl Default for AgentConnectConfig {
    fn default() -> Self {
        Self {
            gateway_url: String::from("http://localhost:7391"),
            api_key: None,
        }
    }
}

/// What to do with audit-event rows once they age past the `warm_days`
/// boundary in [`RetentionConfig`].
///
/// `Drop` is the default — operators must explicitly opt into `Archive`
/// **and** supply an `archive_url` (validation enforced at startup;
/// tracked under E18 S-H / AAASM-1582).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum ColdAction {
    /// Permanently delete cold-tier rows once they pass `warm_days`.
    #[default]
    Drop,
    /// Upload cold-tier rows to the operator-configured `archive_url`
    /// (S3 / GCS / etc.) and remove them from primary storage.
    Archive,
}

/// Hot / warm / cold audit-event lifecycle parameters.
///
/// Defaults align with the SOC 2 / ISO 27001 reference window from the
/// Epic 18 spec: 30 days fully indexed (hot), 90 days
/// compressed-but-queryable (warm), then `cold_action` decides. The
/// `schedule` is a UTC cron expression — default `0 3 * * *` runs the
/// retention sweep at 03:00 UTC daily.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct RetentionConfig {
    /// Days of hot-tier retention — rows are kept fully indexed.
    pub hot_days: u32,
    /// Days of warm-tier retention before `cold_action` kicks in.
    pub warm_days: u32,
    /// What to do with rows past the warm tier.
    pub cold_action: ColdAction,
    /// Required when `cold_action = Archive`; ignored otherwise.
    pub archive_url: Option<String>,
    /// UTC cron expression for the retention sweep job.
    pub schedule: String,
    /// When `true`, the retention task logs what it *would* do without
    /// touching any data — used by operators to validate new policies
    /// before turning them on.
    pub dry_run: bool,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            hot_days: 30,
            warm_days: 90,
            cold_action: ColdAction::Drop,
            archive_url: None,
            schedule: String::from("0 3 * * *"),
            dry_run: false,
        }
    }
}

/// TimescaleDB-specific knobs for the production Postgres backend.
///
/// When `enabled = true` the gateway creates `audit_events` and
/// `metrics` as TimescaleDB hypertables on startup and installs the
/// configured compression policy. The two interval fields are
/// passed through to TimescaleDB verbatim — they accept any Postgres
/// `INTERVAL` literal (e.g. `"7 days"`, `"12 hours"`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct TimescaleConfig {
    /// Whether to enable the TimescaleDB extension on the connected
    /// Postgres instance. Setting `false` falls back to plain Postgres
    /// (no hypertables, no compression policy).
    pub enabled: bool,
    /// Hypertable time-chunk interval. Default: `"7 days"`.
    pub chunk_interval: String,
    /// Age at which chunks are auto-compressed. Default: `"30 days"`.
    pub compression_policy: String,
}

impl Default for TimescaleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            chunk_interval: String::from("7 days"),
            compression_policy: String::from("30 days"),
        }
    }
}

/// Connection pool and TimescaleDB knobs for the production Postgres
/// `StorageBackend`.
///
/// `database_url` is `None` by default so YAML configs without an
/// explicit URL fall back to the `AAASM_DATABASE_URL` env var (wired
/// in the env-override Subtask, AAASM-1735). Pool sizing defaults
/// match the spec's reference values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct PostgresConfig {
    /// PostgreSQL connection URL. Falls back to `AAASM_DATABASE_URL`
    /// (env-override layer); leaving both unset is a startup error
    /// when `storage.backend = Postgres`.
    pub database_url: Option<String>,
    /// Maximum sqlx connection-pool size. Default: `20`.
    pub max_connections: u32,
    /// Minimum sqlx connection-pool size kept warm. Default: `2`.
    pub min_connections: u32,
    /// Connection-establishment timeout in seconds. Default: `10`.
    pub connect_timeout_secs: u64,
    /// TimescaleDB-specific knobs.
    pub timescaledb: TimescaleConfig,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            database_url: None,
            max_connections: 20,
            min_connections: 2,
            connect_timeout_secs: 10,
            timescaledb: TimescaleConfig::default(),
        }
    }
}

/// Local-mode SQLite `StorageBackend` settings.
///
/// `path` is stored raw — the leading `~` is expanded by
/// `GatewayConfig::expand_paths()` (extension landing in Subtask
/// AAASM-1740). `journal_mode = "wal"` gives a better concurrent-read
/// experience for the local dashboard while a developer's gateway is
/// writing audit events.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct SqliteConfig {
    /// SQLite database path. Default: `~/.aasm/local.db` (un-expanded).
    pub path: PathBuf,
    /// SQLite `journal_mode` PRAGMA. Default: `"wal"`.
    pub journal_mode: String,
}

impl Default for SqliteConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("~/.aasm/local.db"),
            journal_mode: String::from("wal"),
        }
    }
}

/// Optional Redis policy / session cache.
///
/// `enabled = false` by default — Redis is opt-in. When the operator
/// measures policy-evaluation latency as a bottleneck they flip
/// `enabled = true` and the gateway's hot-path policy decisions get
/// a `policy_cache_ttl_secs` TTL cache in front of PostgreSQL.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct RedisConfig {
    /// Master switch — when `false`, no Redis dependency is required.
    pub enabled: bool,
    /// Redis connection URL. Falls back to `AAASM_REDIS_URL` (env
    /// override Subtask AAASM-1735); leaving both unset with
    /// `enabled = true` is a startup error.
    pub url: Option<String>,
    /// TTL in seconds for hot-path policy-decision cache entries.
    pub policy_cache_ttl_secs: u64,
    /// Maximum Redis connection-pool size. Default: `10`.
    pub max_connections: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            policy_cache_ttl_secs: 30,
            max_connections: 10,
        }
    }
}

/// Which `StorageBackend` implementation the gateway should boot.
///
/// `Sqlite` is the documented default for local-dev mode; `Postgres`
/// is required for any deployment that needs durability across gateway
/// restarts at production scale. The actual mode-aware default is
/// resolved by `GatewayConfig::resolve_storage_backend()` in Subtask
/// AAASM-1740 — this enum's `Default = Sqlite` only matters when the
/// resolver path is bypassed (e.g. direct `StorageConfig::default()`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum StorageBackendType {
    /// Embedded SQLite database — single file, no external service.
    #[default]
    Sqlite,
    /// PostgreSQL — optionally with TimescaleDB for hypertables.
    Postgres,
}

/// Durable-persistence configuration for the gateway (Epic 18).
///
/// Composes the per-engine knobs (`sqlite`, `postgres`, `redis`) with
/// retention-lifecycle parameters and a `backend` selector. Empty YAML
/// hydrates straight to `Self::default()` thanks to `#[serde(default)]`
/// on the struct itself; missing nested sections use each sub-config's
/// own `Default`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct StorageConfig {
    /// Which `StorageBackend` to instantiate at startup.
    pub backend: StorageBackendType,
    /// SQLite-specific settings (`backend = Sqlite`).
    pub sqlite: SqliteConfig,
    /// Postgres-specific settings (`backend = Postgres`).
    pub postgres: PostgresConfig,
    /// Optional Redis cache (`enabled = false` by default).
    pub redis: RedisConfig,
    /// Hot / warm / cold audit-event lifecycle policy.
    pub retention: RetentionConfig,
}

/// Top-level gateway configuration loaded at startup.
///
/// Composes the four sub-configs and a [`DeploymentMode`] flag. All
/// fields use `#[serde(default)]` so a minimal YAML — even an empty
/// document — deserialises into the documented defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct GatewayConfig {
    /// Which topology to boot — local-dev or remote control-plane.
    pub mode: DeploymentMode,
    /// Settings for `mode = Local`.
    pub local: LocalModeConfig,
    /// Settings for `mode = Remote`.
    pub remote: RemoteModeConfig,
    /// Settings the SDK FFI shim reads to dial the gateway.
    pub agent: AgentConnectConfig,
    /// Durable-persistence configuration (Epic 18 — AAASM-1569).
    pub storage: StorageConfig,
}

#[cfg(feature = "serde")]
impl GatewayConfig {
    /// Parse a `GatewayConfig` from a YAML string.
    ///
    /// Missing fields fall back to their documented defaults thanks to
    /// the type-level `#[serde(default)]` attribute, so an empty
    /// document (`""` or `"{}"`) deserialises to `Self::default()`.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, ConfigError> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Load a `GatewayConfig` from a YAML file on disk.
    ///
    /// A `NotFound` error returns `Self::default()` so missing
    /// `~/.aasm/config.yaml` does not break startup. Any other I/O
    /// error (permission denied, malformed YAML, etc.) propagates
    /// as `ConfigError`.
    pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(yaml) => Self::from_yaml_str(&yaml),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(ConfigError::Io(err)),
        }
    }

    /// Load `GatewayConfig` from the user's `~/.aasm/config.yaml`.
    ///
    /// Equivalent to `load_from_path(dirs::home_dir() / ".aasm/config.yaml")`.
    /// Falls back to `Self::default()` when the file is absent or the
    /// home directory cannot be resolved (e.g. `$HOME` unset in a
    /// systemd unit without `User=`).
    pub fn load_default_path() -> Result<Self, ConfigError> {
        let Some(home) = dirs::home_dir() else {
            return Ok(Self::default());
        };
        Self::load_from_path(home.join(".aasm").join("config.yaml"))
    }

    /// One-shot loader for `aasm start` and the gateway bootstrap path:
    /// read `~/.aasm/config.yaml`, expand `~` in path fields, then apply
    /// the `AA_MODE` / `AAASM_*` env-var overrides.
    ///
    /// Returns the same `ConfigError` variants as the underlying steps.
    pub fn load() -> Result<Self, ConfigError> {
        let mut cfg = Self::load_default_path()?;
        cfg.expand_paths();
        cfg.apply_env_overrides()?;
        Ok(cfg)
    }
}

impl GatewayConfig {
    /// Expand a leading `~` in every path field to the user's home directory.
    ///
    /// Touches `local.storage_path` and both `remote.tls` paths.
    /// A no-op when the home directory cannot be resolved or when
    /// no field starts with `~`. Idempotent — calling twice produces
    /// the same result as calling once.
    pub fn expand_paths(&mut self) {
        if let Some(home) = dirs::home_dir() {
            self.expand_paths_in(&home);
        }
    }

    /// Same as [`expand_paths`](Self::expand_paths) but takes an explicit home
    /// directory — used by tests so the assertion is independent of `$HOME`.
    pub(crate) fn expand_paths_in(&mut self, home: &std::path::Path) {
        self.local.storage_path = expand_tilde(&self.local.storage_path, home);
        if let Some(tls) = &mut self.remote.tls {
            tls.cert_file = expand_tilde(&tls.cert_file, home);
            tls.key_file = expand_tilde(&tls.key_file, home);
        }
    }
}

fn expand_tilde(path: &std::path::Path, home: &std::path::Path) -> PathBuf {
    match path.strip_prefix("~") {
        Ok(stripped) => home.join(stripped),
        Err(_) => path.to_path_buf(),
    }
}

impl GatewayConfig {
    /// Apply the documented `AA_MODE` / `AAASM_*` environment variables
    /// on top of `self`, overriding any fields they set.
    ///
    /// Returns `ConfigError::InvalidMode` / `ConfigError::InvalidPort`
    /// when an env var has been set to a value that cannot be parsed.
    pub fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        self.apply_env_overrides_with(|key| std::env::var(key).ok())
    }

    /// Same as [`apply_env_overrides`](Self::apply_env_overrides) but reads env
    /// vars through the supplied closure. Used by tests to inject a mock
    /// environment without touching process-global state.
    pub(crate) fn apply_env_overrides_with<F>(&mut self, get_env: F) -> Result<(), ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(raw) = get_env("AA_MODE") {
            self.mode = match raw.as_str() {
                "local" => DeploymentMode::Local,
                "remote" => DeploymentMode::Remote,
                _ => return Err(ConfigError::InvalidMode { raw }),
            };
        }
        if let Some(raw) = get_env("AAASM_GATEWAY_PORT") {
            let port: u16 = raw.parse().map_err(|_| ConfigError::InvalidPort { raw: raw.clone() })?;
            self.local.port = port;
            self.remote.listen_addr.set_port(port);
        }
        if let Some(url) = get_env("AAASM_DATABASE_URL") {
            self.storage.postgres.database_url = Some(url);
        }
        if let Some(url) = get_env("AAASM_REDIS_URL") {
            self.remote.redis_url = Some(url);
        }
        let cert = get_env("AAASM_TLS_CERT");
        let key = get_env("AAASM_TLS_KEY");
        if cert.is_some() || key.is_some() {
            let tls = self.remote.tls.get_or_insert(TlsConfig {
                cert_file: PathBuf::new(),
                key_file: PathBuf::new(),
            });
            if let Some(path) = cert {
                tls.cert_file = PathBuf::from(path);
            }
            if let Some(path) = key {
                tls.key_file = PathBuf::from(path);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_mode_default_is_local() {
        assert_eq!(DeploymentMode::default(), DeploymentMode::Local);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deployment_mode_yaml_round_trip_local() {
        let mode: DeploymentMode = serde_yaml::from_str("local").unwrap();
        assert_eq!(mode, DeploymentMode::Local);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deployment_mode_yaml_round_trip_remote() {
        let mode: DeploymentMode = serde_yaml::from_str("remote").unwrap();
        assert_eq!(mode, DeploymentMode::Remote);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deployment_mode_yaml_rejects_unknown_variant() {
        let result: Result<DeploymentMode, _> = serde_yaml::from_str("foobar");
        assert!(result.is_err(), "unknown variant should fail to deserialize");
    }

    #[test]
    fn local_mode_config_default_matches_spec() {
        let cfg = LocalModeConfig::default();
        assert_eq!(cfg.port, 7391);
        assert!(cfg.dashboard);
        assert_eq!(cfg.storage_path, PathBuf::from("~/.aasm/local.db"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn local_mode_config_yaml_overrides_port_keeps_other_defaults() {
        let cfg: LocalModeConfig = serde_yaml::from_str("port: 8080").unwrap();
        assert_eq!(cfg.port, 8080);
        assert!(cfg.dashboard, "dashboard should fall back to default");
        assert_eq!(
            cfg.storage_path,
            PathBuf::from("~/.aasm/local.db"),
            "storage_path should fall back to default"
        );
    }

    #[test]
    fn remote_mode_config_default_binds_all_interfaces() {
        let cfg = RemoteModeConfig::default();
        assert_eq!(cfg.listen_addr, SocketAddr::from(([0, 0, 0, 0], 7391)));
        assert!(cfg.tls.is_none(), "tls should be opt-in, never on by default");
        assert!(cfg.database_url.is_none());
        assert!(cfg.redis_url.is_none());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn remote_mode_config_yaml_overrides_database_keeps_other_defaults() {
        let yaml = r#"database_url: "postgres://aasm@db.internal/aasm""#;
        let cfg: RemoteModeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.database_url.as_deref(), Some("postgres://aasm@db.internal/aasm"));
        assert_eq!(cfg.listen_addr, SocketAddr::from(([0, 0, 0, 0], 7391)));
        assert!(cfg.tls.is_none());
        assert!(cfg.redis_url.is_none());
    }

    #[test]
    fn agent_connect_config_default_points_at_localhost() {
        let cfg = AgentConnectConfig::default();
        assert_eq!(cfg.gateway_url, "http://localhost:7391");
        assert!(cfg.api_key.is_none());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn agent_connect_config_yaml_round_trip() {
        let yaml = r#"
gateway_url: "https://cp.company.internal:7391"
api_key: "secret"
"#;
        let cfg: AgentConnectConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.gateway_url, "https://cp.company.internal:7391");
        assert_eq!(cfg.api_key.as_deref(), Some("secret"));
    }

    #[test]
    fn gateway_config_default_uses_local_mode_and_documented_defaults() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.mode, DeploymentMode::Local);
        assert_eq!(cfg.local.port, 7391);
        assert_eq!(cfg.remote.listen_addr, SocketAddr::from(([0, 0, 0, 0], 7391)));
        assert_eq!(cfg.agent.gateway_url, "http://localhost:7391");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn gateway_config_from_yaml_str_parses_full_epic_example() {
        let yaml = r#"
mode: remote
local:
  port: 8080
  dashboard: false
  storage_path: ~/.aasm/dev.db
remote:
  listen_addr: "127.0.0.1:7391"
  tls:
    cert_file: /etc/aasm/tls.crt
    key_file: /etc/aasm/tls.key
  database_url: "postgres://aasm@db.internal/aasm"
  redis_url: "redis://redis.internal:6379"
agent:
  gateway_url: "https://cp.company.internal:7391"
  api_key: "secret"
"#;
        let cfg = GatewayConfig::from_yaml_str(yaml).expect("valid YAML should parse");
        assert_eq!(cfg.mode, DeploymentMode::Remote);
        assert_eq!(cfg.local.port, 8080);
        assert!(!cfg.local.dashboard);
        assert_eq!(cfg.remote.listen_addr, SocketAddr::from(([127, 0, 0, 1], 7391)));
        let tls = cfg.remote.tls.expect("tls present");
        assert_eq!(tls.cert_file, PathBuf::from("/etc/aasm/tls.crt"));
        assert_eq!(tls.key_file, PathBuf::from("/etc/aasm/tls.key"));
        assert_eq!(
            cfg.remote.database_url.as_deref(),
            Some("postgres://aasm@db.internal/aasm")
        );
        assert_eq!(cfg.agent.api_key.as_deref(), Some("secret"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn gateway_config_from_yaml_str_empty_doc_returns_default() {
        let cfg = GatewayConfig::from_yaml_str("{}").unwrap();
        assert_eq!(cfg, GatewayConfig::default());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn gateway_config_load_from_missing_path_returns_default() {
        let missing = std::env::temp_dir().join("aasm-config-does-not-exist-AAASM-1691.yaml");
        // Make sure the test pre-condition holds even if a stale file lingers.
        let _ = std::fs::remove_file(&missing);
        let cfg = GatewayConfig::load_from_path(&missing).expect("missing file should not error");
        assert_eq!(cfg, GatewayConfig::default());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn gateway_config_load_from_existing_path_parses_yaml() {
        let tmp_dir = std::env::temp_dir().join("aasm-config-AAASM-1691");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let path = tmp_dir.join("config.yaml");
        std::fs::write(&path, "mode: remote\n").unwrap();
        let cfg = GatewayConfig::load_from_path(&path).expect("existing file should parse");
        assert_eq!(cfg.mode, DeploymentMode::Remote);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn expand_paths_in_resolves_tilde_in_storage_path() {
        let mut cfg = GatewayConfig::default();
        let fake_home = PathBuf::from("/srv/dev/bryant");
        cfg.expand_paths_in(&fake_home);
        assert_eq!(cfg.local.storage_path, PathBuf::from("/srv/dev/bryant/.aasm/local.db"));
    }

    #[test]
    fn expand_paths_in_resolves_tilde_in_tls_paths() {
        let mut cfg = GatewayConfig::default();
        cfg.remote.tls = Some(TlsConfig {
            cert_file: PathBuf::from("~/secrets/tls.crt"),
            key_file: PathBuf::from("~/secrets/tls.key"),
        });
        let fake_home = PathBuf::from("/srv/dev/bryant");
        cfg.expand_paths_in(&fake_home);
        let tls = cfg.remote.tls.unwrap();
        assert_eq!(tls.cert_file, PathBuf::from("/srv/dev/bryant/secrets/tls.crt"));
        assert_eq!(tls.key_file, PathBuf::from("/srv/dev/bryant/secrets/tls.key"));
    }

    #[test]
    fn expand_paths_in_is_idempotent() {
        let mut cfg = GatewayConfig::default();
        let fake_home = PathBuf::from("/srv/dev/bryant");
        cfg.expand_paths_in(&fake_home);
        let after_first = cfg.local.storage_path.clone();
        cfg.expand_paths_in(&fake_home);
        assert_eq!(cfg.local.storage_path, after_first, "second call must be a no-op");
    }

    #[test]
    fn expand_paths_in_leaves_absolute_paths_alone() {
        let mut cfg = GatewayConfig::default();
        cfg.local.storage_path = PathBuf::from("/var/lib/aasm.db");
        cfg.expand_paths_in(&PathBuf::from("/srv/dev/bryant"));
        assert_eq!(cfg.local.storage_path, PathBuf::from("/var/lib/aasm.db"));
    }

    /// Helper for env-override tests — builds a closure backed by a
    /// `HashMap`. Keeps test bodies short without bumping into the
    /// borrow checker when mapping `&[(&str, &str)]` over `&str` keys.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn apply_env_overrides_aa_mode_remote_promotes_mode() {
        let mut cfg = GatewayConfig::default();
        cfg.apply_env_overrides_with(env(&[("AA_MODE", "remote")])).unwrap();
        assert_eq!(cfg.mode, DeploymentMode::Remote);
    }

    #[test]
    fn apply_env_overrides_aa_mode_invalid_returns_named_error() {
        let mut cfg = GatewayConfig::default();
        let err = cfg
            .apply_env_overrides_with(env(&[("AA_MODE", "foobar")]))
            .expect_err("invalid value must return Err");
        // The message must include both the env-var name and the bad value
        // so operators can grep startup logs.
        let msg = format!("{err}");
        assert!(matches!(err, ConfigError::InvalidMode { ref raw } if raw == "foobar"));
        assert!(msg.contains("AA_MODE"), "message should name the var: {msg}");
        assert!(msg.contains("foobar"), "message should include the value: {msg}");
    }

    #[test]
    fn apply_env_overrides_port_updates_local_and_remote() {
        let mut cfg = GatewayConfig::default();
        cfg.apply_env_overrides_with(env(&[("AAASM_GATEWAY_PORT", "8080")]))
            .unwrap();
        assert_eq!(cfg.local.port, 8080);
        assert_eq!(cfg.remote.listen_addr.port(), 8080);
        // The bind address (only the port should change) keeps 0.0.0.0.
        assert_eq!(cfg.remote.listen_addr.ip().to_string(), "0.0.0.0");
    }

    #[test]
    fn apply_env_overrides_port_invalid_returns_named_error() {
        let mut cfg = GatewayConfig::default();
        let err = cfg
            .apply_env_overrides_with(env(&[("AAASM_GATEWAY_PORT", "not-a-number")]))
            .expect_err("non-numeric port must return Err");
        let msg = format!("{err}");
        assert!(matches!(err, ConfigError::InvalidPort { ref raw } if raw == "not-a-number"));
        assert!(msg.contains("AAASM_GATEWAY_PORT"));
        assert!(msg.contains("not-a-number"));
    }

    #[test]
    fn apply_env_overrides_database_url_targets_storage_postgres() {
        let mut cfg = GatewayConfig::default();
        cfg.apply_env_overrides_with(env(&[("AAASM_DATABASE_URL", "postgres://aasm@db/aasm")]))
            .unwrap();
        assert_eq!(
            cfg.storage.postgres.database_url.as_deref(),
            Some("postgres://aasm@db/aasm"),
        );
        // Legacy remote.database_url is untouched (removed in E18 S-I).
        assert!(cfg.remote.database_url.is_none());
    }

    #[test]
    fn apply_env_overrides_legacy_redis_url_still_sets_remote_field() {
        let mut cfg = GatewayConfig::default();
        cfg.apply_env_overrides_with(env(&[("AAASM_REDIS_URL", "redis://redis:6379")]))
            .unwrap();
        assert_eq!(cfg.remote.redis_url.as_deref(), Some("redis://redis:6379"));
    }

    #[test]
    fn apply_env_overrides_tls_creates_config_when_yaml_omitted_it() {
        let mut cfg = GatewayConfig::default();
        assert!(cfg.remote.tls.is_none(), "precondition: TLS off by default");
        cfg.apply_env_overrides_with(env(&[
            ("AAASM_TLS_CERT", "/etc/aasm/tls.crt"),
            ("AAASM_TLS_KEY", "/etc/aasm/tls.key"),
        ]))
        .unwrap();
        let tls = cfg.remote.tls.expect("TLS env vars must create TlsConfig");
        assert_eq!(tls.cert_file, PathBuf::from("/etc/aasm/tls.crt"));
        assert_eq!(tls.key_file, PathBuf::from("/etc/aasm/tls.key"));
    }

    #[test]
    fn apply_env_overrides_tls_patches_existing_config_asymmetrically() {
        let mut cfg = GatewayConfig::default();
        cfg.remote.tls = Some(TlsConfig {
            cert_file: PathBuf::from("/old/tls.crt"),
            key_file: PathBuf::from("/old/tls.key"),
        });
        // Only AAASM_TLS_CERT set — key should keep its old path.
        cfg.apply_env_overrides_with(env(&[("AAASM_TLS_CERT", "/new/tls.crt")]))
            .unwrap();
        let tls = cfg.remote.tls.expect("tls preserved");
        assert_eq!(tls.cert_file, PathBuf::from("/new/tls.crt"));
        assert_eq!(tls.key_file, PathBuf::from("/old/tls.key"), "key untouched");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn empty_yaml_hydrates_storage_defaults() {
        let cfg = GatewayConfig::from_yaml_str("{}").expect("empty YAML must parse");
        let s = &cfg.storage;
        assert_eq!(s.backend, StorageBackendType::Sqlite, "default backend");
        assert_eq!(
            s.sqlite.path,
            PathBuf::from("~/.aasm/local.db"),
            "sqlite path un-expanded by default",
        );
        assert_eq!(s.sqlite.journal_mode, "wal");
        assert!(s.postgres.database_url.is_none(), "postgres url unset");
        assert_eq!(s.postgres.max_connections, 20);
        assert_eq!(s.postgres.min_connections, 2);
        assert_eq!(s.postgres.connect_timeout_secs, 10);
        assert!(s.postgres.timescaledb.enabled);
        assert_eq!(s.postgres.timescaledb.chunk_interval, "7 days");
        assert_eq!(s.postgres.timescaledb.compression_policy, "30 days");
        assert!(!s.redis.enabled, "redis opt-in");
        assert!(s.redis.url.is_none());
        assert_eq!(s.redis.policy_cache_ttl_secs, 30);
        assert_eq!(s.redis.max_connections, 10);
        assert_eq!(s.retention.hot_days, 30);
        assert_eq!(s.retention.warm_days, 90);
        assert_eq!(s.retention.cold_action, ColdAction::Drop);
        assert!(s.retention.archive_url.is_none());
        assert_eq!(s.retention.schedule, "0 3 * * *");
        assert!(!s.retention.dry_run);
    }
}
