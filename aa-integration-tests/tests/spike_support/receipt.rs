//! Minimal installation-receipt scaffolding for the AAASM-5276 Spike.
//!
//! # This is Spike scaffolding, not the production model
//!
//! Nothing in the tree today records what an integration changed:
//! `aa-devtool-claude-code/src/apply.rs:59-97` writes managed keys atomically but
//! takes no backup and has no unapply, and no crate exposes an integration plan,
//! a receipt, drift detection or a remove path. The Spike cannot measure
//! idempotence, drift or rollback without *something* recording pre-install
//! state, so this is the smallest thing that permits the measurement.
//!
//! **AAASM-5278 supersedes this.** Deliberately absent here, and required there:
//! transactional multi-mechanism apply, receipt schema versioning + migration,
//! signature/tamper-evidence, concurrent-install locking, partial-install
//! detection, and receipt storage outside the tool's own config tree.
//!
//! # Model
//!
//! A receipt carries, per mechanism, the value AASM installed and the value that
//! preceded it. Drift is "current ≠ installed"; repair rewrites installed values
//! only; removal rewrites pre-install values (or deletes the key where none
//! existed). Because both directions are keyed per-mechanism, a user-authored
//! key perturbed alongside a managed one is provably untouched by either.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The four `settings.json` keys the Claude Code adapter owns.
///
/// Mirrors the private `MANAGED_KEYS` in `aa-devtool-claude-code/src/apply.rs:47`.
/// Duplicated rather than imported because that constant is crate-private; the
/// Spike asserts the two agree by observing what an apply actually mutates
/// (scenario 11.2), so a divergence surfaces as a test failure, not as silent
/// drift between two lists.
pub const AASM_OWNED_SETTINGS_KEYS: &[&str] = &[
    "permissions",
    "permissionMode",
    "enabledMcpjsonServers",
    "disabledMcpjsonServers",
];

/// A managed mechanism the integration installs and can therefore drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Mechanism {
    /// AASM-owned keys inside the resolved Claude Code `settings.json`.
    ManagedSettings,
    /// The proxy endpoint the managed launcher injects as `HTTPS_PROXY`.
    InjectedProxyEndpoint,
}

impl Mechanism {
    /// Stable human-facing name for status output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManagedSettings => "managed-settings",
            Self::InjectedProxyEndpoint => "injected-proxy-endpoint",
        }
    }
}

/// One step recorded as applied, so a partial install is identifiable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedStep {
    /// Stable step identifier, e.g. `"settings.apply"`.
    pub id: String,
    /// Mechanism the step installed.
    pub mechanism: Mechanism,
}

/// Spike installation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpikeReceipt {
    /// Opaque identifier for this integration instance.
    pub integration_id: String,
    /// Tool token (`"claude"`) and detected version, when detection succeeded.
    pub tool: String,
    /// Detected tool version, `None` when the tool was not present.
    pub tool_version: Option<String>,
    /// Version of the adapter crate that performed the install.
    pub adapter_version: String,
    /// Version of the AASM core the install was performed against.
    pub core_version: String,
    /// Steps recorded as applied, in order.
    pub applied_steps: Vec<AppliedStep>,
    /// Settings file the install targeted.
    pub settings_path: PathBuf,
    /// Whether that file existed before the install.
    pub settings_existed_before: bool,
    /// SHA-256 of the file's pre-install bytes, when it existed.
    pub pre_install_settings_sha256: Option<String>,
    /// Pre-install value of each AASM-owned key. `None` means the key was
    /// absent, which removal must restore by *deleting* the key.
    pub pre_install_values: BTreeMap<String, Option<serde_json::Value>>,
    /// Value AASM installed for each owned key — the expectation drift is
    /// measured against.
    pub installed_values: BTreeMap<String, serde_json::Value>,
    /// SHA-256 of the file's post-install bytes.
    pub post_install_settings_sha256: String,
    /// Proxy endpoint the managed launcher injects.
    pub installed_proxy_endpoint: String,
}

/// One detected divergence between a receipt and live state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftFinding {
    /// Mechanism that drifted.
    pub mechanism: Mechanism,
    /// Sub-key within the mechanism (a settings key name, or `"endpoint"`).
    pub key: String,
    /// What the receipt says AASM installed.
    pub expected: String,
    /// What is there now.
    pub actual: String,
}

impl SpikeReceipt {
    /// Record an install of the AASM-owned settings keys.
    ///
    /// `pre` is the file's byte state *before* the install and `post` after, so
    /// the receipt can restore either a value or an absence.
    pub fn record_install(
        integration_id: impl Into<String>,
        tool: impl Into<String>,
        tool_version: Option<String>,
        settings_path: &Path,
        pre: Option<&[u8]>,
        post: &[u8],
        proxy_endpoint: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let pre_json: Option<serde_json::Value> = pre.and_then(|b| serde_json::from_slice(b).ok());
        let post_json: serde_json::Value = serde_json::from_slice(post)?;

        let mut pre_install_values = BTreeMap::new();
        let mut installed_values = BTreeMap::new();
        for &key in AASM_OWNED_SETTINGS_KEYS {
            pre_install_values.insert(key.to_owned(), pre_json.as_ref().and_then(|v| v.get(key).cloned()));
            if let Some(v) = post_json.get(key) {
                installed_values.insert(key.to_owned(), v.clone());
            }
        }

        Ok(Self {
            integration_id: integration_id.into(),
            tool: tool.into(),
            tool_version,
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            core_version: env!("CARGO_PKG_VERSION").to_owned(),
            applied_steps: vec![
                AppliedStep {
                    id: "settings.apply".to_owned(),
                    mechanism: Mechanism::ManagedSettings,
                },
                AppliedStep {
                    id: "launcher.inject-proxy-endpoint".to_owned(),
                    mechanism: Mechanism::InjectedProxyEndpoint,
                },
            ],
            settings_path: settings_path.to_path_buf(),
            settings_existed_before: pre.is_some(),
            pre_install_settings_sha256: pre.map(super::sha256_hex),
            pre_install_values,
            installed_values,
            post_install_settings_sha256: super::sha256_hex(post),
            installed_proxy_endpoint: proxy_endpoint.into(),
        })
    }

    /// Serialise to pretty JSON — the on-disk receipt form.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("receipt serialises")
    }

    /// Write the receipt to `path`.
    pub fn write(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_json())?;
        Ok(())
    }

    /// Read a receipt back from `path`.
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    /// Compare the receipt against live state and report every divergence,
    /// naming expected versus actual per mechanism.
    ///
    /// `current_settings` is the file's current bytes (`None` when deleted) and
    /// `current_endpoint` is the endpoint the launcher would inject right now.
    pub fn detect_drift(&self, current_settings: Option<&[u8]>, current_endpoint: &str) -> Vec<DriftFinding> {
        let mut findings = Vec::new();

        match current_settings.and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok()) {
            None => {
                findings.push(DriftFinding {
                    mechanism: Mechanism::ManagedSettings,
                    key: "<file>".to_owned(),
                    expected: format!("sha256:{}", self.post_install_settings_sha256),
                    actual: "<absent or unparseable>".to_owned(),
                });
            }
            Some(current) => {
                for (key, expected) in &self.installed_values {
                    let actual = current.get(key);
                    if actual != Some(expected) {
                        findings.push(DriftFinding {
                            mechanism: Mechanism::ManagedSettings,
                            key: key.clone(),
                            expected: expected.to_string(),
                            actual: actual.map(|v| v.to_string()).unwrap_or_else(|| "<absent>".to_owned()),
                        });
                    }
                }
            }
        }

        if current_endpoint != self.installed_proxy_endpoint {
            findings.push(DriftFinding {
                mechanism: Mechanism::InjectedProxyEndpoint,
                key: "endpoint".to_owned(),
                expected: self.installed_proxy_endpoint.clone(),
                actual: current_endpoint.to_owned(),
            });
        }

        findings
    }

    /// Rewrite **only** AASM-owned keys back to their installed values.
    ///
    /// Every other key in the file — including one a user perturbed in the same
    /// edit that caused the drift — is carried through untouched. Returns the
    /// bytes written.
    pub fn repair_settings(&self, current_settings: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
        let mut doc: serde_json::Value = current_settings
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("settings file is not a JSON object"))?;
        for (key, value) in &self.installed_values {
            obj.insert(key.clone(), value.clone());
        }
        Ok(serde_json::to_string_pretty(&doc)?.into_bytes())
    }

    /// Undo the install: restore each owned key's pre-install value, or delete
    /// the key where none existed.
    ///
    /// Returns `None` when the file did not exist before the install, meaning
    /// removal must delete it rather than write anything.
    pub fn removal_settings(&self, current_settings: Option<&[u8]>) -> anyhow::Result<Option<Vec<u8>>> {
        if !self.settings_existed_before {
            return Ok(None);
        }
        let mut doc: serde_json::Value = current_settings
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("settings file is not a JSON object"))?;
        for (key, pre) in &self.pre_install_values {
            match pre {
                Some(value) => {
                    obj.insert(key.clone(), value.clone());
                }
                None => {
                    obj.remove(key);
                }
            }
        }
        Ok(Some(serde_json::to_string_pretty(&doc)?.into_bytes()))
    }
}
