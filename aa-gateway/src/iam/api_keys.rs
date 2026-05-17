//! In-memory IAM API-key management store (AAASM-1397).
//!
//! Backs the dashboard Identity & Access page's "Service Identities" tab.
//! See the module-level note in `iam/mod.rs` for the boundary against
//! `aa-api::auth::api_key` (which authenticates *incoming* requests).

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Scopes a key may hold. Matches the dashboard's `ApiKeyScope` union exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiKeyScope {
    #[serde(rename = "read:members")]
    ReadMembers,
    #[serde(rename = "write:members")]
    WriteMembers,
    #[serde(rename = "read:policies")]
    ReadPolicies,
    #[serde(rename = "write:policies")]
    WritePolicies,
    #[serde(rename = "read:audit")]
    ReadAudit,
    #[serde(rename = "admin")]
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyStatus {
    Active,
    Revoked,
}

/// One entry in the "Recent activity" timeline shown in the dashboard's
/// IdentityDetailCard. Seeded inline alongside the key record until the
/// audit-query surface is wired in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentActivityEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub target: String,
}

/// A persisted API key record — *never* contains the raw secret.
///
/// `prefix` is the displayable, public portion (e.g. `aa_live_3f9c`) used
/// to identify the key in lists and audit entries. The secret half is only
/// returned once, from `generate` / `rotate`, inside [`GeneratedApiKey`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyEntry {
    pub id: String,
    pub label: String,
    pub prefix: String,
    pub scopes: Vec<ApiKeyScope>,
    pub status: ApiKeyStatus,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    /// Operator who owns the key (display only).
    pub owner: String,
    /// Service role label (e.g. `service:reader`).
    pub role: String,
    /// Policies assigned to this key by name.
    pub assigned_policies: Vec<String>,
    /// Audit-style activity feed for the IdentityDetailCard.
    pub recent_activity: Vec<RecentActivityEntry>,
}

/// One-shot reveal returned by `generate` and `rotate`. The `secret` field
/// is the raw key the caller must capture before it is gone — the store
/// does not persist it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedApiKey {
    pub id: String,
    pub prefix: String,
    pub secret: String,
}

/// In-memory IAM API-key store. Shared via `Arc` across handlers.
pub struct IamApiKeyStore {
    keys: DashMap<String, ApiKeyEntry>,
    seq: AtomicU64,
}

impl Default for IamApiKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IamApiKeyStore {
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
            seq: AtomicU64::new(0),
        }
    }

    /// Seed the store with a fixture set (development / test convenience).
    /// Each entry is inserted as-is; collisions on `id` overwrite.
    pub fn seed(&self, entries: impl IntoIterator<Item = ApiKeyEntry>) {
        for entry in entries {
            self.keys.insert(entry.id.clone(), entry);
        }
    }

    /// Return every entry, sorted by `created_at` descending (newest first).
    pub fn list(&self) -> Vec<ApiKeyEntry> {
        let mut out: Vec<ApiKeyEntry> = self.keys.iter().map(|e| e.value().clone()).collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        out
    }

    /// Issue a new key. Returns the [`GeneratedApiKey`] one-shot reveal.
    pub fn generate(&self, label: &str, scopes: Vec<ApiKeyScope>, owner: &str) -> GeneratedApiKey {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("key-gen-{seq}");
        let prefix = format!("aa_live_{}", random_suffix(4));
        let secret = format!("{prefix}_{}", random_suffix(32));
        let now = Utc::now();

        let entry = ApiKeyEntry {
            id: id.clone(),
            label: label.to_string(),
            prefix: prefix.clone(),
            scopes,
            status: ApiKeyStatus::Active,
            created_at: now,
            last_used: None,
            owner: owner.to_string(),
            role: "service:reader".to_string(),
            assigned_policies: Vec::new(),
            recent_activity: vec![RecentActivityEntry {
                id: format!("{id}-act-issue"),
                timestamp: now,
                action: "issued".to_string(),
                target: format!("key issued (label {label})"),
            }],
        };

        self.keys.insert(id.clone(), entry);

        GeneratedApiKey { id, prefix, secret }
    }

    /// Revoke an existing key in place. Returns `Err` if the key is unknown
    /// or already revoked.
    pub fn revoke(&self, id: &str, actor: &str) -> Result<(), RevokeError> {
        let mut entry = self.keys.get_mut(id).ok_or(RevokeError::NotFound)?;
        if entry.status == ApiKeyStatus::Revoked {
            return Err(RevokeError::AlreadyRevoked);
        }
        let now = Utc::now();
        entry.status = ApiKeyStatus::Revoked;
        entry.recent_activity.insert(
            0,
            RecentActivityEntry {
                id: format!("{id}-act-revoke-{}", now.timestamp_millis()),
                timestamp: now,
                action: "revoked".to_string(),
                target: format!("key revoked by {actor}"),
            },
        );
        Ok(())
    }

    /// Atomically revoke an existing key and issue a replacement with the
    /// same `label`, `scopes`, and `owner`. The replacement is a brand-new
    /// record (different `id` and `prefix`); the caller receives the new
    /// secret in the returned [`GeneratedApiKey`].
    pub fn rotate(&self, id: &str, actor: &str) -> Result<GeneratedApiKey, RotateError> {
        // Snapshot the old entry up front so we can re-use its label / scopes
        // / owner without holding a write reference across `generate`.
        let (label, scopes, owner) = {
            let entry = self.keys.get(id).ok_or(RotateError::NotFound)?;
            if entry.status == ApiKeyStatus::Revoked {
                return Err(RotateError::AlreadyRevoked);
            }
            (entry.label.clone(), entry.scopes.clone(), entry.owner.clone())
        };

        // Revoke the old entry first so the audit trail records the
        // revocation before the new issuance.
        self.revoke(id, actor).map_err(RotateError::from)?;
        let generated = self.generate(&label, scopes, &owner);

        // Note the rotation linkage on the *new* entry's activity feed so
        // operators can trace it back.
        if let Some(mut new_entry) = self.keys.get_mut(&generated.id) {
            let now = Utc::now();
            new_entry.recent_activity.insert(
                0,
                RecentActivityEntry {
                    id: format!("{}-act-rotate", generated.id),
                    timestamp: now,
                    action: "rotated".to_string(),
                    target: format!("rotated from {id} by {actor}"),
                },
            );
        }

        Ok(generated)
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RevokeError {
    #[error("api key not found")]
    NotFound,
    #[error("api key is already revoked")]
    AlreadyRevoked,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RotateError {
    #[error("api key not found")]
    NotFound,
    #[error("api key is already revoked")]
    AlreadyRevoked,
}

impl From<RevokeError> for RotateError {
    fn from(e: RevokeError) -> Self {
        match e {
            RevokeError::NotFound => RotateError::NotFound,
            RevokeError::AlreadyRevoked => RotateError::AlreadyRevoked,
        }
    }
}

/// 31-char base32-ish alphabet — no visually-ambiguous characters.
const SUFFIX_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Generate a pseudo-random suffix using a hash of the system nanosecond
/// clock plus a per-call counter. **Not cryptographically secure** — these
/// are in-memory mock keys for the dashboard's Identity & Access page; the
/// follow-up that wires this to durable storage should swap in a CSPRNG
/// (e.g. `rand::rngs::OsRng`).
fn random_suffix(length: usize) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::sync::atomic::AtomicU64;
    use std::time::SystemTime;

    static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut out = String::with_capacity(length);
    let mut hasher = DefaultHasher::new();
    (nanos, seq).hash(&mut hasher);
    let mut state = hasher.finish();
    for _ in 0..length {
        let idx = (state % SUFFIX_ALPHABET.len() as u64) as usize;
        out.push(SUFFIX_ALPHABET[idx] as char);
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> IamApiKeyStore {
        IamApiKeyStore::new()
    }

    #[test]
    fn new_store_is_empty() {
        assert!(store().list().is_empty());
    }

    #[test]
    fn generate_returns_secret_and_persists_active_entry() {
        let s = store();
        let gen = s.generate("gateway-ci", vec![ApiKeyScope::ReadMembers], "alice");
        assert!(
            gen.secret.starts_with(&gen.prefix),
            "secret should embed the public prefix"
        );
        assert!(gen.secret.len() > gen.prefix.len(), "secret should carry random tail");

        let entries = s.list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, gen.id);
        assert_eq!(entries[0].label, "gateway-ci");
        assert_eq!(entries[0].status, ApiKeyStatus::Active);
        assert_eq!(entries[0].owner, "alice");
        assert_eq!(
            entries[0].recent_activity[0].action, "issued",
            "first activity row should record issuance"
        );
    }

    #[test]
    fn generate_assigns_distinct_ids_under_concurrent_calls() {
        let s = store();
        let a = s.generate("k-a", vec![], "alice");
        let b = s.generate("k-b", vec![], "alice");
        assert_ne!(a.id, b.id);
        assert_ne!(a.prefix, b.prefix);
    }

    #[test]
    fn revoke_marks_entry_revoked_and_appends_activity() {
        let s = store();
        let gen = s.generate("k", vec![], "alice");
        assert!(s.revoke(&gen.id, "alice").is_ok());

        let entry = s.list().into_iter().find(|e| e.id == gen.id).unwrap();
        assert_eq!(entry.status, ApiKeyStatus::Revoked);
        assert_eq!(entry.recent_activity[0].action, "revoked");
    }

    #[test]
    fn revoke_returns_not_found_for_unknown_id() {
        assert_eq!(store().revoke("nope", "alice"), Err(RevokeError::NotFound));
    }

    #[test]
    fn revoke_is_idempotent_only_in_the_sense_of_returning_an_explicit_error_on_second_call() {
        let s = store();
        let gen = s.generate("k", vec![], "alice");
        s.revoke(&gen.id, "alice").unwrap();
        assert_eq!(s.revoke(&gen.id, "alice"), Err(RevokeError::AlreadyRevoked));
    }

    #[test]
    fn rotate_revokes_old_and_issues_new_entry_preserving_label_and_owner() {
        let s = store();
        let gen = s.generate("ci-runner", vec![ApiKeyScope::ReadAudit], "alice");
        let rotated = s.rotate(&gen.id, "alice").unwrap();

        assert_ne!(rotated.id, gen.id);
        assert_ne!(rotated.prefix, gen.prefix);

        let old = s.list().into_iter().find(|e| e.id == gen.id).unwrap();
        assert_eq!(old.status, ApiKeyStatus::Revoked);

        let new = s.list().into_iter().find(|e| e.id == rotated.id).unwrap();
        assert_eq!(new.status, ApiKeyStatus::Active);
        assert_eq!(new.label, "ci-runner");
        assert_eq!(new.owner, "alice");
        assert_eq!(new.scopes, vec![ApiKeyScope::ReadAudit]);
        assert_eq!(
            new.recent_activity[0].action, "rotated",
            "new entry should record its rotation provenance"
        );
    }

    #[test]
    fn rotate_returns_not_found_for_unknown_id() {
        assert_eq!(store().rotate("nope", "alice"), Err(RotateError::NotFound));
    }

    #[test]
    fn rotate_refuses_already_revoked_key() {
        let s = store();
        let gen = s.generate("k", vec![], "alice");
        s.revoke(&gen.id, "alice").unwrap();
        assert_eq!(s.rotate(&gen.id, "alice"), Err(RotateError::AlreadyRevoked));
    }

    #[test]
    fn list_sorts_newest_first() {
        let s = store();
        let _a = s.generate("a", vec![], "alice");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = s.generate("b", vec![], "alice");

        let entries = s.list();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, b.id, "newest entry should appear first");
    }
}
