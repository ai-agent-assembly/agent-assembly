//! API key generation, validation, and storage.

use std::collections::HashMap;
use std::path::Path;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use dashmap::DashMap;
use rand::RngExt as _;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::scope::Scope;

/// Prefix for all Agent Assembly API keys.
const API_KEY_PREFIX: &str = "aa_";

/// Expected length of the hex portion of an API key.
const API_KEY_HEX_LEN: usize = 32;

/// Hex length of the per-key lookup index derived by [`ApiKey::lookup`].
///
/// 16 hex chars = 64 bits of SHA-256 output — enough that unrelated keys almost
/// never share a bucket (so a bogus token normally selects zero candidates and
/// runs argon2 zero times), while a collision only ever adds one extra argon2
/// verification, never restoring the O(N) fan-out.
const KEY_LOOKUP_HEX_LEN: usize = 16;

/// An Agent Assembly API key in `aa_<32-hex-chars>` format.
#[derive(Debug, Clone)]
pub struct ApiKey(String);

impl ApiKey {
    /// Parse and validate a raw API key string.
    ///
    /// Returns an error if the key doesn't match `aa_<32-hex-chars>`.
    pub fn parse(raw: &str) -> Result<Self, ApiKeyError> {
        let hex_part = raw.strip_prefix(API_KEY_PREFIX).ok_or(ApiKeyError::InvalidPrefix)?;

        if hex_part.len() != API_KEY_HEX_LEN {
            return Err(ApiKeyError::InvalidLength {
                expected: API_KEY_HEX_LEN,
                actual: hex_part.len(),
            });
        }

        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ApiKeyError::InvalidHex);
        }

        Ok(Self(raw.to_string()))
    }

    /// Generate a new cryptographically random API key.
    ///
    /// Returns the `ApiKey` and the plaintext string (for display to the user).
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut hex_bytes = [0u8; API_KEY_HEX_LEN / 2];
        rng.fill(&mut hex_bytes);
        let hex = hex::encode(&hex_bytes);
        Self(format!("{API_KEY_PREFIX}{hex}"))
    }

    /// Return the raw key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash this key using argon2 for secure storage.
    pub fn hash(&self) -> Result<String, ApiKeyError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(self.0.as_bytes(), &salt)
            .map_err(|e| ApiKeyError::HashError(e.to_string()))?;
        Ok(hash.to_string())
    }

    /// Verify this key against a stored argon2 hash.
    pub fn verify(&self, hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        Argon2::default().verify_password(self.0.as_bytes(), &parsed).is_ok()
    }

    /// Derive the fast, non-secret lookup index for this key (AAASM-4075).
    ///
    /// A truncated SHA-256 of the raw key. Because SHA-256 is preimage-resistant,
    /// persisting this alongside the argon2 hash leaks nothing about the key even
    /// if the key store is exfiltrated, yet it lets [`ApiKeyStore::validate_detailed`]
    /// select the single candidate entry in O(1) and run the expensive argon2
    /// verification only on that candidate — never once per stored key. argon2
    /// remains the sole authority for the final match.
    pub fn lookup(&self) -> String {
        let digest = Sha256::digest(self.0.as_bytes());
        let mut out = String::with_capacity(KEY_LOOKUP_HEX_LEN);
        for b in &digest[..KEY_LOOKUP_HEX_LEN / 2] {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

/// A stored API key entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyEntry {
    /// Unique identifier for this key.
    pub id: String,
    /// Argon2 hash of the key (never store plaintext).
    pub key_hash: String,
    /// Scopes granted to this key.
    pub scopes: Vec<Scope>,
    /// Unix timestamp when the key was created.
    pub created_at: u64,
    /// Optional human-readable label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// AAASM-3139 — the team this key is scoped to. When present, a non-admin
    /// key is confined to its own team for per-tenant data. `None` leaves the
    /// key unscoped (admin-gated for cross-tenant data), preserving legacy keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// AAASM-3139 — the org this key is scoped to. See [`ApiKeyEntry::team_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// AAASM-4075 — the fast lookup index ([`ApiKey::lookup`]) for this key.
    ///
    /// Populated when the entry is created from a known raw key so the store can
    /// select it in O(1) and run argon2 only on this candidate. `None` marks a
    /// legacy entry (e.g. loaded from a key file written before this field
    /// existed); such entries fall back to the pre-index argon2 scan, so they do
    /// not benefit from the anti-fan-out guarantee but remain fully valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_lookup: Option<String>,
}

/// In-memory store of API key entries loaded from a JSON file.
pub struct ApiKeyStore {
    entries: Vec<ApiKeyEntry>,
    /// AAASM-4075 — maps a key's [`ApiKey::lookup`] index to the entry indices
    /// sharing it, so `validate_detailed` selects candidates in O(1) instead of
    /// running argon2 against every entry. Built once at construction.
    lookup_index: HashMap<String, Vec<usize>>,
    /// AAASM-4075 — indices of entries with no `key_lookup` (legacy). These are
    /// unavoidably argon2-scanned on every call; the set is normally empty.
    unindexed: Vec<usize>,
    /// Runtime-revoked key IDs; checked during every `validate_detailed` call.
    revoked_ids: DashMap<String, ()>,
}

impl ApiKeyStore {
    /// Build a store directly from in-memory entries.
    ///
    /// Used by the local single-process entrypoint (AAASM-3369), which seeds a
    /// single admin key from the environment (or a generated one) without a
    /// keys-on-disk file.
    pub fn from_entries(entries: Vec<ApiKeyEntry>) -> Self {
        let (lookup_index, unindexed) = Self::build_index(&entries);
        Self {
            entries,
            lookup_index,
            unindexed,
            revoked_ids: DashMap::new(),
        }
    }

    /// Partition entries into the [`ApiKey::lookup`] index and the legacy
    /// (no-`key_lookup`) fallback set. Shared by every constructor so the two
    /// stay in sync (AAASM-4075).
    fn build_index(entries: &[ApiKeyEntry]) -> (HashMap<String, Vec<usize>>, Vec<usize>) {
        let mut lookup_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut unindexed = Vec::new();
        for (idx, entry) in entries.iter().enumerate() {
            match &entry.key_lookup {
                Some(lookup) => lookup_index.entry(lookup.clone()).or_default().push(idx),
                None => unindexed.push(idx),
            }
        }
        (lookup_index, unindexed)
    }

    /// Load API key entries from a JSON file.
    ///
    /// Returns an empty store if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, ApiKeyError> {
        if !path.exists() {
            return Ok(Self::from_entries(Vec::new()));
        }

        let content = std::fs::read_to_string(path).map_err(|e| ApiKeyError::Io(e.to_string()))?;
        let entries: Vec<ApiKeyEntry> =
            serde_json::from_str(&content).map_err(|e| ApiKeyError::ParseError(e.to_string()))?;
        Ok(Self::from_entries(entries))
    }

    /// Mark a key ID as revoked; subsequent `validate_detailed` calls for that
    /// key will return `Err(KeyNotValid::Revoked)`.
    pub fn revoke(&self, key_id: &str) {
        self.revoked_ids.insert(key_id.to_string(), ());
    }

    /// Validate a raw API key and distinguish *revoked* from *not-found*.
    ///
    /// Returns `Ok(&ApiKeyEntry)` on success, `Err(KeyNotValid::Revoked)` if the
    /// key exists but has been revoked, or `Err(KeyNotValid::NotFound)` for any
    /// other failure (parse error, wrong hash, unknown key).
    pub fn validate_detailed(&self, raw_key: &str) -> Result<&ApiKeyEntry, KeyNotValid> {
        let key = ApiKey::parse(raw_key).map_err(|_| KeyNotValid::NotFound)?;

        // AAASM-4075 — select candidates by the cheap SHA-256 lookup index so an
        // unauthenticated attacker bursting well-formed-but-invalid tokens cannot
        // force one argon2 verification per stored key (a CPU/memory DoS). Only
        // entries whose lookup matches, plus any legacy entries lacking the index,
        // are argon2-verified; a bogus token normally selects zero indexed
        // candidates. argon2 stays the sole authority for the final match.
        let lookup = key.lookup();
        let candidates = self
            .lookup_index
            .get(&lookup)
            .into_iter()
            .flatten()
            .chain(self.unindexed.iter())
            .filter_map(|&idx| self.entries.get(idx));

        match candidates.into_iter().find(|entry| key.verify(&entry.key_hash)) {
            None => Err(KeyNotValid::NotFound),
            Some(entry) => {
                if self.revoked_ids.contains_key(&entry.id) {
                    Err(KeyNotValid::Revoked)
                } else {
                    Ok(entry)
                }
            }
        }
    }

    /// Validate a raw API key string against stored entries.
    ///
    /// Returns the matching entry if the key is valid, or `None` if no match.
    /// Use [`validate_detailed`](Self::validate_detailed) when the caller needs
    /// to distinguish revoked keys from unknown keys.
    pub fn validate(&self, raw_key: &str) -> Option<&ApiKeyEntry> {
        self.validate_detailed(raw_key).ok()
    }

    /// Return the number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Reason a key lookup failed during authentication.
#[derive(Debug)]
pub enum KeyNotValid {
    /// No entry matched the supplied raw key.
    NotFound,
    /// The key exists but has been revoked.
    Revoked,
}

/// Errors related to API key operations.
#[derive(Debug, Error)]
pub enum ApiKeyError {
    #[error("API key must start with '{API_KEY_PREFIX}'")]
    InvalidPrefix,
    #[error("API key hex portion must be {expected} characters (got {actual})")]
    InvalidLength { expected: usize, actual: usize },
    #[error("API key hex portion contains non-hex characters")]
    InvalidHex,
    #[error("failed to hash API key: {0}")]
    HashError(String),
    #[error("I/O error reading API keys file: {0}")]
    Io(String),
    #[error("failed to parse API keys file: {0}")]
    ParseError(String),
}

/// Hex encoding helper (avoids adding `hex` crate dependency).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_generate_format() {
        let key = ApiKey::generate();
        let raw = key.as_str();
        assert!(raw.starts_with("aa_"), "key should start with aa_");
        assert_eq!(raw.len(), 3 + API_KEY_HEX_LEN, "key should be aa_ + 32 hex chars");
        assert!(
            raw[3..].chars().all(|c| c.is_ascii_hexdigit()),
            "hex portion should be valid hex"
        );
    }

    #[test]
    fn test_api_key_parse_valid() {
        let key = ApiKey::generate();
        let parsed = ApiKey::parse(key.as_str());
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_api_key_parse_invalid_prefix() {
        let result = ApiKey::parse("bb_00112233445566778899aabbccddeeff");
        assert!(matches!(result, Err(ApiKeyError::InvalidPrefix)));
    }

    #[test]
    fn test_api_key_parse_invalid_length() {
        let result = ApiKey::parse("aa_0011");
        assert!(matches!(
            result,
            Err(ApiKeyError::InvalidLength {
                expected: 32,
                actual: 4
            })
        ));
    }

    #[test]
    fn test_api_key_parse_invalid_hex() {
        let result = ApiKey::parse("aa_gggggggggggggggggggggggggggggggg");
        assert!(matches!(result, Err(ApiKeyError::InvalidHex)));
    }

    #[test]
    fn test_api_key_hash_verify_roundtrip() {
        let key = ApiKey::generate();
        let hash = key.hash().expect("hashing should succeed");
        assert!(key.verify(&hash), "key should verify against its own hash");
    }

    #[test]
    fn test_api_key_verify_wrong_key() {
        let key1 = ApiKey::generate();
        let key2 = ApiKey::generate();
        let hash = key1.hash().expect("hashing should succeed");
        assert!(!key2.verify(&hash), "different key should not verify");
    }

    #[test]
    fn test_api_key_store_load_missing_file() {
        let store = ApiKeyStore::load(Path::new("/nonexistent/path/keys.json"));
        assert!(store.is_ok());
        assert!(store.unwrap().is_empty());
    }

    #[test]
    fn test_api_key_store_validate_roundtrip() {
        let key = ApiKey::generate();
        let hash = key.hash().expect("hashing should succeed");
        let entry = ApiKeyEntry {
            id: "test-key-1".to_string(),
            key_hash: hash,
            scopes: vec![Scope::Read, Scope::Write],
            created_at: 1700000000,
            label: Some("test key".to_string()),
            team_id: None,
            org_id: None,
            key_lookup: Some(key.lookup()),
        };
        let store = ApiKeyStore::from_entries(vec![entry]);

        let result = store.validate(key.as_str());
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "test-key-1");
    }

    #[test]
    fn test_api_key_store_validate_wrong_key() {
        let key1 = ApiKey::generate();
        let key2 = ApiKey::generate();
        let hash = key1.hash().expect("hashing should succeed");
        let entry = ApiKeyEntry {
            id: "test-key-1".to_string(),
            key_hash: hash,
            scopes: vec![Scope::Read],
            created_at: 1700000000,
            label: None,
            team_id: None,
            org_id: None,
            key_lookup: Some(key1.lookup()),
        };
        let store = ApiKeyStore::from_entries(vec![entry]);

        let result = store.validate(key2.as_str());
        assert!(result.is_none());
    }

    #[test]
    fn verify_returns_false_for_unparseable_hash() {
        let key = ApiKey::generate();
        // A non-PHC string can't be parsed into a PasswordHash → verify is false.
        assert!(!key.verify("not-a-valid-argon2-hash"));
    }

    #[test]
    fn verify_round_trips_against_its_own_hash() {
        let key = ApiKey::generate();
        let hash = key.hash().expect("hash");
        assert!(key.verify(&hash));
    }

    #[test]
    fn store_len_is_empty_and_validate_detailed_distinguishes_revoked() {
        let key = ApiKey::generate();
        let entry = ApiKeyEntry {
            id: "key-1".to_string(),
            key_hash: key.hash().expect("hash"),
            scopes: vec![Scope::Admin],
            created_at: 1700000000,
            label: None,
            team_id: None,
            org_id: None,
            key_lookup: Some(key.lookup()),
        };
        let store = ApiKeyStore::from_entries(vec![entry]);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        // Valid before revocation.
        assert!(store.validate(key.as_str()).is_some());

        // After revoking the matching key id, validate_detailed reports Revoked.
        store.revoke("key-1");
        assert!(matches!(
            store.validate_detailed(key.as_str()),
            Err(KeyNotValid::Revoked)
        ));

        // An entirely unknown key is NotFound.
        let other = ApiKey::generate();
        assert!(matches!(
            store.validate_detailed(other.as_str()),
            Err(KeyNotValid::NotFound)
        ));
    }

    #[test]
    fn empty_store_reports_is_empty() {
        let store = ApiKeyStore::from_entries(vec![]);
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }
}
