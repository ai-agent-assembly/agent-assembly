//! API key generation, validation, and storage.

use std::path::Path;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::RngExt as _;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::scope::Scope;

/// Prefix for all Agent Assembly API keys.
const API_KEY_PREFIX: &str = "aa_";

/// Expected length of the hex portion of an API key.
const API_KEY_HEX_LEN: usize = 32;

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
}

/// In-memory store of API key entries loaded from a JSON file.
pub struct ApiKeyStore {
    entries: Vec<ApiKeyEntry>,
}

impl ApiKeyStore {
    /// Load API key entries from a JSON file.
    ///
    /// Returns an empty store if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, ApiKeyError> {
        if !path.exists() {
            return Ok(Self { entries: Vec::new() });
        }

        let content = std::fs::read_to_string(path).map_err(|e| ApiKeyError::Io(e.to_string()))?;
        let entries: Vec<ApiKeyEntry> =
            serde_json::from_str(&content).map_err(|e| ApiKeyError::ParseError(e.to_string()))?;
        Ok(Self { entries })
    }

    /// Validate a raw API key string against stored entries.
    ///
    /// Returns the matching entry if the key is valid, or `None` if no match.
    pub fn validate(&self, raw_key: &str) -> Option<&ApiKeyEntry> {
        let key = ApiKey::parse(raw_key).ok()?;
        self.entries.iter().find(|entry| key.verify(&entry.key_hash))
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
        };
        let store = ApiKeyStore { entries: vec![entry] };

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
        };
        let store = ApiKeyStore { entries: vec![entry] };

        let result = store.validate(key2.as_str());
        assert!(result.is_none());
    }
}
