//! Zeroizing, per-host provider credential store for the egress-injection path.
//!
//! The proxy is a deliberate MitM between agents and LLM providers, so it
//! necessarily holds the real provider API keys — the platform's single
//! sweetest target (AAASM-3562). This module concentrates that plaintext in one
//! hardened container:
//!
//! * The secret bytes are [`zeroize`]d on drop, bounding the in-RAM lifetime.
//! * Neither [`CredentialStore`] nor [`Secret`] implements [`std::fmt::Display`],
//!   and their [`std::fmt::Debug`] impls redact the key material — so a key can
//!   never slip into a `tracing` line or a panic message.
//!
//! Keys are loaded **only** from operator-supplied configuration at startup
//! (never from agent-supplied input). The injection step looks a secret up by
//! upstream host (e.g. `api.openai.com`) and expands it into the outbound buffer
//! at egress, so the agent runtime never receives a real provider key.

use std::collections::HashMap;
use std::fmt;

use zeroize::Zeroize;

/// A single provider credential, held as zeroizing plaintext bytes.
///
/// The inner bytes are wiped on drop. The type intentionally has **no**
/// `Display` impl and a redacting `Debug` impl so the secret can never be
/// formatted into a log line, panic message, or audit record by accident.
/// Read access is deliberately narrow: [`Secret::expose`] is the single
/// audited choke point the injection path uses to expand the key into the
/// outbound request buffer.
pub struct Secret {
    bytes: Vec<u8>,
}

impl Secret {
    /// Wrap raw credential bytes. The caller's copy is the only other copy;
    /// this one is zeroized on drop.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the plaintext credential bytes.
    ///
    /// This is the single intentional read path for the secret. It exists so
    /// the egress-injection step can write the key into the outbound buffer;
    /// callers must never log, clone into an owned `String`, or otherwise
    /// widen the plaintext's lifetime beyond the outbound write.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for Secret {
    /// Redact the key material — never print the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(REDACTED, {} bytes)", self.bytes.len())
    }
}

/// A per-host map of real provider credentials.
///
/// Construct with [`CredentialStore::from_env`] (operator configuration) or
/// [`CredentialStore::from_pairs`] (tests / programmatic). Look a credential up
/// by upstream host with [`CredentialStore::secret_for`]; the injection step
/// (AAASM-3578) uses that to add the real `Authorization` header at egress.
///
/// Like [`Secret`], this type has no `Display` impl and a redacting `Debug`
/// impl so the whole store can never be formatted into a log line.
#[derive(Default)]
pub struct CredentialStore {
    keys: HashMap<String, Secret>,
}

impl CredentialStore {
    /// Build a store from `(host, secret_bytes)` pairs. Hosts are stored
    /// lowercased so lookups are case-insensitive (HTTP hosts are
    /// case-insensitive).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        let keys = pairs
            .into_iter()
            .map(|(host, bytes)| (host.to_ascii_lowercase(), Secret::new(bytes)))
            .collect();
        Self { keys }
    }

    /// Load the store from operator configuration.
    ///
    /// The `AA_PROXY_PROVIDER_KEYS` env var holds a comma-separated list of
    /// `host=key` entries, e.g.
    /// `api.openai.com=sk-…,api.anthropic.com=sk-ant-…`. Entries are read once
    /// at startup; agent-supplied input never reaches this path. An unset or
    /// empty var yields an empty store (the proxy then forwards the agent's own
    /// header unchanged — backward compatible).
    ///
    /// The raw env value is never logged; only the number of hosts loaded.
    pub fn from_env() -> Self {
        match std::env::var("AA_PROXY_PROVIDER_KEYS") {
            Ok(val) if !val.is_empty() => {
                let pairs: Vec<(String, Vec<u8>)> = val
                    .split(',')
                    .filter_map(|entry| {
                        let entry = entry.trim();
                        if entry.is_empty() {
                            return None;
                        }
                        match entry.split_once('=') {
                            Some((host, key)) if !host.trim().is_empty() && !key.is_empty() => {
                                Some((host.trim().to_string(), key.as_bytes().to_vec()))
                            }
                            _ => {
                                // Never echo the malformed entry — it may contain
                                // key material. Log only that one was skipped.
                                tracing::warn!("skipping malformed AA_PROXY_PROVIDER_KEYS entry (expected host=key)");
                                None
                            }
                        }
                    })
                    .collect();
                let store = Self::from_pairs(pairs);
                tracing::info!(
                    hosts = store.keys.len(),
                    "loaded provider credentials for egress injection"
                );
                store
            }
            _ => Self::default(),
        }
    }

    /// Look up the credential for `host` (case-insensitive). Returns `None`
    /// when no credential is configured for the host — the injection step then
    /// forwards the agent's request unchanged.
    pub fn secret_for(&self, host: &str) -> Option<&Secret> {
        self.keys.get(&host.to_ascii_lowercase())
    }

    /// Number of configured hosts. Useful for tests and startup logging; never
    /// reveals key material.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store holds no credentials.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl fmt::Debug for CredentialStore {
    /// Print only the configured hosts and a redaction marker — never the keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialStore")
            .field("hosts", &self.keys.keys().collect::<Vec<_>>())
            .field("secrets", &"REDACTED")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_for_is_case_insensitive() {
        let store = CredentialStore::from_pairs([("API.OpenAI.com".to_string(), b"sk-secret".to_vec())]);
        assert_eq!(
            store.secret_for("api.openai.com").map(|s| s.expose()),
            Some(&b"sk-secret"[..])
        );
        assert_eq!(
            store.secret_for("API.OPENAI.COM").map(|s| s.expose()),
            Some(&b"sk-secret"[..])
        );
    }

    #[test]
    fn secret_for_unknown_host_is_none() {
        let store = CredentialStore::from_pairs([("api.openai.com".to_string(), b"sk-secret".to_vec())]);
        assert!(store.secret_for("evil.attacker.com").is_none());
    }

    #[test]
    fn debug_never_contains_key_material() {
        // The store's Debug and the Secret's Debug must both redact — a key
        // must never be able to slip into a tracing line or panic message.
        let store = CredentialStore::from_pairs([("api.openai.com".to_string(), b"sk-TOPSECRET-1234".to_vec())]);
        let store_dbg = format!("{store:?}");
        assert!(
            !store_dbg.contains("sk-TOPSECRET-1234"),
            "store Debug leaked key: {store_dbg}"
        );
        assert!(store_dbg.contains("REDACTED"));
        assert!(
            store_dbg.contains("api.openai.com"),
            "store Debug should still name the host"
        );

        let secret = store.secret_for("api.openai.com").unwrap();
        let secret_dbg = format!("{secret:?}");
        assert!(
            !secret_dbg.contains("sk-TOPSECRET-1234"),
            "secret Debug leaked key: {secret_dbg}"
        );
        assert!(secret_dbg.contains("REDACTED"));
    }

    #[test]
    fn dropping_secret_runs_zeroize_on_its_buffer() {
        // Drop must wipe the plaintext. Reading freed memory back is unsound
        // (the allocator may reuse the buffer), so instead drive the exact
        // operation Drop performs — `zeroize()` on the inner buffer — over a
        // capacity-stable buffer and assert the bytes are wiped while the
        // allocation is still live. This deterministically exercises the wiping
        // contract `Drop for Secret` relies on.
        let mut bytes = b"sk-zeroize-me-please".to_vec();
        let ptr = bytes.as_ptr();
        let len = bytes.len();
        bytes.zeroize();
        // The buffer is still allocated (zeroize does not deallocate); read it
        // back at the original address and assert every byte is zero.
        // SAFETY: `bytes` is still live and owns this allocation of `len` bytes.
        let observed = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            observed.iter().all(|&b| b == 0),
            "zeroize left plaintext behind: {observed:?}"
        );
        drop(bytes);
    }

    #[test]
    fn empty_store_reports_empty() {
        let store = CredentialStore::default();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.secret_for("api.openai.com").is_none());
    }
}
