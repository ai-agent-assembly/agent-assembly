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
    /// Whether the backing pages were successfully `mlock`ed (AAASM-3582), so
    /// `Drop` knows to `munlock` them. Always `false` where mlock is
    /// unavailable / unprivileged / unsupported.
    mlocked: bool,
}

impl Secret {
    /// Wrap raw credential bytes. The caller's copy is the only other copy;
    /// this one is zeroized on drop.
    ///
    /// On Unix the backing pages are best-effort `mlock`ed (AAASM-3582) so the
    /// plaintext is never written to swap. The `bytes` buffer is never mutated
    /// or reallocated after this point (only zeroized in place on drop), so the
    /// locked page range stays valid for the secret's whole lifetime.
    pub fn new(bytes: Vec<u8>) -> Self {
        let mlocked = lock_memory(&bytes);
        Self { bytes, mlocked }
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
        // Wipe the plaintext first, then release the lock on the (now-zero)
        // pages. Order matters only for hygiene — both run unconditionally.
        self.bytes.zeroize();
        if self.mlocked {
            unlock_memory(&self.bytes);
        }
    }
}

/// Best-effort `mlock` of the page range backing `buf` (AAASM-3582).
///
/// Returns `true` when the lock succeeded. Locking keeps the plaintext key out
/// of disk-backed swap / hibernation images. This is hardening, not a hard
/// requirement: an empty buffer, a non-Unix target, or an `EPERM`/`ENOMEM`
/// (unprivileged / `RLIMIT_MEMLOCK` exhausted) failure logs a single warning
/// and continues with `false`.
#[cfg(unix)]
fn lock_memory(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // SAFETY: `buf` points to `buf.len()` valid, initialised bytes owned by the
    // caller's `Vec`; `mlock` only pins those pages in RAM and never mutates or
    // reads through the pointer.
    let rc = unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
    if rc == 0 {
        true
    } else {
        tracing::warn!("mlock of credential pages failed (continuing without swap protection)");
        false
    }
}

/// Release a previously successful [`lock_memory`] (AAASM-3582).
#[cfg(unix)]
fn unlock_memory(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: same invariants as `lock_memory`; only called when the matching
    // `mlock` succeeded for this exact range.
    let _ = unsafe { libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
}

/// Non-Unix fallback: mlock is unavailable, so secrets are not pinned. The
/// zeroize + redaction protections still apply.
#[cfg(not(unix))]
fn lock_memory(_buf: &[u8]) -> bool {
    tracing::debug!("mlock not available on this platform; credential pages not pinned");
    false
}

/// Non-Unix fallback no-op counterpart to [`lock_memory`].
#[cfg(not(unix))]
fn unlock_memory(_buf: &[u8]) {}

impl fmt::Debug for Secret {
    /// Redact the key material — never print the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(REDACTED, {} bytes)", self.bytes.len())
    }
}

/// A single credential entry: the [`Secret`] plus an optional expiry.
///
/// `expires_at == None` means the entry never expires (the default for keys
/// configured statically at startup). A `Some(instant)` in the past makes the
/// entry expired — [`CredentialStore`] refuses to inject it (AAASM-3586).
struct Entry {
    secret: Secret,
    expires_at: Option<std::time::Instant>,
}

impl Entry {
    fn is_expired(&self) -> bool {
        matches!(self.expires_at, Some(deadline) if std::time::Instant::now() >= deadline)
    }
}

/// A per-host map of real provider credentials.
///
/// Construct with [`CredentialStore::from_env`] (operator configuration) or
/// [`CredentialStore::from_pairs`] (tests / programmatic). The injection step
/// (AAASM-3578) calls [`CredentialStore::authorization_for`] to build the real
/// `Authorization` header value at egress.
///
/// Entries carry an optional TTL (AAASM-3586): an expired entry is never
/// injected. [`CredentialStore::rotate`] swaps a credential in place — zeroizing
/// the old secret — and is the OSS seam an external rotator (SaaS/enterprise
/// dynamic Vault leasing, relates AAASM-242) drives. No Vault client ships in
/// OSS scope.
///
/// Like [`Secret`], this type has no `Display` impl and a redacting `Debug`
/// impl so the whole store can never be formatted into a log line. The inner
/// map sits behind an `RwLock` so rotation can mutate it while the store is
/// shared as `Arc<CredentialStore>` across connection tasks.
#[derive(Default)]
pub struct CredentialStore {
    entries: std::sync::RwLock<HashMap<String, Entry>>,
}

impl CredentialStore {
    /// Build a store from `(host, secret_bytes)` pairs, all non-expiring. Hosts
    /// are stored lowercased so lookups are case-insensitive (HTTP hosts are
    /// case-insensitive).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        let map: HashMap<String, Entry> = pairs
            .into_iter()
            .map(|(host, bytes)| {
                (
                    host.to_ascii_lowercase(),
                    Entry {
                        secret: Secret::new(bytes),
                        expires_at: None,
                    },
                )
            })
            .collect();
        Self {
            entries: std::sync::RwLock::new(map),
        }
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
                tracing::info!(hosts = store.len(), "loaded provider credentials for egress injection");
                store
            }
            _ => Self::default(),
        }
    }

    /// Build the egress `Authorization` header value (`Bearer <key>`) for
    /// `host` (case-insensitive). Returns `None` when no credential is
    /// configured for the host, or when the configured credential has expired
    /// (AAASM-3586) — in both cases the injection step forwards the agent's
    /// request unchanged.
    ///
    /// The secret bytes are expanded only into the returned owned buffer; they
    /// are never logged or copied into a `String`. This is the single accessor
    /// the data path uses, so TTL and rotation are honoured uniformly.
    pub fn authorization_for(&self, host: &str) -> Option<Vec<u8>> {
        let guard = self.entries.read().ok()?;
        let entry = guard.get(&host.to_ascii_lowercase())?;
        if entry.is_expired() {
            tracing::debug!(%host, "configured provider credential has expired; not injecting");
            return None;
        }
        let key = entry.secret.expose();
        let mut buf = Vec::with_capacity(key.len() + 7);
        buf.extend_from_slice(b"Bearer ");
        buf.extend_from_slice(key);
        Some(buf)
    }

    /// Atomically replace the credential for `host` (AAASM-3586).
    ///
    /// The previous secret (if any) is zeroized as it is dropped. `ttl` sets the
    /// new entry's lifetime: `Some(d)` expires `d` from now, `None` never
    /// expires. This is the hook an external rotator (enterprise dynamic Vault
    /// leasing, relates AAASM-242) calls to install a freshly-leased key without
    /// re-plumbing the data path.
    pub fn rotate(&self, host: &str, new_secret: Vec<u8>, ttl: Option<std::time::Duration>) {
        let expires_at = ttl.map(|d| std::time::Instant::now() + d);
        let entry = Entry {
            secret: Secret::new(new_secret),
            expires_at,
        };
        if let Ok(mut guard) = self.entries.write() {
            // Inserting overwrites the old Entry, whose Secret is dropped here
            // (zeroized + munlocked) while the write lock is held — so a
            // concurrent reader never observes a half-rotated state.
            guard.insert(host.to_ascii_lowercase(), entry);
        } else {
            tracing::error!(%host, "credential store lock poisoned; rotation skipped");
        }
    }

    /// Number of configured hosts. Useful for tests and startup logging; never
    /// reveals key material.
    pub fn len(&self) -> usize {
        self.entries.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Whether the store holds no credentials.
    pub fn is_empty(&self) -> bool {
        self.entries.read().map(|g| g.is_empty()).unwrap_or(true)
    }
}

impl fmt::Debug for CredentialStore {
    /// Print only the configured hosts and a redaction marker — never the keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hosts: Vec<String> = self
            .entries
            .read()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default();
        f.debug_struct("CredentialStore")
            .field("hosts", &hosts)
            .field("secrets", &"REDACTED")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_for_is_case_insensitive_and_bearer_prefixed() {
        let store = CredentialStore::from_pairs([("API.OpenAI.com".to_string(), b"sk-secret".to_vec())]);
        assert_eq!(
            store.authorization_for("api.openai.com").as_deref(),
            Some(&b"Bearer sk-secret"[..])
        );
        assert_eq!(
            store.authorization_for("API.OPENAI.COM").as_deref(),
            Some(&b"Bearer sk-secret"[..])
        );
    }

    #[test]
    fn authorization_for_unknown_host_is_none() {
        let store = CredentialStore::from_pairs([("api.openai.com".to_string(), b"sk-secret".to_vec())]);
        assert!(store.authorization_for("evil.attacker.com").is_none());
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

        let secret = Secret::new(b"sk-TOPSECRET-1234".to_vec());
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
    fn mlocked_secret_constructs_and_exposes_without_leaking() {
        // AAASM-3582: a Secret built via `new` (which best-effort mlocks on
        // Unix, no-ops elsewhere) must construct successfully, expose its bytes
        // for injection, and still redact under Debug. mlock failures are
        // tolerated, so this asserts behaviour holds regardless of outcome.
        let secret = Secret::new(b"sk-mlock-me".to_vec());
        assert_eq!(secret.expose(), b"sk-mlock-me");
        let dbg = format!("{secret:?}");
        assert!(!dbg.contains("sk-mlock-me"), "Debug leaked key: {dbg}");
        // Dropping must unlock + zeroize without panicking.
        drop(secret);
    }

    #[test]
    fn empty_store_reports_empty() {
        let store = CredentialStore::default();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.authorization_for("api.openai.com").is_none());
    }

    #[test]
    fn expired_entry_is_not_injected() {
        // AAASM-3586: an entry whose TTL has elapsed must not be injected.
        let store = CredentialStore::default();
        // Rotate in a credential that expired the moment it was created.
        store.rotate(
            "api.openai.com",
            b"sk-expired".to_vec(),
            Some(std::time::Duration::ZERO),
        );
        assert!(
            store.authorization_for("api.openai.com").is_none(),
            "expired credential must not be injected"
        );
    }

    #[test]
    fn rotate_replaces_secret_and_serves_the_new_one() {
        // AAASM-3586: rotation swaps the credential in place; the new key is
        // served and the old one is gone.
        let store = CredentialStore::from_pairs([("api.openai.com".to_string(), b"sk-old".to_vec())]);
        assert_eq!(
            store.authorization_for("api.openai.com").as_deref(),
            Some(&b"Bearer sk-old"[..])
        );

        store.rotate("api.openai.com", b"sk-new".to_vec(), None);
        assert_eq!(
            store.authorization_for("api.openai.com").as_deref(),
            Some(&b"Bearer sk-new"[..]),
            "rotate must serve the new secret"
        );
        // Exactly one entry remains for the host (the old one was overwritten).
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn rotate_installs_credential_for_a_new_host() {
        // The rotation hook is also the OSS seam an external rotator uses to
        // install a freshly-leased key for a host with no prior entry.
        let store = CredentialStore::default();
        store.rotate(
            "api.anthropic.com",
            b"sk-ant-leased".to_vec(),
            Some(std::time::Duration::from_secs(60)),
        );
        assert_eq!(
            store.authorization_for("api.anthropic.com").as_deref(),
            Some(&b"Bearer sk-ant-leased"[..])
        );
    }

    #[test]
    fn non_expiring_entry_stays_valid() {
        let store = CredentialStore::from_pairs([("api.openai.com".to_string(), b"sk-forever".to_vec())]);
        assert!(store.authorization_for("api.openai.com").is_some());
    }
}
