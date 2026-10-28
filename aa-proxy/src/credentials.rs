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
///
/// `secret == None` is a revocation tombstone (AAASM-6262): the secret has been
/// dropped (zeroized) but the host stays in the map. Removing the entry instead
/// would make the host indistinguishable from "no credential configured", and
/// the data path forwards the agent's own headers unchanged in that case — a
/// revoke that falls back to pass-through is fail-open.
struct Entry {
    secret: Option<Secret>,
    expires_at: Option<std::time::Instant>,
}

impl Entry {
    fn is_expired(&self) -> bool {
        matches!(self.expires_at, Some(deadline) if std::time::Instant::now() >= deadline)
    }
}

/// What the data path must do for a host, decided from one read of the store.
///
/// One accessor, one lock acquisition: asking "is it revoked?" and "what is the
/// secret?" separately would leave a window where a revoke lands between the two
/// and the request is injected with a credential that was just revoked, or
/// forwarded uninjected.
pub enum Injection {
    /// Inject this auth header `(name, value)` into the outgoing request.
    Inject(&'static str, Vec<u8>),
    /// No credential is configured for the host: the agent's own headers are
    /// forwarded unchanged (the backward-compatible default).
    NotConfigured,
    /// The configured credential expired (AAASM-3586); forwarded unchanged, as
    /// before this type existed.
    Expired,
    /// The credential was revoked (AAASM-6262): the request must be refused,
    /// never forwarded with the agent's own headers.
    Revoked,
}

/// Result of [`CredentialStore::revoke`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// A live credential was dropped and the host is now revoked.
    Revoked,
    /// The host was already revoked; nothing changed.
    AlreadyRevoked,
    /// No credential is configured for the host; nothing changed. Deliberately
    /// not a revocation: a mistyped host must not start refusing traffic.
    NotConfigured,
}

/// Classify the LLM provider for an egress `host`, to pick the correct
/// injected auth-header shape (AAASM-5926).
///
/// Reuses [`aa_core::llm::Provider`] rather than a parallel enum — the
/// header-shape question ("is this Anthropic?") is exactly the provider
/// question `aa_core::llm` already models, even though its only prior
/// consumer (`Model::infer_from_name`) classifies from a model name string,
/// not a hostname. A plain hostname substring match is enough here: the set
/// of upstream LLM hosts a credential is ever configured for is small and
/// operator-controlled (`AA_PROXY_PROVIDER_KEYS`), not attacker-influenced.
fn classify_provider_for_host(host: &str) -> Option<aa_core::llm::Provider> {
    let host = host.to_ascii_lowercase();
    if host.contains("anthropic") {
        Some(aa_core::llm::Provider::Anthropic)
    } else if host.contains("openai") {
        Some(aa_core::llm::Provider::OpenAi)
    } else if host.contains("cohere") {
        Some(aa_core::llm::Provider::Cohere)
    } else {
        None
    }
}

/// Environment flag (not a secret) saying the provider keys arrive on the
/// proxy's stdin instead of in its environment (AAASM-6395).
///
/// An environment variable is readable by every process of the same user
/// (`ps -Eww` on macOS, `/proc/<pid>/environ` on Linux), and a governed agent is
/// such a process. A pipe that is closed after one read is not.
pub const PROVIDER_KEYS_STDIN_FLAG: &str = "AA_PROXY_PROVIDER_KEYS_STDIN";

/// What `aa-proxy --capabilities` prints when this build can consume provider
/// keys from stdin ([`PROVIDER_KEYS_STDIN_FLAG`]).
pub const PROVIDER_KEYS_STDIN_CAPABILITY: &str = "provider-keys-stdin";

/// Largest provider-key payload accepted on stdin. Kept below the smallest
/// anonymous-pipe buffer (16 KiB on macOS) so the supervisor's single write can
/// never block waiting for a reader that has not started yet.
pub const MAX_PROVIDER_KEYS_BYTES: usize = 8192;

/// Why a provider-key payload was refused.
///
/// Deliberately carries no input text: the payload is key material, and an
/// error that quoted a malformed entry would write a credential into a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKeysError {
    /// Keys were supplied both on stdin and in the environment; which one wins
    /// would be a guess.
    Ambiguous,
    /// The stdin pipe could not be read.
    Unreadable,
    /// Stdin was selected but carried no usable entry.
    Empty,
    /// More than [`MAX_PROVIDER_KEYS_BYTES`] bytes.
    TooLarge,
    /// Not valid UTF-8.
    NotUtf8,
    /// The `index`-th (1-based) non-empty entry is not `host=key`.
    Malformed {
        /// Position of the offending entry.
        index: usize,
    },
}

impl fmt::Display for ProviderKeysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ambiguous => write!(f, "provider keys were given on stdin and in the environment"),
            Self::Unreadable => write!(f, "provider keys could not be read from stdin"),
            Self::Empty => write!(f, "provider keys were selected on stdin but none were delivered"),
            Self::TooLarge => write!(f, "provider keys exceed {MAX_PROVIDER_KEYS_BYTES} bytes"),
            Self::NotUtf8 => write!(f, "provider keys are not valid UTF-8"),
            Self::Malformed { index } => write!(f, "provider key entry {index} is not host=key"),
        }
    }
}

impl std::error::Error for ProviderKeysError {}

/// Parse `host=key,host2=key2` strictly.
///
/// Unlike [`CredentialStore::from_env`], which skips a bad entry so a typo does
/// not take the proxy down, a payload delivered on stdin is the operator's
/// explicit instruction, so a bad entry refuses the whole payload rather than
/// leaving a host silently un-brokered.
///
/// # Errors
///
/// [`ProviderKeysError::Malformed`] for a non-empty entry that is not
/// `host=key` with both halves non-empty; [`ProviderKeysError::Empty`] when no
/// entry remains.
pub fn parse_provider_keys(raw: &str) -> Result<Vec<(String, Vec<u8>)>, ProviderKeysError> {
    let mut pairs = Vec::new();
    for (position, entry) in raw.split(',').map(str::trim).filter(|e| !e.is_empty()).enumerate() {
        match entry.split_once('=') {
            Some((host, key)) if !host.trim().is_empty() && !key.is_empty() => {
                pairs.push((host.trim().to_string(), key.as_bytes().to_vec()));
            }
            _ => return Err(ProviderKeysError::Malformed { index: position + 1 }),
        }
    }
    if pairs.is_empty() {
        return Err(ProviderKeysError::Empty);
    }
    Ok(pairs)
}

/// Read a bounded provider-key payload from `reader` and parse it.
///
/// Reads at most [`MAX_PROVIDER_KEYS_BYTES`] + 1 bytes, so an oversized or
/// endless writer is refused instead of buffered.
///
/// # Errors
///
/// Any [`ProviderKeysError`] other than [`ProviderKeysError::Ambiguous`].
pub fn read_provider_keys(reader: impl std::io::Read) -> Result<Vec<(String, Vec<u8>)>, ProviderKeysError> {
    use std::io::Read;
    let mut buf = Vec::new();
    reader
        .take(MAX_PROVIDER_KEYS_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| ProviderKeysError::Unreadable)?;
    let outcome = if buf.len() > MAX_PROVIDER_KEYS_BYTES {
        Err(ProviderKeysError::TooLarge)
    } else {
        std::str::from_utf8(&buf)
            .map_err(|_| ProviderKeysError::NotUtf8)
            .and_then(parse_provider_keys)
    };
    buf.zeroize();
    outcome
}

/// A per-host map of real provider credentials.
///
/// Construct with [`CredentialStore::from_env`] (operator configuration) or
/// [`CredentialStore::from_pairs`] (tests / programmatic). The injection step
/// (AAASM-3578) calls [`CredentialStore::authorization_for`] to build the real
/// auth header at egress — `Authorization: Bearer <key>` or, for Anthropic
/// hosts, `x-api-key: <key>` (AAASM-5926).
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
                        secret: Some(Secret::new(bytes)),
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

    /// Load the store the way the proxy process is started (AAASM-6395).
    ///
    /// * [`PROVIDER_KEYS_STDIN_FLAG`] set to `1`: read the keys from stdin (see
    ///   [`read_provider_keys`]) and return `Some(store)`. Combined with a
    ///   non-empty `AA_PROXY_PROVIDER_KEYS` this is refused as ambiguous.
    /// * Flag absent: return `None`; the legacy environment path
    ///   ([`Self::from_env`]) keeps working for a proxy started directly, with a
    ///   warning, because that variable is visible to the proxy owner's other
    ///   processes.
    ///
    /// Blocks until the writer closes the pipe. The supervisor writes the whole
    /// payload and closes it before it waits for readiness, so this returns
    /// promptly; if it ever does not, the supervisor's readiness timeout ends the
    /// launch, which fails closed.
    ///
    /// # Errors
    ///
    /// A [`ProviderKeysError`]; the proxy must refuse to start on it.
    pub fn load_startup() -> Result<Option<Self>, ProviderKeysError> {
        let env_present = std::env::var("AA_PROXY_PROVIDER_KEYS").is_ok_and(|v| !v.is_empty());
        let stdin_selected = std::env::var(PROVIDER_KEYS_STDIN_FLAG).is_ok_and(|v| v == "1");
        Self::load_with(stdin_selected, env_present, std::io::stdin().lock())
    }

    /// [`Self::load_startup`] with its three inputs explicit, so each branch can
    /// be driven without touching the process environment or real stdin.
    fn load_with(
        stdin_selected: bool,
        env_present: bool,
        stdin: impl std::io::Read,
    ) -> Result<Option<Self>, ProviderKeysError> {
        match (stdin_selected, env_present) {
            (true, true) => Err(ProviderKeysError::Ambiguous),
            (true, false) => {
                let store = Self::from_pairs(read_provider_keys(stdin)?);
                tracing::info!(
                    hosts = store.len(),
                    "loaded provider credentials for egress injection from stdin"
                );
                Ok(Some(store))
            }
            (false, true) => {
                tracing::warn!(
                    "provider keys came from the AA_PROXY_PROVIDER_KEYS environment variable, which other \
                     processes of this user can read; start the proxy through `aasm` so they are delivered on stdin"
                );
                Ok(None)
            }
            (false, false) => Ok(None),
        }
    }

    /// Build the egress auth header `(name, value)` for `host`
    /// (case-insensitive). Returns `None` when no credential is configured for
    /// the host, or when the configured credential has expired (AAASM-3586) —
    /// in both cases the injection step forwards the agent's request unchanged.
    ///
    /// The header shape is provider-aware (AAASM-5926): Anthropic hosts get
    /// `x-api-key: <key>` (the Messages API's raw-key scheme), everything else
    /// gets `Authorization: Bearer <key>`. That "everything else" default also
    /// covers a host with a credential configured but no recognised provider
    /// classification — we intentionally do not fail the injection in that
    /// case, because `Authorization: Bearer` was the sole existing behaviour
    /// (AAASM-3578) and is the de facto standard for OpenAI-compatible and
    /// self-hosted gateway APIs, so defaulting to it preserves every existing
    /// deployment rather than silently breaking a working custom endpoint.
    ///
    /// The secret bytes are expanded only into the returned owned buffer; they
    /// are never logged or copied into a `String`. This is the single accessor
    /// the data path uses, so TTL and rotation are honoured uniformly.
    ///
    /// A revoked host (AAASM-6262) also yields `None` here, which for a caller
    /// that forwards on `None` is pass-through. The data path must use
    /// [`Self::injection_for`], which tells a revoked host apart.
    pub fn authorization_for(&self, host: &str) -> Option<(&'static str, Vec<u8>)> {
        match self.injection_for(host) {
            Injection::Inject(name, value) => Some((name, value)),
            Injection::NotConfigured | Injection::Expired | Injection::Revoked => None,
        }
    }

    /// Decide what to do for `host` from a single read of the store: inject,
    /// forward unchanged, or refuse because the credential was revoked.
    ///
    /// A poisoned lock reads as [`Injection::NotConfigured`], matching how
    /// [`Self::authorization_for`] has always behaved (`.ok()?`).
    pub fn injection_for(&self, host: &str) -> Injection {
        let Ok(guard) = self.entries.read() else {
            return Injection::NotConfigured;
        };
        let Some(entry) = guard.get(&host.to_ascii_lowercase()) else {
            return Injection::NotConfigured;
        };
        let Some(secret) = entry.secret.as_ref() else {
            return Injection::Revoked;
        };
        if entry.is_expired() {
            tracing::debug!(%host, "configured provider credential has expired; not injecting");
            return Injection::Expired;
        }
        let key = secret.expose();
        match classify_provider_for_host(host) {
            Some(aa_core::llm::Provider::Anthropic) => Injection::Inject("x-api-key", key.to_vec()),
            _ => {
                let mut buf = Vec::with_capacity(key.len() + 7);
                buf.extend_from_slice(b"Bearer ");
                buf.extend_from_slice(key);
                Injection::Inject("Authorization", buf)
            }
        }
    }

    /// Revoke the credential for `host` (AAASM-6262): drop and zeroize the
    /// secret and leave a tombstone, so every later [`Self::injection_for`]
    /// returns [`Injection::Revoked`].
    ///
    /// Takes the write lock, so a lookup that starts after this returns is
    /// refused; a request that already read the credential completes. Revoking
    /// a host the store does not hold changes nothing
    /// ([`RevokeOutcome::NotConfigured`]).
    ///
    /// Revocation is in-memory: a restarted proxy re-reads
    /// `AA_PROXY_PROVIDER_KEYS`. [`Self::rotate`] on a revoked host installs a
    /// fresh credential on purpose: it is the seam an authorized rotator uses to
    /// provision a replacement.
    pub fn revoke(&self, host: &str) -> RevokeOutcome {
        let Ok(mut guard) = self.entries.write() else {
            // Cannot prove the secret is gone; report it rather than claim it.
            tracing::error!(%host, "credential store lock poisoned; revocation not applied");
            return RevokeOutcome::NotConfigured;
        };
        match guard.get_mut(&host.to_ascii_lowercase()) {
            None => RevokeOutcome::NotConfigured,
            Some(entry) if entry.secret.is_none() => RevokeOutcome::AlreadyRevoked,
            Some(entry) => {
                // Dropping the Secret zeroizes and munlocks it while the write
                // lock is held, so no reader can observe it afterwards.
                entry.secret = None;
                entry.expires_at = None;
                RevokeOutcome::Revoked
            }
        }
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
            secret: Some(Secret::new(new_secret)),
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
    fn authorization_for_openai_is_case_insensitive_and_bearer_prefixed() {
        // AC2 (AAASM-5926): OpenAI-classified hosts keep the existing
        // Authorization: Bearer semantics — no regression.
        let store = CredentialStore::from_pairs([("API.OpenAI.com".to_string(), b"sk-secret".to_vec())]);
        assert_eq!(
            store.authorization_for("api.openai.com"),
            Some(("Authorization", b"Bearer sk-secret".to_vec()))
        );
        assert_eq!(
            store.authorization_for("API.OPENAI.COM"),
            Some(("Authorization", b"Bearer sk-secret".to_vec()))
        );
    }

    #[test]
    fn authorization_for_anthropic_uses_x_api_key_not_bearer() {
        // AC1 (AAASM-5926): Anthropic's Messages API authenticates via a raw
        // x-api-key header, not Authorization: Bearer.
        let store = CredentialStore::from_pairs([("api.anthropic.com".to_string(), b"sk-ant-secret".to_vec())]);
        assert_eq!(
            store.authorization_for("api.anthropic.com"),
            Some(("x-api-key", b"sk-ant-secret".to_vec()))
        );
    }

    #[test]
    fn authorization_for_unrecognized_host_with_credential_defaults_to_bearer() {
        // AC3 (AAASM-5926): a credential configured for a host with no
        // recognised provider classification still injects — using the
        // pre-existing Authorization: Bearer default (see the doc comment on
        // `authorization_for` for why Bearer, not a refusal, is the safe
        // choice here) rather than silently dropping a configured credential.
        let store = CredentialStore::from_pairs([("llm.internal-gateway.example".to_string(), b"sk-custom".to_vec())]);
        assert_eq!(
            store.authorization_for("llm.internal-gateway.example"),
            Some(("Authorization", b"Bearer sk-custom".to_vec()))
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
            store.authorization_for("api.openai.com"),
            Some(("Authorization", b"Bearer sk-old".to_vec()))
        );

        store.rotate("api.openai.com", b"sk-new".to_vec(), None);
        assert_eq!(
            store.authorization_for("api.openai.com"),
            Some(("Authorization", b"Bearer sk-new".to_vec())),
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
            store.authorization_for("api.anthropic.com"),
            Some(("x-api-key", b"sk-ant-leased".to_vec())),
            "rotated Anthropic credential must still use x-api-key semantics"
        );
    }

    #[test]
    fn non_expiring_entry_stays_valid() {
        let store = CredentialStore::from_pairs([("api.openai.com".to_string(), b"sk-forever".to_vec())]);
        assert!(store.authorization_for("api.openai.com").is_some());
    }

    #[test]
    fn empty_secret_constructs_and_does_not_pin() {
        // A zero-length credential must not attempt to mlock an empty range
        // (`lock_memory` returns false for an empty buffer) and must still
        // construct, expose, and drop cleanly.
        let secret = Secret::new(Vec::new());
        assert!(secret.expose().is_empty());
        drop(secret);
    }

    // ── from_env operator-configuration parsing ─────────────────────────────
    //
    // `from_env` is the only path that turns operator config into a live store,
    // so its host=key parsing, lowercasing, and malformed-entry skipping are
    // load-bearing for egress injection.

    /// Serialise env-var tests so they don't race each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn from_env_unset_yields_empty_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("AA_PROXY_PROVIDER_KEYS");
        let store = CredentialStore::from_env();
        assert!(store.is_empty());
    }

    #[test]
    fn from_env_empty_string_yields_empty_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_PROXY_PROVIDER_KEYS", "");
        let store = CredentialStore::from_env();
        assert!(store.is_empty());
        std::env::remove_var("AA_PROXY_PROVIDER_KEYS");
    }

    #[test]
    fn from_env_parses_multiple_host_key_pairs_lowercased() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(
            "AA_PROXY_PROVIDER_KEYS",
            " API.OpenAI.com=sk-openai , api.anthropic.com=sk-ant ",
        );
        let store = CredentialStore::from_env();
        assert_eq!(store.len(), 2);
        // Hosts are stored lowercased and trimmed; keys keep their exact bytes.
        assert_eq!(
            store.authorization_for("api.openai.com"),
            Some(("Authorization", b"Bearer sk-openai".to_vec()))
        );
        assert_eq!(
            store.authorization_for("api.anthropic.com"),
            Some(("x-api-key", b"sk-ant".to_vec()))
        );
        std::env::remove_var("AA_PROXY_PROVIDER_KEYS");
    }

    #[test]
    fn from_env_skips_malformed_entries_but_keeps_valid_ones() {
        // Entries without '=', with an empty host, or an empty key are skipped
        // (and never echoed); the surrounding valid entry must still load.
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(
            "AA_PROXY_PROVIDER_KEYS",
            "no-equals-sign,=orphan-key,emptyval=,api.openai.com=sk-ok",
        );
        let store = CredentialStore::from_env();
        assert_eq!(store.len(), 1, "only the well-formed entry should load");
        assert_eq!(
            store.authorization_for("api.openai.com"),
            Some(("Authorization", b"Bearer sk-ok".to_vec()))
        );
        std::env::remove_var("AA_PROXY_PROVIDER_KEYS");
    }
    // AAASM-6262: revocation at the Credential Broker (J84 AC3). Synthetic
    // secrets only.
    const SYNTHETIC: &[u8] = b"sk-ant-QA6262-synthetic";

    #[test]
    fn revoke_stops_injection_and_is_not_the_same_as_not_configured() {
        let store = CredentialStore::from_pairs([("api.anthropic.com".to_string(), SYNTHETIC.to_vec())]);
        // Positive control: the credential injects before the revoke.
        assert!(matches!(
            store.injection_for("api.anthropic.com"),
            Injection::Inject("x-api-key", ref v) if v == SYNTHETIC
        ));
        assert_eq!(store.revoke("api.anthropic.com"), RevokeOutcome::Revoked);
        // The discriminator: a remove-only revoke would answer NotConfigured
        // here, and the data path forwards NotConfigured with the agent's own
        // headers, which is fail-open.
        assert!(matches!(store.injection_for("api.anthropic.com"), Injection::Revoked));
        assert_eq!(store.authorization_for("api.anthropic.com"), None);
    }

    #[test]
    fn revoke_is_case_insensitive_and_idempotent() {
        let store = CredentialStore::from_pairs([("API.Anthropic.com".to_string(), SYNTHETIC.to_vec())]);
        assert_eq!(store.revoke("api.ANTHROPIC.com"), RevokeOutcome::Revoked);
        assert_eq!(store.revoke("api.anthropic.com"), RevokeOutcome::AlreadyRevoked);
        assert!(matches!(store.injection_for("API.ANTHROPIC.COM"), Injection::Revoked));
    }

    #[test]
    fn revoking_an_unconfigured_host_changes_nothing() {
        let store = CredentialStore::from_pairs([("api.openai.com".to_string(), b"sk-synthetic".to_vec())]);
        assert_eq!(store.revoke("api.anthropic.com"), RevokeOutcome::NotConfigured);
        // A mistyped host must not start refusing traffic.
        assert!(matches!(
            store.injection_for("api.anthropic.com"),
            Injection::NotConfigured
        ));
        assert!(matches!(store.injection_for("api.openai.com"), Injection::Inject(..)));
    }

    #[test]
    fn revoking_one_host_leaves_the_others_injecting() {
        let store = CredentialStore::from_pairs([
            ("api.anthropic.com".to_string(), SYNTHETIC.to_vec()),
            ("api.openai.com".to_string(), b"sk-synthetic".to_vec()),
        ]);
        assert_eq!(store.revoke("api.anthropic.com"), RevokeOutcome::Revoked);
        assert!(matches!(
            store.injection_for("api.openai.com"),
            Injection::Inject("Authorization", ref v) if v == b"Bearer sk-synthetic"
        ));
    }

    #[test]
    fn rotate_after_revoke_installs_a_fresh_credential() {
        let store = CredentialStore::from_pairs([("api.anthropic.com".to_string(), SYNTHETIC.to_vec())]);
        store.revoke("api.anthropic.com");
        store.rotate("api.anthropic.com", b"sk-ant-QA6262-replacement".to_vec(), None);
        assert!(matches!(
            store.injection_for("api.anthropic.com"),
            Injection::Inject("x-api-key", ref v) if v == b"sk-ant-QA6262-replacement"
        ));
    }

    #[test]
    fn a_revoked_store_still_never_formats_the_secret() {
        let store = CredentialStore::from_pairs([("api.anthropic.com".to_string(), SYNTHETIC.to_vec())]);
        store.revoke("api.anthropic.com");
        let dbg = format!("{store:?}");
        assert!(!dbg.contains("QA6262"), "Debug leaked secret material: {dbg}");
    }
    // ── AAASM-6395: provider keys delivered on stdin ────────────────────────

    #[test]
    fn a_valid_payload_parses_and_the_store_built_from_it_injects() {
        let pairs =
            parse_provider_keys(" Api.Anthropic.com=sk-ant-QA6395-synth , api.openai.com=sk-QA6395-two ,").unwrap();
        assert_eq!(pairs.len(), 2);
        let store = CredentialStore::from_pairs(pairs);
        // Positive control for every refusal below: the same parser, fed a good payload,
        // produces a store that actually injects.
        assert!(matches!(
            store.injection_for("api.anthropic.com"),
            Injection::Inject("x-api-key", ref v) if v == b"sk-ant-QA6395-synth"
        ));
    }

    #[test]
    fn a_malformed_entry_refuses_the_whole_payload_and_the_error_never_quotes_it() {
        for bad in [
            "api.x.com=ok,SECRETMARK6395",
            "=SECRETMARK6395",
            "api.x.com=",
            "api.x.com=ok,,host-no-equals",
        ] {
            let err = parse_provider_keys(bad).unwrap_err();
            assert!(matches!(err, ProviderKeysError::Malformed { .. }), "{bad}: {err:?}");
            let text = format!("{err} / {err:?}");
            assert!(!text.contains("SECRETMARK6395"), "error quoted the input: {text}");
        }
        assert_eq!(
            parse_provider_keys("api.x.com=ok,SECRETMARK6395").unwrap_err(),
            ProviderKeysError::Malformed { index: 2 }
        );
    }

    #[test]
    fn nothing_usable_is_empty_not_an_empty_store() {
        for blank in ["", "  ", ",,", " , "] {
            assert_eq!(
                parse_provider_keys(blank).unwrap_err(),
                ProviderKeysError::Empty,
                "{blank:?}"
            );
        }
    }

    #[test]
    fn reading_is_bounded_and_refuses_oversize_endless_and_non_utf8_input() {
        let at_limit = format!("h={}", "a".repeat(MAX_PROVIDER_KEYS_BYTES - 2));
        assert_eq!(at_limit.len(), MAX_PROVIDER_KEYS_BYTES);
        assert!(
            read_provider_keys(at_limit.as_bytes()).is_ok(),
            "exactly the limit is accepted"
        );
        let over = format!("h={}", "a".repeat(MAX_PROVIDER_KEYS_BYTES - 1));
        assert_eq!(
            read_provider_keys(over.as_bytes()).unwrap_err(),
            ProviderKeysError::TooLarge
        );
        // An endless writer must be refused after the bound, not buffered forever.
        assert_eq!(
            read_provider_keys(std::io::repeat(b'a')).unwrap_err(),
            ProviderKeysError::TooLarge
        );
        assert_eq!(
            read_provider_keys(&b"h=\xff\xfe"[..]).unwrap_err(),
            ProviderKeysError::NotUtf8
        );
        assert_eq!(read_provider_keys(&b""[..]).unwrap_err(), ProviderKeysError::Empty);
    }

    #[test]
    fn stdin_and_environment_together_are_refused_before_stdin_is_read() {
        // A reader that panics proves stdin is not touched when the request is ambiguous.
        struct Untouchable;
        impl std::io::Read for Untouchable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("stdin was read for an ambiguous request");
            }
        }
        assert_eq!(
            CredentialStore::load_with(true, true, Untouchable).err(),
            Some(ProviderKeysError::Ambiguous)
        );
    }

    #[test]
    fn selecting_stdin_loads_the_delivered_store_and_a_bad_payload_refuses() {
        let store = CredentialStore::load_with(true, false, &b"api.anthropic.com=sk-ant-QA6395-stdin"[..])
            .expect("a valid payload loads")
            .expect("stdin selected yields a store");
        assert!(matches!(
            store.injection_for("api.anthropic.com"),
            Injection::Inject("x-api-key", ref v) if v == b"sk-ant-QA6395-stdin"
        ));
        // The same path with nothing delivered refuses; it must never yield an empty store.
        assert_eq!(
            CredentialStore::load_with(true, false, &b""[..]).err(),
            Some(ProviderKeysError::Empty)
        );
    }

    #[test]
    fn without_the_flag_nothing_is_read_from_stdin_and_the_legacy_path_is_left_alone() {
        struct Untouchable;
        impl std::io::Read for Untouchable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("stdin was read although it was not selected");
            }
        }
        assert!(matches!(CredentialStore::load_with(false, true, Untouchable), Ok(None)));
        assert!(matches!(
            CredentialStore::load_with(false, false, Untouchable),
            Ok(None)
        ));
    }
}
