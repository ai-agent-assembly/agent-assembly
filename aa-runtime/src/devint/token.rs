//! DI-API capability tokens: issue, resolve, rotate, revoke (ADR 0030 §5.3).
//!
//! # Why this is not the AAASM-3922 shape
//!
//! The SDK IPC handshake key is derived from the agent id — which *is* the
//! public socket filename — so any local process that can reach the socket can
//! recompute it. That signature proves integrity and version-binding, not
//! possession of a secret (see [`crate::ipc::handshake`]). ADR 0030 forbidden
//! design 9 names repeating that mistake here.
//!
//! A capability token is therefore built the opposite way, and every one of
//! these properties is load-bearing:
//!
//! * **256 bits straight from the OS CSPRNG.** [`CapabilityToken::generate`]
//!   returns the bytes from `rand::random`; nothing about the token is computed
//!   from the client name, the tool id, the socket path, the token id or any
//!   other value a caller could see or guess.
//! * **Opaque.** The wire carries the hex secret and nothing else — no claims,
//!   no signature, no structure to parse. There is no information in it.
//! * **A server-side record, not a self-contained grant.** Verification is a
//!   *lookup*: [`TokenStore::resolve`] hashes the presented secret and finds
//!   the record, or denies. A JWT-style credential that verifies offline cannot
//!   be revoked, and revocation is a hard requirement of this ticket — hence no
//!   JWT (forbidden design 9 again).
//! * **Revocation is deleting the record.** Immediate and total, precisely
//!   because the token was never self-verifying.
//!
//! # What the store keeps, and what it does not
//!
//! A [`TokenRecord`] holds `{token_id, client_name, issued_at, expires_at,
//! scope}` and the SHA-256 of the secret. The secret itself is returned once,
//! at enrolment, and is never stored, logged, echoed in a response or written
//! to an audit event — the audit trail identifies a token by its `token_id`
//! (§5.3: "the token *id* and the outcome — never the token value").
//!
//! Lookup is by hash, so the comparison that decides admission runs over a
//! fixed-length digest rather than over attacker-controlled input length.
//!
//! # Fail-closed
//!
//! Absent, malformed, unknown, expired and out-of-scope all resolve to a
//! [`TokenDenial`]. There is no fall-through to an implicit grant, no "local
//! connections are trusted", and no anonymous read-only tier — ADR 0015's rule
//! transferred: a resolution failure must fail closed and be audit-visible.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};

use super::scope::TokenScope;
use super::verb::DiVerb;

/// Number of random bytes in a capability token: 256 bits (§5.3).
pub const TOKEN_BYTES: usize = 32;

/// The identifier a token is known by in records, audit events and rotation.
///
/// Deliberately **independent** of the secret: it is drawn from the CSPRNG in
/// its own right, so publishing it in an audit event reveals nothing that helps
/// anyone recover or narrow the secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TokenId(String);

impl TokenId {
    /// Generate a fresh random token id.
    pub fn generate() -> Self {
        TokenId(hex::encode(rand::random::<[u8; 16]>()))
    }

    /// The id as a string, for audit records and rotation calls.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A freshly issued capability token secret.
///
/// Returned exactly once, by [`TokenStore::issue`] and [`TokenStore::rotate`],
/// for the enrolment step to write to a `0600` file. Its [`std::fmt::Debug`]
/// impl redacts the value so it cannot reach a log through a `{:?}` on some
/// enclosing struct.
#[derive(Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    secret_hex: String,
}

impl CapabilityToken {
    /// Draw [`TOKEN_BYTES`] from the OS-seeded CSPRNG.
    ///
    /// `rand::random` *returns* the bytes rather than filling a zeroed buffer,
    /// so no constant literal enters the token's data flow — the same pattern
    /// [`crate::ipc::handshake::generate_nonce`] uses.
    pub fn generate() -> Self {
        CapabilityToken {
            secret_hex: hex::encode(rand::random::<[u8; TOKEN_BYTES]>()),
        }
    }

    /// Wrap a secret presented on the wire.
    pub fn from_wire(secret_hex: impl Into<String>) -> Self {
        CapabilityToken {
            secret_hex: secret_hex.into(),
        }
    }

    /// The hex secret, for writing to the enrolment file or presenting on the
    /// wire. Every other code path should use the [`TokenId`].
    pub fn expose(&self) -> &str {
        &self.secret_hex
    }

    /// Whether the presented string is even shaped like a token.
    ///
    /// Checked before hashing so a client sending a megabyte of text is
    /// rejected on shape, and so "malformed" is distinguishable from "unknown"
    /// in the audit trail without either being distinguishable on the wire.
    fn is_well_formed(&self) -> bool {
        self.secret_hex.len() == TOKEN_BYTES * 2 && self.secret_hex.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// The lookup key: SHA-256 of the secret's bytes.
    fn lookup_hash(&self) -> [u8; 32] {
        Sha256::digest(self.secret_hex.as_bytes()).into()
    }
}

impl std::fmt::Debug for CapabilityToken {
    /// Redacted on purpose: a token that can be `{:?}`-printed will eventually
    /// be `{:?}`-printed into a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapabilityToken(<redacted>)")
    }
}

/// The server-side record a presented token resolves to.
///
/// This is the whole grant. Nothing about it travels on the wire, and nothing
/// in it is derivable from the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    /// Stable identifier for this enrolment, used in audit and rotation.
    pub token_id: TokenId,
    /// Who enrolled, for the user-visible "which clients can talk to AASM?"
    /// list. Display only — never an authentication factor.
    pub client_name: String,
    /// When it was issued, seconds since the Unix epoch.
    pub issued_at_unix_secs: u64,
    /// Absolute expiry, seconds since the Unix epoch. Not a sliding window: a
    /// token that is used constantly still dies on schedule.
    pub expires_at_unix_secs: u64,
    /// What it may do.
    pub scope: TokenScope,
}

impl TokenRecord {
    /// Whether this record is still within its absolute lifetime at `now`.
    pub fn is_live(&self, now_unix_secs: u64) -> bool {
        now_unix_secs < self.expires_at_unix_secs
    }
}

/// Why a request was refused at the authentication or authorization layer.
///
/// These reasons are for the **audit trail**. The wire deliberately collapses
/// the first three into one code so a probing client cannot tell them apart
/// (see `DenyCode` in `proto/devint.proto`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenDenial {
    /// No token was presented at all.
    Absent,
    /// Something was presented, but it is not shaped like a token.
    Malformed,
    /// Well-formed, but no record resolves it — including a token that was
    /// revoked, which is the same thing as never having existed.
    Unknown,
    /// A record resolved, and it is past its absolute expiry.
    Expired {
        /// Which enrolment expired.
        token_id: TokenId,
    },
    /// A live record resolved, but its scope does not admit this verb on this
    /// tool.
    OutOfScope {
        /// Which enrolment was used.
        token_id: TokenId,
        /// What it tried to do.
        verb: DiVerb,
    },
}

impl TokenDenial {
    /// The enrolment involved, when one was identified. `None` for denials
    /// where no record was reached, which is exactly when there is no id to
    /// record.
    pub fn token_id(&self) -> Option<&TokenId> {
        match self {
            TokenDenial::Absent | TokenDenial::Malformed | TokenDenial::Unknown => None,
            TokenDenial::Expired { token_id } | TokenDenial::OutOfScope { token_id, .. } => Some(token_id),
        }
    }

    /// A stable snake_case outcome name for the audit trail.
    pub const fn outcome(&self) -> &'static str {
        match self {
            TokenDenial::Absent => "token_absent",
            TokenDenial::Malformed => "token_malformed",
            TokenDenial::Unknown => "token_unknown",
            TokenDenial::Expired { .. } => "token_expired",
            TokenDenial::OutOfScope { .. } => "out_of_scope",
        }
    }
}

/// The runtime's enrolment book.
///
/// Cheap to clone (`Arc` inside) so the accept loop and each connection share
/// one book and a revocation takes effect on every live connection at once,
/// not at the next reconnect.
#[derive(Debug, Clone, Default)]
pub struct TokenStore {
    inner: Arc<RwLock<StoreInner>>,
}

#[derive(Debug, Default)]
struct StoreInner {
    /// SHA-256(secret) → record. Keyed by hash so the store never holds a
    /// secret it could leak.
    by_hash: HashMap<[u8; 32], TokenRecord>,
    /// token_id → SHA-256(secret), so revocation and rotation can find a
    /// record without the secret.
    hash_by_id: HashMap<TokenId, [u8; 32]>,
}

impl TokenStore {
    /// An empty store. Empty means *nothing is authorized*, which is the right
    /// starting state: enrolment is an explicit, user-visible step, never an
    /// implicit grant on first connect.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enrol a client and return its one and only copy of the secret.
    ///
    /// The caller writes the returned token to a `0600` file; the store keeps
    /// only the hash. There is no way to read a secret back out of the store,
    /// by design.
    pub fn issue(
        &self,
        client_name: impl Into<String>,
        scope: TokenScope,
        issued_at_unix_secs: u64,
        ttl_secs: u64,
    ) -> (CapabilityToken, TokenRecord) {
        let token = CapabilityToken::generate();
        let record = TokenRecord {
            token_id: TokenId::generate(),
            client_name: client_name.into(),
            issued_at_unix_secs,
            expires_at_unix_secs: issued_at_unix_secs.saturating_add(ttl_secs),
            scope,
        };
        let hash = token.lookup_hash();
        {
            let mut inner = self.write();
            inner.hash_by_id.insert(record.token_id.clone(), hash);
            inner.by_hash.insert(hash, record.clone());
        }
        (token, record)
    }

    /// Resolve a presented token for `verb` on `tool_id`.
    ///
    /// Every failure path returns [`Err`]; there is no variant of this function
    /// that admits a request without a live, in-scope record.
    pub fn resolve(
        &self,
        presented: Option<&CapabilityToken>,
        verb: DiVerb,
        tool_id: &str,
        now_unix_secs: u64,
    ) -> Result<TokenRecord, TokenDenial> {
        let Some(token) = presented else {
            return Err(TokenDenial::Absent);
        };
        if !token.is_well_formed() {
            return Err(TokenDenial::Malformed);
        }
        let record = {
            let inner = self.read();
            inner.by_hash.get(&token.lookup_hash()).cloned()
        };
        // A revoked token lands here identically to one that never existed:
        // revocation removed the record, so there is nothing left to resolve.
        let record = record.ok_or(TokenDenial::Unknown)?;
        if !record.is_live(now_unix_secs) {
            return Err(TokenDenial::Expired {
                token_id: record.token_id,
            });
        }
        if !record.scope.permits(verb, tool_id) {
            return Err(TokenDenial::OutOfScope {
                token_id: record.token_id,
                verb,
            });
        }
        Ok(record)
    }

    /// Issue a replacement carrying the same client name and scope.
    ///
    /// Rotation is deliberately **issue-new-then-revoke-old**: the old token
    /// keeps working until the caller revokes it, so a rotation never opens a
    /// window in which no valid token exists. Returns `None` when `token_id`
    /// names no enrolment.
    pub fn rotate(
        &self,
        token_id: &TokenId,
        issued_at_unix_secs: u64,
        ttl_secs: u64,
    ) -> Option<(CapabilityToken, TokenRecord)> {
        let existing = self.record(token_id)?;
        Some(self.issue(existing.client_name, existing.scope, issued_at_unix_secs, ttl_secs))
    }

    /// Delete an enrolment. Returns whether one was there.
    ///
    /// Immediate and total: the next `resolve` of that secret finds nothing,
    /// including on a connection that is already open.
    pub fn revoke(&self, token_id: &TokenId) -> bool {
        let mut inner = self.write();
        match inner.hash_by_id.remove(token_id) {
            Some(hash) => inner.by_hash.remove(&hash).is_some(),
            None => false,
        }
    }

    /// Look up an enrolment's record by id, for display and rotation.
    pub fn record(&self, token_id: &TokenId) -> Option<TokenRecord> {
        let inner = self.read();
        let hash = inner.hash_by_id.get(token_id)?;
        inner.by_hash.get(hash).cloned()
    }

    /// Every live enrolment at `now`, for the user-visible "which clients can
    /// talk to AASM?" list. Records only — never secrets.
    pub fn live_records(&self, now_unix_secs: u64) -> Vec<TokenRecord> {
        let inner = self.read();
        let mut records: Vec<TokenRecord> = inner
            .by_hash
            .values()
            .filter(|r| r.is_live(now_unix_secs))
            .cloned()
            .collect();
        records.sort_by(|a, b| a.token_id.cmp(&b.token_id));
        records
    }

    /// Drop every record that has passed its expiry, returning how many went.
    ///
    /// Housekeeping only: an expired record already denies, so this changes no
    /// admission decision.
    pub fn purge_expired(&self, now_unix_secs: u64) -> usize {
        let mut inner = self.write();
        let dead: Vec<TokenId> = inner
            .by_hash
            .values()
            .filter(|r| !r.is_live(now_unix_secs))
            .map(|r| r.token_id.clone())
            .collect();
        for id in &dead {
            if let Some(hash) = inner.hash_by_id.remove(id) {
                inner.by_hash.remove(&hash);
            }
        }
        dead.len()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, StoreInner> {
        // A poisoned lock means a panic happened while a write was in flight.
        // Recovering the guard is correct here: the map is a plain
        // `HashMap` with no cross-entry invariant to have been left broken,
        // and refusing to read would take the DI-API down instead of denying
        // one request.
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, StoreInner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devint::scope::ToolScope;

    const NOW: u64 = 1_700_000_000;
    const HOUR: u64 = 3600;

    fn store_with_claude_token() -> (TokenStore, CapabilityToken, TokenRecord) {
        let store = TokenStore::new();
        let (token, record) = store.issue(
            "vscode-aasm",
            TokenScope::full_lifecycle(ToolScope::tools(["claude-code"])),
            NOW,
            HOUR,
        );
        (store, token, record)
    }

    #[test]
    fn a_generated_token_is_256_bits_of_hex() {
        let token = CapabilityToken::generate();
        assert_eq!(token.expose().len(), TOKEN_BYTES * 2);
        assert!(token.expose().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn two_generated_tokens_differ() {
        // A weak smoke test for "actually random", not a statistical one: what
        // it really rules out is a constant or a counter.
        let a = CapabilityToken::generate();
        let b = CapabilityToken::generate();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn a_token_is_not_derived_from_any_public_value() {
        // AAASM-3922's mistake was a key recomputable from the socket filename.
        // Two enrolments with identical client name, scope, and issue time must
        // still produce unrelated secrets — if the secret were a function of
        // those inputs, these would collide.
        let store = TokenStore::new();
        let scope = TokenScope::read_only(ToolScope::tools(["claude-code"]));
        let (a, _) = store.issue("vscode-aasm", scope.clone(), NOW, HOUR);
        let (b, _) = store.issue("vscode-aasm", scope, NOW, HOUR);
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let token = CapabilityToken::generate();
        let rendered = format!("{token:?}");
        assert!(!rendered.contains(token.expose()));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn a_live_in_scope_token_resolves() {
        let (store, token, record) = store_with_claude_token();
        let resolved = store
            .resolve(Some(&token), DiVerb::Apply, "claude-code", NOW)
            .expect("live token");
        assert_eq!(resolved.token_id, record.token_id);
    }

    #[test]
    fn an_absent_token_is_denied() {
        let (store, _, _) = store_with_claude_token();
        assert_eq!(
            store.resolve(None, DiVerb::Status, "claude-code", NOW),
            Err(TokenDenial::Absent)
        );
    }

    #[test]
    fn a_malformed_token_is_denied() {
        let (store, _, _) = store_with_claude_token();
        let junk = CapabilityToken::from_wire("not-a-token");
        assert_eq!(
            store.resolve(Some(&junk), DiVerb::Status, "claude-code", NOW),
            Err(TokenDenial::Malformed)
        );
    }

    #[test]
    fn an_unknown_but_well_formed_token_is_denied() {
        let (store, _, _) = store_with_claude_token();
        let stranger = CapabilityToken::generate();
        assert_eq!(
            store.resolve(Some(&stranger), DiVerb::Status, "claude-code", NOW),
            Err(TokenDenial::Unknown)
        );
    }

    #[test]
    fn an_expired_token_is_denied_and_names_its_enrolment() {
        let (store, token, record) = store_with_claude_token();
        let denial = store
            .resolve(Some(&token), DiVerb::Status, "claude-code", NOW + HOUR + 1)
            .expect_err("expired");
        assert_eq!(
            denial,
            TokenDenial::Expired {
                token_id: record.token_id
            }
        );
    }

    #[test]
    fn expiry_is_absolute_not_sliding() {
        let (store, token, _) = store_with_claude_token();
        // Use it repeatedly right up to the boundary; it must still die on time.
        for t in [NOW, NOW + 1, NOW + HOUR - 1] {
            assert!(store.resolve(Some(&token), DiVerb::Status, "claude-code", t).is_ok());
        }
        assert!(store
            .resolve(Some(&token), DiVerb::Status, "claude-code", NOW + HOUR)
            .is_err());
    }

    #[test]
    fn a_cross_tool_request_is_denied_for_every_tool_scoped_verb() {
        let (store, token, record) = store_with_claude_token();
        for verb in DiVerb::ALL.into_iter().filter(|v| v.is_tool_scoped()) {
            let denial = store
                .resolve(Some(&token), verb, "codex", NOW)
                .expect_err("cross-tool must be denied");
            assert_eq!(
                denial,
                TokenDenial::OutOfScope {
                    token_id: record.token_id.clone(),
                    verb
                }
            );
        }
    }

    #[test]
    fn revocation_takes_effect_immediately() {
        let (store, token, record) = store_with_claude_token();
        assert!(store.resolve(Some(&token), DiVerb::Status, "claude-code", NOW).is_ok());
        assert!(store.revoke(&record.token_id));
        assert_eq!(
            store.resolve(Some(&token), DiVerb::Status, "claude-code", NOW),
            Err(TokenDenial::Unknown)
        );
    }

    #[test]
    fn revoking_twice_reports_the_second_as_absent() {
        let (store, _, record) = store_with_claude_token();
        assert!(store.revoke(&record.token_id));
        assert!(!store.revoke(&record.token_id));
    }

    #[test]
    fn rotation_leaves_no_window_without_a_valid_token() {
        let (store, old, old_record) = store_with_claude_token();
        let (new, new_record) = store.rotate(&old_record.token_id, NOW + 10, HOUR).expect("rotated");

        // Both work between issue and revoke — that is the point of the order.
        assert!(store
            .resolve(Some(&old), DiVerb::Apply, "claude-code", NOW + 10)
            .is_ok());
        assert!(store
            .resolve(Some(&new), DiVerb::Apply, "claude-code", NOW + 10)
            .is_ok());
        assert_ne!(old.expose(), new.expose());
        assert_ne!(old_record.token_id, new_record.token_id);
        assert_eq!(new_record.client_name, old_record.client_name);

        store.revoke(&old_record.token_id);
        assert!(store
            .resolve(Some(&old), DiVerb::Apply, "claude-code", NOW + 10)
            .is_err());
        assert!(store
            .resolve(Some(&new), DiVerb::Apply, "claude-code", NOW + 10)
            .is_ok());
    }

    #[test]
    fn rotating_an_unknown_enrolment_yields_nothing() {
        let (store, _, _) = store_with_claude_token();
        assert!(store.rotate(&TokenId::generate(), NOW, HOUR).is_none());
    }

    #[test]
    fn an_empty_store_authorizes_nothing() {
        let store = TokenStore::new();
        let token = CapabilityToken::generate();
        for verb in DiVerb::ALL {
            assert!(store.resolve(Some(&token), verb, "claude-code", NOW).is_err());
        }
    }

    #[test]
    fn live_records_hide_expired_ones_and_carry_no_secret() {
        let (store, token, record) = store_with_claude_token();
        let live = store.live_records(NOW);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].token_id, record.token_id);
        let rendered = format!("{live:?}");
        assert!(!rendered.contains(token.expose()));
        assert!(store.live_records(NOW + HOUR).is_empty());
    }

    #[test]
    fn purge_removes_only_expired_records() {
        let store = TokenStore::new();
        let scope = TokenScope::read_only(ToolScope::AllTools);
        let (_, short) = store.issue("a", scope.clone(), NOW, 10);
        let (_, long) = store.issue("b", scope, NOW, HOUR);
        assert_eq!(store.purge_expired(NOW + 20), 1);
        assert!(store.record(&short.token_id).is_none());
        assert!(store.record(&long.token_id).is_some());
    }

    #[test]
    fn a_token_id_is_not_derivable_from_the_secret() {
        // Records identify enrolments in audit events. If the id were a
        // digest of the secret, publishing it would publish a verifier for the
        // secret. Assert the id is not any obvious function of it.
        let (_, token, record) = store_with_claude_token();
        let digest = hex::encode(Sha256::digest(token.expose().as_bytes()));
        assert!(!digest.contains(record.token_id.as_str()));
        assert!(!token.expose().contains(record.token_id.as_str()));
    }
}
