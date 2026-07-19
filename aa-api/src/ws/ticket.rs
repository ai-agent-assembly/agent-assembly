//! Short-lived, single-use WebSocket authorization tickets (AAASM-4861).
//!
//! Browsers cannot set an `Authorization` header on a WebSocket handshake, so
//! the dashboard historically appended the long-lived session JWT to the WS URL
//! as `?token=…`. Any intermediary that logs request URLs (reverse proxy, CDN,
//! load balancer) then captured a live credential. This module replaces that
//! with a short-TTL, single-use ticket the dashboard mints over an authenticated
//! REST call ([`crate::routes::auth::issue_ws_ticket`]) and presents once on the
//! upgrade as `?ticket=…`.
//!
//! Security properties (see ADR 0012 — WebSocket & Browser Credential Handling):
//! * **Opaque** — a random 256-bit token, meaningless without the server store.
//! * **Short-lived** — [`WsTicketStore::TTL`]; expired tickets are rejected.
//! * **Single-use** — [`WsTicketStore::consume`] atomically removes the entry, so
//!   a replayed ticket (or a race between two upgrades) succeeds at most once.
//! * **Purpose-bound** — a ticket minted for one stream cannot open another.
//! * **Identity/tenant-bound** — the caller snapshot is captured server-side at
//!   mint; the client cannot alter the identity, scopes, or tenant it resolves to.
//! * **Not a REST credential** — the token is only ever accepted by the WS
//!   upgrade; presented as a Bearer to any REST route it fails validation (it is
//!   neither an `aa_…` API key nor a JWT).
//! * **Not refreshable** — there is no renew path; a reconnect mints a fresh one.

use std::time::{Duration, Instant};

use rand::RngExt as _;
use serde::{Deserialize, Serialize};

use crate::auth::scope::Scope;
use crate::auth::{AuthenticatedCaller, Tenant};

/// What a ticket authorizes. A ticket minted for one purpose is rejected by any
/// other WS endpoint, so a leaked live-ops ticket can't open the alert stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WsTicketPurpose {
    /// `GET /api/v1/ws/events` — governance event stream (live-ops + approvals).
    Events,
    /// `GET /api/v1/alerts/ws` — alert lifecycle stream.
    Alerts,
}

/// The server-side record a minted ticket resolves to.
///
/// Captures the caller's verified identity at mint time so consuming the ticket
/// reconstructs exactly that caller — the client can never widen its own scope
/// or redirect its tenant by choosing a different `?ticket=` value, because the
/// value is an opaque index into this server-held record, not a bearer of claims.
#[derive(Debug, Clone)]
pub struct WsTicket {
    /// API-key id / JWT subject of the caller that minted this ticket.
    pub key_id: String,
    /// Scopes granted to that caller.
    pub scopes: Vec<Scope>,
    /// Team the caller is confined to, if any.
    pub team_id: Option<String>,
    /// Org the caller is confined to, if any.
    pub org_id: Option<String>,
    /// The single stream this ticket may open.
    pub purpose: WsTicketPurpose,
    /// Monotonic instant after which the ticket is invalid.
    ///
    /// The authoritative expiry check lives in [`WsTicketStore::consume`] and
    /// reads this field — it does **not** rely on the `moka` TTL alone, because
    /// `moka`'s `remove` returns an entry that is past its TTL but not yet
    /// evicted (a background pass evicts it later). For a security boundary that
    /// lazy window is unacceptable: an expired ticket must never authenticate.
    /// The TTL remains as the memory-reclamation backstop.
    pub expires_at: Instant,
}

impl WsTicket {
    /// Rebuild the authenticated caller this ticket stands in for.
    fn into_caller(self) -> AuthenticatedCaller {
        AuthenticatedCaller {
            key_id: self.key_id,
            scopes: self.scopes,
            tenant: Tenant {
                team_id: self.team_id,
                org_id: self.org_id,
            },
        }
    }
}

/// Opaque-token prefix. Deliberately not the `aa_` API-key prefix, so the REST
/// auth path never routes a ticket down the API-key branch — a ticket presented
/// to a REST route falls through to JWT validation and is rejected.
const TICKET_PREFIX: &str = "wst_";

/// A TTL + single-use store for [`WsTicket`]s.
///
/// Cheap to clone — the inner `moka` cache is `Arc`-shared, so the mint handler
/// and the WS upgrade handlers all observe the same entries when the store is
/// layered as one `Extension` in `build_app_with_spa`.
///
/// **Single-node.** The store is in-process: the OSS `aa-api` runs as one
/// process, so there is no shared key-value store to back it and none is
/// introduced. A ticket therefore does not survive a restart and would not be
/// valid across a hypothetical multi-instance deployment — an accepted limitation
/// recorded in ADR 0012. Tickets are short-lived and single-use, so the blast
/// radius of that limitation is a failed upgrade that the client simply re-mints.
#[derive(Clone)]
pub struct WsTicketStore {
    tickets: moka::future::Cache<String, WsTicket>,
    ttl: Duration,
}

impl WsTicketStore {
    /// Default ticket lifetime. Long enough to cover a mint→connect round-trip,
    /// short enough that a captured ticket is useless within seconds.
    pub const TTL: Duration = Duration::from_secs(30);

    /// Build a store with the default [`TTL`](Self::TTL).
    pub fn new() -> Self {
        Self::with_ttl(Self::TTL)
    }

    /// Build a store with a custom TTL. Test-only — real builds use [`new`](Self::new).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            tickets: moka::future::Cache::builder()
                .time_to_live(ttl)
                .max_capacity(8192)
                .build(),
            ttl,
        }
    }

    /// The configured ticket lifetime (surfaced in the mint response so clients
    /// know when to re-mint).
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Mint a fresh single-use ticket bound to `caller` and `purpose`, returning
    /// the opaque token the client presents on the WS upgrade.
    ///
    /// The token is never logged: only the caller holds the plaintext, and it is
    /// worthless after [`consume`](Self::consume) or the TTL, whichever is first.
    pub async fn mint(&self, caller: &AuthenticatedCaller, purpose: WsTicketPurpose) -> String {
        let token = generate_token();
        let ticket = WsTicket {
            key_id: caller.key_id.clone(),
            scopes: caller.scopes.clone(),
            team_id: caller.tenant.team_id.clone(),
            org_id: caller.tenant.org_id.clone(),
            purpose,
            expires_at: Instant::now() + self.ttl,
        };
        self.tickets.insert(token.clone(), ticket).await;
        token
    }

    /// Atomically consume `token`, returning the caller it authorizes iff the
    /// ticket exists, has not expired, and was minted for `purpose`.
    ///
    /// `moka`'s `remove` is atomic, so under a concurrent double-connect exactly
    /// one caller receives the ticket and every other gets `None` — a replayed or
    /// raced ticket cannot open a second socket. Expiry and a wrong-`purpose`
    /// attempt both still burn the entry (the remove happens first), so neither
    /// can be retried against the endpoint the ticket *was* minted for.
    ///
    /// Expiry is checked here against [`WsTicket::expires_at`] rather than trusting
    /// `moka`'s TTL: `moka`'s `remove` will hand back an entry that is past its TTL
    /// but not yet evicted, so a TTL-only design would let an expired ticket
    /// authenticate during that lazy-eviction window.
    pub async fn consume(&self, token: &str, purpose: WsTicketPurpose) -> Option<AuthenticatedCaller> {
        let ticket = self.tickets.remove(token).await?;
        if Instant::now() >= ticket.expires_at {
            return None;
        }
        if ticket.purpose != purpose {
            return None;
        }
        Some(ticket.into_caller())
    }
}

impl Default for WsTicketStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a 256-bit opaque ticket token, hex-encoded with the `wst_` prefix.
///
/// Uses the same CSPRNG (`rand::rng`) as API-key generation. 256 bits of entropy
/// makes the token unguessable; it is meaningless without the server-side store.
fn generate_token() -> String {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    format!("{TICKET_PREFIX}{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(key_id: &str, team: Option<&str>, scopes: Vec<Scope>) -> AuthenticatedCaller {
        AuthenticatedCaller {
            key_id: key_id.to_string(),
            scopes,
            tenant: Tenant {
                team_id: team.map(str::to_string),
                org_id: None,
            },
        }
    }

    #[tokio::test]
    async fn minted_ticket_consumes_once_to_the_bound_caller() {
        let store = WsTicketStore::new();
        let c = caller("key-1", Some("support"), vec![Scope::Read, Scope::Write]);
        let token = store.mint(&c, WsTicketPurpose::Events).await;
        assert!(token.starts_with("wst_"), "ticket is opaque, wst_-prefixed");

        let resolved = store
            .consume(&token, WsTicketPurpose::Events)
            .await
            .expect("valid ticket resolves");
        assert_eq!(resolved.key_id, "key-1");
        assert_eq!(resolved.scopes, vec![Scope::Read, Scope::Write]);
        assert_eq!(resolved.tenant.team_id.as_deref(), Some("support"));
    }

    #[tokio::test]
    async fn ticket_is_single_use_replay_is_rejected() {
        let store = WsTicketStore::new();
        let token = store
            .mint(&caller("key-1", None, vec![Scope::Read]), WsTicketPurpose::Events)
            .await;

        assert!(store.consume(&token, WsTicketPurpose::Events).await.is_some());
        assert!(
            store.consume(&token, WsTicketPurpose::Events).await.is_none(),
            "a consumed ticket must not resolve a second time"
        );
    }

    #[tokio::test]
    async fn expired_ticket_is_rejected() {
        let store = WsTicketStore::with_ttl(Duration::from_millis(20));
        let token = store
            .mint(&caller("key-1", None, vec![Scope::Read]), WsTicketPurpose::Events)
            .await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        // moka evicts lazily; run_pending_tasks makes the TTL eviction deterministic.
        assert!(
            store.consume(&token, WsTicketPurpose::Events).await.is_none(),
            "a ticket past its TTL must not resolve"
        );
    }

    #[tokio::test]
    async fn wrong_purpose_is_rejected_and_burns_the_ticket() {
        let store = WsTicketStore::new();
        let token = store
            .mint(&caller("key-1", None, vec![Scope::Read]), WsTicketPurpose::Events)
            .await;

        assert!(
            store.consume(&token, WsTicketPurpose::Alerts).await.is_none(),
            "an events ticket must not open the alerts stream"
        );
        assert!(
            store.consume(&token, WsTicketPurpose::Events).await.is_none(),
            "the wrong-purpose attempt still consumed the ticket — no retry"
        );
    }

    #[tokio::test]
    async fn unknown_token_is_rejected() {
        let store = WsTicketStore::new();
        assert!(store.consume("wst_deadbeef", WsTicketPurpose::Events).await.is_none());
    }

    #[tokio::test]
    async fn concurrent_consume_resolves_exactly_once() {
        let store = WsTicketStore::new();
        let token = store
            .mint(&caller("key-1", None, vec![Scope::Read]), WsTicketPurpose::Events)
            .await;

        // Fire many concurrent consumes of the same ticket; the atomic remove
        // must hand the caller to exactly one of them.
        let mut handles = Vec::new();
        for _ in 0..32 {
            let store = store.clone();
            let token = token.clone();
            handles.push(tokio::spawn(async move {
                store.consume(&token, WsTicketPurpose::Events).await.is_some()
            }));
        }
        let mut winners = 0;
        for h in handles {
            if h.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one concurrent consumer wins the ticket");
    }

    #[tokio::test]
    async fn each_mint_yields_a_distinct_token() {
        let store = WsTicketStore::new();
        let c = caller("key-1", None, vec![Scope::Read]);
        let a = store.mint(&c, WsTicketPurpose::Events).await;
        let b = store.mint(&c, WsTicketPurpose::Events).await;
        assert_ne!(a, b, "tickets are unguessable and unique per mint");
    }
}
