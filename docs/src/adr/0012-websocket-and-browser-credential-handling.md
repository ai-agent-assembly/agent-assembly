# ADR 0012: WebSocket & Browser Credential Handling (OSS vs SaaS)

**Status**: Accepted
**Date**: 2026-07
**Ticket**: [AAASM-4861](https://lightning-dust-mite.atlassian.net/browse/AAASM-4861)
(WebSocket ticket auth — implementation),
[AAASM-4860](https://lightning-dust-mite.atlassian.net/browse/AAASM-4860)
(OSS dashboard token storage — accepted risk)

This ADR records **how browser-held credentials and WebSocket upgrades are
authenticated** across the two editions of the product — the open-source (OSS)
operator dashboard shipped in this repo, and the future SaaS dashboard. It exists
because the two editions have **different threat models** and therefore make
**different, deliberate** trade-offs, and because a browser API limitation (a WS
handshake cannot carry an `Authorization` header) forced a specific credential
design that must not be reinvented ad hoc each time a new stream is added.

It complements [ADR 0008](0008-saas-host-routing-auth-cookie-boundaries.md)
(SaaS host routing, auth & cookie boundaries) and does not contradict it: 0008
governs *SaaS cookie scoping across hosts*; this ADR governs *where a browser
credential may live* and *how a WebSocket authenticates* in each edition.

---

## Context

### Threat model A — OSS operator dashboard (this repo)

The OSS dashboard (`dashboard/`, served by `aa-api`) is a **single-process,
local / self-hosted, operator-controlled** surface. It ships in the
limited-function OSS stack an operator runs on their own host or private network.
Its session credential is a JWT the dashboard obtains from `POST
/api/v1/auth/token` and stores in the browser. Under this threat model the
adversary of concern is a network observer or a curious co-tenant on the same
box — **not** a multi-tenant public-internet attacker.

The token was historically kept in `localStorage`; it was moved to
`sessionStorage` ([AAASM-4322](https://lightning-dust-mite.atlassian.net/browse/AAASM-4322))
so an XSS on the dashboard origin is confined to the current tab and the token is
dropped when the tab closes. `sessionStorage` is still **JS-readable**: it is not
a defence against same-origin XSS. A server-managed `HttpOnly` cookie surface
would be stronger, but no such backend surface exists in the OSS edition, and
building one is out of scope for a local/self-hosted operator tool.

### Threat model B — SaaS dashboard (future)

The SaaS dashboard is **multi-tenant** and served over the **public internet**
(`app.agent-assembly.com`, per ADR 0008). Its adversary includes remote attackers
and cross-tenant actors. A JS-readable long-lived credential is **not acceptable**
here: an XSS or a malicious dependency could exfiltrate a live session.

### Threat model C — WebSocket authentication (both editions)

The dashboard opens WebSocket streams for live governance events
(`GET /api/v1/ws/events` — live-ops + approvals) and alerts
(`GET /api/v1/alerts/ws`, [AAASM-1389](https://lightning-dust-mite.atlassian.net/browse/AAASM-1389)).
The **browser WebSocket API cannot set request headers**, so a bearer token
cannot travel in an `Authorization` header on the upgrade. The original
workaround put the long-lived JWT in the query string
(`?token=<jwt>`,
[AAASM-4861](https://lightning-dust-mite.atlassian.net/browse/AAASM-4861)).
Request URLs are logged by every intermediary — reverse proxies, CDNs, load
balancers — so this leaked a **live, long-lived credential** into
infrastructure logs, an exposure channel entirely distinct from XSS and
unaffected by any `sessionStorage`/CSP hardening. Per-connection tenant gating
already exists ([AAASM-3980](https://lightning-dust-mite.atlassian.net/browse/AAASM-3980));
the defect was purely *how the connection authenticates*.

---

## Decision

### 1. OSS dashboard auth — `sessionStorage` + strict CSP (accepted trade-off)

The OSS dashboard keeps its session JWT in **`sessionStorage`**, hardened by a
strict Content-Security-Policy, and treats this as an **intentional, accepted
trade-off** under threat model A. It is **not** considered secure against a
same-origin XSS, and this is stated plainly rather than papered over. There is no
`HttpOnly`-cookie backend in the OSS edition and none is added by this decision.
The OSS dashboard **must not be exposed directly to the public internet** without
a trusted authenticating layer in front of it (VPN, private network, or an
authenticated reverse proxy). Recorded as an accepted risk in
[AAASM-4860](https://lightning-dust-mite.atlassian.net/browse/AAASM-4860); the
storage tier is [AAASM-4322](https://lightning-dust-mite.atlassian.net/browse/AAASM-4322).

### 2. SaaS dashboard auth — server-managed cookies (must not copy OSS)

The SaaS dashboard **must not** store a long-lived credential in `localStorage`
or `sessionStorage`. It uses **server-managed `HttpOnly` + `Secure` +
`SameSite`** cookies (host-only, per ADR 0008) with CSRF defence, plus token
expiry / refresh / logout / server-side revocation. The SaaS edition **must not
copy the OSS `sessionStorage` design** — that design is an accepted compromise
scoped to the OSS local threat model only, and inheriting it into a multi-tenant
public surface would be a regression.

### 3. WebSocket auth — short-lived, single-use, purpose-bound tickets

No long-lived credential — JWT, API key, or session cookie value — may appear in
a WebSocket URL, in **either** edition. Instead:

- The client authenticates a normal **REST** call to
  `POST /api/v1/auth/ws-ticket` (Bearer header, which a `fetch`/`XHR` *can*
  set) and receives a **short-lived (30–60 s), single-use, opaque** ticket.
- The client opens the socket with `?ticket=<opaque>`; the upgrade handler
  **atomically consumes** the ticket (replay-safe) and rebuilds the caller from
  the server-side record.
- The ticket is **bound to the minting caller's identity, tenant, scopes, and a
  single stream purpose** (`events` vs `alerts`); it is **not** accepted as a
  REST credential and is **not** refreshable. Every connect and **every
  reconnect mints a fresh ticket**.

CLI and non-browser clients — which *can* set an `Authorization` header — keep
using bearer-header auth on the WS upgrade unchanged; the ticket is the
browser-only path. Implemented in
[AAASM-4861](https://lightning-dust-mite.atlassian.net/browse/AAASM-4861).

---

## Accepted risks

- **OSS JS-readable token.** The OSS session JWT is readable by same-origin
  JavaScript (`sessionStorage`). Accepted under threat model A (local /
  self-hosted / operator-controlled). Mitigations: strict CSP, `sessionStorage`
  (tab-scoped, dropped on close), and the operational guidance not to expose the
  dashboard publicly.
- **OSS ticket store is in-memory / single-node.** The OSS `aa-api` is a single
  process; there is no Redis / shared KV in the OSS stack, so the WS-ticket store
  is **in-process**. Tickets do not survive a restart and are not valid across a
  hypothetical multi-instance deployment. Accepted because tickets are
  short-lived and single-use — the worst case is a failed upgrade the client
  simply re-mints.
- **Infrastructure outside the repo is not automatically protected.** We do not
  claim that a reverse proxy / CDN / load balancer an operator runs is safe. The
  repo's own request-logging layer logs the request **path only, not the query
  string**, so a ticket is not written to app logs; but operators must configure
  their **own** edge log redaction of `token` / `ticket` query parameters. This
  is documented, not asserted as automatic.

---

## Explicitly forbidden designs

- Any long-lived credential (JWT, API key, session value) in a URL — including a
  WebSocket query string — in either edition.
- Reusing a WS ticket as a REST credential, or minting a refreshable / long-TTL
  ticket.
- Storing a long-lived credential in `localStorage` or `sessionStorage` in the
  **SaaS** edition.
- Copying the OSS `sessionStorage` design into the SaaS dashboard.
- Adding a new browser-facing WebSocket stream that authenticates by any means
  other than the ticket flow in Decision §3.

---

## Consequences

- **OSS operators**: unchanged login; the dashboard now mints a ticket before each
  stream connect, so no credential is ever in a WS URL or infra log. The
  exposure caveat is documented in `SECURITY.md` and the CLI `start`/`dashboard`
  docs.
- **SaaS**: a hard constraint is on record before the SaaS dashboard is built —
  cookies, not web storage; it cannot silently inherit the OSS compromise.
- **SDK / CLI**: **unchanged.** Bearer-token auth for programmatic and CLI clients
  (including on the WS upgrade, via the `Authorization` header) is untouched.
- **New streams**: adding one is now a well-defined recipe — add a
  `WsTicketPurpose`, mint with that purpose, consume it on the upgrade.

## Operational guidance

- Do **not** expose the OSS dashboard / `aa-api` HTTP surface to the public
  internet. Front it with a VPN, a private network, or an authenticated reverse
  proxy.
- Configure edge (reverse-proxy / CDN / LB) access-log redaction of `token` and
  `ticket` query parameters. The application already logs path-only.
- Bind `aa-api` to loopback unless a trusted authenticating layer sits in front
  (see `SECURITY.md` and `docs/src/cli/start-stop.md`).

## Validation requirements

The WS-ticket flow ([AAASM-4861](https://lightning-dust-mite.atlassian.net/browse/AAASM-4861))
must be covered by tests asserting: mint requires authentication; mint is
scope/tenant-bound; the ticket is single-use (replay rejected); an expired ticket
is rejected; a wrong-purpose / wrong-tenant / malformed ticket is rejected; the
ticket is **not** valid for REST auth; a concurrent double-consume resolves for
exactly one caller; application logs contain no raw JWT or ticket; and a reconnect
mints a fresh ticket. The browser clients must be covered by tests asserting the
WS URL carries a ticket (never the JWT) and that a reconnect re-mints.

## Reconsideration triggers

Re-open this ADR if any of the following change:

- The OSS edition ships an `HttpOnly`-cookie auth backend (then OSS §1 can be
  hardened).
- `aa-api` is ever run **multi-instance** (the in-memory ticket store must move to
  a shared KV or a signed stateless ticket).
- A reachable XSS sink is found in the OSS dashboard (re-weigh the accepted
  `sessionStorage` risk).
- SaaS dashboard work begins (§2 becomes an implementation contract, aligned with
  ADR 0008).

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-4322](https://lightning-dust-mite.atlassian.net/browse/AAASM-4322) | OSS dashboard token → `sessionStorage` (the storage tier this ADR accepts) |
| [AAASM-4860](https://lightning-dust-mite.atlassian.net/browse/AAASM-4860) | OSS `sessionStorage` token — accepted-risk decision (Decision §1) |
| [AAASM-4861](https://lightning-dust-mite.atlassian.net/browse/AAASM-4861) | WebSocket ticket auth — implementation (Decision §3) |
| [AAASM-245](https://lightning-dust-mite.atlassian.net/browse/AAASM-245) | Dashboard authentication surface (related) |
| [AAASM-1331](https://lightning-dust-mite.atlassian.net/browse/AAASM-1331) | Live-ops WebSocket stream (related) |
| [AAASM-1389](https://lightning-dust-mite.atlassian.net/browse/AAASM-1389) | Alerts WebSocket stream (`/alerts/ws`) (related) |
| [AAASM-297](https://lightning-dust-mite.atlassian.net/browse/AAASM-297) | Approvals stream (related) |
| [AAASM-3980](https://lightning-dust-mite.atlassian.net/browse/AAASM-3980) | Per-connection WebSocket tenant gating (related) |
| [ADR 0008](0008-saas-host-routing-auth-cookie-boundaries.md) | SaaS cookie / host boundary (complements Decision §2) |
| Implementation PRs | PR-A `#TBD` (this ADR + exposure docs, AAASM-4860); PR-B `#TBD` (WS-ticket code + tests, AAASM-4861) |
