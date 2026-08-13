# ADR 0008: SaaS Host Routing, Auth & Cookie Boundaries

**Status**: Proposed
**Date**: 2026-06
**Ticket**: [AAASM-3656](https://lightning-dust-mite.atlassian.net/browse/AAASM-3656) (Epic [AAASM-3651](https://lightning-dust-mite.atlassian.net/browse/AAASM-3651))

---

## Context

[ADR 0007](0007-public-domain-and-url-contract.md) fixes the public host surface:
`agent-assembly.com` (marketing + `/install.sh`), `app.`, `api.`, `docs.`,
`status.`, and the `<tenant>.agent-assembly.com` wildcard. Once a wildcard host
serves untrusted, customer-controlled tenant slugs alongside first-party hosts
(`app.`, `api.`), **cookie domain scoping and cross-host auth become a security
question**, not a routing convenience.

The classic failure mode: an app or auth cookie scoped to the registrable apex
(`Domain=agent-assembly.com`) is sent by the browser to **every** subdomain,
including `<tenant>.agent-assembly.com`. Because tenant hosts may run
customer-influenced content, an apex-scoped session cookie is readable/forwardable
across the tenant boundary — a session-fixation / token-leak vector.

This ADR proposes the **host-to-content map and the cookie/session boundary rules**
for the SaaS surface. The SaaS control plane is still a placeholder (the
`agent-assembly-cloud` repo is not yet built), so this is a **design proposal for
owner ratification** that the future app/api implementation must honor — not a
description of running code.

**Out of scope:** *tenant data isolation* (row-level security, per-tenant storage
keys, query scoping) is a separate, deeper concern owned by the cloud persistence
work (see ADR 0001 / `agent-assembly-cloud`); this ADR covers only the **web edge**:
which host serves what, and how browser cookies/sessions are scoped across hosts.

---

## Which host serves what

| Host | Serves | Trust |
| --- | --- | --- |
| `agent-assembly.com` | Marketing site; `/install.sh` (install Worker route) | First-party, public, unauthenticated |
| `www.agent-assembly.com` | 301 → apex | First-party redirect |
| `app.agent-assembly.com` | Login / workspace selector / app shell | First-party, **authenticated** |
| `api.agent-assembly.com` | Public SaaS API | First-party, **token-authenticated** |
| `docs.agent-assembly.com` | Canonical docs (Epic AAASM-3659) | First-party, public |
| `status.agent-assembly.com` | Status page | Third-party hosted, public |
| `<tenant>.agent-assembly.com` | Tenant workspace (customer-scoped) | **Customer-influenced — treat as a distinct origin** |

---

## Decision

### 1. No apex-scoped (`Domain=`) cookies for sessions or auth

Session and auth cookies are **host-only** (no `Domain` attribute), so the browser
sends them **only** to the exact host that set them. Specifically:

- `app.agent-assembly.com` sets host-only session cookies; they are **not** sent to
  `api.`, to the apex, or to any `<tenant>.` host.
- `api.agent-assembly.com` does not rely on browser cookies for cross-host auth at
  all (see #3); any cookie it sets is host-only.
- **Never** set `Domain=agent-assembly.com` (or `Domain=.agent-assembly.com`) on a
  cookie that carries identity or session state. Doing so leaks it to the tenant
  wildcard, which is the boundary this ADR exists to protect.

### 2. Cookie flags

All first-party cookies: `Secure`, `HttpOnly` (for anything not read by JS),
`SameSite=Lax` by default. Use `SameSite=Strict` for pure first-party session
cookies where no cross-site top-level navigation needs them; reserve
`SameSite=None; Secure` only for cookies that genuinely must travel cross-site
(avoid for session/auth).

### 3. Cross-host auth strategy: tokens, not shared cookies

`app.` (browser session) and `api.` (programmatic) **do not share a cookie domain**.
Instead:

- The browser app at `app.` holds a host-only session and calls `api.` with a
  **bearer token** (e.g. an `Authorization` header) minted for the authenticated
  user/workspace, not with an ambient apex cookie.
- This keeps `api.` stateless w.r.t. browser cookies and removes the temptation to
  apex-scope a cookie so both hosts can read it.

### 4. CSRF

For any state-changing request that **does** rely on a cookie session (the `app.`
host), require a CSRF defense: a per-session CSRF token (double-submit or
synchronizer pattern) **in addition to** `SameSite`. `SameSite` alone is not treated
as sufficient CSRF protection.

### 5. Tenant wildcard is a distinct origin

`<tenant>.agent-assembly.com` is treated as a **separate origin** from first-party
hosts for all browser-security purposes: no shared cookies, no shared
`localStorage`/`sessionStorage` (already origin-isolated by the browser), and CORS on
`api.` must allow tenant origins explicitly rather than wildcarding
`*.agent-assembly.com`. Reserved slugs (AAASM-3655) ensure no tenant can claim a
first-party host like `app`, `api`, or `docs`.

### 6. CSP / framing

First-party authenticated hosts (`app.`) set `X-Frame-Options: DENY` (or a CSP
`frame-ancestors 'self'`) so a tenant or third-party page cannot frame the app shell
and drive clickjacking against the session.

---

## Why tenant data isolation is out of scope here

Tenant data isolation — ensuring tenant A can never read tenant B's data at the
storage/query layer — is enforced **server-side** (row-level security, per-tenant
keys, authorization checks), independent of host or cookie scoping. It is owned by
the cloud persistence design (ADR 0001 and the `agent-assembly-cloud` control plane),
not by the web-edge routing decided here. This ADR deliberately limits itself to the
**browser/edge boundary** so the two concerns can be ratified and built separately.
A correct cookie boundary does not substitute for server-side isolation, and vice
versa — both are required.

---

## Consequences

### What this enables

- A clear, auditable rule (“no apex-scoped session cookies”) that the future `app.`
  and `api.` implementations must follow, set **before** any auth code is written.
- The tenant wildcard can be served safely alongside first-party hosts without an
  ambient-cookie leak across the tenant boundary.

### What this blocks / defers

- It constrains cross-host SSO ergonomics: because cookies are host-only, any future
  “sign in once across `app.` and a tenant host” flow must use an explicit token
  exchange (OIDC/redirect), not a shared apex cookie. That is the intended trade-off.
- Server-side tenant data isolation is **not** decided here (out of scope, above).

### Owner-gated / future-build

- This ADR is **Proposed**; it describes rules for a control plane that is not yet
  built. Ratification commits the future `app.`/`api.` work to these boundaries.

---

## Related

- Builds on: [ADR 0007](0007-public-domain-and-url-contract.md) — public domain & URL contract
- Tenant slug policy: [AAASM-3655](https://lightning-dust-mite.atlassian.net/browse/AAASM-3655) — `infra/tenant/`
- Redirects: [AAASM-3657](https://lightning-dust-mite.atlassian.net/browse/AAASM-3657) — `infra/redirects/`
- Storage / data isolation: [ADR 0001](0001-storage-architecture.md) and `agent-assembly-cloud`
- Epic: [AAASM-3651](https://lightning-dust-mite.atlassian.net/browse/AAASM-3651)
