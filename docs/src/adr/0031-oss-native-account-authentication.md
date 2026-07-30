# ADR 0031: OSS Native Account Authentication (email/password, no OAuth)

**Status**: Accepted (2026-07-30, product + security). Native email/password login is ratified for OSS, coexisting with the retained API-key path, Postgres-gated, first-user-admin-then-invite, no OAuth. The five open questions are resolved in [§ Decision](#decision-2026-07-30) below: **Q1** roles map fully onto the existing scopes; **Q2** argon2id at the OWASP floor; **Q3** open registration off by default behind an opt-in flag; **Q4** password reset **is** in v1, which brings a new pluggable SMTP mailer into OSS; **Q5** a `GET /api/v1/auth/methods` capability endpoint drives the frontend. Implementation is authorised under Epic AAASM-5301.
**Date**: 2026-07-30
**Ticket**: [AAASM-5302](https://lightning-dust-mite.atlassian.net/browse/AAASM-5302) (Epic [AAASM-5301](https://lightning-dust-mite.atlassian.net/browse/AAASM-5301))

This ADR proposes a design for a **native email/password account login** in the
open-source dashboard + `aa-api`, porting the *experience* of the cloud `LoginPage`
while **removing all OAuth/social login**. **It changes nothing by merging.** No code,
schema, migration, or endpoint is introduced here — it is written for sign-off, because
authentication touches credential storage and the enforcement trust boundary, and the
standing rule forbids inventing that silently.

It follows the sign-off-gating precedent of ADR 0018/0019 and complements ADR 0004
(governance enforcement flow), ADR 0012 (websocket/browser credential handling), and
ADR 0002 (SDK security boundary).

---

## Context

### What OSS has today

The open-source dashboard authenticates with an **API key only**. `LoginPage.tsx` is a
single password-style input; `AuthProvider.login(apiKey)` does
`POST /api/v1/auth/token` with `Authorization: Bearer <apiKey>` and receives a scoped
JWT (`aa-api/src/routes/auth.rs`, route registered at `aa-api/src/routes/mod.rs:70`).
The JWT's scope claim is read by `parseScopesFromJwt` and drives every RBAC gate in the
UI.

There is **no user/account concept in OSS**: no user table, no password hash, no
email, no session, no invite. A grep for `struct User` / `password_hash` / `argon2` /
`bcrypt` across `aa-api`, `aa-gateway`, and `aa-storage-postgres` returns nothing in
production code. The API key *is* the identity.

### What cloud has (the port source)

`agent-assembly-cloud` ships a full account system whose UX this ADR ports:

- `design/hi-fi/saas-shell.jsx` → `LoginPage`: one page, two tabs (sign-in / sign-up),
  a work-email + password form, "Forgot?" link, and — to be **removed** for OSS —
  "Continue with Google" / "Continue with GitHub" buttons.
- `apps/web/src/core/api/auth.ts` → the contract:
  - `POST /auth/login` `{ email, password, remember_me }` → `{ access_token, expires_in }`;
    refresh token delivered as an **HttpOnly cookie**; `401` invalid creds, `423` locked
    (with `retry-after`).
  - `POST /auth/register` `{ tenant_name, email, password }` → `{ tenant_id, user_id }`;
    `409` email exists, `422` weak password.
  - `POST /auth/password/reset` + `/auth/password/reset/confirm`.
  - `POST /auth/refresh` (reads the HttpOnly cookie, `credentials: 'include'`).
  - OAuth routes `/auth/oauth/{google,github}` — **out of scope / removed for OSS**.

Cloud's account system is backed by Postgres and a tenant model. The relevant cloud
tickets (all Done, in the cloud repo): AAASM-1790 (account create + login), AAASM-2119
(password reset), AAASM-2200–2203 (profile management), AAASM-2816 (SSO-enforce),
AAASM-1793/2825 (refresh-cookie).

### The two constraints that shape the design

1. **API key must survive.** SDKs and agents authenticate to `aa-api`/gateway
   programmatically with the API key. That path is the credential lifeline for
   machine callers and cannot be removed. Native accounts are **additive**, for human
   operators at the dashboard.
2. **OSS runs with or without Postgres.** `AppState` has an in-memory mode
   (`aa-api/src/state.rs`) and a Postgres-backed mode. Passwords must be durably and
   safely stored — which an in-memory map cannot do across a restart — so native
   accounts are **Postgres-gated**, and the in-memory mode stays API-key-only.

---

## Decisions already ratified (2026-07-30)

These were settled with product before this ADR was written; the ADR records the design
that implements them.

| # | Decision |
|---|---|
| D1 | **Account and API key coexist.** email/password for humans (dashboard); API key retained for machines (SDK/agent). Both mint the **same scoped JWT** the RBAC gates already read. |
| D2 | **Postgres-gated.** Native login is available only on a Postgres-backed deployment. In-memory mode stays API-key-only and the login page degrades honestly. |
| D3 | **First-user-is-admin, then invite-only.** The first account created on a fresh instance becomes `owner`; subsequent accounts are created only via an admin invite. Public open sign-up is **not** enabled by default. |
| D4 | **No OAuth.** The two-tab UI is ported with all social-login buttons removed; `/auth/oauth/*` routes are not implemented. |

---

## Proposed design

### 1. Data model (Postgres)

A new `users` table (migration in `aa-storage-postgres`):

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `email` | citext unique | case-insensitive unique |
| `password_hash` | text | argon2id encoded string (includes params + salt) |
| `tenant_id` | uuid FK | the org/team the user belongs to; ties into the existing tenant model |
| `role` | enum | `owner` / `admin` / `developer` / `viewer` — maps to the existing scope model |
| `status` | enum | `active` / `invited` / `disabled` |
| `created_at` / `updated_at` | timestamptz | |
| `last_login_at` | timestamptz null | |

Supporting tables: `user_invites` (token hash, email, tenant, role, expiry, invited_by,
consumed_at) and `login_attempts` (or a Postgres-backed counter) for lockout. Refresh
tokens: a `refresh_tokens` table (token hash, user, expiry, revoked_at) so sessions are
revocable and survive restart — **never** in memory.

**Open question for sign-off (§Q1):** how `role` maps onto the existing `Scope` set the
JWT already carries, and whether OSS needs the full four-role ladder or a reduced set.

### 2. Password storage — argon2id

- Hash with **argon2id** (memory-hard; resists GPU brute force). Store the full encoded
  string (algorithm, version, `m`/`t`/`p` params, salt) so parameters can be upgraded
  without a schema change.
- Proposed starting params: `m=19456 (19 MiB)`, `t=2`, `p=1` — the OWASP-recommended
  argon2id floor as of 2024; **to be confirmed at sign-off (§Q2)** against the gateway's
  latency budget.
- Verify in constant time; never log the password or the hash; never return the hash on
  any wire.

### 3. Endpoints (mirror the cloud contract, minus OAuth)

All under `aa-api`, only mounted when Postgres is configured (D2):

| Endpoint | Body | Success | Errors |
|---|---|---|---|
| `POST /api/v1/auth/login` | `{ email, password, remember_me }` | `{ access_token, expires_in }` + HttpOnly refresh cookie | `401` bad creds, `423` locked (+`retry-after`) |
| `POST /api/v1/auth/register` | `{ email, password }` (**no `tenant_name`** — see §4) | `{ user_id }` (+ tokens for the bootstrap admin) | `403` registration closed, `409` email exists, `422` weak password |
| `POST /api/v1/auth/invite` | `{ email, role }` (admin only) | `{ invite_id }` | `403` not admin |
| `POST /api/v1/auth/invite/accept` | `{ token, password }` | `{ user_id }` + tokens | `422` token expired/used |
| `POST /api/v1/auth/refresh` | — (reads HttpOnly cookie) | `{ access_token, expires_in }` | `401` cookie missing/revoked |
| `POST /api/v1/auth/logout` | — | `204` (revokes refresh) | |
| `POST /api/v1/auth/password/reset` + `/confirm` | as cloud | | **optional v1 — needs email dispatch (§Q4)** |

The existing `POST /api/v1/auth/token` (API-key → JWT) is **unchanged**. Both login and
`/auth/token` produce the same JWT shape, so every downstream RBAC gate is untouched.

### 4. Registration / tenancy (D3)

OSS is single-workspace by default (unlike cloud's multi-tenant sign-up), so `register`
does **not** take a `tenant_name`:

- **Bootstrap:** if the `users` table is empty, `POST /auth/register` is open and the
  first user becomes `owner` of the single default workspace/tenant.
- **After bootstrap:** `register` returns `403` (registration closed). New users are
  created via `POST /auth/invite` (admin) → email/link → `/auth/invite/accept`.
- A deployment may set an env flag to keep open registration (opt-in), but the default
  is closed. **Sign-off (§Q3):** confirm the flag name and whether open registration is
  even offered in v1.

### 5. JWT / session

- Access token: short-lived JWT (proposed 15 min) with the same scope claim shape
  `parseScopesFromJwt` reads today, so RBAC is unchanged.
- Refresh token: opaque, hashed-at-rest, delivered as an **HttpOnly, Secure,
  SameSite=Strict cookie** (mirrors cloud AAASM-1793/2825 and aligns with ADR 0012's
  browser-credential handling). `remember_me` extends refresh lifetime.
- Logout and password change revoke outstanding refresh tokens.

### 6. Frontend (D4)

- Port the cloud two-tab `LoginPage` per `agent-assembly-cloud/design/hi-fi/saas-shell.jsx`,
  **removing** the "Continue with Google/GitHub" buttons and the "or continue with email"
  divider. Sign-in (email + password + Forgot?) and sign-up (email + password, no
  workspace-name field per §4).
- `AuthProvider` gains `loginWithCredentials(email, password, rememberMe)` and `signup`
  alongside the existing `login(apiKey)` — both set the same token state.
- **Honest degradation (D2):** when the backend is in-memory (no Postgres), the
  dashboard must not present a password form that cannot work. The login page shows the
  API-key path and states that account login requires a Postgres-backed deployment —
  rendered from a backend capability signal, not guessed client-side. **Sign-off (§Q5):**
  confirm how the frontend learns whether native auth is available (a public
  `GET /api/v1/auth/methods` capability endpoint is proposed).
- Per development rule 6, implementation will run the dashboard, walk the login page, and
  attach screenshots to the implementation PR as self-verification against the design.

---

## Security considerations (development rule 7)

- **Credential storage:** argon2id only; parameters upgradable; hash never leaves the DB.
- **Brute force:** per-account lockout after N failed attempts → `423` + `retry-after`
  (cloud precedent); consider per-IP throttling. Counter is Postgres-backed, not in
  memory.
- **Enumeration:** `login` returns a uniform `401` for both unknown-email and
  bad-password; password-reset responds `202` regardless of whether the email exists.
- **Refresh cookie:** HttpOnly + Secure + SameSite=Strict; rotate on use; revocable.
- **Bootstrap race:** the "first user becomes owner" check must be transactional (a
  unique constraint / advisory lock) so two concurrent registrations cannot both claim
  owner.
- **No new enforcement authority:** accounts mint the *same* scoped JWT as API keys and
  add no new capability to the enforcement path — this is an authentication surface, not
  an authorization change. The gateway remains the authority (ADR 0004).
- **Invite tokens:** single-use, expiring, hashed-at-rest; accepting an invite is the
  only way to set the initial password for an invited user.

---

## Consequences

- **Positive:** OSS operators get a familiar account login without standing up an
  external IdP; the API-key path is untouched for machines; RBAC is unchanged because
  the JWT shape is shared.
- **Negative / accepted:** native login requires Postgres; in-memory deployments stay
  API-key-only (surfaced honestly, not hidden). Password reset needs an email-dispatch
  mechanism OSS does not have yet (§Q4) — it may be deferred out of v1.
- **Neutral:** this is the OSS counterpart of cloud's account system; the two share a
  wire contract shape but not code (cloud is a separate repo). A future shared package
  (Epic AAASM-1750) could unify them, but that is explicitly out of scope here.

## Open questions for sign-off

- **Q1 — role↔scope mapping.** How do `owner/admin/developer/viewer` map onto the
  existing `Scope` set the JWT carries? Full four-role ladder or a reduced OSS set?
- **Q2 — argon2id params.** Confirm `m/t/p` against the deployment's latency budget.
- **Q3 — open-registration flag.** Is an opt-in open-registration mode offered in v1, or
  strictly first-user-then-invite? Confirm the env flag name if offered.
- **Q4 — password reset in v1?** It needs email dispatch (SMTP config) OSS lacks. Include
  (with a pluggable mailer) or defer to a follow-up?
- **Q5 — auth-methods capability signal.** Confirm a public `GET /api/v1/auth/methods`
  (advertising `["api_key"]` or `["api_key","password"]`) as the way the frontend decides
  what to render, so the login page never offers a password form the backend can't serve.

Until Q1–Q2 (at minimum) are answered, **no implementation ticket should be opened.**
Merging this ADR authorises nothing.

## What this unblocks

- The OSS native-account-authentication implementation tickets under Epic
  [AAASM-5301](https://lightning-dust-mite.atlassian.net/browse/AAASM-5301): BE (user
  model + argon2 + endpoints), BE (JWT + invite flow), FE (two-tab login, OAuth removed),
  and their tests.

## Traceability

- Proposes the design for [AAASM-5302](https://lightning-dust-mite.atlassian.net/browse/AAASM-5302)
  under Epic [AAASM-5301](https://lightning-dust-mite.atlassian.net/browse/AAASM-5301).
- Ports the UX/contract of the cloud account system (AAASM-1790, 2119, 2200–2203,
  1793/2825) minus OAuth. Browser-credential handling follows ADR 0012; the enforcement
  trust boundary is unchanged per ADR 0004. Follows the sign-off-gating precedent of
  ADR 0018/0019.
