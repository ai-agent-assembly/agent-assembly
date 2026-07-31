# Authentication

Agent Assembly's `aa-api` supports **two credential paths**, side by side:

- **API keys** — for machines. SDKs, agents, and scripts authenticate
  programmatically with an API key. This path is unchanged and is available on
  every deployment.
- **Native email/password accounts** — for human operators at the dashboard.
  This is an *additive* path for people; it never replaces the API key. It is
  **only available on a Postgres-backed deployment** (see below).

Both paths mint the **same scoped JWT** that every RBAC gate already reads, so
enabling accounts changes nothing about how authorization works — it only adds a
second way for a human to obtain that token.

## Which methods a deployment offers

A deployment advertises its available credential methods through a public
endpoint, so the dashboard never presents a login form the backend cannot serve:

```console
$ curl http://localhost:7700/api/v1/auth/methods
{"methods":["api_key"]}                 # in-memory deployment (API key only)

$ curl http://localhost:7700/api/v1/auth/methods
{"methods":["api_key","password"]}      # Postgres-backed deployment
```

`password` appears only when a Postgres account store is configured. On an
in-memory deployment the native-auth endpoints below respond `503 Service
Unavailable` and the dashboard shows only the API-key path.

> **Native accounts require Postgres.** Passwords must be stored durably and
> safely, which an in-memory map cannot do across a restart, so the account
> endpoints are Postgres-gated. In-memory deployments stay API-key-only. This is
> a deliberate, surfaced limitation — not a hidden failure.

## The API-key path (machines)

Unchanged. A caller exchanges an API key for a scoped JWT:

```console
$ curl -X POST http://localhost:7700/api/v1/auth/token \
    -H "Authorization: Bearer <api-key>"
```

Use this for SDKs and agents. It works on every deployment, with or without
Postgres.

## The native-account path (human operators)

When a Postgres store is configured, `aa-api` mounts a set of account endpoints
under `/api/v1/auth`:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/auth/methods` | `GET` | Advertise the available methods (`api_key`, and `password` when Postgres-backed). Public. |
| `/api/v1/auth/login` | `POST` | Email + password → access token (+ refresh cookie). |
| `/api/v1/auth/register` | `POST` | Register the first (bootstrap) account, or a self-registered account when open registration is enabled. |
| `/api/v1/auth/invite` | `POST` | Create a single-use invite for a new account. **Admin scope required.** |
| `/api/v1/auth/invite/accept` | `POST` | Set the initial password and activate an invited account. |
| `/api/v1/auth/refresh` | `POST` | Exchange the refresh cookie for a fresh access token. |
| `/api/v1/auth/logout` | `POST` | Revoke the refresh session and clear the cookie. |
| `/api/v1/auth/password/reset` | `POST` | Request a password-reset email. Requires the [SMTP mailer](#password-reset-email-smtp) to deliver mail. |
| `/api/v1/auth/password/reset/confirm` | `POST` | Consume a reset token and set a new password. |

The access token is short-lived (15 minutes) and returned in the response body;
the refresh token is delivered as an `HttpOnly; Secure; SameSite=Strict` cookie
scoped to `/api/v1/auth`, and is rotated on every refresh. `remember_me` on login
extends the refresh lifetime from 12 hours to 30 days.

### First user is admin, then invite-only

On a fresh instance the `users` table is empty, so registration bootstraps:

1. **Bootstrap.** The **first** account created via `POST /api/v1/auth/register`
   becomes the `owner` of the single default workspace. Registration is open
   only for this first account.
2. **After bootstrap.** Once any account exists, `register` returns `403`
   (registration closed). New accounts are created by an admin:
   `POST /api/v1/auth/invite` (admin scope) mints a single-use, expiring invite
   token; the invitee sets their password via `POST /api/v1/auth/invite/accept`.

An invite token is returned to the inviting admin exactly once (only its hash is
stored) and expires after 7 days. Deliver it to the invitee out of band.

### Opening self-registration (optional)

To let anyone self-register (not just the first user), set:

```bash
AA_AUTH_OPEN_REGISTRATION=true
```

The default is `false` (closed — first-user-then-invite). Only the truthy
spellings `1`, `true`, or `yes` (case-insensitive) enable it; any other value or
leaving it unset keeps registration closed. When open registration is enabled,
accounts created after the bootstrap owner receive the `developer` role.

### Password policy

Passwords are hashed with **argon2id** and must be at least **12 characters**.
A shorter password is rejected with `422`. Login is enumeration-safe: an unknown
email and a wrong password both return a uniform `401`, and repeated failures
lock the account (`423` with a `Retry-After` header) after 5 attempts for
15 minutes.

## Password-reset email (SMTP)

Password reset (`POST /api/v1/auth/password/reset`) needs to deliver a reset
token to the account owner by email. `aa-api` ships a pluggable SMTP mailer
configured entirely through environment variables:

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `AA_SMTP_HOST` | yes, to send mail | _(unset)_ | SMTP relay host. **Its presence is what switches on real email delivery.** |
| `AA_SMTP_PORT` | no | `587` | SMTP port (submission with STARTTLS). |
| `AA_SMTP_USER` | no | _(unset)_ | Username for authenticated submission. Omit for an unauthenticated relay. |
| `AA_SMTP_PASS` | no | _(unset)_ | Password for authenticated submission. |
| `AA_SMTP_FROM` | no | `no-reply@localhost` | The `From:` address stamped on outbound mail. |

When `AA_SMTP_HOST` is set, `aa-api` builds a real SMTP transport (STARTTLS,
authenticated when a user + pass are supplied) and password-reset emails are
delivered.

### When SMTP is not configured

When `AA_SMTP_HOST` is **unset**, `aa-api` falls back to a **logging mailer**: it
does not send anything, it logs that an email *would* have been sent (recipient
and subject only — never the token). The deployment still boots and the reset
endpoint still behaves correctly:

- `POST /api/v1/auth/password/reset` always returns `202 Accepted`, whether or
  not the email exists and whether or not mail can be delivered. This is
  deliberate — the response must never reveal which addresses are registered.
- With no SMTP configured, **no reset email is actually sent**; the operator sees
  the log line instead. Users cannot self-serve a password reset until SMTP is
  wired up.

The same fallback applies if `AA_SMTP_HOST` is set but the transport cannot be
built (a bad host or credential): `aa-api` logs a warning and falls back to the
logging mailer rather than refusing to start.

## Related

- [Configuration](../quick-start/configuration.md) — environment-variable
  reference, including the auth and SMTP variables.
- [Self-hosting](self-hosting.md) — the Postgres-backed stack that unlocks native
  accounts.
