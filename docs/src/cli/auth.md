# Authentication (`login` / `logout` / `whoami`)

`aasm` authenticates to the gateway with an **API key**, but the key is a
long-lived operator credential you do not want on every command line or in every
CI environment variable. The auth workflow exchanges that key **once** for a
short-lived, **scoped JWT** (the *session*) that the rest of the CLI presents on
your behalf. This is the **recommended** way to authenticate: run
[`aasm login`](#aasm-login) once and subsequent commands authenticate without
re-prompting.

The three commands on this page manage that session:

| Command | Purpose |
|---|---|
| [`aasm login`](#aasm-login) | Exchange an API key for a scoped session and store it. |
| [`aasm logout`](#aasm-logout) | Clear the local session for the active context. |
| [`aasm whoami`](#aasm-whoami) | Show the active session — scopes, expiry, source-key hint. |

## The session model

`aasm login` sends your API key to `POST /api/v1/auth/token` (source:
`aa-cli/src/auth/token.rs`) and gets back `{ token, expires_at, scopes }`. That
scoped JWT — not the raw key — is what later commands attach as
`Authorization: Bearer <jwt>`. The session is stored **per context** (source:
`aa-cli/src/auth/session.rs`), so you can be logged into several gateways at once
and each is managed independently.

Compared with putting the raw key on `--api-key` / `AASM_API_KEY`:

- The key never appears in argv, shell history, or process listings when you use
  the [hidden prompt](#the-hidden-prompt).
- The credential that travels on each request is **short-lived** (24h) and can be
  **scope-narrowed** (`--scope read`), limiting blast radius.

The raw-key path still works for non-interactive use — see
[Environment / flag fallback](#environment-and-flag-fallback).

---

## `aasm login`

Exchange an API key for a scoped session and store it for the active context.

### Synopsis

```text
aasm login [--scope <read|write|admin>]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--scope <SCOPE>` | `read` \| `write` \| `admin` | _(caller's full grants)_ | Request a narrowed session scope. Omit to receive all scopes your key is granted. Requesting more than your key grants is rejected by the server. |

Plus the [global options](overview.md#global-options).

### Where the key comes from — resolution precedence

`login` resolves the API key **without ever placing it on argv** (source:
`aa-cli/src/commands/login.rs`), in this order:

1. The key already resolved into the active context — from `--api-key`,
   `AASM_API_KEY`, or the context's stored `api_key` in
   [`~/.aa/config.yaml`](overview.md#config-and-context-resolution) (this is the
   [global-options](overview.md#global-options) precedence).
2. Otherwise, a **hidden interactive prompt** (see below).

#### The hidden prompt

When no key is resolvable from the context, `login` prompts on stderr:

```text
API key:
```

Input is read as a **secure line** (not echoed to the terminal), so the secret
never lands in your shell history or on the command line. A blank entry is
rejected rather than attempting an exchange with an empty credential.

### What it stores, and where

On success the session is written to **`~/.aa/credentials.yaml`** (source:
`aa-cli/src/auth/session.rs`), a file kept **separate** from `config.yaml` so
that logging out never rewrites your context definitions. On Unix the file is
locked to `0600` and its directory to `0700`, matching `config.yaml`. The stored
session carries the JWT, its expiry, the granted scopes, and the source key it
was minted from (retained for [auto-refresh](#expiry-and-auto-refresh)).

### What it prints

A single confirmation line naming the context (its friendly name, or the URL for
an unnamed context), the granted scopes, and a coarse expiry hint. It **never**
prints the API key or the JWT.

### Example

```bash
aasm login
```

```text
API key:
Logged in to production (scopes: read, write; expires in 1d).
```

Request a read-only session:

```bash
aasm login --scope read
```

```text
Logged in to production (scopes: read; expires in 1d).
```

Non-interactive (key supplied by the environment — no prompt appears):

```bash
AASM_API_KEY=aa_live_… aasm login --context staging
```

### Errors

| Message | Meaning |
|---|---|
| `authentication failed: the API key was rejected` | The gateway returned `401` — the key is wrong, absent, or revoked. |
| _(server scope message, e.g. `insufficient scope for this operation`)_ | The gateway returned `403` — you requested a `--scope` your key is not granted. |
| `error: no API key provided` | You pressed Enter at the hidden prompt without typing a key. |

`login` exits non-zero (`ExitCode::FAILURE`) on any of these.

---

## `aasm logout`

Clear the local session for the active context.

### Synopsis

```text
aasm logout
```

`logout` takes no arguments of its own — it acts on the active context selected
by the [global options](overview.md#global-options) (`--context` / `--api-url`).

### Local-only — does *not* revoke the key

> **`logout` is local-only.** It removes the session credential from
> `~/.aa/credentials.yaml` on this machine, but it does **not** revoke the
> underlying API key server-side. The source key stays valid at the gateway, so a
> session minted from it on another machine keeps working. Revoking the key
> itself is a **separate IAM operation** (`POST /iam/api-keys/{id}/revoke`),
> deliberately kept distinct so logging out of one machine never invalidates a
> key in use elsewhere.

If a key is actually compromised, revoke it via IAM — `logout` alone is not
enough.

### Idempotent

Logging out of a context with no active session is a **success, not an error**,
so scripts can call `aasm logout` unconditionally.

### Examples

```bash
aasm logout
```

```text
Logged out of context 'production'.
```

When there was nothing to clear:

```text
No active session for 'production'.
```

---

## `aasm whoami`

Show the active session for the current context — context name, gateway URL,
scopes, expiry, and a truncated source-key hint.

### Synopsis

```text
aasm whoami [--output <table|json|yaml>]
```

Being **not logged in is a normal state**: `whoami` exits `0` either way, and
prints guidance to run `aasm login`. It **never** prints the JWT or the full API
key — every output format is built from a secret-free projection that carries
only a short `source_key_hint` (source: `aa-cli/src/commands/whoami.rs`).

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output <FORMAT>` | `table` \| `json` \| `yaml` | `table` | Output format. (This is the [global `--output`](overview.md#output-formats).) |

### Examples

Default table:

```bash
aasm whoami
```

```text
Logged in
  context:    production
  api_url:    https://api.example.com
  scopes:     read, write
  expires_at: 1000000 (in 23h 41m)
  source_key: aa_live_su…
```

Not logged in:

```bash
aasm whoami
```

```text
Not logged in (run 'aasm login').
```

JSON (for scripting):

```bash
aasm whoami --output json
```

```json
{
  "logged_in": true,
  "context": "production",
  "api_url": "https://api.example.com",
  "scopes": [
    "read",
    "write"
  ],
  "expires_at": 1000000,
  "expires_in_secs": 1000,
  "expired": false,
  "source_key_hint": "aa_live_su…"
}
```

When not logged in, the machine-readable shape is simply `{ "logged_in": false }`.

---

## Expiry and auto-refresh

The scoped JWT has a **24-hour TTL** and the server issues **no refresh token**
(source: `aa-cli/src/auth/token.rs`). Instead, the CLI retains the source API key
inside the session and **silently re-exchanges** it for a fresh JWT when the old
one expires — this "auto-refresh" is transparent: you do not run any command for
it (source: `aa-cli/src/client.rs`).

Re-exchange happens in two places:

1. **Before a request**, if the stored JWT is already past its expiry — the CLI
   re-mints from the source key and persists the fresh session.
2. **On a `401`** that slips past the pre-send check (clock skew, or a token
   revoked mid-flight then re-granted) — the CLI re-mints **once** and resends.
   A *second* consecutive `401` is treated as a genuine rejection, not retried
   further.

You must **log in again** only when the **source key itself** is revoked or
rotated server-side: re-exchange then fails, and the CLI surfaces the
[not-logged-in error](#error-messages-you-may-see) prompting you to run
`aasm login`.

---

## Environment and flag fallback

The raw-key path is fully supported and is the right choice for CI and other
non-interactive environments where an interactive login is impractical:

- **`AASM_API_KEY`** — set the key in the environment.
- **`--api-key <KEY>`** — pass the key as a global flag.

When no stored session exists, the client attaches the raw key as the bearer
directly (source: `aa-cli/src/client.rs`). Bearer resolution order is:

1. A stored session's JWT (auto-refreshed on expiry).
2. Otherwise, `--api-key` / `AASM_API_KEY` (or the context's stored key).
3. Otherwise, no `Authorization` header at all.

> **Use `aasm login` interactively; use `AASM_API_KEY` / `--api-key` in CI.** In
> interactive use prefer `login` so the key never touches argv or the environment.
> The raw-key path avoids a persisted session on ephemeral CI runners.

The CLI does **not** fail-fast locally on a missing credential — the gateway is
the sole authorization authority (a bypass-default gateway serves unauthenticated
requests fine). The client sends what it has and lets the server rule.

---

## Error messages you may see

Because the gateway is deny-by-default, an unauthenticated or under-scoped
request is answered by the **server**, and the CLI translates the status into an
actionable message (source: `aa-cli/src/client.rs`):

| Server status | What the CLI shows | What it means |
|---|---|---|
| `401 Unauthorized` | an auth-required error prompting you to run `aasm login` | No valid credential reached the gateway — you are not logged in, or the source key was revoked so auto-refresh failed. Run `aasm login`. |
| `403 Forbidden` | the server's scope-explanation message (e.g. `insufficient scope for this operation` or `requires admin scope`) | You are authenticated, but the session's scopes do not cover this operation. Re-run `aasm login` requesting the needed scope (if your key grants it). |

---

## Security notes

- The API key and the JWT are **never printed** by any command — not by `login`'s
  confirmation line, not by `whoami` in any output format.
- When entered at the prompt, the key is **never placed on argv**; it is read as a
  hidden secure line and kept off your shell history.
- The credential store `~/.aa/credentials.yaml` is locked to `0600` (directory
  `0700`) on Unix, and is kept separate from `config.yaml`.
- A corrupt or partially-written credential file fails **closed** to "no session"
  rather than wedging the CLI.

## See also

- [CLI Overview — config and context resolution](overview.md#config-and-context-resolution)
- [`aasm context`](context.md) — manage the named contexts a session is keyed to.
