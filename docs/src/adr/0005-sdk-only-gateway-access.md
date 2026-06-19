# ADR 0005: SDK-Client-Only Gateway Access — Two-Plane Mutual Auth + Dashboard Control-Plane

**Status**: Accepted
**Date**: 2026-06
**Epic**: [AAASM-3416](https://lightning-dust-mite.atlassian.net/browse/AAASM-3416)

---

## Context

The gateway (`aa-gateway`) is the policy source-of-truth and the destination for the
agent fast-path. ADR 0004 established that the **SDK** reaches the core only through the
single `aa-sdk-client` transport boundary (gRPC `AgentLifecycleService.Register` to the
gateway, `CheckAction` forwarded through `aa-runtime`). ADR 0002 established that the
**SDK is not a security boundary** — it is untrusted, and authoritative enforcement lives
in `aa-runtime` (scan/redact/normalize) and the gateway (policy SoT).

Epic [AAASM-3416](https://lightning-dust-mite.atlassian.net/browse/AAASM-3416) asks for
two related properties:

1. **Make `aa-sdk-client` the only _authenticated, supported_ path to the gateway** and
   **fail-closed reject** every other connection attempt across *all* transports
   (HTTP/HTTPS, gRPC, UDS).
2. **Give the dashboard its own operator-authenticated control-plane** so it never reuses
   agent data-plane credentials.

This ADR decides the auth mechanism, the attested-handshake shape, the two-plane split,
states the honest security boundary, and sequences the Epic's implementation Stories. It
**gates Stories 2–6** of AAASM-3416 — none of them should start until the mechanism here
is agreed.

---

## Current-State Audit (what each transport enforces TODAY)

This section records the *as-is* posture from a read-only audit of `remote/master`.

### gRPC — `aa-gateway` (default `127.0.0.1:50051`)

| Property | State today | Evidence |
| --- | --- | --- |
| Transport-layer auth (mTLS) | **None** | `aa-gateway/src/server.rs:448` — `Server::builder().add_service(...)` is called with **no `.tls_config(...)`** and **no interceptor**. `tonic` is pulled in `aa-gateway/Cargo.toml:36` **without** any TLS feature; there is no `ServerTlsConfig` / `ClientTlsConfig` anywhere in `aa-gateway`, `aa-api`, `aa-runtime`, or `aa-sdk-client`. |
| Connection acceptance | **Unauthenticated** | Any client that can reach `50051` can open a gRPC channel and call any service (`PolicyService`, `AgentLifecycleService`, `AuditService`, `ApprovalService`, `TopologyService`, `SecretsService`, `InvalidationService`). |
| `Register` RPC itself | **Unauthenticated** | Any caller can invoke `AgentLifecycleService.Register` with an arbitrary `agent_id` and receive a fresh `credential_token` (`aa-gateway/src/service/lifecycle_service.rs:108,156,195`). There is no auth interceptor in front of it. |
| `credential_token` (issued at Register) | **Issued + verified at the _application_ layer, not the transport** | `CheckAction` validates it via `validate_credential_token` (`aa-gateway/src/service/policy_service.rs:978`), called before policy eval (`policy_service.rs:~1031`); `Heartbeat`/`Deregister` validate via `validate_token` (`lifecycle_service.rs:213,285,326`). It denies a *registered* identity presenting a wrong/missing token (`policy_service.rs:987-989`) and a token registered to a *different* agent (`policy_service.rs:1005`). **But** it returns `None` (skip) for an unregistered agent presenting an *empty* token (`policy_service.rs:1002`) — it is an A2A-impersonation guard, not a connection gate, and the token travels **plaintext** in the gRPC message (no transport TLS). |

**Conclusion (gRPC): unauthenticated at the transport, and `Register` is unauthenticated.**
The `credential_token` is an in-band, app-level anti-impersonation check on `CheckAction` /
`Heartbeat` / `Deregister`, not a transport credential — and anyone can mint one by calling
`Register`.

### HTTP / REST — `aa-api` (operator / dashboard surface; default `7700` via `AA_API_ADDR`)

| Property | State today | Evidence |
| --- | --- | --- |
| Auth | **Required, deny-by-default** | `aa-api/src/auth/gate.rs:30` — `require_authentication`; per-route `AuthenticatedCaller` `FromRequestParts` extractor returns 401/403/429 and never reaches the handler on failure. Public exceptions: `GET /api/v1/health` (no auth) and `POST /api/v1/auth/token` (mints a JWT, caller must already be authenticated). |
| Mechanisms | **API key + JWT (Bearer)** | `aa-api/src/auth/{api_key,jwt,config,scope,policy_auth,rate_limit}.rs`. API keys (`aa_<32-hex>`) are argon2-hashed in `~/.aa/api-keys.json`; JWT is HMAC-SHA256, 24 h expiry, scopes from `AA_JWT_SECRET`. `AppState` carries `auth_config`, `key_store`, `jwt_signer`, `jwt_verifier` (`aa-api/src/server.rs:56-60`). |
| Authorization model | **Scopes `Read < Write < Admin`** | `aa-api/src/auth/scope.rs:15` — `RequireRead/Write/Admin` extractors. |
| Default posture | **Auth enabled by default** | `aa-api/src/auth/config.rs:18` — `AuthMode` defaults to enabled; explicit bypass is `AA_AUTH=off` (synthetic admin caller). `AA_JWT_SECRET` required when enabled. |

**Conclusion (REST): already authenticated and deny-by-default**, with API-key + JWT and a
Read/Write/Admin scope model. The operator control-plane primitives the dashboard needs
**already exist here**; the gap is the agent data-plane (gRPC/UDS), not REST.

### UDS / IPC — `aa-runtime`

Local Unix-domain-socket fast-path between `aa-sdk-client` and `aa-runtime`. Authentication
is **filesystem permissions only** (socket path ownership/mode); there is no cryptographic
client authentication on the socket. This is acceptable for the in-host trust domain but is
called out so the "all transports" requirement is honestly scoped.

### Dashboard → backend

The dashboard is a static SPA served by `aa-gateway/src/dashboard_server.rs`
(`dashboard_router`, mounted under `http://localhost:7391/` in local mode). It talks to the
backend **only over the `aa-api` REST surface** (`/api/v1/*`, base from `VITE_API_BASE_URL`,
defaulting to same-origin), **never** over gRPC. It obtains a **JWT** via
`POST /api/v1/auth/token`, stores it in `localStorage`, and sends `Authorization: Bearer <jwt>`
on every request (`dashboard/src/api/client.ts`). It does **not** hold an agent
`credential_token`. It therefore already authenticates (or, with `AA_AUTH=off` in local dev,
bypasses) through the REST `require_authentication` gate, never through the agent path.

### Existing mTLS prior art to reuse

mTLS plumbing is **already proven in `aa-storage-gateway`** (an enterprise-repo crate, in
`agent-assembly-enterprise`, not this monorepo): a tonic `ClientTlsConfig` carrying
`ca_certificate` / `identity` / `domain_name`, with the server enforcing `client_ca_root`
so a bad client cert is rejected at the first RPC. The gRPC-hardening Story should lift this
pattern into `aa-gateway` / `aa-sdk-client` rather than invent a new one.

---

## Decision

### 1. Auth mechanism per transport (default fail-closed)

**Both layers, defense-in-depth: mTLS at the transport + the Register-issued
`credential_token` at the application layer. Fail-closed on every transport.**

| Transport | Transport-layer auth | Application-layer auth | Posture |
| --- | --- | --- | --- |
| **gRPC** (gateway, `50051`) | **mTLS required** — `ServerTlsConfig` with `client_ca_root`; reject the connection when the client presents no/invalid cert. Lift the `aa-storage-gateway` `ClientTlsConfig` pattern. | `credential_token` (and the attested-handshake claims, below) required on `Register` and on every `CheckAction`; **no skip-on-empty** for production agents. | **Fail-closed**: no cert → no connection; valid cert but no/invalid token → `Deny`. |
| **UDS / IPC** (`aa-runtime`) | Filesystem socket ownership/mode (in-host trust domain). | Same `credential_token` + handshake claims forwarded on the pipeline. | **Fail-closed** at the application layer; a forged in-host client without a valid token is denied downstream. |
| **HTTP / REST** (`aa-api`, default `7700`; dashboard/local-mode `7391`) | TLS in production (terminated at `aa-api` / ingress). | **Keep the existing deny-by-default API-key + JWT gate**; this is the *operator* plane, not the agent plane (see Decision 3). | **Fail-closed**: already deny-by-default. |

**Rationale.** mTLS authenticates the *channel and the client population* (only holders of a
gateway-issued client cert can open a connection); the `credential_token` authenticates the
*specific registered agent identity* per request and already exists. Neither alone is
sufficient: mTLS without the token cannot distinguish one agent from another sharing a cert;
the token without mTLS leaves the connection itself open to anyone on the port. Requiring
**both** closes the transport-acceptance gap (today's biggest hole) and the
per-identity gap together, and reuses two mechanisms already present in the codebase.

**Why not `credential_token` only (rejected as the sole mechanism).** It is the cheapest
change but leaves the gRPC port open to unauthenticated connections; the
`validate_credential_token` skip-on-empty path (`policy_service.rs:1002`) means an
unregistered client is not gated at connection time. A token alone cannot satisfy "fail-closed
reject every other connection attempt across all transports."

**Why not mTLS only (rejected as the sole mechanism).** mTLS gates the connection but not the
agent identity; we would lose the existing per-agent / anti-impersonation guarantees that
`credential_token` already provides, and would have to rebuild identity binding on top of
certs. Keeping the token preserves that work.

### 2. Attested SDK handshake

The Register/handshake (carried on `AgentLifecycleService.Register`, gRPC) is extended so the
client **attests** what it is. The client presents:

- **Agent identity** — the `did:key` agent id + matching Ed25519 `public_key` (already on
  Register per ADR 0004), plus the topology/lineage fields (`parent_agent_id`, `team_id`) —
  see Decision 5.
- **SDK descriptor** — the SDK language + **SDK version** (and `aa-sdk-client` build), so the
  gateway can **version-gate**: reject SDK versions below a configured floor (e.g. those
  predating fail-closed enforcement) and record the version for audit.
- **Signed nonce** — the gateway issues a server nonce; the client signs `nonce ‖ agent_id ‖
  sdk_descriptor` with its Ed25519 private key. The gateway verifies the signature against the
  presented `public_key`, binding the handshake to this client and defeating naïve replay.

The gateway **distinguishes "an SDK client" from "any gRPC client"** by the *combination* of
(a) a valid client cert from the gateway-issued CA (Decision 1), (b) a well-formed signed
handshake, and (c) an acceptable SDK version. Any connection failing (a) is dropped at TLS;
any failing (b)/(c) is denied at `Register` and issued **no** `credential_token`, so it cannot
proceed to `CheckAction`. **This is the explicit "non-SDK client" denial.**

### 3. Two-plane separation

| Plane | Who | Path | Auth | Credential |
| --- | --- | --- | --- | --- |
| **Agent data-plane** | agents | SDK → `aa-sdk-client` → gateway gRPC (+ `aa-runtime` UDS) | mTLS client cert **+** `credential_token` + attested handshake (Decisions 1–2) | per-agent, issued at Register |
| **Operator control-plane** | dashboard, operators, `aasm` data cmds | dashboard/operator → `aa-api` REST `/api/v1/*` | the **existing** deny-by-default API-key / JWT gate with `Read/Write/Admin` scopes (`aa-api/src/auth/`) | operator credential — **never an agent `credential_token`** |

**The dashboard authenticates as an operator, not as an agent.** It continues to use the
`aa-api` REST surface (where it already lives) with an operator credential (API key or JWT;
OIDC/session may layer on later as an `aa-api` auth backend). It MUST NOT obtain or present a
`credential_token` and MUST NOT open the agent gRPC channel. This keeps the two credential
families disjoint: compromising an operator session cannot impersonate an agent on the
data-plane, and a leaked agent token cannot drive operator/admin REST actions.

**Recommendation for the dashboard control-plane client:** a thin operator client/BFF over
`aa-api` (API-key or JWT today; OIDC-backed JWT later). No new transport is introduced — the
REST plane is already the right home and already deny-by-default.

### 4. Honest boundary statement (defense-in-depth, not absolute)

**"Only the SDK client can connect" is NOT, and cannot be, an absolute cryptographic
guarantee.** Anyone who can run the SDK can extract its client cert, private key, and
`credential_token` from the host and craft a byte-for-byte-equivalent client. The attested
handshake, mTLS, and SDK-version gating are a strong **defense-in-depth + version gate +
speed-bump**: they make the *unmodified, current* SDK the only **authenticated, supported**
path, raise the cost of crafting a rogue client, let us cut off old/known-bad SDK versions,
and turn casual direct-to-gateway access into an authenticated, audited, deny-by-default
event. They are **not** an unbreakable boundary.

The **authoritative** bypass-prevention remains the product's three-layer model, exactly as
ADR 0002 records that **the SDK is not a security boundary**:

1. **Runtime / gateway policy** — `aa-runtime` scans/redacts/normalizes *every* event
   unconditionally and the gateway is the policy SoT; nothing the client asserts can shorten
   that work (ADR 0002 invariant).
2. **`aa-proxy` (sidecar MitM)** — enforces network-egress policy on outbound traffic without
   code changes, catching what the SDK path misses, **including a client that bypassed the SDK**.
3. **eBPF (`aa-ebpf*`)** — kernel hooks (uprobes on SSL libs, exec/file syscalls) catch
   everything else, including deliberate bypass attempts. Linux-only.

**Positioning:** this Epic hardens the SDK path and makes everything else *fail-closed and
authenticated*; the **proxy + eBPF layers are the real backstop** against a client that
extracts SDK credentials and goes direct. The ADR must not be read as claiming the handshake
prevents a determined attacker from reaching the gateway — it prevents *unauthenticated* and
*unattested* access, and it gates SDK versions; the proxy/eBPF layers are what stop the
authenticated-but-rogue case.

### 5. Sequencing (gates the Epic; subsumes AAASM-3415)

- The **Register/handshake proto change** in Decision 2 modifies the same
  `AgentLifecycleService.Register` message and the same `aa-sdk-client` → per-SDK shim path
  that [AAASM-3415](https://lightning-dust-mite.atlassian.net/browse/AAASM-3415)
  (forward `parent_agent_id` / `team_id` over native Register) touches. To avoid double
  rework on the proto and the three SDK shims, **AAASM-3415 is subsumed into / sequenced with
  Story 3** (the attested-client handshake): the lineage/team fields are added to the Register
  message in the *same* proto revision as the handshake claims, plumbed once through
  `aa-sdk-client` and `aa-ffi-{python,node,go}`.
- **Epic AAASM-3416 Stories 2–6 are gated on this ADR (Story 1).** They proceed in this order:
  1. (this ADR)
  2. **Gateway**: require mutual auth on all transports, fail-closed reject non-authenticated /
     non-SDK clients (mTLS server config + token/handshake enforcement; reuse
     `aa-storage-gateway`'s `ClientTlsConfig` pattern).
  3. **`aa-sdk-client`**: attested client handshake + cert/`credential_token` presentation +
     version gating (**includes AAASM-3415's lineage/team fields**).
  4. **Per-SDK adoption** of the attested client (python / node / go).
  5. **Dashboard control-plane** client/component over `aa-api` (operator auth, separate from
     the agent data-plane).
  6. **Proxy + eBPF backstop**: block direct-to-gateway bypass at the network/kernel layer
     (the authoritative backstop of Decision 4).

---

## Consequences

### Positive

- **Closes the open-port gap.** The gRPC transport moves from "anyone on `50051`" to
  "mTLS client-cert holders only," and `Register`/`CheckAction` require a valid attested
  identity — fail-closed across transports.
- **Reuses existing mechanisms.** `credential_token` (Register), the `aa-api` deny-by-default
  auth gate + scopes, and the `aa-storage-gateway` mTLS pattern all already exist; this ADR
  composes them rather than inventing new infrastructure.
- **Clean two-plane split.** Operator and agent credentials are disjoint; a compromise on one
  plane does not grant the other.
- **Version gating.** Old / known-bad SDK versions can be cut off at the gateway.
- **Honest, reviewable security story.** The boundary limitation is recorded, so no one builds
  on a false guarantee; proxy + eBPF remain the documented authoritative backstop.

### Negative / accepted trade-offs

- **Certificate lifecycle.** mTLS introduces client-cert issuance, distribution, and rotation
  for agents — new operational surface (mitigated by reusing the `aa-storage-gateway`
  rotation pattern; rotation by `file_name` match + tokio `Handle` in the notify callback).
- **Local-dev friction.** Fully fail-closed gRPC complicates zero-config local dev; an
  explicit, clearly-named local-dev bypass (mirroring `aa-api`'s `AuthMode` off-switch) is
  needed so dev does not weaken the production default.
- **Not an absolute boundary.** As stated in Decision 4 — a determined attacker who extracts
  SDK credentials can still craft an equivalent client; proxy/eBPF are the backstop, not this
  handshake.
- **Proto churn.** The Register message changes; SDK pins must be advanced (folding in
  AAASM-3415 keeps this to a single churn rather than two).

---

## Alternatives Considered

### `credential_token` only, no mTLS (rejected)

Cheapest, but leaves the gRPC port open to unauthenticated connections and cannot satisfy
"fail-closed reject every connection attempt on all transports." See Decision 1.

### mTLS only, drop `credential_token` (rejected)

Gates the connection but not the per-agent identity; discards the existing anti-impersonation
guarantees and forces rebuilding identity binding on certs. See Decision 1.

### Reuse the agent `credential_token` for the dashboard (rejected)

Collapses the two planes — a leaked agent token would then drive operator/admin actions, and
an operator-session compromise could impersonate an agent. The disjoint-credential split in
Decision 3 exists precisely to prevent this.

### Treat the attested handshake as the authoritative boundary (rejected)

Overstates the guarantee. The SDK is not a security boundary (ADR 0002); credentials are
extractable. Recorded explicitly in Decision 4; proxy + eBPF remain authoritative.

---

## Related

- Epic: [AAASM-3416](https://lightning-dust-mite.atlassian.net/browse/AAASM-3416) — Enforce SDK-client-only gateway access + dashboard control-plane (this ADR is its Story 1, gating Stories 2–6)
- Story: [AAASM-3417](https://lightning-dust-mite.atlassian.net/browse/AAASM-3417) — this ADR
- Subsumed: [AAASM-3415](https://lightning-dust-mite.atlassian.net/browse/AAASM-3415) — forward `parent_agent_id` / `team_id` over native Register (folded into Story 3's proto rework)
- Builds on: [ADR 0002](0002-sdk-security-boundary.md) — SDK is not a security boundary; trust model
- Builds on: [ADR 0004](0004-governance-enforcement-flow.md) — SDK → `aa-sdk-client` → core; Register issues `credential_token`
- Prior art: `aa-storage-gateway` (enterprise) `ClientTlsConfig` (`ca_certificate` / `identity` / `domain_name`) + server `client_ca_root`
