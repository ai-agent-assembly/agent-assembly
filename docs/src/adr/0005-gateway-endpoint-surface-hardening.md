# ADR 0005: Gateway Endpoint Surface Hardening — Per-Endpoint Auth + Two-Plane (not SDK-client-only blocking)

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

Epic [AAASM-3416](https://lightning-dust-mite.atlassian.net/browse/AAASM-3416) was
originally framed as "make `aa-sdk-client` the *only* path to the gateway and fail-closed
**reject every connection that is not the SDK client** across all transports, backed by an
attested SDK handshake and mandatory mTLS everywhere." On product review that framing was
**rejected** (see *Alternatives Considered → Reject-all-non-SDK + mandatory mTLS + attested
handshake*). The gateway's network surface is a deliberate **integration surface** — the
dashboard consumes it today, and enterprise / control-plane integrations will consume it
tomorrow — and it is an **extension point for the enterprise business model**. A blanket
"prove you are the SDK client or be rejected" gate fights both of those purposes, and — per
ADR 0002 — "prove it's the unmodified SDK" is unwinnable anyway (SDK credentials are
extractable).

This ADR therefore reframes the Epic from *SDK-client-only blocking* to **gateway endpoint
surface hardening**: a deliberate, minimal, clearly-scoped endpoint surface with
**per-endpoint authentication / authorization**, with endpoints that need not be publicly
exposed **removed or consolidated**. It keeps the two-plane separation (agent data-plane vs
operator control-plane) and keeps the honest-boundary statement. It **gates the Epic's
implementation Stories** — they are re-scoped to this direction and should not start until
the principles here are agreed.

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
called out so the surface is honestly scoped.

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
so a bad client cert is rejected at the first RPC. This pattern is available to lift **if and
where** transport-level mTLS is wanted (per Decision 3, that is an optional / enterprise
hardening, not a universal requirement).

---

## Decision

Harden the gateway by **rationalizing and authenticating its endpoint surface**, not by
trying to detect-and-block "non-SDK" callers. Five decisions:

### 1. Rationalize the endpoint surface

Treat the gateway surface as a **deliberate, minimal, clearly-scoped** API, not an
accidental superset of everything `aa-gateway` happens to serve. A follow-up Story will
**inventory every gRPC service / method and every REST route** and classify each as:

- **agent data-plane** — must be reachable by registered agents (e.g. `Register`,
  `CheckAction`, `Heartbeat`, `Deregister`);
- **operator control-plane** — for the dashboard / operators (the `aa-api` REST surface);
- **internal-only** — must not be publicly exposed (consolidate behind an internal listener
  or remove from the public surface);
- **remove-candidate** — exposed today with no legitimate external consumer; **remove or
  consolidate**.

The concrete inventory and its classification are **implementation work under that Story**;
this ADR fixes the *principle*: an endpoint that does not need to be publicly exposed is
removed or moved off the public surface, so the attack surface is small and every remaining
endpoint has a stated reason to exist. Reducing the surface is the first-order security win;
authenticating what remains (Decision 2) is the second.

### 2. Authenticate every remaining endpoint, fail-closed

Every endpoint that survives Decision 1 must enforce authentication and authorization and
**fail closed** (deny on missing / invalid credentials).

- **REST (`aa-api`) — already there.** Keep the existing deny-by-default API-key + JWT gate
  with `Read/Write/Admin` scopes. No regression; this is the model the rest of the surface
  should match.
- **gRPC (`:50051`) — the priority gap.** The gRPC plane has **zero authentication today**,
  and `Register` lets *anyone* mint a `credential_token`. Add authentication to the gRPC
  plane — **token-based at minimum** (an auth interceptor in front of the services; a bootstrap
  / registration credential for `Register`; the per-agent `credential_token` enforced without
  the skip-on-empty bypass for production agents). This must be done:
  - **without breaking the dashboard** — the dashboard is REST-only and already JWT-authenticated;
    it does not touch gRPC, so gRPC auth does not affect it; and
  - **without foreclosing enterprise integration** — the gRPC plane stays an integration
    surface; we are authenticating it, not restricting it to a single client identity.

  Authentication here means *the caller proves a credential the gateway issued/accepts*, **not**
  *the caller proves it is the unmodified SDK client*. Any authenticated, authorized integrator
  (enterprise control plane, future first-party tools) is a legitimate caller.

### 3. mTLS is optional / enterprise hardening, not universal

mTLS is **downgraded** from "mandatory everywhere" (the rejected framing) to an **optional
deployment and enterprise hardening**. Token-based authentication (Decision 2) is the baseline
that closes the open-port gap. Deployments that want channel-level client-population
authentication can enable mTLS using the `aa-storage-gateway` `ClientTlsConfig` /
`client_ca_root` prior art, but it is **not** a precondition for the gateway to be considered
hardened, and it is **not** required of every integrator.

### 4. Keep the two-plane separation

The agent data-plane vs operator control-plane split is sound and **largely already exists**
(agent gRPC vs operator REST/JWT). Keep it.

| Plane | Who | Path | Auth | Credential |
| --- | --- | --- | --- | --- |
| **Agent data-plane** | agents | SDK → `aa-sdk-client` → gateway gRPC (+ `aa-runtime` UDS) | **gRPC endpoint authentication** (token-based baseline; optional mTLS) + per-agent `credential_token` (Decisions 2–3) | per-agent, issued at Register |
| **Operator control-plane** | dashboard, operators, `aasm` data cmds | dashboard/operator → `aa-api` REST `/api/v1/*` | the **existing** deny-by-default API-key / JWT gate with `Read/Write/Admin` scopes (`aa-api/src/auth/`) | operator credential — **never an agent `credential_token`** |

**The dashboard authenticates as an operator, not as an agent.** It continues to use the
`aa-api` REST surface (where it already lives) with an operator credential (API key or JWT;
OIDC/session may layer on later as an `aa-api` auth backend). It MUST NOT obtain or present a
`credential_token` and MUST NOT open the agent gRPC channel. This keeps the two credential
families disjoint: compromising an operator session cannot impersonate an agent on the
data-plane, and a leaked agent token cannot drive operator/admin REST actions. No new
transport is introduced — the REST plane is already the right home and already deny-by-default.

### 5. Honest boundary statement (defense-in-depth, not absolute)

**Authenticating an endpoint is NOT the same as proving the caller is "the SDK," and is not an
absolute boundary.** Per ADR 0002, **the SDK is not a security boundary**: anyone who can run
the SDK can extract its `credential_token` (and, where used, its client cert / private key)
from the host and craft a byte-for-byte-equivalent caller. Per-endpoint authentication turns
casual, unauthenticated, direct-to-gateway access into an authenticated, authorized,
deny-by-default, **audited** event, and a small surface (Decision 1) means there is little to
reach. That is a real, reviewable improvement — but it is **not** an unbreakable boundary, and
it does not (and should not) try to distinguish "the unmodified SDK" from any other holder of a
valid credential.

The **authoritative** bypass-prevention remains the product's three-layer model, exactly as
ADR 0002 records:

1. **Runtime / gateway policy** — `aa-runtime` scans/redacts/normalizes *every* event
   unconditionally and the gateway is the policy SoT; nothing the client asserts can shorten
   that work (ADR 0002 invariant).
2. **`aa-proxy` (sidecar MitM)** — enforces network-egress policy on outbound traffic without
   code changes, catching what the SDK path misses, **including a caller that bypassed the SDK**.
3. **eBPF (`aa-ebpf*`)** — kernel hooks (uprobes on SSL libs, exec/file syscalls) catch
   everything else, including deliberate bypass attempts. Linux-only.

**Positioning:** this Epic hardens the *endpoint surface* — small, authenticated, fail-closed;
the **proxy + eBPF layers are the real backstop** against a caller that extracts credentials and
goes direct. The ADR must not be read as claiming endpoint authentication prevents a determined
attacker from reaching the gateway — it prevents *unauthenticated* access and shrinks the
surface; the proxy/eBPF layers are what stop the authenticated-but-rogue case.

---

## Consequences

### Positive

- **Closes the open-port gap honestly.** The gRPC transport moves from "anyone on `50051` can
  mint a token" to "authenticated, authorized callers only," fail-closed — without pretending to
  detect the SDK.
- **Smaller attack surface.** Surface rationalization (Decision 1) removes / consolidates
  endpoints that need not be public, which is the cheapest, highest-leverage security win.
- **Preserves the integration surface and the enterprise extension point.** Authenticating
  rather than client-locking keeps the gateway open to legitimate dashboard and
  enterprise/control-plane integrations.
- **Reuses existing mechanisms.** The `aa-api` deny-by-default auth gate + scopes, the
  `credential_token`, and (optionally) the `aa-storage-gateway` mTLS pattern all already exist;
  this ADR composes them rather than inventing new infrastructure.
- **Clean two-plane split.** Operator and agent credentials are disjoint; a compromise on one
  plane does not grant the other.
- **Honest, reviewable security story.** The boundary limitation is recorded, so no one builds
  on a false guarantee; proxy + eBPF remain the documented authoritative backstop.

### Negative / accepted trade-offs

- **Inventory + classification work.** Rationalizing the surface requires auditing every gRPC
  method and REST route and deciding its disposition (a dedicated Story).
- **gRPC auth plumbing.** Adding an auth interceptor + a bootstrap/registration credential to a
  plane that has none today is real work, and needs a clearly-named local-dev bypass (mirroring
  `aa-api`'s `AuthMode` off-switch) so dev does not weaken the production default.
- **Optional-mTLS operational surface.** Where mTLS is enabled it adds cert issuance /
  distribution / rotation (mitigated by reusing the `aa-storage-gateway` rotation pattern) — but
  it is now opt-in, not a universal cost.
- **Not an absolute boundary.** As stated in Decision 5 — a determined attacker who extracts
  credentials can still craft an equivalent caller; proxy/eBPF are the backstop.

### Sequencing (gates the Epic; subsumes AAASM-3415)

- **The gateway `Register` / gRPC-auth change subsumes [AAASM-3415](https://lightning-dust-mite.atlassian.net/browse/AAASM-3415)
  where the proto is touched.** Adding gRPC authentication touches the same
  `AgentLifecycleService.Register` message and the same `aa-sdk-client` → per-SDK shim path that
  AAASM-3415 (forward `parent_agent_id` / `team_id` over native Register) touches. To avoid
  double rework on the proto and the three SDK shims, AAASM-3415's lineage/team fields are added
  to the Register message in the **same** proto revision as the auth change and plumbed once
  through `aa-sdk-client` and `aa-ffi-{python,node,go}`.
- **Epic [AAASM-3416](https://lightning-dust-mite.atlassian.net/browse/AAASM-3416) Stories are
  re-scoped to this direction** (endpoint-surface hardening, not SDK-client-only blocking) and
  gated on this ADR (Story 1). Indicative ordering:
  1. (this ADR)
  2. **Endpoint inventory + classification** (Decision 1) — produce the concrete
     agent/operator/internal/remove map; remove or consolidate the remove-candidates.
  3. **Gateway gRPC authentication** (Decision 2) — auth interceptor + bootstrap/registration
     credential + per-agent `credential_token` without skip-on-empty (**includes AAASM-3415's
     lineage/team fields in the same proto revision**); REST stays as-is.
  4. **`aa-sdk-client` + per-SDK adoption** of the authenticated Register/credential path
     (python / node / go).
  5. **Dashboard control-plane** client/component over `aa-api` (operator auth, separate from the
     agent data-plane) — confirm it never touches gRPC.
  6. **Optional mTLS hardening** (Decision 3) for deployments/enterprise that want it.
  7. **Proxy + eBPF backstop**: block direct-to-gateway bypass at the network/kernel layer (the
     authoritative backstop of Decision 5).

---

## Alternatives Considered

### Reject-all-non-SDK + mandatory mTLS + attested SDK handshake (rejected — previous framing)

The Epic's original proposal: make `aa-sdk-client` the only path, **reject every connection
that is not the SDK client** across all transports, backed by mandatory mTLS everywhere and an
attested SDK handshake (signed nonce + SDK-version gate) that lets the gateway distinguish "an
SDK client" from "any gRPC client." **Rejected** by product review for three reasons:

1. **It fights the surface's purpose.** The gateway endpoints exist as an **integration
   surface** — the dashboard today, enterprise / control-plane integrations tomorrow. A blanket
   "reject any connection that isn't the SDK client" closes that surface to legitimate
   non-SDK callers.
2. **It forecloses the enterprise business model.** The surface is an **extension point** for
   enterprise; locking it to SDK-client-only removes legitimate integration paths the business
   depends on.
3. **It targets the wrong thing.** Real security comes from a **deliberate, minimal,
   clearly-scoped endpoint surface with per-endpoint authn/authz — and removing endpoints that
   shouldn't be exposed** — not from a blanket gate bolted onto an unrationalized surface. And
   per ADR 0002 the SDK is **not** a security boundary and its credentials are extractable, so
   "prove it's the unmodified SDK" is both **unwinnable** (any holder of the credential can
   forge it) and **undesirable** (it would block legitimate integrators). Mandatory mTLS
   everywhere is likewise over-broad operational cost for what token auth + a small surface
   already achieve.

This ADR keeps the *useful parts* of the rejected proposal — the two-plane split, the
honest-boundary statement, and fail-closed gRPC authentication — while dropping the
client-locking, the universal mTLS mandate, and the attested-handshake "is it the SDK?"
detection.

### Reuse the agent `credential_token` for the dashboard (rejected)

Collapses the two planes — a leaked agent token would then drive operator/admin actions, and
an operator-session compromise could impersonate an agent. The disjoint-credential split in
Decision 4 exists precisely to prevent this.

### Treat endpoint authentication as the authoritative boundary (rejected)

Overstates the guarantee. The SDK is not a security boundary (ADR 0002); credentials are
extractable. Recorded explicitly in Decision 5; proxy + eBPF remain authoritative.

---

## Related

- Epic: [AAASM-3416](https://lightning-dust-mite.atlassian.net/browse/AAASM-3416) — Gateway endpoint surface hardening + dashboard control-plane (this ADR is its Story 1, gating/re-scoping the remaining Stories)
- Story: [AAASM-3417](https://lightning-dust-mite.atlassian.net/browse/AAASM-3417) — this ADR
- Subsumed: [AAASM-3415](https://lightning-dust-mite.atlassian.net/browse/AAASM-3415) — forward `parent_agent_id` / `team_id` over native Register (folded into the gRPC-auth proto rework)
- Builds on: [ADR 0002](0002-sdk-security-boundary.md) — SDK is not a security boundary; trust model
- Builds on: [ADR 0004](0004-governance-enforcement-flow.md) — SDK → `aa-sdk-client` → core; Register issues `credential_token`
- Prior art: `aa-storage-gateway` (enterprise) `ClientTlsConfig` (`ca_certificate` / `identity` / `domain_name`) + server `client_ca_root` — available for *optional* mTLS hardening
