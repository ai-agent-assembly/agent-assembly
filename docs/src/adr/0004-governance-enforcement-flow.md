# ADR 0004: Governance Enforcement Flow — SDK → `aa-sdk-client` → core (gRPC / UDS)

**Status**: Accepted
**Date**: 2026-06
**Epic**: [AAASM-3385](https://lightning-dust-mite.atlassian.net/browse/AAASM-3385)

---

## Context

The user-facing language SDKs (`python-sdk`, `node-sdk`, `go-sdk`) exist to intercept
agent actions and obtain allow/deny decisions from the core. Every SDK must reach the
core to:

- emit audit events for an intercepted action, and
- get a pre-execution allow/deny decision (the policy `check`) before a wrapped tool/LLM
  call is allowed to run.

There is more than one transport the core can be reached over:

| Transport | Core endpoint | Spoken by |
| --- | --- | --- |
| **gRPC** | `aa-gateway` — `PolicyService.CheckAction`, audit RPCs | the canonical control-plane RPC surface |
| **UDS / IPC** | `aa-runtime` — local Unix-domain-socket pipeline | the in-process / local fast-path |
| **REST `/api/v1/*`** | `aa-api` router (e.g. a hypothetical `/api/v1/policy/check`) | dashboard / operators / CLI data commands |

A QA finding ([AAASM-3380](https://lightning-dust-mite.atlassian.net/browse/AAASM-3380))
surfaced an `examples/` README that implied the SDK should call a REST endpoint
**directly** to get a policy decision (a "production mode" snippet pointing the SDK at an
HTTP `/api/v1/...` path). That is wrong and unsafe:

- It bypasses the single transport boundary (`aa-sdk-client`), which is the one place where
  transport selection, connection lifecycle, codec, identity, ret/timeout, and
  fail-closed behaviour are implemented and reviewed.
- It encourages **endpoint sprawl**: every SDK then hard-codes its own URL, auth, and
  error handling, and they drift (exactly the divergence ADR 0002 was written to prevent).
- The REST surface is shaped for human/operator consumers (dashboard, `aasm` data
  commands), not for the SDK fast-path, and it has no guarantee of carrying the
  same semantics as the gRPC `CheckAction`.

This ADR records the intended layering so the broken example cannot be mistaken for the
contract, and so future SDK work has a single rule to follow.

---

## Decision

**The user-facing SDK public API NEVER calls a core or REST endpoint directly.**

All SDK ↔ core communication goes through the single FFI-agnostic transport boundary,
`aa-sdk-client`. The layering is:

```
┌─────────────────────────────────────────────────────────────────────┐
│  SDK public API   (python-sdk / node-sdk / go-sdk)                    │
│  init_assembly(...) · @wrap / wrappers · hooks · event capture        │   UNTRUSTED
└───────────────────────────────┬─────────────────────────────────────┘
                                 │  thin pyo3 / napi / cgo shim
                                 │  (aa-ffi-{python,node,go})
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  aa-sdk-client       THE single transport boundary                    │
│  • picks transport   • codec   • connection lifecycle                 │   no security
│  • identity (did:key) on Register   • advisory preflight              │   authority
└───────────────┬──────────────────────────────────┬──────────────────┘
                │ gRPC                               │ UDS / IPC
                ▼                                    ▼
┌───────────────────────────────┐    ┌──────────────────────────────────┐
│  aa-gateway                    │    │  aa-runtime                       │
│  PolicyService.CheckAction     │    │  local pipeline (mandatory        │   TRUSTED
│  (allow/deny) · audit RPCs     │    │  chokepoint; scan/redact/policy)  │   ENFORCEMENT
│  · policy SoT                  │    │                                   │
└───────────────────────────────┘    └──────────────────────────────────┘

      ╳  SDK public API ──▶ REST /api/v1/...   (FORBIDDEN — never the SDK path)

┌─────────────────────────────────────────────────────────────────────┐
│  aa-api  REST  /api/v1/*   (dashboard · operators · aasm data cmds)   │
│  NON-SDK consumers only                                               │
└─────────────────────────────────────────────────────────────────────┘
```

Concretely:

| Rule | Detail |
| --- | --- |
| Single transport boundary | `aa-sdk-client` is the only component the SDK API talks to; the per-language bindings are thin shims over it (see ADR 0002). |
| Allowed transports | **gRPC** to `aa-gateway`, or **UDS / IPC** to `aa-runtime`. The choice lives inside `aa-sdk-client`, not in the SDK public API. |
| Policy check is gRPC | The authoritative pre-execution decision is `PolicyService.CheckAction` (gRPC). The SDK never reconstructs that call over HTTP. |
| REST is non-SDK only | A REST `/api/v1/policy/check`, **if it is ever added**, exists solely for non-SDK consumers (dashboard, operators, CLI data commands). It is never on the SDK path. |
| Identity on Register | Registration through `aa-sdk-client` carries the `did:key` identity requirement; an out-of-band REST call would not, which is another reason the SDK path must stay on the boundary. |

### Decision (Register transport)

`aa-sdk-client` owns a **direct gateway gRPC client for `AgentLifecycleService.Register`**.
On registration it derives a deterministic Ed25519 keypair from the agent identifier,
sends the `did:key` agent id plus the matching `public_key`, and **stores the returned
`credential_token`**. That token is then attached to every subsequent
`CheckActionRequest`, so the gateway's `validate_credential_token` does not deny a
registered agent.

`CheckAction` itself stays on the **UDS / IPC forward through `aa-runtime`** (the mandatory
chokepoint) — it is **not** sent directly to the gateway. This keeps the fast-path single
chokepoint intact while closing the gap that nothing on the SDK path called `Register`
(so no `credential_token` was ever issued or carried). Both transports still live inside
`aa-sdk-client`, behind one API. See [AAASM-3396](https://lightning-dust-mite.atlassian.net/browse/AAASM-3396),
[AAASM-3397](https://lightning-dust-mite.atlassian.net/browse/AAASM-3397),
[AAASM-3398](https://lightning-dust-mite.atlassian.net/browse/AAASM-3398).

---

## Rationale / Consequences

### Positive

- **One place to secure, version, and observe.** Auth, TLS, identity, codec, timeouts,
  retries, and fail-closed behaviour are implemented and reviewed once, in `aa-sdk-client`,
  instead of N times across SDKs.
- **Prevents drift like the broken "production mode".** The example that pointed an SDK at
  a REST URL cannot become the real path, because the SDK API has no endpoint-calling
  surface to begin with.
- **Aligns with the thin-FFI-shim design (ADR 0002).** `aa-ffi-*` → `aa-sdk-client` is
  already the established topology; this ADR makes the transport rule that topology implies
  explicit.
- **The core stays authoritative.** Decisions come from the gateway / runtime over their
  real RPC surface, not from SDK-side logic.

### Negative / accepted trade-offs

- **The SDK cannot "just curl" the core for a quick decision.** Any new SDK capability that
  needs the core must be added to `aa-sdk-client` (and, where applicable, to the gRPC
  surface), not bolted on as an HTTP call. This is deliberate friction.
- **A REST policy-check endpoint, if added for operators, must be clearly fenced** as
  non-SDK, or it will tempt exactly the bypass this ADR forbids.

### Related open work

- SDK client `check()` wiring — the pre-execution policy `check()` on the SDK fast-path is
  still being wired through `aa-sdk-client` to `CheckAction`
  ([AAASM-3021](https://lightning-dust-mite.atlassian.net/browse/AAASM-3021),
  [AAASM-3380](https://lightning-dust-mite.atlassian.net/browse/AAASM-3380)).
- The `did:key` identity requirement on Register is part of the same boundary work.

---

## Alternatives Considered

### SDK calls the REST endpoint directly (rejected)

This is what the broken example implied. Rejected: it bypasses the `aa-sdk-client` boundary,
so there is no single transport to secure/version/observe; it duplicates auth and error
handling per SDK; and it encourages endpoint sprawl and drift. The REST surface is also
shaped for operators, not for the SDK fast-path.

### SDK embeds the policy logic (rejected)

Letting the SDK evaluate policy locally would avoid a round-trip, but the SDK is untrusted
(ADR 0002) and the core must be authoritative. A bypassed or outdated SDK would then make
its own decisions. Rejected — the decision must come from the gateway/runtime.

### Multiple ad-hoc transports chosen by the SDK API (rejected)

Letting each SDK pick gRPC vs UDS vs REST at the public-API layer reproduces the divergence
problem. Transport selection belongs **inside** `aa-sdk-client`, behind one API, so the
choice is a single, reviewable implementation detail.

---

## Related

- Epic: [AAASM-3385](https://lightning-dust-mite.atlassian.net/browse/AAASM-3385) — ADR for the governance enforcement flow
- Story: [AAASM-3386](https://lightning-dust-mite.atlassian.net/browse/AAASM-3386) — this ADR
- Origin finding: [AAASM-3380](https://lightning-dust-mite.atlassian.net/browse/AAASM-3380) — examples README implied a direct SDK→REST call
- Related: [AAASM-3021](https://lightning-dust-mite.atlassian.net/browse/AAASM-3021) — SDK `check()` wiring
- Builds on: [ADR 0002](0002-sdk-security-boundary.md) — SDK security boundary & thin-FFI-shim topology
