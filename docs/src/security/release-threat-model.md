# Release threat model

> **Threat-model version: 1**
> **Last full refresh: `v0.0.1-beta.3`** (the current pre-release tip; this doc
> is seeded against it)
> **Scope: the _release process_** — what a release can newly expose, and which
> layer is supposed to stop it.

This is the **versioned, operational** threat model that is reviewed on *every*
release and rewritten in full at *every major*. It is deliberately distinct from
the conceptual [threat model](threat-model.md) (the durable assets / adversaries
/ scenarios catalogue, which changes rarely): this page answers the narrower
question *"what does **this** release change about our exposure, and is each
change covered?"*

It is consumed by two operational artifacts:

- the [trust-boundary review checklist](trust-boundary-review-checklist.md) — the
  per-release delta form a reviewer fills in, and
- the `/security-review` SKILL — the release-gate review scaled by release type.

## Why a threat model needs a version

A threat model that is not versioned silently goes stale. What was modeled at
v1 stops describing what actually ships at v3 — a new endpoint, a loosened
policy default, a new egress path — and an attacker operates precisely in that
gap between *modeled* and *shipped*. Pinning a **version number** plus a
**per-major full refresh** makes staleness *visible and auditable*: if the
`Threat-model version` has not advanced across a major, that is itself a finding.

## The layered "assume previous layer breached" map

The release threat model inherits the defense-in-depth layer chain from
[Three-layer defense in depth](three-layer-defense.md) and
[Trust boundaries](trust-boundaries.md), and adds the explicit zero-trust
assumption for each layer: **every layer assumes the layer before it has already
been breached.** A release that changes a layer must answer "does the *next*
layer still hold if this one is bypassed?"

| # | Layer | Crate(s) | Assumes breached | What it must still guarantee |
|---|---|---|---|---|
| 1 | **SDK (in-process)** | `aa-sdk-client` + per-language shims | The agent process itself (the SDK is untrusted — [ADR 0002](../adr/0002-sdk-security-boundary.md)) | Nothing security-critical. Advisory preflight only; no wire trust marker is emitted or honored. |
| 2 | **Sidecar proxy** | `aa-proxy` | The SDK was removed, stubbed, or lied | Outbound HTTPS is still observed and egress-policed without any SDK cooperation. |
| 3 | **Runtime (mandatory chokepoint)** | `aa-runtime` | The SDK and proxy were both bypassed for inbound events | Every event is scanned, redacted, normalized **unconditionally** before forward/audit, on every path. |
| 4 | **Sandbox / execution isolation** | execution isolation around tool/agent runs | The runtime forwarded an action it should not have | A denied or out-of-policy action cannot escalate beyond its confined execution context. |
| 5 | **eBPF (kernel floor)** | `aa-ebpf`, `aa-ebpf-probes` | Every userspace layer above was bypassed | TLS `SSL_write`/`SSL_read` and exec/file syscalls are still observed from below anything the agent can reach (Linux). |
| 6 | **Storage / audit sink** | gateway audit-write sanitizer (`aa-gateway/src/sanitizer/`) + audit publisher (`aa-runtime/src/audit_publisher/`) | Some upstream layer let a tainted record through | The write-boundary sanitizer is the final backstop; no raw secret is persisted, and the audit trail stays tamper-evident. |

The invariant across the chain: **position — not code — confers authority.** A
release must never move an authoritative guarantee *up* the chain into a layer
that assumes itself breached (e.g. relocating the only credential scan back into
the SDK).

## What a release can change about exposure

Every release is reviewed for these delta classes (enumerated row-by-row in the
[trust-boundary review checklist](trust-boundary-review-checklist.md)):

- A **new endpoint** or RPC method (new attack surface to authn/authz).
- A **loosened policy default** (a default that now permits what it used to deny).
- A **new network egress path** (`aa-gateway/src/policy/network.rs`).
- A **new IPC / UDS surface** between SDK ↔ runtime ↔ gateway.
- A **changed sanitizer / redaction scope** (a field newly carried, or newly
  exempted from scanning).
- A **new dependency or advisory** (a transitive CVE shipping in the release).

## When this is refreshed

| Release type | Action on this doc |
|---|---|
| **patch** (e.g. `…beta.3` → `…beta.4` forward-roll) | **Delta touch.** Confirm no row of the layer map changed; bump "Last full refresh" only if it did; record the review in the release's sign-off artifact. |
| **minor** | **Delta touch + attack-surface review.** Re-examine every delta-class row above against the release diff; update affected layer-map rows. |
| **major** | **Full rewrite.** Re-derive the entire layer map from current crates, advance `Threat-model version`, and add a row to the revision table below. A major whose version field did not advance is itself a finding. |

## Revision table

One row per **full refresh** (each major). Delta touches are recorded in the
per-release [sign-off artifact](../../release/security-signoff/) instead, to keep
this table a clean major-version history.

| Threat-model version | Date | Release tag | Refresh type | Notes |
|---|---|---|---|---|
| 1 | 2026-06-23 | `v0.0.1-beta.3` | Initial | Seeded the versioned release threat model + the 6-layer "assume previous breached" map. |

## See also

- [Threat model](threat-model.md) — durable assets / adversaries / scenarios.
- [Trust boundaries](trust-boundaries.md) — where trust is placed and why.
- [Trust-boundary review checklist](trust-boundary-review-checklist.md) — the
  per-release delta form keyed to this layer map.
- [ADR 0002 — SDK Security Boundary](../adr/0002-sdk-security-boundary.md).
