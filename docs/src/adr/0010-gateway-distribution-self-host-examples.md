# ADR 0010: Gateway Distribution for Self-Host & Examples

**Status**: Proposed
**Date**: 2026-06
**Ticket**: [AAASM-3809](https://lightning-dust-mite.atlassian.net/browse/AAASM-3809)

---

## Context

The 2026-06-26 QA round ([AAASM-3791](https://lightning-dust-mite.atlassian.net/browse/AAASM-3791),
`agent-assembly-examples` PR #166) surfaced a **distribution gap** in this repo: the
`live-core-enforcement` example scenario — meant to demonstrate the product's headline
**per-tool allow/deny** governance (`read_file` allowed, `delete_file` denied) against a
real, locally-running core — cannot run out of the box. Two coupled gaps cause this.

### Gap 1 — there is no published gateway image

> **Update (2026-07, [AAASM-4480](https://lightning-dust-mite.atlassian.net/browse/AAASM-4480)):**
> this gap is now **closed** — the `publish-gateway` job in `docker.yml` publishes
> `ghcr.io/ai-agent-assembly/aa-gateway` (version tag + `:latest`) on release tags, exactly the
> Option A distribution this ADR adopts. The description below records the state at the time of
> writing (2026-06) that motivated the decision.

At the time of writing, the org published only `aa-runtime`, `go`, `python`, and `node`
images to GHCR; **`ghcr.io/ai-agent-assembly/aa-gateway` was not yet published.** The
[examples](https://lightning-dust-mite.atlassian.net/browse/AAASM-3791) scenario — and
any limited-function OSS self-host of the gateway over Docker — therefore had no gateway
image to pull. PR #166 had to *build* `aa-gateway` from the monorepo just to verify agent
registration. Verified on macOS+Docker: only `:8080` was open on the runtime image, there
was no `aa-gateway` image in GHCR, and `docker inspect` showed the runtime image is
distroless.

This is in tension with the existing, **accepted** policy decision in
[ADR 0006](0006-limited-self-host-k8s-terraform.md): its limited-function self-host
component table already lists **`aa-gateway` (policy engine, registry) → "Yes (limited)"**
as part of the single-node OSS tier. ADR 0006 assumed the gateway would be runnable in the
limited tier; this ADR resolves *how* it is distributed so that assumption holds.

### Gap 2 — the runtime's local policy is action-type-based, not per-tool

Even with a master-built gateway, the demo still cannot show the per-tool verdict. With a
locally-running core, the SDK's `check_tool_start` resolves locally against an
**action-type-based** local policy (which returns *allow*) rather than producing a gateway
`CheckAction`. So a **per-tool** `read_file`-allow / `delete_file`-deny decision is never
exercised against the gateway's policy engine. This is the policy-resolution coupling: the
demo's whole point is a per-tool verdict, but the live path it hits resolves by action
type. (Background on the SDK → `aa-sdk-client` → core enforcement path is
[ADR 0004](0004-governance-enforcement-flow.md).)

### Constraint noted on AAASM-3544 — publishing alone is insufficient

The [AAASM-3544](https://lightning-dust-mite.atlassian.net/browse/AAASM-3544) reviewer
noted that **publishing an image is necessary but not sufficient**: a usable cross-platform
self-host/example story also needs **Windows-aware native-runtime packaging and paths**
(the win32 dependency). A published Linux gateway image makes the Compose example work; it
does not by itself make a native Windows developer experience work. This ADR must address
that dependency rather than silently assume Linux-only.

### Policy constraints that bound the decision

Per **project policy (revised 2026-06-21)**, restated in
[ADR 0006](0006-limited-self-host-k8s-terraform.md):

1. **Limited-function self-hosting via open source IS acceptable** — sample infra configs,
   a **Docker Compose** example, and the docs that describe it, for a *limited-function*
   local stack.
2. **Complete/full functionality remains SaaS-only** — managed control plane, hosted
   persistence/retention, compliance evidence, and cross-team budget governance at scale.
3. **Production orchestration (Helm / Terraform / Kubernetes) is NOT committed build work**
   — it is a research-spike/ADR question only, never proposed as ready-to-build tickets.

Any decision here must (a) keep the gateway *runnable* in the limited OSS tier that ADR
0006 already promises, while (b) not leaking full/SaaS-grade functionality into the OSS
artifact, and (c) not committing production orchestration work.

---

## Options Considered

### Option A — Publish a limited-function OSS `aa-gateway` image to GHCR

Add `aa-gateway` to the governed image build/versioning pipeline (the immutable
product-version tag axis + reproducible pinning model from
[ADR 0009](0009-versioned-base-image-tags-and-sdk-pinning.md)) and the release fan-out,
then point the example's Compose at a **pinned** tag. The image ships the *limited-function*
gateway only: single instance, local policy engine + registry, SQLite/single-PostgreSQL
persistence ([ADR 0001](0001-storage-architecture.md) / ADR 0006), no managed retention,
compliance evidence, multi-tenant budgets, or scale-out fan-out.

- **Pro:** Directly delivers what ADR 0006 already promises ("`aa-gateway` … Yes (limited)")
  — the limited self-host tier and the example can pull a real, version-matched gateway
  instead of building from source.
- **Pro:** Reproducible/pinnable for free by reusing ADR 0009's tag + pin model; one more
  image in an established pipeline rather than a new mechanism.
- **Pro:** Makes the `live-core-enforcement` example a true out-of-the-box demo once the
  policy path (below) is also addressed.
- **Con / risk:** A published gateway image invites the assumption that it is the *full*
  gateway. Must be **clearly labelled limited-function** and the feature boundary enforced
  in the build, or it blurs the OSS↔SaaS line that policy 2 protects.
- **Con / risk:** New surface to keep version-matched in the release fan-out (cross-repo
  ordering, like ADR 0009's SDK pins).
- **Con:** On its own it does **not** resolve Gap 2 (per-tool policy) or the AAASM-3544
  win32 packaging dependency — both remain follow-ups.
- **Effort:** Medium — wire one crate's image into `docker.yml`, the version/pin manifest,
  and the release fan-out; mostly reuse of ADR 0009 plumbing.

### Option B — Keep the gateway SaaS-only; reframe the example/docs as SaaS-gateway

Do **not** publish a gateway image. Re-document the `live-core-enforcement` example to be
explicit that the **live gateway is SaaS**: the example demonstrates *wiring* (SDK →
runtime → gateway endpoint) and how to point at a SaaS gateway, not a bundled local
gateway. The OSS Compose example would stop short of a self-hosted policy verdict.

- **Pro:** Zero new OSS distribution surface; maximally protects the OSS↔SaaS boundary —
  full functionality, including any gateway, stays SaaS.
- **Pro:** Lowest immediate effort (docs/reframe only).
- **Con:** **Contradicts ADR 0006**, which already accepted that `aa-gateway` is part of
  the limited-function self-host tier. Choosing B would *supersede* that line of ADR 0006
  and shrink the promised OSS tier.
- **Con:** The example loses its headline: it can no longer show a real per-tool verdict
  locally; it becomes a wiring diagram, not a working governance demo.
- **Con:** Pushes self-hosters toward building the gateway from source anyway (which they
  can, since the code is open), so the boundary is rhetorical, not technical.
- **Effort:** Low (docs only) — but reopens a settled policy decision.

### Option C — Hybrid: ship a clearly-labelled limited-function / demo gateway image used only by examples

Publish a gateway image but **scope and label it as a demo/example artifact** (e.g. an
`aa-gateway` image carrying an explicit "limited-function / example use" label and a
fixed-demo policy bundle), referenced only by the examples Compose, and *not* positioned as
a general self-host building block. Functionally similar to A but with a narrower,
example-first contract and stronger labelling.

- **Pro:** Unblocks the example out-of-the-box while keeping the strongest possible "this is
  not the full product" signal.
- **Pro:** Could ship a **demo per-tool policy bundle** inside the image, which partially
  addresses Gap 2 for the example specifically (the demo carries a per-tool policy the
  gateway evaluates).
- **Con:** Risks a confusing two-tier story — a "demo" gateway image *and* (eventually) a
  "self-host" gateway image — versus Option A's single limited-function image that serves
  both. Contradicts ADR 0006's framing that the limited tier *is* the self-host tier.
- **Con:** A demo-only image that diverges from the real limited-function gateway can rot /
  drift from the product it is meant to demonstrate.
- **Effort:** Medium — similar to A, plus extra labelling/policy-bundle scoping; arguably
  more long-term maintenance than A for less generality.

### The coupled questions (apply across options)

- **Per-tool vs action-type policy resolution (Gap 2).** Independent of which image option
  is chosen, the live runtime must be able to produce a gateway `CheckAction` so a per-tool
  verdict (`read_file` allow / `delete_file` deny) is actually exercised. Today the local
  path resolves by action type and short-circuits to *allow*. This is a **core behaviour
  question** that needs its own confirmation/clarification (and likely a follow-up
  implementation ticket) regardless of distribution — see Consequences.
- **Win32 native packaging (AAASM-3544).** A published Linux image makes Compose work but
  does not deliver a native Windows developer path. The Windows-aware native-runtime
  packaging/paths dependency must be tracked as a separate follow-up; it is **out of scope
  for this distribution decision** but must not be forgotten.

---

## Decision

**Adopt Option A — publish a clearly-labelled, limited-function OSS `aa-gateway` image to
GHCR, wired into the governed image build/versioning ([ADR 0009](0009-versioned-base-image-tags-and-sdk-pinning.md))
and the release fan-out, with the example's Compose pinned to a version-matched tag.**

The per-tool policy path (Gap 2) and the win32 native packaging dependency (AAASM-3544) are
**acknowledged as coupled follow-ups** and are recorded below, not resolved by this ADR.

Rationale, grounded in policy:

1. **It honours an already-accepted decision.** ADR 0006 (Accepted) lists `aa-gateway` as
   "Yes (limited)" in the limited-function self-host tier. Option A simply *delivers* the
   distribution that decision presupposes; Options B and C would, in effect, **supersede**
   ADR 0006 and shrink the promised OSS tier — a bigger policy move that should not be made
   implicitly to fix a QA gap.
2. **It is squarely inside the revised self-host policy.** Policy 1 explicitly blesses a
   Docker Compose example + sample infra for a *limited-function* local stack. A
   limited-function gateway image is exactly that artifact. Policy 2 is preserved by
   **scoping and labelling the image as limited-function** and keeping full functionality
   (managed retention, compliance evidence, multi-tenant/scale-out budgets) out of the OSS
   image. Policy 3 is untouched: no Helm/Terraform/K8s work is implied — Compose only.
3. **It reuses an established mechanism.** ADR 0009 already defines immutable
   product-version tags + reproducible pinning for governed images; adding `aa-gateway`
   rides that pipeline rather than inventing a parallel one. This is why Option A is
   preferred over Option C: a single limited-function image serves both self-host and the
   example, avoiding a confusing demo-image/self-host-image split that would also drift
   from the real product.
4. **Option B is rejected** because it technically resolves nothing (the code is open;
   self-hosters build the gateway anyway), guts the example's headline, and quietly reverses
   ADR 0006. If the owner *wants* to reverse ADR 0006 and make the gateway SaaS-only, that
   should be a deliberate superseding ADR — not a side effect of an examples fix.

> **This ADR is `Proposed` and tees up the choice for ratification.** It does **not**
> build or publish any image, and it changes no CI or release workflow. Those are the
> follow-up implementation tickets below, gated on ratification.

---

## Consequences

### What this enables

- The limited-function self-host tier (ADR 0006) and the `live-core-enforcement` example
  (AAASM-3791) can pull a real, version-matched `aa-gateway` image instead of building from
  source — the example becomes an out-of-the-box demo once Gap 2 is also closed.
- Reproducible, pinnable gateway images for self-hosters via the ADR 0009 tag/pin model.

### What this blocks / defers (follow-up work, gated on ratification)

1. **Implementation ticket — publish `aa-gateway` image.** ✅ **Done
   ([AAASM-4480](https://lightning-dust-mite.atlassian.net/browse/AAASM-4480)):** the
   `publish-gateway` job in `docker.yml` now builds and pushes
   `ghcr.io/ai-agent-assembly/aa-gateway` (version tag + `:latest`) on release tags, labelled
   **limited-function**. Remaining wiring — the version/pin manifest, compatibility matrix, and
   pointing the examples Compose at the pinned tag — follows the ADR 0009 model.
2. **Core follow-up — per-tool policy resolution (Gap 2).** Confirm/clarify and, if needed,
   implement the path so the live runtime emits a gateway `CheckAction` for tool checks, so
   the demo's `read_file` allow / `delete_file` deny is actually evaluated by the gateway
   policy engine rather than short-circuited by the action-type local policy. This is a
   **core behaviour** question (relates to ADR 0004) and must be tracked as its own ticket;
   publishing the image without it leaves the headline demo incomplete.
3. **Cross-platform follow-up — win32 native packaging (AAASM-3544).** Track Windows-aware
   native-runtime packaging/paths separately. A Linux gateway image unblocks Compose but
   not a native Windows developer path; this dependency must remain visible.

### Boundary the decision must hold

- The OSS gateway image must stay **limited-function and clearly labelled**. Full
  functionality (managed retention, compliance evidence, multi-tenant/scale-out budgets)
  stays SaaS-only (policy 2). The build must enforce, not merely document, that boundary.
- No Helm/Terraform/Kubernetes is implied or committed (policy 3); the only delivery vehicle
  for the limited tier remains Docker Compose (ADR 0006).

### What would change this decision

- If the owner decides the gateway should be **SaaS-only** after all, supersede this ADR
  *and* the relevant line of ADR 0006 with a deliberate decision (Option B), and reframe
  the example as SaaS-gateway-wiring.

---

## Related

- Ticket: [AAASM-3809](https://lightning-dust-mite.atlassian.net/browse/AAASM-3809) — this distribution spike / ADR
- Origin: [AAASM-3791](https://lightning-dust-mite.atlassian.net/browse/AAASM-3791) — `live-core-enforcement` example E2E fix (PR `agent-assembly-examples`#166)
- Coupled constraint: [AAASM-3544](https://lightning-dust-mite.atlassian.net/browse/AAASM-3544) — Windows-aware native-runtime packaging/paths
- Builds on: [ADR 0009](0009-versioned-base-image-tags-and-sdk-pinning.md) — governed image versioning / reproducible pinning ([AAASM-3765](https://lightning-dust-mite.atlassian.net/browse/AAASM-3765))
- Builds on: [ADR 0006](0006-limited-self-host-k8s-terraform.md) — limited-function self-host tier (lists `aa-gateway` as in-tier) + revised self-host policy
- Relates to: [ADR 0004](0004-governance-enforcement-flow.md) — governance enforcement flow (per-tool `CheckAction` path)
- Relates to: [ADR 0001](0001-storage-architecture.md) — storage modes for the limited tier
