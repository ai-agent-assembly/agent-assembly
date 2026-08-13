# ADR 0006: Limited-Function Self-Host — Kubernetes (Helm) / Terraform Support

**Status**: Accepted
**Date**: 2026-06
**Ticket**: [AAASM-3521](https://lightning-dust-mite.atlassian.net/browse/AAASM-3521)

---

## Context

Until 2026-06-21 the project policy was *"self-hosted deployment is out of scope
product-wide"*. On **2026-06-21 the owner revised that policy**:

- **Limited-function self-hosting via open source is now acceptable.** Users may
  stand up a *limited-function* stack locally from open-source artifacts — sample
  infra configs, a **Docker Compose** example, and the docs that describe it.
- **Full functionality remains SaaS-only.** The complete feature set (managed
  control plane, hosted persistence/retention, compliance evidence, cross-team
  budget governance at scale) is delivered exclusively via the SaaS service.
- **Production orchestration (Helm / Terraform / Kubernetes) is *not* committed
  build work.** It must be decided via an ADR before any implementation is
  scheduled. This ADR is that decision.

The concrete question: now that a limited-function OSS self-host tier exists, should
that tier **also** ship a **Helm chart** and/or **Terraform modules**, or is the
Docker Compose example ([AAASM-3519](https://lightning-dust-mite.atlassian.net/browse/AAASM-3519))
sufficient for it?

### What the limited-function self-host tier is today

The limited-function stack is the small, locally-runnable subset of the system that
an open-source user can operate without the SaaS control plane. It mirrors the infra
design captured in the dataflow diagram
([AAASM-3517](https://lightning-dust-mite.atlassian.net/browse/AAASM-3517)) and is
delivered as a Docker Compose example
([AAASM-3519](https://lightning-dust-mite.atlassian.net/browse/AAASM-3519)):

| Component | In limited-function self-host? | Notes |
| --- | --- | --- |
| `aa-runtime` (enforcement chokepoint) | Yes | Already in `examples/docker-compose`. |
| `aa-gateway` (policy engine, registry) | Yes (limited) | Single instance; no HA/load-balanced fan-out. |
| `aa-api` + `dashboard` | Yes | Operator UI for the local stack. |
| Persistence | Yes — **SQLite / single PostgreSQL** | Per [ADR 0001](0001-storage-architecture.md): SQLite local, PostgreSQL+TimescaleDB for "production". A self-hoster gets a single node, not a managed durable tier. |
| Sample agent / SDK shim | Yes (placeholder) | The `agent-stub` swap-in slot. |
| Managed retention, compliance evidence, multi-tenant budgets, scale-out gateway | **No — SaaS-only** | These are the "full functionality" reserved for SaaS. |

The defining property of this tier is **single-node, single-tenant, low-ops**. It is
a local/dev-shaped deployment, not a multi-instance production cluster. That framing
matters for the K8s/Terraform question, because Helm and Terraform exist to manage
exactly the multi-instance, multi-environment production topology this tier
deliberately does **not** target.

---

## Options Considered

### Option A — Build Helm chart + Terraform modules now

Ship, alongside the Compose example, a Helm chart (gateway / api / dashboard /
runtime / persistence as Deployments + Services + a values schema) and Terraform
modules (e.g. a module that provisions a managed Postgres and applies the chart).

- **Pro:** A K8s-native user could `helm install` the limited-function stack; an
  IaC shop gets a declarative module.
- **Con:** Large, *ongoing* surface to build and maintain — chart templating,
  values schema, upgrade/migration paths, RBAC/NetworkPolicy/PodSecurity, secrets,
  ingress/TLS, HPA, and a Terraform provider/module lifecycle — for a tier that is
  single-node by design.
- **Con (security boundary):** A Helm/Terraform deployment invites *production*
  expectations (HA, network policy, secret management, multi-tenant isolation) that
  the limited-function tier explicitly does **not** provide. We would either have to
  meet those expectations (which is the SaaS scope) or ship a chart that looks
  production-ready but is not — a support and security-boundary liability.
- **Con:** No evidence of concrete demand yet; this is speculative.

### Option B — Defer: Docker Compose only for the limited-function tier, revisit on demand

Keep the limited-function self-host tier on **Docker Compose** (AAASM-3519) plus the
infra diagram (AAASM-3517). Do **not** ship Helm or Terraform now. Record explicit
triggers that would reopen this decision (see Consequences).

- **Pro:** Compose already satisfies the stated need — a user can stand up the
  single-node limited-function stack with `docker compose up`. The tier is
  single-node/single-tenant, which is precisely Compose's sweet spot.
- **Pro:** Zero added maintenance, support, and security-boundary burden; the team
  stays focused on the SaaS path that carries full functionality.
- **Pro:** Reversible — deferring forecloses nothing; a chart/module can be added
  later if demand appears, and it would be *better* informed by that demand.
- **Con:** A user who only operates Kubernetes must wrap the images themselves (they
  can, using the published container images, but we provide no first-class manifest).

### Option C — Decline Kubernetes / Terraform entirely

State as policy that the project will never ship Helm/Terraform for self-host;
production-grade orchestration is SaaS-only, full stop.

- **Pro:** Maximally clear boundary; no future ambiguity.
- **Con:** Over-commits. It pre-decides a question we have no demand signal for yet
  and throws away optionality. If a real, recurring K8s self-host demand emerges for
  the limited-function tier, a permanent "never" would be the wrong answer and would
  have to be re-litigated anyway.

---

## Decision

**Adopt Option B — defer Helm/Terraform; the limited-function self-host tier ships
on Docker Compose only for now, and this decision is revisited on concrete demand.**

Rationale:

1. **Compose satisfies the stated need.** The limited-function tier is single-node,
   single-tenant, low-ops by design (ADR 0001's local/single-Postgres shape). Docker
   Compose ([AAASM-3519](https://lightning-dust-mite.atlassian.net/browse/AAASM-3519))
   stands that up directly; Helm/Terraform add nothing the tier's scope requires.
2. **Helm/Terraform cost is disproportionate to current demand.** They carry an
   *ongoing* maintenance, support, and upgrade-path burden, and they pull in
   production concerns (HA, RBAC/NetworkPolicy, secret management, multi-tenant
   isolation) that belong to **full functionality — which is SaaS-only**. Shipping
   them for a deliberately limited tier either under-delivers (a non-production chart
   that looks production-ready) or scope-creeps into SaaS territory.
3. **No demand signal yet.** This question arose from a QA-review spike, not from
   user requests. Building speculatively here trades real SaaS focus for
   hypothetical self-host ergonomics.
4. **Deferring keeps optionality; declining throws it away.** Option C over-commits.
   Option B forecloses nothing: the published container images already let an
   advanced user run the stack on their own K8s, and a first-class chart/module can
   be added later — better-informed by actual demand.

This decision does **not** weaken the boundary that **full functionality is
SaaS-only**. It only declines to invest in *additional* orchestration packaging for
the limited-function tier at this time.

---

## Consequences

### What this enables

- The team ships the limited-function self-host tier now via Compose (AAASM-3519)
  and the infra diagram (AAASM-3517) without taking on Helm/Terraform scope.
- The SaaS path — where full functionality and production-grade operations live —
  remains the focus.
- Advanced users are not blocked: the published container images
  (`ghcr.io/ai-agent-assembly/*`) can be deployed on their own Kubernetes by hand;
  we simply do not provide or support a first-class chart/module.

### What this blocks / defers

- No Helm chart, no Terraform modules, and no support commitment for K8s self-host
  of the limited-function tier are delivered. A follow-up **implementation epic,
  gated on this ADR**, would be opened only if a trigger below fires.
- We do not promise production-grade self-host operability (HA, declarative
  upgrades, RBAC/NetworkPolicy hardening). Those remain SaaS scope.

### What would trigger revisiting this decision

Reopen and supersede this ADR (build a follow-up implementation epic) when **any** of:

- **Concrete, recurring demand** — multiple users/customers ask to run the
  limited-function tier on Kubernetes via a supported chart, or it becomes a
  recurring sales/adoption blocker.
- **Compose proves insufficient** for the limited-function tier's stated scope
  (e.g. the example can't express a needed single-node topology) — though that would
  more likely be fixed within Compose first.
- **A SaaS/enterprise need pulls a chart in anyway** — if the SaaS/enterprise
  control plane itself is delivered via Helm/Terraform, a limited-function chart
  could be a low-marginal-cost byproduct and the cost/benefit flips.

If revisited, the follow-up epic must re-evaluate the security boundary explicitly:
a supported chart must either stay clearly limited-function (and say so) or move into
SaaS-grade scope — it must not blur the two.

---

## Related

- Ticket: [AAASM-3521](https://lightning-dust-mite.atlassian.net/browse/AAASM-3521) — this spike / ADR
- Pairs with: [AAASM-3519](https://lightning-dust-mite.atlassian.net/browse/AAASM-3519) — limited-function self-host **Docker Compose** example + docs
- Pairs with: [AAASM-3517](https://lightning-dust-mite.atlassian.net/browse/AAASM-3517) — end-to-end infra design + dataflow diagram
- Builds on: [ADR 0001](0001-storage-architecture.md) — storage modes (SQLite local / PostgreSQL production / SaaS)
- Origin: Epic [AAASM-3198](https://lightning-dust-mite.atlassian.net/browse/AAASM-3198) — QA review
