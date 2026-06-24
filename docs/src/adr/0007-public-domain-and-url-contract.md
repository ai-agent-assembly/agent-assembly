# ADR 0007: Public Domain & URL Contract

**Status**: Proposed
**Date**: 2026-06
**Ticket**: [AAASM-3652](https://lightning-dust-mite.atlassian.net/browse/AAASM-3652) (Epic [AAASM-3651](https://lightning-dust-mite.atlassian.net/browse/AAASM-3651))

---

## Context

The product is moving from a developer-tooling footprint (a single install host on
`agent-assembly.dev`) to a SaaS service that needs a coherent, public, multi-host
domain surface: a marketing site, an app/login host, a public API host, a docs host,
a status page, and per-tenant customer workspaces. Today only one host is in service:

- **`tool.agent-assembly.dev`** — the Cloudflare Worker that serves the one-line CLI
  installer (`infra/install-endpoint/`, ADR-less, ticket AAASM-2339). It is a
  `custom_domain` route that serves `scripts/install-cli.sh` at the host root.

There is no published contract for which host serves what, no decision on which TLD
is primary, and no agreed location for the canonical installer URL. The SaaS control
plane itself is still a placeholder (the `agent-assembly-cloud` repo is not yet
built), so most of these hosts describe a **future** surface — but the URL contract
must be decided **now**, because it drives DNS, cookie scoping, redirects, the
installer route, and docs links that are being set up in this epic
([AAASM-3653](https://lightning-dust-mite.atlassian.net/browse/AAASM-3653) DNS,
[AAASM-3654](https://lightning-dust-mite.atlassian.net/browse/AAASM-3654) installer
route, [AAASM-3656](https://lightning-dust-mite.atlassian.net/browse/AAASM-3656)
host routing/cookies, [AAASM-3657](https://lightning-dust-mite.atlassian.net/browse/AAASM-3657)
redirects, [AAASM-3658](https://lightning-dust-mite.atlassian.net/browse/AAASM-3658)
ops runbook).

This ADR is a **design proposal for owner ratification**; it documents the URL
contract and the TLD decision. It does **not** authorize any deployment — every DNS
and deploy step is owner-gated (see ADR 0008 and `infra/RUNBOOK-domains.md`).

---

## Decisions already made by the owner

These framing decisions are inputs to this ADR, not open questions:

1. **`.com` is primary.** `agent-assembly.com` is the primary public domain for the
   SaaS service and marketing.
2. **`.dev` stays working.** The existing `tool.agent-assembly.dev` install host is
   **kept** and continues to serve the installer; it is not retired.
3. **The canonical installer is `https://agent-assembly.com/install.sh`** — apex host,
   `/install.sh` path. The `.dev` host remains a working alternate.

---

## The public URL surface

| Host | Purpose | Serves | Status |
| --- | --- | --- | --- |
| `agent-assembly.com` (apex) | Marketing site **+** the installer at `/install.sh` | Marketing pages; `/install.sh` → `scripts/install-cli.sh` via the install Worker route | Primary |
| `www.agent-assembly.com` | Canonical-redirect alias of the apex | 301 → `agent-assembly.com` (see AAASM-3657) | Primary |
| `app.agent-assembly.com` | Login / workspace selector | SaaS app shell (future control plane) | Future (placeholder) |
| `api.agent-assembly.com` | Public SaaS API | REST/gRPC public API (future control plane) | Future (placeholder) |
| `docs.agent-assembly.com` | Canonical documentation host | mdBook/doc sites — see Epic [AAASM-3659](https://lightning-dust-mite.atlassian.net/browse/AAASM-3659) | Future (placeholder) |
| `status.agent-assembly.com` | Status page | Hosted status provider | Future (placeholder) |
| `<tenant>.agent-assembly.com` | Per-customer workspace | Tenant-scoped app served via the `*` wildcard | Future (placeholder) |
| `tool.agent-assembly.dev` | Legacy installer host (kept) | `scripts/install-cli.sh` at the host root | Live (kept) |

### Installer URL contract

- **Canonical:** `curl -fsSL https://agent-assembly.com/install.sh | sh`
- **Alternate (kept working):** `curl -fsSL https://tool.agent-assembly.dev | sh`
- Both resolve to the **same script** (`scripts/install-cli.sh`), served by the same
  Cloudflare Worker (`infra/install-endpoint/`). The apex is wired as a **path route**
  (`agent-assembly.com/install.sh*`), not a `custom_domain`, because the apex also
  hosts the marketing site; the `.dev` host stays a `custom_domain` route. See
  AAASM-3654.

### How `docs.agent-assembly.com` (Epic AAASM-3659) fits

`docs.agent-assembly.com` is the **canonical documentation host** for the product. It
is owned and built by Epic AAASM-3659 (docs consolidation), not by this epic. This
ADR only reserves the host in the URL contract and the DNS set (AAASM-3653) so that:

- Marketing (`agent-assembly.com`) links to `docs.agent-assembly.com`.
- The existing per-repo GitHub Pages docs (`ai-agent-assembly.github.io/<repo>/`)
  are redirected to the canonical docs host as part of AAASM-3657 / AAASM-3665.

The content, doc-site tooling, and version-channel model under
`docs.agent-assembly.com` remain AAASM-3659's responsibility.

---

## Options Considered

### TLD primacy

- **Option A — `.com` primary, `.dev` kept (chosen by owner).** `agent-assembly.com`
  is the canonical public face; `tool.agent-assembly.dev` keeps working as an
  installer alternate. Pro: `.com` is the expected commercial TLD; existing `.dev`
  links and any HSTS-preload benefit of `.dev` are not broken. Con: two TLDs to
  hold and renew.
- **Option B — `.dev` only.** Reject: `.dev` reads as a tooling/preview domain, not a
  commercial SaaS, and the owner has chosen `.com` as primary.
- **Option C — `.com` only, retire `.dev`.** Reject: breaks the existing installer
  one-liner that users and docs already reference; the owner explicitly chose to keep
  `.dev` working.

### Installer location on the apex

- **Path route `agent-assembly.com/install.sh` (chosen).** The apex is shared with a
  marketing site, so the installer must be a **single-path route**, leaving every
  other apex path to the marketing origin. Pro: clean, memorable URL; no separate
  host. Con: the Worker must pass through / 404 non-installer apex paths so it never
  shadows marketing.
- **Dedicated host `install.agent-assembly.com`.** Reject: the owner chose the apex
  `/install.sh`; a dedicated host would be a second thing to remember and would not
  match the decided contract.

---

## Decision

Adopt the URL surface in the table above with **`.com` primary, `.dev` kept**, the
**canonical installer at `agent-assembly.com/install.sh`** (apex path route) with
**`tool.agent-assembly.dev` retained** as a working alternate, and
**`docs.agent-assembly.com`** reserved here but owned by Epic AAASM-3659.

This decision is **Proposed** — it is the contract the rest of this epic builds
against, pending owner ratification. No host is provisioned by adopting it; DNS and
deploys are owner-gated (AAASM-3653, AAASM-3654, AAASM-3658).

---

## Consequences

### What this enables

- A single, documented URL contract that DNS (AAASM-3653), the installer route
  (AAASM-3654), host routing/cookies (ADR 0008 / AAASM-3656), redirects
  (AAASM-3657), and the ops runbook (AAASM-3658) all reference, instead of each
  inventing its own host list.
- The installer one-liner becomes `https://agent-assembly.com/install.sh` while every
  existing `tool.agent-assembly.dev` reference keeps working.

### What this blocks / defers

- The `app.`, `api.`, `status.`, and `<tenant>.` hosts describe a **future** SaaS
  control plane that does not exist yet. Reserving them in DNS and the contract does
  **not** build them.
- Tenant data isolation, auth, and cookie boundaries are **not** decided here — see
  [ADR 0008](0008-saas-host-routing-auth-cookie-boundaries.md).
- Canonical docs content/tooling on `docs.agent-assembly.com` is **not** in scope —
  see Epic AAASM-3659.

### Owner-gated follow-through

- Holding/renewing the `agent-assembly.com` zone and keeping `agent-assembly.dev`.
- Creating the DNS records (AAASM-3653) and deploying the installer route
  (AAASM-3654) — neither is auto-deployable from this repo.

---

## Related

- Epic: [AAASM-3651](https://lightning-dust-mite.atlassian.net/browse/AAASM-3651) — SaaS service domain, DNS, and tenant-hosting operations
- DNS set: [AAASM-3653](https://lightning-dust-mite.atlassian.net/browse/AAASM-3653) — `infra/dns/`
- Installer route: [AAASM-3654](https://lightning-dust-mite.atlassian.net/browse/AAASM-3654) — `infra/install-endpoint/`
- Tenant slugs: [AAASM-3655](https://lightning-dust-mite.atlassian.net/browse/AAASM-3655) — `infra/tenant/`
- Host routing / cookies: [ADR 0008](0008-saas-host-routing-auth-cookie-boundaries.md) ([AAASM-3656](https://lightning-dust-mite.atlassian.net/browse/AAASM-3656))
- Redirects: [AAASM-3657](https://lightning-dust-mite.atlassian.net/browse/AAASM-3657) — `infra/redirects/`
- Ops runbook: [AAASM-3658](https://lightning-dust-mite.atlassian.net/browse/AAASM-3658) — `infra/RUNBOOK-domains.md`
- Canonical docs host: Epic [AAASM-3659](https://lightning-dust-mite.atlassian.net/browse/AAASM-3659)
- Install endpoint origin: AAASM-2339 — `infra/install-endpoint/`
