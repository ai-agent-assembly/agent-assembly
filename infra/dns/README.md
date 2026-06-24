# DNS record set — `agent-assembly.com` (+ kept `agent-assembly.dev`)

> **OWNER-GATED — not auto-deployable.** This directory documents the exact DNS
> records the **owner** must create in Cloudflare. Nothing here is applied by CI or
> by this repo. The Terraform in [`cloudflare.tf`](cloudflare.tf) is the IaC
> source-of-truth, but it requires Cloudflare API credentials and a manual
> `terraform apply` that only the owner can run.

Implements the host surface decided in
[ADR 0007 — Public Domain & URL Contract](../../docs/src/adr/0007-public-domain-and-url-contract.md)
(Epic [AAASM-3651](https://lightning-dust-mite.atlassian.net/browse/AAASM-3651),
ticket [AAASM-3653](https://lightning-dust-mite.atlassian.net/browse/AAASM-3653)).

## Records to create in the `agent-assembly.com` zone

| Name (host) | Type | Value | Proxy | Notes |
| --- | --- | --- | --- | --- |
| `agent-assembly.com` (apex `@`) | CNAME (flattened) **or** A/AAAA | Marketing origin / Cloudflare Pages target | 🟠 Proxied | Cloudflare **CNAME flattening** lets the apex be a CNAME. Serves marketing **+** the `/install.sh` Worker route. |
| `www` | CNAME | `agent-assembly.com` | 🟠 Proxied | Canonicalized to apex by a Redirect Rule (see `infra/redirects/`). |
| `app` | CNAME | App/control-plane origin (future) | 🟠 Proxied | Login / workspace selector. Placeholder until the SaaS app exists. |
| `api` | CNAME | API origin (future) | 🟠 Proxied | Public SaaS API. Placeholder. |
| `docs` | CNAME | Docs host target (Epic AAASM-3659) | 🟠 Proxied | Canonical docs. Target owned by AAASM-3659. |
| `status` | CNAME | Hosted status-page provider target | ⚪ Grey-cloud (DNS-only) | Status pages are usually served by a third-party (e.g. statuspage/instatus) and must **not** be proxied so the provider terminates TLS. |
| `*` (tenant wildcard) | CNAME | Tenant app origin (future) | 🟠 Proxied | `<tenant>.agent-assembly.com` customer workspaces. Reserved-slug policy: `infra/tenant/`. Placeholder until the control plane exists. |

### Proxy / grey-cloud guidance

- **🟠 Proxied (orange-cloud):** routes through Cloudflare — required for the apex so
  the **install Worker route** (`agent-assembly.com/install.sh*`, AAASM-3654) can run,
  and for Always-HTTPS/HSTS/WAF on first-party hosts. Use for apex, `www`, `app`,
  `api`, `docs`, and `*`.
- **⚪ Grey-cloud (DNS-only):** bypasses Cloudflare's proxy. Use for `status` when a
  third-party status provider terminates TLS and serves the page directly. (If the
  provider supports proxied CNAMEs + custom-host TLS, proxied is fine — follow the
  provider's docs.)

### Wildcard caveat

A proxied wildcard (`*`) needs **Advanced Certificate Manager** (or a wildcard in the
edge cert SAN) to cover `*.agent-assembly.com` for TLS. Confirm the zone's cert plan
covers the wildcard before enabling tenant hosts. The wildcard must **not** shadow
the explicit `app`/`api`/`docs`/`status`/`www` records — explicit records win over
the wildcard, which is why the reserved-slug list (`infra/tenant/reserved-slugs.txt`)
also blocks those names at the application layer.

## Install route note

The apex record only needs to **exist and be proxied**; the actual `/install.sh`
handling is a **Cloudflare Worker route**, not a DNS record. See
[`infra/install-endpoint/`](../install-endpoint/) (AAASM-3654). DNS gets traffic to
Cloudflare's edge; the Worker route decides what `/install.sh` returns.

## The kept `agent-assembly.dev` zone

`agent-assembly.dev` **stays working** (ADR 0007). Its only required record is the
existing installer host:

| Name (host) | Type | Value | Proxy | Notes |
| --- | --- | --- | --- | --- |
| `tool` | (managed by Worker `custom_domain`) | — | 🟠 Proxied | `tool.agent-assembly.dev` is provisioned/managed by the install Worker's `custom_domain = true` route — Wrangler creates and manages this record on `wrangler deploy`. Do **not** hand-create it. |

## How to apply (owner)

See the ordered steps and verification checklist in
[`infra/RUNBOOK-domains.md`](../RUNBOOK-domains.md). In short:

1. Add the `agent-assembly.com` zone to Cloudflare; point the registrar at
   Cloudflare's nameservers.
2. Create the records above (UI, or `terraform apply` with `cloudflare.tf`).
3. Deploy the install Worker (`cd infra/install-endpoint && wrangler deploy`).
4. Enable Always-HTTPS + HSTS; attach `docs`/`app`/`api` origins as they come online.
