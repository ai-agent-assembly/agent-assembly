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

## Google Workspace mail — `agent-assembly.com` (AAASM-5517)

> **⚠️ DISABLED SCAFFOLD — PREPARATION ONLY.** The Workspace mail records live in
> [`workspace_mail.tf`](workspace_mail.tf) and are **disabled by default**
> (`enable_workspace_mail = false`). With the default, `terraform plan` proposes
> **zero** mail records. Every value is an **obvious non-functional placeholder**
> (`REPLACE_WITH_TENANT_ISSUED_VALUE`) — **no real tenant value exists yet**.
>
> These records stay disabled and carry placeholder values **until a real Google
> Workspace tenant is purchased/attached (POST_PURCHASE)**. Enabling and applying
> them with real tenant-issued values is a **PRODUCTION_CHANGE gate** — it changes
> live mail delivery for the domain and must be coordinated with the cutover Story
> ([AAASM-5523](https://lightning-dust-mite.atlassian.net/browse/AAASM-5523)).

### Source-of-truth ownership

| Record group | Host(s) | Owned by | File |
| --- | --- | --- | --- |
| Workspace **human** mail: verification TXT, MX, apex SPF, DKIM, DMARC | apex `@`, `_dmarc`, `<selector>._domainkey` | AAASM-5517 | [`workspace_mail.tf`](workspace_mail.tf) |
| **Transactional** sender domain | `mail.agent-assembly.com` | AAASM-5521 | (separate; not in this repo dir yet) |
| Web / SaaS host surface | `@` (CNAME), `www`, `app`, `api`, `docs`, `status`, `*` | AAASM-3653 | [`cloudflare.tf`](cloudflare.tf) |

Human mail and transactional mail are deliberately separated: the transactional
provider lives under the `mail.` label with its own SPF/DKIM subtree, so it does
not collide with the apex policy managed here. **Exactly one SPF TXT** may exist at
the apex — add new legitimate senders by extending `workspace_spf_includes`, never
by publishing a second apex SPF record.

### Apply prerequisites (owner-run only)

Applying the Workspace mail records requires **all** of the following; do **not**
apply until each is satisfied:

1. A real Google Workspace tenant is attached to `agent-assembly.com`.
2. The tenant-issued values are collected from the Admin Console: site-verification
   TXT, MX set (with Google-assigned priorities), DKIM selector + public key, and an
   approved DMARC aggregate-report (`rua`) mailbox (never a private recovery address).
3. `enable_workspace_mail = true` is set, with every typed variable populated (the
   `null_resource.workspace_mail_guard` preconditions reject an incomplete enable).
4. A redacted `terraform plan` has been reviewed and shows **only** the intended
   mail records — **no** destructive change to the proxied web/SaaS/Worker records.
5. Cloudflare API token scoped to `Zone:DNS:Edit` is exported at runtime
   (`CLOUDFLARE_API_TOKEN`); it is **never** committed or attached to Jira.

```bash
# owner, after collecting tenant-issued values into a *.tfvars kept out of git:
export CLOUDFLARE_API_TOKEN=...
terraform plan  -var "zone_id=<agent-assembly.com zone id>" \
                -var "marketing_origin=<apex origin>" \
                -var "enable_workspace_mail=true" \
                -var-file=workspace-mail.auto.tfvars   # tenant-issued, git-ignored
terraform apply -var ...                                # PRODUCTION_CHANGE
```

### Verification commands (after apply)

```bash
dig +short TXT agent-assembly.com                 # site-verification + single SPF
dig +short MX  agent-assembly.com                 # Google MX set
dig +short TXT <selector>._domainkey.agent-assembly.com   # DKIM public key
dig +short TXT _dmarc.agent-assembly.com          # DMARC (expect p=none initially)
```

Then confirm domain verification and DKIM authentication succeed in the Google
Workspace Admin Console.

### Rollback

- **Before apply:** capture the pre-change MX/TXT set and the current Cloudflare
  Email Routing state (`dig` output + a dashboard screenshot kept outside git).
- **To roll back:** set `enable_workspace_mail = false` and `terraform apply`, which
  removes the Workspace records and restores the prior state. Do **not** delete the
  prior mail path (Cloudflare Email Routing) until the cutover Story
  ([AAASM-5523](https://lightning-dust-mite.atlassian.net/browse/AAASM-5523))
  confirms replacement delivery.
- If old routing and Workspace MX cannot coexist safely during cutover, follow the
  exact staged commands in the cutover Story rather than improvising in the dashboard.

### DKIM rotation

DKIM keys are **not secrets** but are tenant-owned. To rotate: generate a new key in
the Admin Console, update `workspace_dkim_selector` / `workspace_dkim_public_key`,
`terraform apply`, verify the new selector resolves and authenticates, then retire
the old selector in Admin Console. Keep the old selector record until the new one is
confirmed authenticating to avoid a signing gap.

### DMARC hardening trigger

DMARC starts at `p=none` (observation). **Do not** ship a stricter initial policy.
Move to `p=quarantine`, then `p=reject`, only **after** aggregate reports confirm all
legitimate senders (Workspace, transactional provider, any others) are aligned and
passing for a sustained observation window, and with owner approval. Update the
`content` of `cloudflare_record.workspace_dmarc` and re-apply at each step.

## How to apply (owner)

See the ordered steps and verification checklist in
[`infra/RUNBOOK-domains.md`](../RUNBOOK-domains.md). In short:

1. Add the `agent-assembly.com` zone to Cloudflare; point the registrar at
   Cloudflare's nameservers.
2. Create the records above (UI, or `terraform apply` with `cloudflare.tf`).
3. Deploy the install Worker (`cd infra/install-endpoint && wrangler deploy`).
4. Enable Always-HTTPS + HSTS; attach `docs`/`app`/`api` origins as they come online.
5. **Workspace mail (POST_PURCHASE / PRODUCTION_CHANGE):** once a real tenant exists,
   follow the *Google Workspace mail* section above to enable, plan-review, and apply
   `workspace_mail.tf`.
