# RUNBOOK — domain operations (OWNER-GATED)

> **Every step in this runbook is performed by the OWNER.** Nothing here is applied
> by CI or by this repo — they require Cloudflare account access, DNS control, and
> `wrangler deploy`, none of which are available to automation. Status of the
> underlying design: **Proposed** (ADR 0007 / ADR 0008).

Brings up the public domain surface from
[ADR 0007 — Public Domain & URL Contract](../docs/src/adr/0007-public-domain-and-url-contract.md):
`agent-assembly.com` (marketing + `/install.sh`), `app.`, `api.`, `docs.`,
`status.`, the `*` tenant wildcard, and the kept `tool.agent-assembly.dev`.

Related: DNS set [`infra/dns/`](dns/), installer [`infra/install-endpoint/`](install-endpoint/),
redirects [`infra/redirects/`](redirects/), tenant slugs [`infra/tenant/`](tenant/)
(Epic [AAASM-3651](https://lightning-dust-mite.atlassian.net/browse/AAASM-3651),
ticket [AAASM-3658](https://lightning-dust-mite.atlassian.net/browse/AAASM-3658)).

---

## Ordered owner steps

### 1. Add the zone to Cloudflare

1. In Cloudflare, **Add a Site** → `agent-assembly.com`.
2. At the registrar, point the domain at the Cloudflare nameservers Cloudflare gives
   you. Wait for the zone to go **Active**.
3. Ensure `agent-assembly.dev` is also an Active zone in the same account (it already
   hosts `tool.agent-assembly.dev`).

### 2. Create the DNS records

Apply the records in [`infra/dns/README.md`](dns/README.md) — either by hand in the
dashboard or via Terraform:

```sh
cd infra/dns
export CLOUDFLARE_API_TOKEN=...        # Zone:DNS:Edit on agent-assembly.com
terraform init
terraform plan  -var "zone_id=<zone id>" -var "marketing_origin=<apex origin>"
terraform apply -var "zone_id=<zone id>" -var "marketing_origin=<apex origin>"
```

Apex + `www` proxied (🟠); `status` DNS-only (⚪); `app`/`api`/`docs`/`*` proxied as
their origins come online (set the matching Terraform `*_origin` var to create each).
Confirm the wildcard TLS cert covers `*.agent-assembly.com` (Advanced Certificate
Manager) before enabling tenant hosts.

### 3. Deploy the install Worker

```sh
cd infra/install-endpoint
node test/worker.test.mjs        # local routing sanity check first
wrangler login
wrangler deploy                  # binds agent-assembly.com/install.sh* +
                                 # provisions the tool.agent-assembly.dev custom domain
```

If the release smoke test should run, enable it:

```sh
gh variable set INSTALL_ENDPOINT_LIVE --body true --repo ai-agent-assembly/agent-assembly
```

### 4. Enable Always-HTTPS + HSTS

In the `agent-assembly.com` zone:

- **SSL/TLS → Edge Certificates → Always Use HTTPS: On.**
- **HSTS: Enable** — `max-age=31536000`, **Include subdomains: On**,
  **Preload: On** (only enable Preload once you are confident every subdomain,
  including future tenant hosts, can serve HTTPS — preload is hard to undo).
- Minimum TLS 1.2.

### 5. Apply redirect rules

Apply the rules in [`infra/redirects/README.md`](redirects/README.md):
`www → apex` (301), staging `noindex`, and — coordinated with AAASM-3665 — the legacy
`github.io/<repo>` → `docs.agent-assembly.com` redirects. **Do not** redirect
`tool.agent-assembly.dev`; it stays a co-serving installer host.

### 6. Attach docs / app / api custom domains

As each service comes online, attach its custom domain to the proxied host:

- `docs.agent-assembly.com` → the docs host (Epic AAASM-3659).
- `app.agent-assembly.com` → the app/control-plane origin.
- `api.agent-assembly.com` → the API origin.
- `status.agent-assembly.com` → the status-page provider (DNS-only; follow the
  provider's custom-domain + TLS instructions).

Enforce the cookie/auth boundaries from
[ADR 0008](../docs/src/adr/0008-saas-host-routing-auth-cookie-boundaries.md) when the
`app.`/`api.` hosts are built (host-only session cookies, token cross-host auth).

---

## Verification checklist

Run after each step. Replace placeholders with real values.

### DNS resolves

```sh
dig +short agent-assembly.com
dig +short www.agent-assembly.com
dig +short docs.agent-assembly.com
dig +short status.agent-assembly.com
dig +short anytenant.agent-assembly.com      # wildcard: should resolve once * exists
dig +short tool.agent-assembly.dev
```

Each should return Cloudflare/edge addresses (proxied hosts) or the provider target
(`status`). A non-empty answer for `anytenant.agent-assembly.com` confirms the `*`
wildcard is live.

### Installer serves at both hosts

```sh
# Canonical apex path:
curl -fsSL https://agent-assembly.com/install.sh | head -5     # prints the install script
# Legacy host (kept):
curl -fsSL https://tool.agent-assembly.dev        | head -5     # same script
# Health:
curl -fsS  https://tool.agent-assembly.dev/healthz              # -> ok
# Full end-to-end one-liner (installs aasm; run in a throwaway shell/container):
curl -fsSL https://agent-assembly.com/install.sh | sh
aasm --version
```

### Apex marketing NOT shadowed by the Worker

```sh
curl -fsSL https://agent-assembly.com/            | head -5     # marketing home, NOT the script
curl -fsSL https://agent-assembly.com/pricing     | head -5     # marketing page (or its 404), NOT the script
```

The Worker must only answer `/install.sh`; other apex paths fall through to marketing.

### www canonicalization

```sh
curl -fsSI https://www.agent-assembly.com/ | grep -i '^location:'   # -> https://agent-assembly.com/
```

Expect a `301` with `Location: https://agent-assembly.com/...` (path preserved).

### HTTPS + HSTS

```sh
# Always-HTTPS: http -> https
curl -sI http://agent-assembly.com/ | grep -i '^location:'          # -> https://...
# HSTS header present on the apex and subdomains:
curl -sI https://agent-assembly.com/      | grep -i strict-transport-security
curl -sI https://app.agent-assembly.com/  | grep -i strict-transport-security
```

Expect `strict-transport-security: max-age=31536000; includeSubDomains` (and
`; preload` if Preload was enabled).

### Per-host serving (as they come online)

```sh
curl -fsSI https://docs.agent-assembly.com/   | head -1     # 200 (docs host, AAASM-3659)
curl -fsSI https://app.agent-assembly.com/    | head -1     # 200/302 to login
curl -fsSI https://api.agent-assembly.com/healthz | head -1 # 200
curl -fsSI https://status.agent-assembly.com/ | head -1     # 200 (provider page)
```

---

## Sign-off

All green ⇒ the public domain surface matches ADR 0007. Record the completion (and
any deviations) on AAASM-3658. Cookie/auth boundary verification for `app.`/`api.`
(ADR 0008) is done when those hosts are actually built, not at DNS bring-up.
