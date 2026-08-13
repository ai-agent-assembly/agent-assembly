# Redirects + staging/preview policy

> **OWNER-GATED — not auto-deployable.** The Cloudflare Redirect Rules below are
> applied by the **owner** in the Cloudflare dashboard (or via API/Terraform); this
> repo does not apply them. Status: **Proposed**, pending owner ratification.

Implements the canonicalization decided in
[ADR 0007 — Public Domain & URL Contract](../../docs/src/adr/0007-public-domain-and-url-contract.md)
(Epic [AAASM-3651](https://lightning-dust-mite.atlassian.net/browse/AAASM-3651),
ticket [AAASM-3657](https://lightning-dust-mite.atlassian.net/browse/AAASM-3657)).

## 1. Apex / `www` canonicalization

The apex `agent-assembly.com` is canonical; `www` redirects to it.

**Cloudflare Redirect Rule — "www → apex":**

- **When incoming requests match:** `http.host eq "www.agent-assembly.com"`
- **Then:** Dynamic redirect
  - Expression: `concat("https://agent-assembly.com", http.request.uri.path)`
  - Status: **301**
  - Preserve query string: **on**

This preserves path + query, so `https://www.agent-assembly.com/install.sh?x=1`
→ `https://agent-assembly.com/install.sh?x=1`.

## 2. The `.dev` ↔ `.com` stance — BOTH serve, no redirect

Per ADR 0007, **`.com` is canonical and `.dev` is KEPT working** — the installer
host `tool.agent-assembly.dev` continues to **serve** the install script, it is
**not** redirected to `.com`. Both hosts serve the same `scripts/install-cli.sh`
(via the same Worker). Do **not** add a `.dev → .com` redirect for
`tool.agent-assembly.dev`.

If any *other* `agent-assembly.dev` host (not `tool.`) is ever pointed at marketing
content, redirect it to the `.com` equivalent; but the installer host stays a live,
co-serving alternate.

| Host | Behaviour |
| --- | --- |
| `agent-assembly.com` | Canonical — serves directly |
| `www.agent-assembly.com` | 301 → apex (rule #1) |
| `tool.agent-assembly.dev` | **Serves** the installer (kept, no redirect) |
| other `*.agent-assembly.dev` (if any) | 301 → `.com` equivalent |

## 3. Legacy GitHub Pages docs → canonical docs (ties to AAASM-3665)

The per-repo docs currently live at `ai-agent-assembly.github.io/<repo>/`. Once
`docs.agent-assembly.com` (Epic AAASM-3659) is the canonical docs host, the legacy
GitHub Pages URLs should redirect there. GitHub Pages cannot host arbitrary 301
rules, so the redirect is implemented at the **canonical docs host / repo level**,
coordinated by **[AAASM-3665](https://lightning-dust-mite.atlassian.net/browse/AAASM-3665)**:

- Preferred: a small redirect stub / `<meta http-equiv="refresh">` + `rel=canonical`
  on the GitHub Pages site pointing at the matching path under
  `docs.agent-assembly.com`.
- Where a host-level rule is possible (custom domain on the Pages site fronted by
  Cloudflare), a Cloudflare Redirect Rule:
  - **When:** `http.host eq "ai-agent-assembly.github.io"` and
    `starts_with(http.request.uri.path, "/<repo>/")`
  - **Then:** 301 → `concat("https://docs.agent-assembly.com", http.request.uri.path)`

The exact per-repo path mapping is owned by AAASM-3665 / AAASM-3659; this file records
the **intent and the rule shape**, not the final per-repo table.

## 4. Staging / preview domains

Staging and preview environments must be clearly non-production and must **not** be
indexed or treated as canonical:

- **Staging host convention:** `*.staging.agent-assembly.com` (or a dedicated
  `staging.agent-assembly.com`). Proxied, but:
  - serve `X-Robots-Tag: noindex, nofollow` (Cloudflare Response Header Transform
    Rule) so previews never enter search results;
  - never set `rel=canonical` to a staging URL — canonical always points at the
    production `.com` host;
  - gate behind Cloudflare Access (auth) where the content is not meant to be public.
- **Cloudflare Pages preview deployments** (`<hash>.<project>.pages.dev`) are
  inherently non-canonical; do not alias them onto `agent-assembly.com`. Link to
  previews by their `.pages.dev` URL only.
- No staging/preview host is canonical for the installer: `/install.sh` is served
  only from `agent-assembly.com` and `tool.agent-assembly.dev` (ADR 0007).

## How to apply (owner)

See [`infra/RUNBOOK-domains.md`](../RUNBOOK-domains.md). Redirect Rules are created
under **Rules → Redirect Rules** in the Cloudflare zone; Response Header Transforms
under **Rules → Transform Rules**. None of this is applied by CI.
