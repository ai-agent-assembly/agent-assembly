# aasm install endpoint

Cloudflare Worker that serves [`scripts/install-cli.sh`](../../scripts/install-cli.sh)
at two hosts (per [ADR 0007](../../docs/src/adr/0007-public-domain-and-url-contract.md)):

- **Canonical:** `https://agent-assembly.com/install.sh` — apex **path** route.
- **Legacy (kept working):** `https://tool.agent-assembly.dev` — host root.

powering the one-line installer:

```sh
curl -fsSL https://agent-assembly.com/install.sh | sh   # canonical
curl -fsSL https://tool.agent-assembly.dev        | sh   # alternate, still works
```

Both serve the **same** script. On the `.com` apex the Worker is bound only to
`agent-assembly.com/install.sh*` (a route, **not** `custom_domain`) because the apex
also hosts the marketing site — every other apex path passes through to the origin,
so the marketing site is unaffected. On `tool.agent-assembly.dev` the script is served
at the host root, as before.

The `.dev` TLD is HSTS-preloaded (HTTPS-only), so that endpoint can never be served
over plaintext `http`. The Worker fetches the install script from a pinned ref
(`SCRIPT_REF`) and serves it verbatim; the installer then downloads the release
binary and verifies its **SHA-256 checksum + cosign signature** (AAASM-2700).

## Local routing test

`wrangler deploy` is **OWNER-GATED** (see below). To verify the routing logic
locally without deploying:

```sh
node infra/install-endpoint/test/worker.test.mjs
```

It exercises the fetch handler with mocked Cloudflare globals and asserts that
`/install.sh` (apex) and the `.dev` root serve the script while other apex paths pass
through to the origin.

## Deploy (one-time, operator) — OWNER-GATED

Prerequisites: a Cloudflare account with **both** the `agent-assembly.com` and
`agent-assembly.dev` zones added (apex DNS proxied — see `infra/dns/`), and
[`wrangler`](https://developers.cloudflare.com/workers/wrangler/) installed
(`npm i -g wrangler`).

```sh
cd infra/install-endpoint
wrangler login
wrangler deploy          # binds the agent-assembly.com/install.sh* route +
                         # provisions the tool.agent-assembly.dev custom domain
```

Verify:

```sh
curl -fsSL https://agent-assembly.com/install.sh | head -5   # should print the install script
curl -fsSL https://tool.agent-assembly.dev       | head -5   # alternate, same script
curl -fsS  https://agent-assembly.com/install.sh             # serves; other apex paths untouched
curl -fsS  https://tool.agent-assembly.dev/healthz           # -> ok
```

## Enable the release smoke test

The `smoke-curl-installer` job in `.github/workflows/smoke-test.yml` is gated on a
repo variable so it only runs once the endpoint is live:

```sh
gh variable set INSTALL_ENDPOINT_LIVE --body true --repo ai-agent-assembly/agent-assembly
```

Until that variable is `true`, the job is skipped (no false-red on releases).

## Pinning the served script

For an immutable, auditable installer, pin `SCRIPT_REF` in `wrangler.toml` to a
release tag and re-deploy:

```toml
[vars]
SCRIPT_REF = "v0.0.1"
```

`master` (the default) always serves the latest reviewed installer.
