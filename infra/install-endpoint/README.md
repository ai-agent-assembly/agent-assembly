# aasm install endpoint

> **Canonical endpoint:** the one-line installer is published at
> **`https://agent-assembly.com/install.sh`** (served as a static file by the
> official website — see AAASM-3654). The `tool.agent-assembly.dev` Worker below is
> a kept alias; both serve the identical `scripts/install-cli.sh`.

Cloudflare Worker that serves [`scripts/install-cli.sh`](../../scripts/install-cli.sh)
at **`https://tool.agent-assembly.dev`**, powering the one-line installer:

```sh
curl -fsSL https://tool.agent-assembly.dev | sh
```

The `.dev` TLD is HSTS-preloaded (HTTPS-only), so the endpoint can never be served
over plaintext `http`. The Worker fetches the install script from a pinned ref
(`SCRIPT_REF`) and serves it verbatim; the installer then downloads the release
binary and verifies its **SHA-256 checksum + cosign signature** (AAASM-2700).

## Deploy (one-time, operator)

Prerequisites: a Cloudflare account with the **`agent-assembly.dev`** zone added,
and [`wrangler`](https://developers.cloudflare.com/workers/wrangler/) installed
(`npm i -g wrangler`).

```sh
cd infra/install-endpoint
wrangler login
wrangler deploy          # provisions the Worker + the tool.agent-assembly.dev custom domain
```

Verify:

```sh
curl -fsSL https://tool.agent-assembly.dev | head -5     # should print the install script
curl -fsS  https://tool.agent-assembly.dev/healthz       # -> ok
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
