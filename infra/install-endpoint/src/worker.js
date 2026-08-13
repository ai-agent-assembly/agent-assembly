// Cloudflare Worker — the aasm install endpoint (AAASM-2339, AAASM-3654).
//
// Serves `scripts/install-cli.sh` from the agent-assembly repo at two hosts
// (ADR 0007 — Public Domain & URL Contract):
//
//   * Canonical:  https://agent-assembly.com/install.sh   (apex PATH route)
//   * Legacy:     https://tool.agent-assembly.dev          (host root, kept working)
//
// so users can run either:
//
//   curl -fsSL https://agent-assembly.com/install.sh | sh
//   curl -fsSL https://tool.agent-assembly.dev        | sh
//
// On the `.com` apex this Worker is bound only to `agent-assembly.com/install.sh*`,
// so it must NEVER shadow the marketing site: any apex path that is not the install
// script is passed through to the origin (and 404s only if no origin answers). On
// the legacy `.dev` host the script is served at the host root, exactly as before.
//
// The `.dev` TLD is HSTS-preloaded (HTTPS-only). The script is fetched from a pinned
// ref (SCRIPT_REF) and served verbatim; the installer itself then downloads the
// release binary and verifies its checksum + cosign signature (AAASM-2700).

const DEFAULT_REPO = "ai-agent-assembly/agent-assembly";
const DEFAULT_REF = "master";
const SCRIPT_PATH = "scripts/install-cli.sh";

// The legacy installer host serves the script at its root; the canonical apex serves
// it at /install.sh. A request is an "install request" when either is true.
const LEGACY_INSTALL_HOST = "tool.agent-assembly.dev";
const INSTALL_PATHS = new Set(["/", "/install.sh"]);

function isInstallRequest(url) {
  if (url.hostname === LEGACY_INSTALL_HOST) {
    // Legacy host: serve the script at the root (and at /install.sh for symmetry).
    return url.pathname === "/" || url.pathname === "/install.sh";
  }
  // Any other host (the .com apex): only the explicit /install.sh path.
  return url.pathname === "/install.sh";
}

export default {
  async fetch(request, env, ctx) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed\n", {
        status: 405,
        headers: { Allow: "GET, HEAD", "content-type": "text/plain; charset=utf-8" },
      });
    }

    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return new Response("ok\n", {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    // Not an install request: pass through to the origin so the marketing site (or
    // whatever serves the apex) is unaffected. `fetch(request)` follows the route's
    // origin; if nothing answers it surfaces as the origin's own response/404.
    if (!isInstallRequest(url)) {
      return fetch(request);
    }

    const repo = env.SCRIPT_REPO || DEFAULT_REPO;
    const ref = env.SCRIPT_REF || DEFAULT_REF;
    const src = `https://raw.githubusercontent.com/${repo}/${ref}/${SCRIPT_PATH}`;

    // Serve from the edge cache to avoid hammering raw.githubusercontent.com.
    const cache = caches.default;
    const cached = await cache.match(request);
    if (cached) return cached;

    const upstream = await fetch(src, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (!upstream.ok) {
      return new Response(`error: could not fetch install script (HTTP ${upstream.status})\n`, {
        status: 502,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    const body = await upstream.text();
    const resp = new Response(body, {
      status: 200,
      headers: {
        "content-type": "text/x-shellscript; charset=utf-8",
        "cache-control": "public, max-age=300",
        "x-content-type-options": "nosniff",
        "x-install-source": src,
      },
    });
    ctx.waitUntil(cache.put(request, resp.clone()));
    return resp;
  },
};
