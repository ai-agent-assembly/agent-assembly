// Cloudflare Worker — the aasm install endpoint (AAASM-2339).
//
// Serves `scripts/install-cli.sh` from the agent-assembly repo at
// https://tool.agent-assembly.dev so users can run:
//
//   curl -fsSL https://tool.agent-assembly.dev | sh
//
// The `.dev` TLD is HSTS-preloaded (HTTPS-only), so this endpoint can never be
// reached over plaintext http. The script is fetched from a pinned ref
// (SCRIPT_REF) and served verbatim; the installer itself then downloads the
// release binary and verifies its checksum + cosign signature (AAASM-2700).

const DEFAULT_REPO = "ai-agent-assembly/agent-assembly";
const DEFAULT_REF = "master";
const SCRIPT_PATH = "scripts/install-cli.sh";

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
