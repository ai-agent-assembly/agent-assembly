// Local routing test for the install Worker (AAASM-3654).
//
// Cannot `wrangler deploy` here (OWNER-GATED), so this exercises the Worker's
// fetch handler directly under Node with mocked Cloudflare globals (caches,
// ctx.waitUntil) and a stubbed upstream/origin `fetch`, asserting:
//
//   * GET https://agent-assembly.com/install.sh        -> serves the script
//   * GET https://tool.agent-assembly.dev/              -> serves the script (legacy root)
//   * GET https://agent-assembly.com/pricing            -> passes through to origin
//   * GET https://agent-assembly.com/                   -> passes through (apex not shadowed)
//   * GET .../healthz                                   -> ok
//   * POST .../install.sh                               -> 405
//
// Run: node infra/install-endpoint/test/worker.test.mjs

import assert from "node:assert/strict";
import worker from "../src/worker.js";

const SCRIPT_BODY = "#!/bin/sh\n# fake install-cli.sh\necho installed\n";
const RAW_PREFIX = "https://raw.githubusercontent.com/";
const ORIGIN_MARKER = "MARKETING_ORIGIN_PAGE";

// Minimal edge-cache mock: always a miss, records puts.
function makeCaches() {
  const puts = [];
  return {
    puts,
    default: {
      async match() {
        return undefined;
      },
      async put(req, resp) {
        puts.push({ req, resp });
      },
    },
  };
}

// Stub global fetch: raw.githubusercontent.com -> the script; anything else (the
// origin pass-through) -> a marker marketing page.
function installStubFetch() {
  globalThis.fetch = async (input) => {
    const u = typeof input === "string" ? input : input.url;
    if (u.startsWith(RAW_PREFIX)) {
      return new Response(SCRIPT_BODY, { status: 200 });
    }
    return new Response(ORIGIN_MARKER, {
      status: 200,
      headers: { "content-type": "text/html" },
    });
  };
}

function makeCtx() {
  const pending = [];
  return { waitUntil: (p) => pending.push(p), pending };
}

const env = { SCRIPT_REPO: "ai-agent-assembly/agent-assembly", SCRIPT_REF: "master" };

async function call(method, urlStr) {
  globalThis.caches = makeCaches();
  const ctx = makeCtx();
  const req = new Request(urlStr, { method });
  const resp = await worker.fetch(req, env, ctx);
  const text = await resp.clone().text();
  return { resp, text };
}

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok  - ${name}`);
  } catch (e) {
    failures++;
    console.error(`  FAIL- ${name}\n      ${e.message}`);
  }
}

installStubFetch();

// 1. Canonical apex /install.sh serves the script.
{
  const { resp, text } = await call("GET", "https://agent-assembly.com/install.sh");
  check("apex /install.sh -> 200 script", () => {
    assert.equal(resp.status, 200);
    assert.equal(text, SCRIPT_BODY);
    assert.match(resp.headers.get("content-type"), /shellscript/);
  });
}

// 2. Legacy .dev root serves the script.
{
  const { resp, text } = await call("GET", "https://tool.agent-assembly.dev/");
  check("legacy .dev root -> 200 script", () => {
    assert.equal(resp.status, 200);
    assert.equal(text, SCRIPT_BODY);
  });
}

// 3. Apex non-install path passes through to the marketing origin.
{
  const { resp, text } = await call("GET", "https://agent-assembly.com/pricing");
  check("apex /pricing -> pass-through to origin", () => {
    assert.equal(resp.status, 200);
    assert.equal(text, ORIGIN_MARKER);
  });
}

// 4. Apex root passes through (Worker must NOT shadow the marketing home page).
{
  const { resp, text } = await call("GET", "https://agent-assembly.com/");
  check("apex / -> pass-through (not shadowed)", () => {
    assert.equal(resp.status, 200);
    assert.equal(text, ORIGIN_MARKER);
  });
}

// 5. healthz.
{
  const { resp, text } = await call("GET", "https://agent-assembly.com/healthz");
  check("/healthz -> ok", () => {
    assert.equal(resp.status, 200);
    assert.equal(text.trim(), "ok");
  });
}

// 6. Non-GET/HEAD on the install path -> 405.
{
  const { resp } = await call("POST", "https://agent-assembly.com/install.sh");
  check("POST /install.sh -> 405", () => {
    assert.equal(resp.status, 405);
    assert.equal(resp.headers.get("Allow"), "GET, HEAD");
  });
}

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall worker routing checks passed");
