// Minimal Node agent for the base-image smoke harness (AAASM-3524).
//
// The smallest "an agent runs on the base image with no manual config" program:
// it `require()`s the SDK exactly as a developer's containerised agent would
// (resolved via the image's global NODE_PATH=/usr/local/lib/node_modules), wraps
// a tool with governance, runs an allowed call, and exits 0.
//
// It is COPYed onto `ghcr.io/ai-agent-assembly/node:<ver>` and run with no extra
// npm install, no local package.json, and no source mount — proving the base
// image ships everything an agent needs (`@agent-assembly/sdk` + `aasm` on PATH).
//
// Honest tiering (mirrors the Python agent):
//   * Tier A (always, real): the SDK resolves, `withAssembly` governs a tool call,
//     an allowed call returns. Clean exit ⇒ no startup / missing-dep failure.
//   * Tier B (governance transport): a real UDS transport to the aa-runtime
//     sidecar is exercisable only once the image ships the SDK's compiled native
//     binding. The published base image installs the JS SDK from the npm `beta`
//     dist-tag (no bundled native client wired to a socket), so this honestly
//     reports transport=offline rather than faking a live connection.
//
// Prints one line of JSON as its last stdout line for the runner to parse.

"use strict";

function emit(result) {
  process.stdout.write(JSON.stringify(result) + "\n");
}

async function main() {
  const result = {
    lang: "node",
    ok: false,
    tier_a: false,
    transport: "offline",
    agent_id: process.env.AA_AGENT_ID || "",
  };

  // Tier A — the SDK resolves on the base image's global module path.
  let sdk;
  try {
    sdk = require("@agent-assembly/sdk");
  } catch (err) {
    result.error = `SDK require failed on base image: ${err && err.message}`;
    emit(result);
    return 1;
  }

  const { withAssembly, createNoopGatewayClient, PolicyViolationError } = sdk;
  if (typeof withAssembly !== "function") {
    result.error = "SDK does not export withAssembly — base image SDK is broken";
    emit(result);
    return 1;
  }

  // Govern a single tool with a self-contained client so the smoke run needs no
  // gateway URL or API key (the "no manual config" guarantee).
  try {
    const tools = withAssembly(
      {
        search: {
          execute: async (args) => `searched: ${JSON.stringify(args)}`,
        },
      },
      {
        // "sdk-only" keeps the governed call self-contained (no gateway URL /
        // API key), the "no manual config" guarantee. createNoopGatewayClient
        // requires the mode argument.
        gatewayClient: createNoopGatewayClient("sdk-only"),
        agentId: result.agent_id || "smoke-node",
      },
    );

    const out = await tools.search.execute({ q: "hello" });
    if (typeof out !== "string") {
      result.error = "governed tool call returned unexpected result";
      emit(result);
      return 1;
    }
  } catch (err) {
    // A PolicyViolationError on an allowed action would itself be a real bug;
    // surface anything thrown rather than swallowing it.
    const kind = err instanceof PolicyViolationError ? "policy-violation" : "error";
    result.error = `governed allowed call failed (${kind}): ${err && err.message}`;
    emit(result);
    return 1;
  }

  result.tier_a = true;

  // Tier B — honest: the npm `beta` base-image SDK ships no socket-dialing native
  // client, so no live aa-runtime transport is asserted here.
  result.transport_note =
    "JS SDK installed from npm beta has no bundled native client wired to the " +
    "aa-runtime UDS; SDK ran in its offline path. Live transport is exercisable " +
    "once the image ships the compiled native binding.";

  result.ok = true;
  emit(result);
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stdout.write(
      JSON.stringify({ lang: "node", ok: false, error: String(err && err.stack || err) }) + "\n",
    );
    process.exit(1);
  });
