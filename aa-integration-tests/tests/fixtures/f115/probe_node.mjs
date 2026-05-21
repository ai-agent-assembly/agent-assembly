// AAASM-1230 — Node.js probe driver for the F115 runtime lifecycle tests.
//
// Imports the sibling node-sdk's built `dist/esm/runtime.js` and dispatches
// on argv[2]: "find" prints find_aasm_binary()'s result, "init" invokes
// init_assembly() and exits non-zero with INSTALL_HINT on stderr when no
// binary is found.
//
// Path resolution: NODE_SDK_PATH (set by CI) → fall back to the in-process
// sibling-checkout convention.

import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { env, argv, exit } from "node:process";

const sdkRoot = env.NODE_SDK_PATH ?? resolve(import.meta.dirname, "../../../../..", "node-sdk");
const runtimeUrl = pathToFileURL(resolve(sdkRoot, "dist/esm/runtime.js")).href;

let runtime;
try {
  runtime = await import(runtimeUrl);
} catch (err) {
  // Surface the error so the Rust harness skips with a clear message.
  console.error(`probe_node: cannot import ${runtimeUrl}: ${err.message}`);
  exit(64);
}

const action = argv[2];
if (action === "find") {
  console.log(runtime.findAasmBinary() ?? "NONE");
} else if (action === "init") {
  await runtime.initAssembly();
  console.log("OK");
} else {
  console.error(`probe_node: unknown action ${JSON.stringify(action)}`);
  exit(2);
}
