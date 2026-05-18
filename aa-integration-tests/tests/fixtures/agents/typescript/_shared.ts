// Shared helpers for TypeScript agent fixture scripts (AAASM-1514 / F116 ST-B).
//
// Each fixture script imports this module for standardised env-var reading and
// structured JSON-line output. The Rust E2E harness (e2e_sdk_node.rs) and the
// developer runner (run_agents_ts.sh) both invoke fixture scripts via:
//
//   AA_GATEWAY_ADDR=<host:port> AA_AGENT_ID=<id> pnpm exec tsx <script>
//
// Selftest mode (AA_SELFTEST=1) emits synthetic events without connecting to
// a real gateway, so scripts can be exercised hermetically in CI.

import { randomBytes } from "node:crypto";

export interface AgentConfig {
  gatewayAddr: string;
  agentId: string;
  task: string;
  proxyAddr?: string; // undefined = Layer 2 inactive
}

export function loadConfig(): AgentConfig {
  const gatewayAddr = process.env.AA_GATEWAY_ADDR;
  if (!gatewayAddr) {
    console.error("error: AA_GATEWAY_ADDR required");
    process.exit(2);
  }
  return {
    gatewayAddr,
    agentId: process.env.AA_AGENT_ID ?? `e2e-${randomBytes(4).toString("hex")}`,
    task: process.env.AA_TASK ?? "noop",
    proxyAddr: process.env.AA_PROXY_ADDR,
  };
}

export function emit(event: Record<string, unknown>): void {
  console.log(JSON.stringify(event));
}
