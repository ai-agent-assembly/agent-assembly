// F116 ST-B — single-agent LangChain fixture (AAASM-1514).
//
// Registers one agent via @agent-assembly/sdk, invokes a LangChain tool, then
// shuts down. In selftest mode (AA_SELFTEST=1) skips SDK/gateway entirely and
// emits synthetic events so the Rust harness can exercise the fixture toolchain
// hermetically (no native bindings, no running gateway required).
//
// Invocation:
//   AA_GATEWAY_ADDR=127.0.0.1:PORT AA_AGENT_ID=e2e-lc \
//     pnpm exec tsx single_agent/langchain_agent.ts
//
//   AA_SELFTEST=1 AA_GATEWAY_ADDR=dummy pnpm exec tsx single_agent/langchain_agent.ts

import { loadConfig, emit, type AgentConfig } from "../_shared.js";

async function runReal(cfg: AgentConfig): Promise<void> {
  const { initAssembly } = await import("@agent-assembly/sdk");
  const ctx = await initAssembly({
    gatewayUrl: `http://${cfg.gatewayAddr}`,
    apiKey: "e2e-test-key",
    agentId: cfg.agentId,
    teamId: "f116-e2e",
    mode: "sdk-only",
  });

  emit({ event: "started", agent_id: cfg.agentId });

  // Simulate a LangChain tool call (echo pattern).
  const result = `echo: ${cfg.task}`;
  emit({ event: "tool_call", tool: "echo", input: cfg.task });

  await ctx.shutdown();
  emit({ event: "done", result });
}

const cfg = loadConfig();

if (process.env.AA_SELFTEST === "1") {
  emit({ event: "started", agent_id: cfg.agentId });
  emit({ event: "tool_call", tool: "echo", input: cfg.task });
  emit({ event: "done", result: "selftest-ok" });
  process.exit(0);
}

await runReal(cfg);
