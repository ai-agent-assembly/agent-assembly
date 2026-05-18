// F116 ST-B — two-agent LangChain team fixture (AAASM-1514).
//
// Registers a root agent plus one child agent (inheriting lineage from root),
// each invoking a LangChain tool. Verifies multi-agent registration in sdk-only
// mode. In selftest mode emits synthetic events for hermetic CI runs.
//
// Invocation:
//   AA_GATEWAY_ADDR=127.0.0.1:PORT AA_AGENT_ID=e2e-lc-root \
//     pnpm exec tsx agent_team/langchain_team.ts
//
//   AA_SELFTEST=1 AA_GATEWAY_ADDR=dummy pnpm exec tsx agent_team/langchain_team.ts

import { loadConfig, emit, type AgentConfig } from "../_shared.js";
import { initAssembly } from "@agent-assembly/sdk";

async function runReal(cfg: AgentConfig): Promise<void> {
  const rootCtx = await initAssembly({
    gatewayUrl: `http://${cfg.gatewayAddr}`,
    apiKey: "e2e-test-key",
    agentId: cfg.agentId,
    teamId: "f116-e2e",
    mode: "sdk-only",
  });

  emit({ event: "started", agent_id: cfg.agentId, role: "root" });

  const memberCtx = await initAssembly({
    gatewayUrl: `http://${cfg.gatewayAddr}`,
    apiKey: "e2e-test-key",
    agentId: `${cfg.agentId}-member`,
    teamId: "f116-e2e",
    parentAgentId: cfg.agentId,
    mode: "sdk-only",
  });

  emit({ event: "started", agent_id: `${cfg.agentId}-member`, role: "member" });

  // Simulate a LangChain team tool call.
  const result = `team-echo: ${cfg.task}`;
  emit({ event: "tool_call", tool: "echo", input: cfg.task });

  await memberCtx.shutdown();
  await rootCtx.shutdown();
  emit({ event: "done", result });
}

const cfg = loadConfig();

if (process.env.AA_SELFTEST === "1") {
  emit({ event: "started", agent_id: cfg.agentId, role: "root" });
  emit({ event: "started", agent_id: `${cfg.agentId}-member`, role: "member" });
  emit({ event: "tool_call", tool: "echo", input: cfg.task });
  emit({ event: "done", result: "selftest-ok" });
  process.exit(0);
}

await runReal(cfg);
