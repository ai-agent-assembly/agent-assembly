// F116 ST-B — single-agent LangGraph fixture (AAASM-1514).
//
// Registers one agent, builds a minimal two-node LangGraph (start → echo_node
// → END), invokes it, then shuts down. In selftest mode emits synthetic events.
//
// Invocation:
//   AA_GATEWAY_ADDR=127.0.0.1:PORT AA_AGENT_ID=e2e-lg \
//     pnpm exec tsx single_agent/langgraph_agent.ts
//
//   AA_SELFTEST=1 AA_GATEWAY_ADDR=dummy pnpm exec tsx single_agent/langgraph_agent.ts

import { loadConfig, emit, type AgentConfig } from "../_shared.js";
import { initAssembly } from "@agent-assembly/sdk";
import { StateGraph, Annotation } from "@langchain/langgraph";

const StateAnnotation = Annotation.Root({
  task: Annotation<string>(),
  result: Annotation<string>(),
});

async function runReal(cfg: AgentConfig): Promise<void> {
  const ctx = await initAssembly({
    gatewayUrl: `http://${cfg.gatewayAddr}`,
    apiKey: "e2e-test-key",
    agentId: cfg.agentId,
    teamId: "f116-e2e",
    mode: "sdk-only",
  });

  emit({ event: "started", agent_id: cfg.agentId });

  const graph = new StateGraph(StateAnnotation)
    .addNode("echo_node", async (state) => ({
      result: `echo: ${state.task}`,
    }))
    .addEdge("__start__", "echo_node")
    .addEdge("echo_node", "__end__")
    .compile();

  const output = await graph.invoke({ task: cfg.task, result: "" });
  emit({ event: "tool_call", tool: "echo_node", input: cfg.task });

  await ctx.shutdown();
  emit({ event: "done", result: output.result });
}

const cfg = loadConfig();

if (process.env.AA_SELFTEST === "1") {
  emit({ event: "started", agent_id: cfg.agentId });
  emit({ event: "tool_call", tool: "echo_node", input: cfg.task });
  emit({ event: "done", result: "selftest-ok" });
  process.exit(0);
}

await runReal(cfg);
