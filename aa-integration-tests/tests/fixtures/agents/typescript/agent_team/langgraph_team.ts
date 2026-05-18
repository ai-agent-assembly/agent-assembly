// F116 ST-B — two-agent LangGraph team fixture (AAASM-1514).
//
// Registers a root agent, then builds a LangGraph where the coordinator node
// spins up a child assembly context (simulating agent delegation). In selftest
// mode emits synthetic events for hermetic CI runs.
//
// Invocation:
//   AA_GATEWAY_ADDR=127.0.0.1:PORT AA_AGENT_ID=e2e-lg-root \
//     pnpm exec tsx agent_team/langgraph_team.ts
//
//   AA_SELFTEST=1 AA_GATEWAY_ADDR=dummy pnpm exec tsx agent_team/langgraph_team.ts

import { loadConfig, emit, type AgentConfig } from "../_shared.js";
import { initAssembly } from "@agent-assembly/sdk";
import { StateGraph, Annotation } from "@langchain/langgraph";

const StateAnnotation = Annotation.Root({
  task: Annotation<string>(),
  results: Annotation<string[]>({ reducer: (a, b) => [...a, ...b], default: () => [] }),
});

async function runReal(cfg: AgentConfig): Promise<void> {
  const rootCtx = await initAssembly({
    gatewayUrl: `http://${cfg.gatewayAddr}`,
    apiKey: "e2e-test-key",
    agentId: cfg.agentId,
    teamId: "f116-e2e",
    mode: "sdk-only",
  });

  emit({ event: "started", agent_id: cfg.agentId, role: "coordinator" });

  const graph = new StateGraph(StateAnnotation)
    .addNode("coordinator", async (state) => {
      const workerCtx = await initAssembly({
        gatewayUrl: `http://${cfg.gatewayAddr}`,
        apiKey: "e2e-test-key",
        agentId: `${cfg.agentId}-worker`,
        teamId: "f116-e2e",
        parentAgentId: cfg.agentId,
        mode: "sdk-only",
      });
      emit({ event: "started", agent_id: `${cfg.agentId}-worker`, role: "worker" });
      await workerCtx.shutdown();
      return { results: [`worker: ${state.task}`] };
    })
    .addEdge("__start__", "coordinator")
    .addEdge("coordinator", "__end__")
    .compile();

  const output = await graph.invoke({ task: cfg.task });
  emit({ event: "tool_call", tool: "coordinator", input: cfg.task });

  await rootCtx.shutdown();
  emit({ event: "done", result: output.results.join(", ") });
}

const cfg = loadConfig();

if (process.env.AA_SELFTEST === "1") {
  emit({ event: "started", agent_id: cfg.agentId, role: "coordinator" });
  emit({ event: "started", agent_id: `${cfg.agentId}-worker`, role: "worker" });
  emit({ event: "tool_call", tool: "coordinator", input: cfg.task });
  emit({ event: "done", result: "selftest-ok" });
  process.exit(0);
}

await runReal(cfg);
