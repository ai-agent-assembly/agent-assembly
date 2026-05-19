// F116 ST-B — root + sub-agents LangGraph hierarchy fixture (AAASM-1514).
//
// Registers a root agent that spawns two sub-agents through a multi-level
// LangGraph DAG. Exercises the parent→child lineage chain. In selftest mode
// emits synthetic events for hermetic CI runs.
//
// Invocation:
//   AA_GATEWAY_ADDR=127.0.0.1:PORT AA_AGENT_ID=e2e-root \
//     pnpm exec tsx root_sub_agents/langgraph_hierarchy.ts
//
//   AA_SELFTEST=1 AA_GATEWAY_ADDR=dummy pnpm exec tsx root_sub_agents/langgraph_hierarchy.ts

import { loadConfig, emit, type AgentConfig } from "../_shared.js";
import { StateGraph, Annotation } from "@langchain/langgraph";

const StateAnnotation = Annotation.Root({
  task: Annotation<string>(),
  sub_results: Annotation<string[]>({
    reducer: (a, b) => [...a, ...b],
    default: () => [],
  }),
});

async function runReal(cfg: AgentConfig): Promise<void> {
  const { initAssembly } = await import("@agent-assembly/sdk");
  const rootCtx = await initAssembly({
    gatewayUrl: `http://${cfg.gatewayAddr}`,
    apiKey: "e2e-test-key",
    agentId: cfg.agentId,
    teamId: "f116-e2e",
    mode: "sdk-only",
  });

  emit({ event: "started", agent_id: cfg.agentId, role: "root" });

  const graph = new StateGraph(StateAnnotation)
    .addNode("planner", async (state) => {
      const plannerCtx = await initAssembly({
        gatewayUrl: `http://${cfg.gatewayAddr}`,
        apiKey: "e2e-test-key",
        agentId: `${cfg.agentId}-planner`,
        teamId: "f116-e2e",
        parentAgentId: cfg.agentId,
        mode: "sdk-only",
      });
      emit({ event: "started", agent_id: `${cfg.agentId}-planner`, role: "planner" });
      await plannerCtx.shutdown();
      return { sub_results: [`planned: ${state.task}`] };
    })
    .addNode("executor", async (state) => {
      const executorCtx = await initAssembly({
        gatewayUrl: `http://${cfg.gatewayAddr}`,
        apiKey: "e2e-test-key",
        agentId: `${cfg.agentId}-executor`,
        teamId: "f116-e2e",
        parentAgentId: cfg.agentId,
        mode: "sdk-only",
      });
      emit({ event: "started", agent_id: `${cfg.agentId}-executor`, role: "executor" });
      await executorCtx.shutdown();
      return { sub_results: [`executed: ${state.task}`] };
    })
    .addEdge("__start__", "planner")
    .addEdge("planner", "executor")
    .addEdge("executor", "__end__")
    .compile();

  const output = await graph.invoke({ task: cfg.task });
  emit({ event: "tool_call", tool: "hierarchy_graph", input: cfg.task });

  await rootCtx.shutdown();
  emit({ event: "done", result: output.sub_results.join(" → ") });
}

const cfg = loadConfig();

if (process.env.AA_SELFTEST === "1") {
  emit({ event: "started", agent_id: cfg.agentId, role: "root" });
  emit({ event: "started", agent_id: `${cfg.agentId}-planner`, role: "planner" });
  emit({ event: "started", agent_id: `${cfg.agentId}-executor`, role: "executor" });
  emit({ event: "tool_call", tool: "hierarchy_graph", input: cfg.task });
  emit({ event: "done", result: "selftest-ok" });
  process.exit(0);
}

await runReal(cfg);
