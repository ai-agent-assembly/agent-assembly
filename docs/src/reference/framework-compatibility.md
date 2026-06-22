# AI-Agent Framework Compatibility

This is the **canonical** answer to "which AI-agent frameworks does Agent
Assembly support, with which SDK, at what version range?" The language SDK docs
(python-sdk, node-sdk, go-sdk) link here rather than maintaining their own copy.

## What "supported" means

A framework is **supported** when both of these are true:

1. **It has a first-class adapter** in one of the SDKs — a dedicated integration
   module that hooks the framework's tool/agent execution path so governance
   (event emission, pre-execution allow/deny, audit capture) attaches
   automatically.
2. **It has a live smoke test** in the QA suite established by
   [AAASM-3525](https://lightning-dust-mite.atlassian.net/browse/AAASM-3525) —
   a minimal agent built on that framework, wired to the SDK + core
   (`aa-runtime` / gateway), with the highlight governance functions exercised
   end-to-end against a real runtime.

The **tested version** column is anchored to the versions the AAASM-3525 live
smoke runs actually executed against. The **supported version range** is sourced
from the adapter's real constraints and each SDK's declared dependency pins.

### Honesty about version ranges

Agent Assembly's SDKs deliberately **do not pin the agent frameworks as hard
runtime dependencies** — the frameworks are *peer* (Node) / *optional* (Python
lazy-import, Go duck-typed) dependencies, so an integrator brings their own.
That means a precise, exhaustively-validated `>=a,<b` range usually does not
exist. Where it isn't independently verifiable, this page states the **tested
version** plus a conservative "compatible with the X.Y line; not exhaustively
version-tested" rather than inventing exact bounds. Trust the **Tested version**
column as the ground truth; treat wider ranges as best-effort guidance.

## Compatibility matrix

| Framework | Language / SDK | Adapter module | Supported version range | Tested version (AAASM-3525) | Notes |
|---|---|---|---|---|---|
| LangChain | Python (`agent-assembly`) | `agent_assembly.adapters.langchain` (hooks `langchain_core.callbacks`) | `0.3.x` line; not exhaustively version-tested | latest `0.3.x` at run time | No runtime pin in `pyproject.toml`; integrator supplies `langchain` / `langchain-core`. Two-layer enforcement (callback redaction + tool wrapper). |
| LangGraph | Python (`agent-assembly`) | `agent_assembly.adapters.langgraph` (hooks `langgraph.graph.state`) | `0.x` line; not exhaustively version-tested | latest at run time | No runtime pin; shares the LangChain callback path. |
| Pydantic AI | Python (`agent-assembly`) | `agent_assembly.adapters.pydantic_ai` (hooks `pydantic_ai.tools` / `.toolsets`) | `>=0.3.0` (**tested/dev**) — see contradiction note below | `0.3.x` (dev/test group: `pydantic-ai>=0.3.0`) | ⚠️ The Python SDK example docs pin `>=0.1.0,<0.3.0`; the dev/test group and AAASM-3525 use `>=0.3.0`. See "Known contradiction" below. |
| CrewAI | Python (`agent-assembly`) | `agent_assembly.adapters.crewai` (hooks `crewai.tools`) | `1.14.x` line; not exhaustively version-tested | `1.14.x` | No runtime pin; installed at latest for the smoke run. |
| Google ADK | Python (`agent-assembly`) | `agent_assembly.adapters.google_adk` (hooks `google.adk.agents` / `.tools`) | latest `google-adk`; not exhaustively version-tested | latest at run time | PyPI package `google-adk`, imported as `google.adk`. No runtime pin. |
| MCP | Python (`agent-assembly`) | `agent_assembly.adapters.mcp` (hooks `mcp`) | `1.27.x` line; not exhaustively version-tested | `1.27.x` | Model Context Protocol client. No runtime pin. |
| OpenAI Agents | Python (`agent-assembly`) | `agent_assembly.adapters.openai_agents` (hooks the `agents` package) | `>=0.1.0`, tested at `0.17.x`; not exhaustively version-tested | `0.17.x` | PyPI package `openai-agents`, imported as `agents` (**not** `openai.agents`). Dev/test group pins `openai-agents>=0.1.0`. |
| LangChain.js | Node (`@agent-assembly/sdk`) | `src/adapters/langchain` + `src/hooks` (`@langchain/core`) | `>=0.3.0` (declared `peerDependency`) | latest `0.3.x` line | Declared optional peer dep `@langchain/core >=0.3.0`. Two-layer enforcement (callback + wrapper). |
| LangGraph.js | Node (`@agent-assembly/sdk`) | `src/hooks/langgraph` (`@langchain/langgraph`) | `0.x` line; not exhaustively version-tested | latest at run time | Detected by presence of `@langchain/langgraph`; **peer dep not declared** in `package.json`. |
| Vercel AI SDK | Node (`@agent-assembly/sdk`) | `src/hooks/ai-sdk` (`ai`) | `4.x` line; not exhaustively version-tested | latest at run time | Detected by presence of the `ai` package; peer dep not declared. Tools match by **description**, not name; pre-execution `tool()` interception is partial (tracked in AAASM-213) — does **not** have full LangChain parity. |
| Mastra | Node (`@agent-assembly/sdk`) | `src/hooks/mastra` (`@mastra/core`) | `0.x` line; not exhaustively version-tested | latest at run time | Detected by presence of `@mastra/core`; peer dep not declared. |
| OpenAI Agents | Node (`@agent-assembly/sdk`) | `src/hooks/openai-agents` (`@openai/agents`) | `>=0.1.0` (declared `peerDependency`) | latest at run time | Declared optional peer dep `@openai/agents >=0.1.0`. Uses the handoff hook for parent→child agent lineage. |
| LangChainGo | Go (`github.com/ai-agent-assembly/go-sdk`) | `assembly` package — `WrapChain` / `WrapTools` (duck-typed `Chain` / `tools.Tool`) | `v0.1.x` line; not exhaustively version-tested | `v0.1.14` | The SDK matches `github.com/tmc/langchaingo`'s `chains.Chain` and `tools.Tool` **by interface, without importing langchaingo** — so any version whose interfaces match works. Example pins `v0.1.14`. Generic `WrapTools` governs any tool satisfying the same interface, framework-agnostic. |

**Legend**

- **Supported version range** — best-effort; trust the *Tested version* column as
  ground truth (see "Honesty about version ranges").
- ⚠️ — has a documented caveat; read the Notes column and the section below.

## Known contradiction: Pydantic AI

The Python SDK's example documentation
(`python-sdk/docs/examples/pydantic-ai.md`) instructs integrators to pin
`pydantic-ai>=0.1.0,<0.3.0`, explaining that the adapter hooks the internal
`Tool._run` entry point present in the `0.1.x`–`0.2.x` line, and that newer
`1.x` releases renamed that internal API.

However, the Python SDK's **dev/test dependency group** pins
`pydantic-ai>=0.3.0`, and the **AAASM-3525 live smoke suite runs against the
`0.3.x` line** — i.e. the tested-and-passing version is on the *other side* of
the `<0.3.0` bound the docs recommend.

**Resolution (as documented here):** the **tested** surface is `pydantic-ai
>=0.3.0` — that is what the AAASM-3525 smoke suite exercises and is therefore
the version range this matrix treats as supported. The example doc's `<0.3.0`
pin is **stale guidance** describing the older `Tool._run` hook path and should
be reconciled to `>=0.3.0` in the python-sdk docs as a follow-up. Until that
reconciliation lands, the two sources disagree; **this page is authoritative**
and the `>=0.3.0` tested range wins.

## How this is kept in sync

This matrix is driven by two sources of truth, both of which must stay aligned
with it when frameworks or versions change:

1. **The AAASM-3525 live smoke suite** — the executable proof that each
   (language × framework) combination runs end-to-end with the governance
   highlights working. When the suite adds a framework, bumps a tested version,
   or drops coverage, update the matching row's **Tested version** here.
2. **Each SDK's declared dependencies** — the Node `peerDependencies` in
   `package.json`, the Python dev/test extras in `pyproject.toml`, and the Go
   example pin. When an SDK changes a declared range, update the **Supported
   version range** column.

A framework should appear here **only** when it has both a first-class adapter
and a live smoke test. A framework that is documented as integrable but lacks a
smoke test is **not** listed as supported — no silent gaps (per the AAASM-3525
acceptance criteria).
