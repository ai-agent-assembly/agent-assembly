# AI-Agent Framework Compatibility

Framework support is **implemented and documented per SDK**. The adapters that
make a framework governable live in each language SDK — not in this core repo — so
**each SDK's own docs are the authoritative source** for which frameworks it
supports and at what version range. This page is a thin index that points you to
them.

> **Why per-SDK?** The adapters
> (`python-sdk/agent_assembly/adapters/`, `node-sdk/src/hooks/`,
> `go-sdk/assembly/`) ship and version *with each SDK*. Keeping the
> supported-framework list and version ranges next to that implementation is what
> keeps them accurate — a duplicated copy here would drift out of sync. The core
> (`agent-assembly`) is the gateway / runtime / policy engine; it implements no
> framework adapter.

## Per-SDK framework compatibility

For the supported frameworks **and their version ranges**, see each SDK's
compatibility page:

| SDK | Frameworks (high level) | Authoritative compatibility doc |
|---|---|---|
| **Python** (`agent-assembly`) | LangChain · LangGraph · Pydantic AI · CrewAI · Google ADK · MCP · OpenAI Agents · LlamaIndex · Agno · Microsoft Agent Framework · Smolagents · Haystack | [python-sdk → Framework compatibility](https://docs.agent-assembly.com/python-sdk/stable/compatibility/frameworks/) |
| **Node / TypeScript** (`@agent-assembly/sdk`) | LangChain.js · LangGraph.js · Vercel AI SDK · Mastra · OpenAI Agents | [node-sdk → Framework compatibility](https://docs.agent-assembly.com/node-sdk/stable/compatibility-versioning/compatibility/) |
| **Go** (`go-sdk`) | LangChainGo (+ generic tool wrapping) | [go-sdk → Framework compatibility](https://docs.agent-assembly.com/go-sdk/stable/compatibility/) |

The `/stable/` links resolve at the first GA release (consistent with the docs
versioning convention); until then they 404 by design.

## What "supported" means

An SDK lists a framework as supported when it has both:

1. a **first-class adapter** in that SDK that attaches governance — event
   emission, pre-execution allow/deny, audit capture — to the framework's
   tool/agent execution path; and
2. a **live smoke test** in the QA suite established by
   [AAASM-3525](https://lightning-dust-mite.atlassian.net/browse/AAASM-3525) — a
   minimal agent on that framework, wired to the SDK + core (`aa-runtime` /
   gateway), exercised end-to-end against a real runtime.

The Python list was expanded with LlamaIndex, Agno, Microsoft Agent Framework,
Smolagents, and Haystack under
[AAASM-3535](https://lightning-dust-mite.atlassian.net/browse/AAASM-3535).

The exact **supported version range** and the **tested version** live in each
per-SDK doc above — anchored to that adapter's real constraints and the
AAASM-3525 tested versions, and kept in sync with the SDK's own dependency
declarations (Node `peerDependencies`, Python adapter `get_supported_versions()`,
the Go example pin). A framework appears only when it has both an adapter and a
live smoke — no silent gaps.
