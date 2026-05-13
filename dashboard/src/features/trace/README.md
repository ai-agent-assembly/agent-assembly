# Trace Feature

Per-session trace view for an agent — vertical timeline of LLM calls,
tool calls, and policy decisions with severity highlighting for policy
violations and credential leaks.

Implements the trace half of [AAASM-95](https://lightning-dust-mite.atlassian.net/browse/AAASM-95).
Decomposed into:

| Subtask | Scope |
|---|---|
| AAASM-1065 | Route + `useTraceQuery` + page shell |
| AAASM-1067 | `<TraceTimeline>` with severity color tokens + filter bar |
| AAASM-1069 | Payload preview + `<PayloadModal>` |
| AAASM-1071 | JSON export with zod schema + Playwright E2E |
