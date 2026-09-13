# Reference — optional-tool preferred→fallback semantics

RTK, CodeGraph, and similar accelerators are **current preferred
implementations of a capability, never company semantic invariants** (per
`governance/engineering/agent-skill-architecture.md` §6). The capability
they accelerate — "find the relevant code", "understand call paths",
"iterate quickly" — is the actual requirement. The tool is swappable.

## Preferred → fallback pairs

| Capability | Preferred accelerator | Native fallback |
|---|---|---|
| Locate relevant symbols/call paths | CodeGraph (`codegraph_explore` / `codegraph explore`) — one query returns verbatim source plus call paths, including dynamic-dispatch hops grep can't follow | `grep`/`rg` + `Read`, or the language's own cross-reference tool (`rust-analyzer`, `jedi`, `gopls`) |
| Token-efficient dev-op proxying | RTK (`rtk <cmd>`) — filtered/compressed output for common git/build/test invocations | The underlying native command run directly (`git`, `cargo`, `pytest`, etc.) with its normal output |

Check availability before assuming either is present (e.g. `.codegraph/`
directory exists, `rtk --version` succeeds) — never hardcode a dependency
on one being installed.

## The two forbidden failure modes

1. **Silent degradation to nothing.** If RTK or CodeGraph is missing,
   unavailable, or errors, the correct response is "use the native tool
   instead" — never "skip the check". A missing accelerator must never
   quietly turn a required Explore/Narrow/Validate step into a no-op. If a
   skill's procedure reads "run CodeGraph to find callers" and CodeGraph
   isn't installed, the next line is "run `grep`/native cross-reference
   instead", not silence.
2. **Treating navigation/static evidence as correctness proof.**
   CodeGraph-style output (a symbol's call graph, "no callers found",
   static dependency edges) is evidence for *finding* code, never proof
   that a change is safe at runtime. A compiler/test/build/runtime gate
   (the Full Gate stage of the execution model) is never replaced by a
   static graph claiming "nothing calls this" or "no blast radius". Use
   the graph to decide *where to look and what to run*; let the actual
   gate decide *whether the change works*.

## Applying this to other platform-specific tools

The same contract applies beyond RTK/CodeGraph: "real browser evidence"
for a web surface and "native/XCUITest evidence" for an Apple-native
surface are the actual requirements; Playwright and XCUITest are today's
implementations, not the invariant itself. Whichever tool a stack-specific
skill names, that skill must also name what to do when the tool isn't
present — this reference is the shared template, not a substitute for
each skill stating its own fallback explicitly.
