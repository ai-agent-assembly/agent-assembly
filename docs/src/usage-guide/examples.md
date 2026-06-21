# Runnable examples

The pages in this guide explain *how* governance works. When you want to **run**
it, the framework-specific, end-to-end examples live in the dedicated
[`agent-assembly-examples`](https://github.com/ai-agent-assembly/agent-assembly-examples)
repository rather than in this book — that keeps the runnable code versioned and
testable on its own, while these pages stay focused on the concepts.

> **Want to stand up the infrastructure itself?** The
> [Self-hosting guide](self-hosting.md) walks through the open-source Docker Compose
> stack — its architecture, which containers run (and who each is for), and how to
> set up, run, and maintain the program's infra locally.

Every example is governed by the same three-layer interception model described
in [Choosing interception layers](interception-layers.md): a gateway as the
brain, at least one interception layer (SDK shim, `aa-proxy` sidecar, or eBPF),
and a policy. Pick the language you are integrating, or browse the cross-cutting
scenarios:

- **Node** — [examples-repo/node](https://github.com/ai-agent-assembly/agent-assembly-examples/tree/master/node)
- **Python** — [examples-repo/python](https://github.com/ai-agent-assembly/agent-assembly-examples/tree/master/python)
- **Go** — [examples-repo/go](https://github.com/ai-agent-assembly/agent-assembly-examples/tree/master/go)
- **Scenarios** (cross-cutting: approval-gates, audit-trace, budget-limits, policy-enforcement, sidecar-runtime) — [examples-repo/scenarios](https://github.com/ai-agent-assembly/agent-assembly-examples/tree/master/scenarios)
