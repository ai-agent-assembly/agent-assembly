# Runnable examples

The pages in this guide explain *how* governance works. When you want to **run**
it, the framework-specific, end-to-end examples live in the dedicated
[`agent-assembly-examples`](https://github.com/ai-agent-assembly/agent-assembly-examples)
repository rather than in this book — that keeps the runnable code versioned and
testable on its own, while these pages stay focused on the concepts.

> **Want to stand up the infrastructure itself?** The
> [Self-hosting guide](self-hosting.md) walks through the open-source Docker Compose
> stack — its architecture, which containers run (and who each is for), and how to
> set up, run, and maintain the program's infra locally. For the wiring diagram
> behind that stack — how a single agent action travels across every hop and the
> real config knob at each one — see the
> [Infrastructure overview](../architecture/infra-overview.md).

Every example is governed by the same three-layer interception model described
in [Choosing interception layers](interception-layers.md): a gateway as the
brain, at least one interception layer (SDK shim, `aa-proxy` sidecar, or eBPF),
and a policy. Pick the language you are integrating, or browse the cross-cutting
scenarios:

- **Node** — [examples-repo/node](https://github.com/ai-agent-assembly/agent-assembly-examples/tree/master/node)
- **Python** — [examples-repo/python](https://github.com/ai-agent-assembly/agent-assembly-examples/tree/master/python)
- **Go** — [examples-repo/go](https://github.com/ai-agent-assembly/agent-assembly-examples/tree/master/go)
- **Scenarios** (cross-cutting: approval-gates, audit-trace, budget-limits, policy-enforcement, sidecar-runtime) — [examples-repo/scenarios](https://github.com/ai-agent-assembly/agent-assembly-examples/tree/master/scenarios)

## Per-SDK example docs

Each language SDK also publishes its examples as rendered documentation, with the
governance walkthrough alongside the code. These are the same scenarios as the
repo links above, presented in the SDK's own docs site.

<!--
  Link convention: we point at each SDK's channel-agnostic documentation root, not
  a pinned version and not a hardcoded `pre-release`/`latest` segment. Per the docs
  versioning model the root auto-redirects to the latest *stable* channel when one
  exists (falling back to the best-available channel while the products are still in
  beta). A `/stable/examples/` deep link does not resolve yet (the stable channel has
  no published version during `0.0.1-beta.x`), so we link the SDK doc root — which
  always tracks stable and returns HTTP 200 — and let its navigation surface the
  examples section. Revisit deep `/stable/examples/` links once a stable release ships.
-->

- **Python** — [python-sdk examples](https://ai-agent-assembly.github.io/python-sdk/)
- **Node** — [node-sdk examples](https://ai-agent-assembly.github.io/node-sdk/)
- **Go** — [go-sdk examples](https://ai-agent-assembly.github.io/go-sdk/)
