# Runnable examples

The pages in this guide explain *how* governance works. When you want to **run**
it, the framework-specific, end-to-end examples live in the dedicated
[`examples`](https://github.com/ai-agent-assembly/examples)
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

- **Node** — [examples-repo/node](https://github.com/ai-agent-assembly/examples/tree/master/node)
- **Python** — [examples-repo/python](https://github.com/ai-agent-assembly/examples/tree/master/python)
- **Go** — [examples-repo/go](https://github.com/ai-agent-assembly/examples/tree/master/go)
- **Scenarios** (cross-cutting: approval-gates, audit-trace, budget-limits, policy-enforcement, sidecar-runtime) — [examples-repo/scenarios](https://github.com/ai-agent-assembly/examples/tree/master/scenarios)

## Per-SDK example docs

Each language SDK also publishes its examples as rendered documentation, with the
governance walkthrough alongside the code. These are the same scenarios as the
repo links above, presented in the SDK's own docs site.

<!--
  Link convention: always point at the **stable** documentation channel — never a
  hardcoded `pre-release`/`latest` segment and never a pinned version. These links
  intentionally use `/stable/`, which 404s while the products are still in
  `0.0.1-beta.x` (the stable channel has no published version yet). That 404 is
  expected and correct: as soon as a stable release ships, every link resolves to
  the right stable page with no further edits. (mdBook does not validate external
  links and the docs CI has no link-checker, so the temporary 404 does not break the
  build.) Do NOT "fix" these by switching to pre-release/latest.
-->

- **Python** — [python-sdk examples](https://docs.agent-assembly.com/python-sdk/stable/examples/)
- **Node** — [node-sdk examples](https://docs.agent-assembly.com/node-sdk/stable/examples/)
- **Go** — [go-sdk examples](https://docs.agent-assembly.com/go-sdk/stable/examples/)
