# Usage Guide

This guide walks through the real, day-to-day tasks an operator performs with
Agent Assembly, using the `aasm` CLI, the governance gateway, the three
interception layers, and the dashboard. Every command and every screenshot on
these pages was produced against the actual `0.0.1-beta.3` build — where a
scenario needs a platform Agent Assembly does not target locally (for example
the Linux-only eBPF layer, or the SaaS control-plane API the web dashboard
talks to), the page says so explicitly rather than showing a mock-up.

## What you can do

| Scenario | Goal | Page |
|---|---|---|
| Govern an agent | Launch a real AI dev tool under governance, end to end | [Govern an agent end-to-end](govern-an-agent.md) |
| Egress control | Restrict which hosts an agent may reach, and dry-run it before applying | [Enforce an egress policy](enforce-egress-policy.md) |
| Cost control | Set per-team spend caps and watch spend accumulate | [Team budgets and cost](team-budgets.md) |
| Observe | Watch the fleet in the web dashboard and the terminal TUI | [Observe in the dashboard](observe-in-dashboard.md) |
| Architecture in practice | Choose and combine the SDK, proxy, and eBPF layers | [Choosing interception layers](interception-layers.md) |
| When things break | Diagnose the most common local failures | [Troubleshooting](troubleshooting.md) |

## The shape of every scenario

Agent Assembly governance always has the same three moving parts:

1. **A gateway** — the brain. It holds the agent registry, evaluates policy,
   tracks budgets, and writes the audit log. You start it once.
2. **At least one interception layer** — the SDK shim, the `aa-proxy` sidecar,
   or the eBPF kernel hooks — that observes what an agent does and asks the
   gateway for an allow/deny decision.
3. **A policy** — a YAML document describing what is allowed: capabilities,
   network egress, per-tool rules, budgets, and approval gates.

The operator surface for all of this is the `aasm` binary:

```text
aasm — command-line tool for Agent Assembly

Commands:
  admin       Gateway administrative operations
  agent       Manage monitored agent processes
  alerts      Manage governance alerts
  audit       Query audit log entries and export compliance reports
  logs        Query and stream audit log events
  policy      Manage governance policies
  context     Manage named API contexts (connection profiles)
  config      Validate an `agent-assembly.toml` runtime configuration file
  completion  Generate shell completion scripts
  status      Show fleet health, agents, approvals, and budget at a glance
  version     Show CLI and gateway version information
  trace       Visualize a session trace (tree or timeline)
  approvals   Manage human-in-the-loop approval requests
  cost        Query cost summary and forecast spending
  dashboard   Open an interactive TUI dashboard for real-time governance monitoring
  gateway     Manage the aa-gateway governance daemon
  sandbox     Run a WebAssembly tool inside the Agent Assembly sandbox
  topology    Visualize agent topology, trees, lineage, and statistics
  proxy       Manage the aa-proxy sidecar — lifecycle, CA trust, and log tailing
  start       Start the locally-managed Agent Assembly gateway process
  stop        Stop the locally-managed Agent Assembly gateway process
```

Two global flags appear in nearly every example below:

- `--api-url <URL>` — where the CLI sends its requests. Defaults to the SaaS
  control-plane API on `http://localhost:8080`. When you run the local gateway
  (`aasm start` / `aa-gateway --mode local`) it serves its HTTP API on
  `http://127.0.0.1:7391`, so the local-mode examples pass
  `--api-url http://127.0.0.1:7391`.
- `--output <table|json|yaml>` — table for humans, `json`/`yaml` for scripting.

> **A note on ports.** The gRPC policy server listens on `127.0.0.1:50051`
> (where SDKs and the proxy connect). The local control-plane HTTP API and the
> embedded dashboard are served on `127.0.0.1:7391`. The full web dashboard's
> data API (`/api/v1/fleet`, `/api/v1/policies`, …) is provided by the
> SaaS/cloud control plane on port `8080`, which is not part of the open-source
> local runtime — see [Observe in the dashboard](observe-in-dashboard.md) for
> what renders locally and what needs the hosted backend.
