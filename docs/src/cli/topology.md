# aasm topology

Visualize agent topology — fleet overview, delegation trees, teams, ancestry
lineage, and aggregate statistics.

## Synopsis

```text
aasm topology <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`overview`](#aasm-topology-overview) | Fleet-wide topology overview. |
| [`tree`](#aasm-topology-tree) | Render a subtree rooted at a given agent. |
| [`team`](#aasm-topology-team) | Show all agents in a team. |
| [`lineage`](#aasm-topology-lineage) | Show the ancestry chain for a given agent. |
| [`stats`](#aasm-topology-stats) | Show aggregate topology statistics. |

All subcommands accept the [global options](overview.md#global-options),
including `--output table|json|yaml`. Only `tree` renders as a box-drawing tree;
`overview`, `team`, `lineage`, and `stats` render as tables in the default
`table` mode.

---

## aasm topology overview

Show a fleet-wide topology overview across all teams and root agents.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--status <STATUS>` | string | — | Filter agents by status (`active`, `suspended`, `deregistered`). |
| `--show-budget` | flag | off | Request each agent's governance level from the server. Only surfaced in `--output json`/`yaml`; the `table` view has no governance column, so this flag has no visible effect in table mode. |

```bash
aasm topology overview --status active
```

---

## aasm topology tree

Render a delegation subtree rooted at one agent, using box-drawing characters.

| Name | Type | Default | Description |
|---|---|---|---|
| `<AGENT_ID>` | string (arg) | — | Root agent ID (hex-encoded UUID). |
| `--max-depth <DEPTH>` | integer | — | Maximum traversal depth from the root. When omitted, the depth parameter is not sent and the server applies its own default (there is no client-side default). Must be at least `1`. |
| `--status <STATUS>` | string | — | Filter tree nodes by status. |
| `--show-budget` | flag | off | Request each node's governance level from the server. Only surfaced in `--output json`/`yaml`; the tree view has no governance column, so this flag has no visible effect in table mode. |

```bash
aasm topology tree a1b2c3… --max-depth 3
```

Each node prints as `<name> [<status>] <<team_id>>` (the `<team_id>` segment is
shown only when the agent has a team). Agent IDs are not printed in tree mode —
use `--output json` if you need them.

```text
└── research-bot [active] <research>
    ├── fetch-worker [active] <research>
    │   └── parse-worker [active] <research>
    └── summarize-worker [active] <research>
```

---

## aasm topology team

Show all agents belonging to a single team.

| Name | Type | Default | Description |
|---|---|---|---|
| `<TEAM_ID>` | string (arg) | — | Team ID. |
| `--status <STATUS>` | string | — | Filter members by status. |
| `--show-budget` | flag | off | Request each member's governance level from the server. Only surfaced in `--output json`/`yaml`; the `table` view has no governance column, so this flag has no visible effect in table mode. |

```bash
aasm topology team research --status active
```

---

## aasm topology lineage

Show an agent's complete ancestry chain, ordered root-first. In `table` mode the
lineage renders as a flat table with columns
`DEPTH | AGENT_ID | NAME | TEAM | DELEGATION_REASON`, followed by a
`(this is a root agent)` note when the agent has no ancestors above it.

| Name | Type | Default | Description |
|---|---|---|---|
| `<AGENT_ID>` | string (arg) | — | Agent ID (hex-encoded UUID). |
| `--show-permissions` | flag | off | After the lineage, also print the agent's effective capability set with cascade provenance. |

```bash
aasm topology lineage 778899… --show-permissions
```

```text
Agent: 778899…  |  Ancestors: 3

┌───────┬──────────┬──────────────┬──────────┬───────────────────┐
│ DEPTH ┆ AGENT_ID ┆ NAME         ┆ TEAM     ┆ DELEGATION_REASON │
╞═══════╪══════════╪══════════════╪══════════╪═══════════════════╡
│ 0     ┆ a1b2c3…  ┆ root-bot     ┆ research ┆ -                 │
│ 1     ┆ d4e5f6…  ┆ fetch-worker ┆ research ┆ fetch upstream    │
│ 2     ┆ 778899…  ┆ parse-worker ┆ research ┆ parse response    │
└───────┴──────────┴──────────────┴──────────┴───────────────────┘
```

---

## aasm topology stats

Show aggregate topology statistics — total/root/active/suspended/deregistered
counts, max depth, teams, orphans, and average children per parent. Takes no
flags of its own (uses the global `--output`). In `table` mode each metric is
its own row.

```bash
aasm topology stats --output json
```

```text
┌─────────────────────┬───────┐
│ METRIC              ┆ VALUE │
╞═════════════════════╪═══════╡
│ Total agents        ┆ 42    │
│ Root agents         ┆ 5     │
│ Max depth           ┆ 4     │
│ Active              ┆ 38    │
│ Suspended           ┆ 3     │
│ Deregistered        ┆ 1     │
│ Teams               ┆ 5     │
│ Orphans             ┆ 0     │
│ Avg children/parent ┆ 2.31  │
└─────────────────────┴───────┘
```

When present, a `Depth histogram` (`DEPTH | COUNT`) and a `Team-size histogram`
(`TEAM_SIZE | COUNT`) are printed as additional tables below the summary.
