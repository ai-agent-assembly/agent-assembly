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
including `--output table|json|yaml` (tables render via box-drawing trees for
`tree`/`lineage`).

---

## aasm topology overview

Show a fleet-wide topology overview across all teams and root agents.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--status <STATUS>` | string | — | Filter agents by status (`active`, `suspended`, `deregistered`). |
| `--show-budget` | flag | off | Include governance level in agent nodes. |

```bash
aasm topology overview --status active
```

---

## aasm topology tree

Render a delegation subtree rooted at one agent, using box-drawing characters.

| Name | Type | Default | Description |
|---|---|---|---|
| `<AGENT_ID>` | string (arg) | — | Root agent ID (hex-encoded UUID). |
| `--max-depth <DEPTH>` | integer | `10` | Maximum traversal depth from the root. |
| `--status <STATUS>` | string | — | Filter tree nodes by status. |
| `--show-budget` | flag | off | Include governance level in tree nodes. |

```bash
aasm topology tree a1b2c3… --max-depth 3
```

```text
research-bot (a1b2c3…)
├── fetch-worker (d4e5f6…)
│   └── parse-worker (778899…)
└── summarize-worker (aabbcc…)
```

---

## aasm topology team

Show all agents belonging to a single team.

| Name | Type | Default | Description |
|---|---|---|---|
| `<TEAM_ID>` | string (arg) | — | Team ID. |
| `--status <STATUS>` | string | — | Filter members by status. |
| `--show-budget` | flag | off | Include governance level in agent nodes. |

```bash
aasm topology team research --status active
```

---

## aasm topology lineage

Show an agent's complete ancestry chain, ordered root-first.

| Name | Type | Default | Description |
|---|---|---|---|
| `<AGENT_ID>` | string (arg) | — | Agent ID (hex-encoded UUID). |
| `--show-permissions` | flag | off | After the lineage, also print the agent's effective capability set with cascade provenance. |

```bash
aasm topology lineage 778899… --show-permissions
```

```text
root-bot (a1b2c3…)
└── fetch-worker (d4e5f6…)
    └── parse-worker (778899…)   ← target
```

---

## aasm topology stats

Show aggregate topology statistics — total/root/active/suspended counts, max
depth, team sizes, and depth/spawn histograms. Takes no flags of its own
(uses the global `--output`).

```bash
aasm topology stats --output json
```

```text
Total agents:    42
Root agents:     5
Max depth:       4
Active:          38   Suspended: 3   Deregistered: 1
Teams:           5
Avg children/parent: 2.31
```
