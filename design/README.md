# Design Assets

This directory contains design reference files for the Agent Assembly governance dashboard.

## Structure

```
design/
└── v1/
    └── hi-fi/          ← High-fidelity prototype (React JSX + plain CSS)
        ├── index.html  ← Prototype entry point — open directly in a browser
        ├── shell.jsx   ← App shell / navigation skeleton
        ├── styles.css  ← Shared prototype styles
        └── *.jsx       ← Individual page prototypes
```

## How to view the prototype

Open `design/v1/hi-fi/index.html` directly in a browser (no build step required).
Each JSX file is a standalone React component rendered via the CDN build embedded in `index.html`.

## Relationship to dashboard source

The files in `design/v1/hi-fi/` are **reference designs only** — not production source.
When implementing a page, use the corresponding prototype file as the visual spec and
translate the structure into the TypeScript components under `dashboard/src/`.

| Prototype file | Dashboard page |
|---|---|
| `shell.jsx` | `src/components/AppShell.tsx` |
| `overview.jsx` | `src/pages/OverviewPage.tsx` |
| `fleet.jsx` | `src/pages/AgentsPage.tsx` |
| `agent-detail.jsx` | `src/pages/AgentDetailPage.tsx` |
| `policy-editor.jsx` | `src/pages/PolicyEditorPage.tsx` |
| `audit-log.jsx` | `src/pages/AuditLogPage.tsx` |
| `topology.jsx` | `src/pages/TopologyPage.tsx` |
| `costs.jsx` | `src/pages/CostsPage.tsx` |
| `identity.jsx` | `src/pages/IdentityPage.tsx` |
| `teams.jsx` | `src/pages/TeamsPage.tsx` |
| `alerts.jsx` | `src/pages/AlertsPage.tsx` |

## v2 — current (light / dark theme)

`design/v2/hi-fi/` is the latest hi-fi spec (Claude Design handoff). It introduces the
**light/dark theme** shipped in the dashboard under AAASM-2595: `styles.css` carries the
`:root` + `:root[data-theme="dark"]` token system, and `design/v2/screenshots/` holds the
light/dark reference captures (`theme-light.png`, `theme-dark.png`, `0X-dark-pages.png`).

`design/v1/` remains as the pre-theme reference. Use **v2** as the current visual spec.

### Which directory is authoritative — and why the closed audits still stand

**`design/v2/hi-fi/` is the authoritative visual specification** (ADR 0025).
`design/v1/hi-fi/` is a **historical pre-theme reference**, kept in-tree because
ADR 0017's ratification items cite it by file and because its `SUPERSESSION NOTE`
banners are part of the AAASM-5077 record. Do not delete it; do not treat it as a
build target.

ADR 0017, Epic AAASM-5020, Epic AAASM-5077 and every per-surface parity audit to date
cite **v1** paths. Those verdicts **remain valid**, and the re-anchor to v2 is not
grounds to re-run any of them. The reason is verifiable: a file-by-file diff of all 25
files in both directories (ADR 0025) found 17 byte-identical, and the overwhelming
majority of changed lines in the remaining 8 are one of — a hard-coded colour replaced
by a theme token; a JS-side palette introduced because `<canvas>` / SVG stroke
attributes cannot read CSS custom properties (`live-ops.jsx`, `topology.jsx`); or the
theme control itself (the topbar toggle in `shell.jsx`, the Theme radio in
`tweaks.jsx`, `.theme-toggle` in `styles.css`).

"Overwhelming majority", not "every line" — ADR 0025 names five exceptions found in
review (two token→token colour swaps on `.modal` and `.rule-num`, a deeper `.modal`
box-shadow literal, a new `color:` on `.layer-counter`, and a `transition` added to
~20 pre-existing selectors). All five are colour or easing changes; none alters
structure. **No page's layout, component tree, information architecture, state model or
data shape differs.** v2 is v1 plus theme tokenisation.

The one structural addition is the theme switch itself — v2's `shell.jsx` renders a
topbar button v1 does not. It is confined to the app chrome and touches no governance
surface, so no audit verdict turns on it.

### Evidence standard

All future light/dark screenshots and visual-regression evidence are captured against
the **v2** prototype. A capture taken against v1 is evidence about the pre-theme
prototype and does not satisfy a visual-fidelity acceptance criterion.

Note that this is a requirement on *capture*, not a claim that a stored baseline
exists: `design/v2/screenshots/` currently holds 9 files (1 light, 8 dark) against 43
in `design/v1/screenshots/`, so there is no per-surface light/dark v2 baseline yet. See
ADR 0025 item 4.

New deviations found between the shipped dashboard and v2 are recorded as an addendum
to ADR 0017, following the AAASM-5099 addendum convention — not as a new parity
programme.
