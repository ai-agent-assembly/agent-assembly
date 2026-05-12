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
