# Design Artefacts — Claude Design Handoff

This directory is the original **Claude Design handoff export** for the Agent Assembly community dashboard.

## Canonical location

All design artefacts have been versioned at the canonical path:

```
agent-assembly/design/v1/
```

Open [`design/v1/index.html`](../../design/v1/index.html) in a browser to run the interactive hi-fi prototype locally (no build step required — React 18 + Babel standalone).

The public Claude Design share link is also available at:
https://claude.ai/design/p/019de74a-402c-7641-8152-534cf3516d02?file=hi-fi%2Findex.html&via=share

## About this directory

The raw `project/` export from Claude Design lives here on disk but is excluded from git (see `.gitignore`). Engineers implementing the dashboard should read from `design/v1/`, not from `project/`.

## Related ticket

AAASM-1279 — Design: Community dashboard open-source hi-fi prototype (Sprints 1–3)
