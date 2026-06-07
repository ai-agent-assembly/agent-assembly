# Verification Report — AAASM-2074

**Story:** agent-assembly README and docs are production-ready and link into the org documentation map
**Epic:** AAASM-2072 — Production documentation coverage across ai-agent-assembly organization repos
**Component / repo:** `agent-assembly` (OSS core runtime)
**Date:** 2026-06-06

## Sub-tasks

| Sub-task | Type | PR |
|---|---|---|
| AAASM-2652 | Implementation — README production-ready | #979 |
| AAASM-2653 | Implementation — mdBook docs coverage + navigation | #981 (stacked on #979) |
| AAASM-2654 | Verification (this report) | stacked on #981 |

## Method

- `mdbook build docs` with mdBook 0.5.2 + mdbook-mermaid 0.17.0 (the versions pinned in `.github/workflows/docs.yml`).
- Orphan check: every `*.md` under `docs/src/` is reachable from `SUMMARY.md`.
- Relative-link + README-anchor scan across `README.md` and all of `docs/src/`.
- External-link reachability probe for the links added by this Story.

## Acceptance-criteria walkthrough

| Area | Acceptance Criteria | Result | Evidence |
|---|---|---|---|
| README | Purpose, architecture, install paths, quick start, release state, supported platforms, links to docs | ✅ Pass | Overview + Crate Map (architecture); `curl` and **Homebrew** install paths; Quickstart; dated Project Status; new **Supported platforms** matrix; Documentation chapter table. |
| Docs | Cover local development, gateway/runtime architecture, policy model, CLI usage, dashboard, releases, operations | ✅ Pass | New `cli.md`, `dashboard.md`, `development/local-development.md`, `releases.md`; existing `architecture.md`, `policy-rbac.md` (now linked), `governance/capability-matrix.md`, `operations/*`. |
| Cross-links | README links to SDK repos, Homebrew tap, cloud/enterprise, spec, security/support, canonical docs site | ✅ Pass | **Ecosystem** table (python/node/go-sdk, homebrew tap, cloud, enterprise, docs site); spec noted as in-monorepo per project policy; **Security & Support** section; canonical docs-site link. |
| Status | Alpha/stable + Homebrew/package status accurate and dated | ✅ Pass | Project Status dated _2026-06-06_, latest pre-release `v0.0.1-alpha.5` (2026-06-03, verified via `gh release list`); per-channel package table. |
| Validation | Links checked; examples runnable or clearly marked as planned | ✅ Pass | See results below. Commands sourced from the real `aa-cli` `Commands` enum and the `Makefile`/`dashboard` configs. |

## Validation results

- **mdBook build:** clean (HTML written; only the benign mdbook-mermaid version-skew warning, also present on CI).
- **Orphan pages:** none — all in-`src` pages reachable from `SUMMARY.md`.
- **Relative / anchor links:** 87 checked across `README.md` + `docs/src/`, **0 broken**.
- **External links (in-scope):** all 200 —
  - `https://ai-agent-assembly.github.io/agent-assembly-docs/` (canonical docs site)
  - `python-sdk`, `node-sdk`, `go-sdk`, `homebrew-agent-assembly` repos
  - `releases/tag/v0.0.1-alpha.5`

## Findings fixed during verification

- **Pre-existing broken link** in `docs/src/migration/template.md`: `conformance/vectors/` was linked at `../../conformance/vectors/` (resolves to `docs/conformance/...`, missing) instead of `../../../conformance/vectors/` (repo-root, exists). Fixed in this sub-task.

## Notes / scope boundaries

- `docs/devtools/` and `docs/release/` live **outside** the book's `src/`, so they cannot be `SUMMARY.md` entries without breaking the build. The new `releases.md` links the GitHub Releases page and names the `docs/release/RUNBOOK.md` path instead; the CLI page links the devtools governance-limits doc by absolute URL.
- Package-channel status (crates.io / PyPI / npm / GHCR / Homebrew) is stated from the verified GitHub pre-releases and the in-repo `docs/release/` notes; live registry endpoints were not reachable from the validation environment and are not asserted beyond the release record.

## Conclusion

All five Story acceptance criteria are satisfied with evidence. README and mdBook docs are production-ready and cross-linked into the org documentation map. **AAASM-2074 ready to close once #979 → #981 → this PR merge.**
