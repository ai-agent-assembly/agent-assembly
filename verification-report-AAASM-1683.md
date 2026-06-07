# AAASM-1683 — dashboard source-map fix verification

**Bug sub-task:** AAASM-1683 — [BUG] aasm release binary exceeds 2–8 MB AC target
**Parent Story:** AAASM-1200 — F110: Cross-platform CI release pipeline
**PR:** [ai-agent-assembly/agent-assembly#638](https://github.com/ai-agent-assembly/agent-assembly/pull/638)
**Verified by:** workflow_dispatch dry-run on the branch
**Run:** [release.yml #26201143804](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/26201143804)
**Date:** 2026-05-21 (UTC)

## Root cause

`aa-cli/src/commands/dashboard/start.rs:21` uses `include_dir!("$CARGO_MANIFEST_DIR/../dashboard/dist")` to bake the entire built dashboard SPA into every aasm release binary. `dashboard/vite.config.ts` had `build.sourcemap = true`, so every `pnpm build` produced a JS source map (`assets/index-*.js.map`) alongside the runtime bundle — and `include_dir!` embedded it. The source map is never served by `aasm dashboard start`; it's pure waste in the binary.

Local measurement against `master` showed the .js.map alone was 3.4 MB of a 4.2 MB `dashboard/dist`. The CI build (which compiles a real release bundle with all React/vite/dep source baked into the map) turns out to ship an even larger source map — about 5–6 MB.

## Fix

Single commit in this PR — `dashboard/vite.config.ts`:

```diff
   build: {
     outDir: 'dist',
-    sourcemap: true,
+    // Source maps are not served by the embedded `aasm dashboard` server and add
+    // ~3.4 MB to the final aasm binary (include_dir! embeds every file in dist/).
+    // Disable for production builds; dev (`vite`) generates inline sourcemaps via
+    // its own pipeline and is unaffected.
+    sourcemap: false,
   },
```

Dev experience (`vite` / `pnpm dev`) is unaffected — `build.sourcemap` controls the `vite build` output only; dev-server source maps come from a separate inline pipeline.

## Before vs after (CI measurement)

Pre-fix (from AAASM-1209 dry-run [#26197408878](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/26197408878)) vs post-fix (this PR's dry-run [#26201143804](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/26201143804)):

| Target | Before | After | Saved | vs original 2–8 MB AC |
| --- | --- | --- | --- | --- |
| `aarch64-unknown-linux-gnu` | 15 MB | **8.7 MB** | 6.3 MB | 0.7 MB over |
| `x86_64-unknown-linux-gnu` | 15 MB | **9.6 MB** | 5.4 MB | 1.6 MB over |
| `aarch64-apple-darwin` | 12 MB | **6.9 MB** | 5.1 MB | within AC ✓ |
| `x86_64-apple-darwin` | 13 MB | **7.9 MB** | 5.1 MB | within AC ✓ |

`aasm --version` still reports `aasm 0.0.1` on all four; `file` confirms unchanged architecture per target.

## SHA256SUMS (this PR's dry-run)

```
3d0d7b938660ab58adb1e0e7957c87b00d446d951c70bd4fb260f7d9345ebc72  aasm-aarch64-apple-darwin.tar.gz
fcbdc88612dd7342a7f8f80a1a95af3fe7b44380c52774f3a257d9f3d59388ef  aasm-aarch64-unknown-linux-gnu.tar.gz
4d1c2385fa9c4c5df9fcc1fc0fa8cd17854c7853e193f277a5485255b2712728  aasm-x86_64-apple-darwin.tar.gz
60fe489a7d3b4ece10bafd589e15fb51d001bff8330595209018fde827d274cc  aasm-x86_64-unknown-linux-gnu.tar.gz
```

## AC revision proposal for AAASM-1200

The fix saves more than expected, but Linux binaries still exceed the upper bound of the original 2–8 MB AC by 0.7 MB (aarch64) and 1.6 MB (x86_64). Linux ELF + glibc dynamic-linker overhead is just structurally heavier than Mach-O for binaries of this complexity (linked-in `aa-api` + `aa-gateway` + `aa-proto` + axum + tokio + reqwest + …).

**Proposed new AC on AAASM-1200**: replace "Binary size target: 2–8 MB per target" with **"Binary size target: ≤ 10 MB per target"**. This:

* Covers all 4 actual measurements with ~0.4 MB headroom.
* Stays meaningful — it's still a real ceiling, just calibrated to what's actually achievable with the current architecture.
* Doesn't preclude further optimisation later (slim feature flag or external dashboard assets), which can be tracked under separate tickets.

The AC revision is a Jira-only edit; no code change beyond this PR is needed.

## Out of scope

Further size reductions remain possible:

* Cargo feature flag to compile aa-cli without `include_dir!(dashboard/dist)` ("slim build") — saves the remaining ~750 KB of dashboard assets in the slim variant.
* Move dashboard assets out of the binary entirely (download/cache under `~/.aasm/assets/` on first `aasm dashboard start`) — Playwright-browser-pattern; biggest architectural change.

Both are future tickets if the team decides to push under 8 MB on Linux too.
