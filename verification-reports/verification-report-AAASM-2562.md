# Verification Report — AAASM-2562

**Story:** 🗑️ (agent-assembly) Remove fat `aa-ffi-*` bindings from the workspace
**Epic:** AAASM-2552 — SDK security boundary + FFI consolidation (final story)
**Implementation:** AAASM-2646 — PR [#973](https://github.com/AI-agent-assembly/agent-assembly/pull/973)
**Verification:** AAASM-2647 (this report)
**Date:** 2026-06-06

---

## Summary

The fat `aa-ffi-python` and `aa-ffi-node` binding crates have been removed from the
`agent-assembly` Cargo workspace. The thin Node/Python shims now live in the sibling
`node-sdk` / `python-sdk` repos on the pinned `aa-sdk-client` (AAASM-2560 / AAASM-2561),
the runtime is the authoritative enforcement boundary (gate AAASM-2568, merged), and
`aa-security` is extracted (AAASM-2567) — so the in-workspace FFI copies were redundant.

All three acceptance criteria are met.

---

## AC1 — Workspace no longer lists the extracted `aa-ffi-*` members; build measurably smaller

**PASS.**

| Metric | `master` (before) | branch (after) | Delta |
|---|---|---|---|
| `[workspace] members` | 31 | 29 | −2 (`aa-ffi-python`, `aa-ffi-node`) |
| `Cargo.lock` `[[package]]` entries | 884 | 868 | **−16** |

`cargo metadata --no-deps` resolves cleanly. `aa-ffi-python` / `aa-ffi-node` are absent;
`aa-ffi-go` and `aa-sdk-client` are retained.

The −16 lockfile entries are the **pyo3** and **napi** FFI dependency subtrees, now
absent from the workspace dependency graph:

```
aa-ffi-python   aa-ffi-node
pyo3            napi
pyo3-ffi        napi-sys
pyo3-build-config   napi-derive
pyo3-macros         napi-derive-backend
pyo3-macros-backend napi-build
                    ctor
                    libloading
                    nohash-hasher
```

> **Build-time note (perf Epic AAASM-2557).** The stable, reproducible metric for the
> core-workspace shrink is the dependency-graph delta above (−16 packages, −2 members,
> entire pyo3/napi proc-macro + build-script chains gone). Cold wall-clock build time on
> the macOS dev box is too noisy (±2–3× per the AAASM-2557 baseline harness, 69–211 s
> observed) to publish as an authoritative figure; the dep-graph delta is the signal.

`cargo build --workspace` no longer compiles pyo3 (proc-macros + libpython link) or napi
(proc-macros + build script), which were two of the heavier FFI dep chains.

## AC2 — `compat-matrix-check` and all workflows green

**PASS (local) / pending CI.**

- Root `Cargo.toml` is a version-carrying file, so `.ci/check-compatibility-matrix.sh`
  requires `docs/src/compatibility.md` to change in the same PR. Both files are in the
  diff → the gate is satisfied (precedent AAASM-1602 / AAASM-2357). No version bump was
  introduced; the SDK compatibility tables are unchanged.
- `ci.yml` cleaned of the now-dead `--exclude aa-ffi-python` flags (Coverage + Clippy
  jobs) and the `sdk_bench` benchmark line (preserved in `python-sdk` per AAASM-2561).
  YAML validated.
- `codecov.yml`, `sonar-project.properties`, `.github/CODEOWNERS`, `.github/dependabot.yml`
  no longer reference the deleted crates.
- Lefthook gates ran green on the implementation branch: `cargo fmt --all --check`,
  `cargo clippy --all-targets --all-features` (clean across the remaining 29 members),
  `cargo deny check`, and the pre-push `cargo doc --workspace --no-deps`.

The authoritative workflow run is the PR #973 CI; this report records the local result.

## AC3 — No SDK regression (Node/Python/Go native builds against the pinned crates)

**PASS (by construction).**

The SDKs do **not** depend on the deleted in-workspace crates — each consumes the shared
Rust crates from its own repo via the git-SHA pin chosen in the ADR (AAASM-2558 / 2559):

- **Python** (`python-sdk/rust/aa-ffi-python`, AAASM-2561) — thin pyo3 shim over
  `aa-sdk-client`; the deleted `agent-assembly/aa-ffi-python` was the *old* fat copy.
- **Node** (`node-sdk/native/aa-ffi-node`, AAASM-2560) — thin napi shim over
  `aa-sdk-client`; the deleted `agent-assembly/aa-ffi-node` was the *old* reimplementation.
- **Go** (`aa-ffi-go`) — **unchanged and retained**: it builds the C-ABI staticlib
  artifact (`.github/workflows/ffi-go-staticlib.yml`) that go-sdk consumes, so its
  placement in the workspace is correct. No sibling-shim story exists for Go.

Cross-layer/integration coverage is preserved:

- `aa-sdk-client` (the shared client the shims wrap) **stays** a workspace member.
- `workspace.exclude = ["node-sdk"]` and the CI node-sdk checkout/symlink dance **stay**
  (2 checkout steps confirmed in `ci.yml`) — the `aa-integration-tests` `e2e_sdk_node`
  `real_*` tests still build the *sibling* node-sdk thin shim (`pnpm native:build`). The
  AAASM-1602 workaround remains required; removing it would break those e2e tests.

The Node/Python native builds are exercised authoritatively by their own repos' CI
(`pnpm native:build` + `pnpm test`; `uv sync` + `pytest`), already green from AAASM-2560 /
AAASM-2561 against the pinned shared crates.

---

## Scope decisions recorded

The Story description asked to "re-evaluate `aa-ffi-go`'s placement" and "clean up the
`exclude = ["node-sdk"]` workaround … if no longer required". The evaluated outcome:

1. **Keep `aa-ffi-go`** — it is the build site of the Go staticlib artifact, not a
   sibling-repo shim.
2. **Keep `exclude = ["node-sdk"]`** and the checkout dance — still required by the
   `e2e_sdk_node` tests.

Both decisions are documented in the Story/subtask Jira comments and PR #973.

---

## Conclusion

**All acceptance criteria satisfied.** AAASM-2562 completes Epic AAASM-2552: the duplicated
FFI bindings are consolidated into one shared `aa-sdk-client` with thin per-language shims,
and the fat copies are gone from the workspace, shrinking the core-workspace dependency
graph by 16 packages (the full pyo3 + napi chains).
