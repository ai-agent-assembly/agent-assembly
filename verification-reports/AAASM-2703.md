# AAASM-2703 — Verification: remove `aa-ffi-go` from the workspace

Story **AAASM-2703** (Epic AAASM-2552). Subtasks **AAASM-2705** (crate),
**AAASM-2706** (CI/config), **AAASM-2707** (docs/ADR). This is **AAASM-2708**.

Reverses ADR 0002's "Go: aa-ffi-go stays in the monorepo" decision: the thin Go
shim is relocated into the `go-sdk` repo (`native/aa-ffi-go`, AAASM-2704), so the
monorepo hosts no FFI shim — matching the Node (AAASM-2560) / Python (AAASM-2561)
model. Mirrors AAASM-2562's python/node removal.

## How verified

| # | Method |
|---|--------|
| 1 | `cargo metadata --format-version 1` → resolves clean; **no `aa-ffi*` package** in the graph. (A leaf-crate removal — nothing in the workspace depends on `aa-ffi-go`, confirmed via `git grep 'aa-ffi-go' -- '**/Cargo.toml'` — so it cannot break compilation of other crates.) |
| 2 | `git grep -i 'aa-ffi-go\|aa_ffi_go'` over tracked files → only (a) historical changelog rows in `compatibility.md`, (b) the ADR 0002 amendment, and (c) the accurate `aa-sdk-client` module doc-comment naming the three shims. No live build/config/workflow reference. |
| 3 | `mdbook build docs` → succeeds (HTML written), so the doc edits are well-formed. |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| `aa-ffi-go/` gone; not a workspace member; workspace resolves | ✅ Pass | dir deleted; dropped from root `Cargo.toml` members; `Cargo.lock` regenerated; `cargo metadata` shows no `aa-ffi*` |
| `ffi-go-staticlib.yml` deleted; no workflow references aa-ffi-go | ✅ Pass | workflow file removed; `git grep` over `.github/` is clean |
| CODEOWNERS / dependabot / codecov / sonar no longer reference aa-ffi-go | ✅ Pass | all four scrubbed (AAASM-2706) |
| Docs no longer present aa-ffi-go as an in-workspace crate | ✅ Pass | removed from README (table+tree), api-reference, architecture (mermaid+narrative+L1 table), proto comment |
| ADR 0002 amended; compat-matrix gate satisfied | ✅ Pass | amendment banner + revised Go bullets; `Cargo.toml` **and** `docs/src/compatibility.md` both in the PR diff (+ a fresh gate comment) → `.ci/check-compatibility-matrix.sh` green |
| Only historical verification-reports / changelog refs remain | ✅ Pass | see How-verified #2 |

## Notes

- The compat-matrix **SDK labels** (`Go SDK (aa-ffi-go)`) and matrix rows are left
  unchanged, consistent with how AAASM-2646 handled the python/node relocation —
  they are SDK-level labels, not crate-location claims.
- The `aa-sdk-client` doc comment that names `aa-ffi-python`/`aa-ffi-node`/`aa-ffi-go`
  is accurate and intentionally kept: those shims still wrap this crate; they now
  live in their respective SDK repos.

## Outcome

All ACs **pass**. The monorepo no longer hosts any FFI shim; `aa-ffi-go` is fully
removed and its relocation is recorded in ADR 0002 + the compatibility changelog.
Vendoring into go-sdk is the sibling Story **AAASM-2704**.
