# Verification Report — AAASM-2559

**Story:** 🔧 (agent-assembly) Make shared crates (`aa-core`/`aa-proto`/`aa-security`/`aa-sdk-client`) pinnable for SDK repos
**Epic:** AAASM-2552 — SDK security boundary + FFI consolidation (Story 5 of 9)
**Component / repo:** `agent-assembly`
**Date:** 2026-06-06

## Summary

The thin per-language SDK shims (`python-sdk`, `node-sdk`) consume four Rust
crates from **outside** this monorepo: `aa-core` (wire types), `aa-proto`
(generated protobuf/gRPC), `aa-security` (advisory preflight), and
`aa-sdk-client` (UDS transport + `AssemblyClient` lifecycle). The distribution
mechanism chosen in ADR 0002 (AAASM-2558) is a **git SHA pin** — crates.io was
rejected, and a bare branch name does not resolve once a crate consumes the
dependency, so a full SHA is required.

This Story formalises that mechanism for all four crates and adds a regression
guard so a future path-coupling change cannot silently break the SDK repos. It
is **purely additive**: no crate's public surface changes, and no SDK-side
scanning is removed, so the Epic's boundary-first gating invariant is unaffected.

Delivered as 3 stacked subtasks, one PR each (all base `master`):

| Subtask | PR | Scope |
|---|---|---|
| AAASM-2637 | #963 | `scripts/standalone-build-smoke.sh` + `make standalone-smoke` |
| AAASM-2638 | #965 | `crate-pinnability-smoke.yml` CI workflow + `aa-sdk-client` git-pin declaration + *Consuming the Shared Crates* docs guide |
| AAASM-2639 | (this) | Acceptance verification + this report |

## Acceptance criteria

### AC1 — An external repo can depend on a specific version/SHA of each shared crate

**Met.** All four crates resolve as git-SHA-pinned dependencies:

- `scripts/standalone-build-smoke.sh` builds a throwaway consumer for each crate
  with `<crate> = { git = "file://<clean-clone>", rev = "<HEAD-sha>", package = "<crate>" }`
  and asserts the build succeeds — see the AC2 run below.
- This is already proven in production for two of the four: `python-sdk`'s
  `rust/aa-ffi-python/Cargo.toml` pins both crates at an exact SHA —

  ```toml
  aa-core  = { git = "https://github.com/ai-agent-assembly/agent-assembly.git", rev = "ed4aa11a8c1d1ce1e6f96b08cf2179fd772099b2", package = "aa-core", features = ["serde"] }
  aa-proto = { git = "https://github.com/ai-agent-assembly/agent-assembly.git", rev = "ed4aa11a8c1d1ce1e6f96b08cf2179fd772099b2", package = "aa-proto" }
  ```

- `aa-sdk-client` is `publish = false` (distributed only via the git pin, never
  to crates.io); `publish = false` does not block a git dependency, so the crate
  is fully pinnable. Its manifest note now records this explicitly.

### AC2 — Each shared crate builds from a clean checkout outside the agent-assembly workspace

**Met.** The smoke clones HEAD into a temp dir (committed files only — exactly
what `cargo` fetches for a git dependency, so uncommitted working-tree files
never leak) and builds each crate from a consumer whose own `[workspace]` table
detaches it from the agent-assembly workspace. Run at HEAD `76220fce`:

```
AAASM-2559 standalone-build smoke
  HEAD:  76220fce9fc9c17a6b59b3cdf54d11e66be2a82a
  crates: aa-core aa-proto aa-security aa-sdk-client

==> aa-core:        ✓ builds standalone (git pin, outside the workspace)
==> aa-proto:       ✓ builds standalone (git pin, outside the workspace)
==> aa-security:    ✓ builds standalone (git pin, outside the workspace)
==> aa-sdk-client:  ✓ builds standalone (git pin, outside the workspace)

✓ all 4 shared crates build standalone at 76220fce9fc9c17a6b59b3cdf54d11e66be2a82a
```

Exit code: `0`. Workspace inheritance (`version.workspace`, `[lints] workspace`,
`dep = { workspace = true }`) and `aa-proto`'s `build.rs` proto inputs (committed
at the workspace root, mirrored to `_embedded/` at build time) all resolve
through the git checkout — the external consumer reproduces none of it.

### AC3 — Standalone-build smoke check wired into CI

**Met.** `.github/workflows/crate-pinnability-smoke.yml` runs
`scripts/standalone-build-smoke.sh` on `pull_request` and `master` `push`,
path-scoped to the four shared crates, `proto/`, the script, and the workflow
itself:

```
paths:
  - "aa-core/**"
  - "aa-proto/**"
  - "aa-security/**"
  - "aa-sdk-client/**"
  - "proto/**"
  - "Cargo.toml"
  - "Cargo.lock"
  - "scripts/standalone-build-smoke.sh"
  - ".github/workflows/crate-pinnability-smoke.yml"
```

The job installs `protobuf-compiler` (required by `aa-proto`'s `build.rs`), the
stable toolchain, and the shared rust-cache, then runs the smoke. A regression
that breaks external consumption of any shared crate fails this check.

## Conclusion

All three acceptance criteria are met. The four shared crates are consumable as
git-SHA-pinned dependencies from a clean checkout outside the workspace, and a
CI guard (the *Crate Pinnability Smoke* workflow) prevents path-coupling
regressions. Story AAASM-2559 is complete.
