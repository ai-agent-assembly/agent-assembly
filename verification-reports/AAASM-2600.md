# AAASM-2600 — Verification: Docker/FFI build-light on PR

Verifies Story **AAASM-2600** (Docker/FFI PR-time build reduction).
Implementation in subtask **AAASM-2605** (PR #945); this subtask (**AAASM-2606**)
checks it against the Story acceptance criteria.

## Scope correction (recorded during pickup)

The amd64-on-PR / multi-arch-on-tag split was **already present** before this Story
(`docker.yml` `platforms: … 'linux/amd64,linux/arm64' || 'linux/amd64'`; `push:` and
GHCR login already tag-gated). So the implemented scope is the *remaining* PR waste:
QEMU-step gating + PR-time matrix reduction.

## How verified

| # | Method |
|---|--------|
| 1 | `yaml.safe_load` on both workflows after the edits — parse clean; jobs = `docker`: `build-and-push` / `prep` / `build-and-push-language-images`; `ffi-go`: `prep` / `build-aa-ffi-go`. |
| 2 | Ran the `prep` `jq` selection locally for both event types. |
| 3 | Confirmed publish path unchanged: `push:` + GHCR login remain `if: …refs/tags/v…`. |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| `aa-runtime` PR builds amd64-only, one version per language | ✅ Pass | `platforms` already amd64-on-PR; `Set up QEMU` now `if: …tags/v` (both jobs); `prep` `fromJSON` → PR matrix = python `3.14-slim` + go `1.26-alpine` (the `is_latest` pins). Smoke step retained. |
| `v*` tag builds + pushes full multi-arch + full matrix | ✅ Pass | `prep` returns the full 6-entry matrix on non-PR; `platforms` → `linux/amd64,linux/arm64`; `push:`/login tag-gated (unchanged). |
| `aa-ffi-go` PR builds only `x86_64-unknown-linux-gnu`; tag/master full 4-target | ✅ Pass | `prep` `jq select(.target=="x86_64-unknown-linux-gnu")` → 1 entry on PR; full 4 on push. Verified locally (PR→1, tag→4). |
| No publish on PR (unchanged) | ✅ Pass | docker GHCR push/login still tag-gated; ffi-go only `upload-artifact`. |
| Both workflows parse as valid YAML | ✅ Pass | `yaml.safe_load` clean on both. |
| Measured PR wall-clock drop | ⏳ Post-merge | Compare a `docker`/`ffi-go`-triggering PR run before vs after: docker language images 6→2, ffi-go targets 4→1 (drops macOS ×2 + arm cross), QEMU setup removed on PR. |

## Outcome

- Structural ACs: **pass**; jq filtering proven locally. Wall-clock delta is observed on
  the first post-merge PR that touches `aa-runtime`/`docker` or `aa-ffi-go`.
- No gaps found; nothing filed back to AAASM-2605.
