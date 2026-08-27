# Per-language Docker base-image smoke harness (AAASM-3524)

A real (not mock) smoke harness that verifies the **9 published per-language base
images** — `ghcr.io/ai-agent-assembly/{python,node,go}:<version>` — actually run a
minimal agent **with no manual config**, against a **real `aa-runtime` sidecar**,
re-runnable per release.

It goes beyond what `.github/workflows/docker.yml` already does (build-time
`aasm --version` + a bare SDK import). This harness builds each image, drops a
minimal agent **onto** it with nothing but the agent source added, brings up the
governance compose stack (agent + `aa-runtime` sharing the IPC socket), and
asserts the agent runs clean.

## The image matrix

Single source of truth: [`images.json`](./images.json) (mirrors the publish
matrix in `docker.yml`). 3 languages × 3 versions = 9 base images:

| Lang | Versions | Dockerfile |
|---|---|---|
| python | 3.14-slim (`:latest`), 3.13-slim, 3.12-slim | `docker/Dockerfile.python-3.*-slim` |
| node | 24-slim (`:latest`), 22-slim, 20-slim | `docker/Dockerfile.node-*-slim` |
| go | 1.26-alpine (`:latest`), 1.25-alpine, 1.24-alpine | `docker/Dockerfile.go-1.*-alpine` |

## What it verifies, per image

Each image is verified across tiers, and the harness reports **honestly** which
tier was actually exercised — it never fakes a green for something the base image
cannot prove today.

1. **Image builds** — `docker build -f docker/Dockerfile.<...>` succeeds (or
   `docker pull` in release mode). The Dockerfile's own build-time asserts
   (`aasm --version`, SDK import) must pass.
2. **Image hygiene** — `aasm --version` runs on the image; the toolchain + SDK
   are present with no extra config. (The language images intentionally inherit
   the upstream runtime default entrypoint — python/node REPL, go — there is no
   custom `ENTRYPOINT`/`CMD`, by design.)
3. **Agent runs with no manual config (Tier A — real, always asserted)** — a
   minimal per-language agent (`agents/<lang>/`) is COPYed onto the base image
   with **no pip/npm install, no PYTHONPATH/package.json, no source mount**. It
   imports the SDK as a developer would, runs `init_assembly(...)` / `withAssembly`
   / `WrapTools`, performs one governed tool call, and exits 0. A non-zero exit or
   a missing SDK / missing `aasm` binary fails the image.
4. **Governance path to a real `aa-runtime` (Tier B — real where provable)** —
   the compose stack runs the authoritative `aa-runtime` sidecar (built from
   `aa-runtime/Dockerfile`) loading [`policy.toml`](./policy.toml), sharing
   `/tmp` (and so the UDS `/tmp/aa-runtime-<AA_AGENT_ID>.sock`) with the agent.
   The agent opens the **genuine native transport** to the runtime **when the
   image ships the SDK's compiled native client**. See "Governance path" below
   for why `transport=offline` is the honest result for the base images today.
5. **Governed-call enforcement (Tier C — real, AAASM-5886)** — a standalone probe
   (`aa-sdk-client/examples/governed_call_probe.rs`, built into
   `probe/Dockerfile.probe`) drives one real `TOOL_CALL` (expect ALLOW) and one
   real `PROCESS_EXEC` (expect DENY) `CheckAction` through the running,
   containerized `aa-runtime` sidecar over the same shared UDS, and the runner
   fails the leg if either lands on the wrong decision. See "Governed-call
   enforcement" below for why this doesn't need to wait on the base image's own
   SDK build.

## Governance path — why `transport=offline` is honest, not a cop-out

The "real governance path" the ticket asks for is `SDK → aa-runtime → core`. The
harness wires that path for real (the sidecar is the real `aa-runtime` binary,
reachable over the shared UDS). But whether the agent **dials** that socket
depends on the SDK build that the *base image* ships, and that varies per image.
(Each image installs the pinned `SDK_VERSION` when set, else the latest stable /
latest pre-release default — see ADR 0009.)

- **Python** installs the published `agent-assembly` SDK via `pip`. Where a native
  wheel exists for the image's interpreter (e.g. the `cp312` manylinux wheel),
  `agent_assembly._core` **is** present and the agent *attempts* live transport;
  where only the pure-Python sdist applies (e.g. 3.13 / 3.14 today), it stays
  offline. Either way it ends up `transport=offline`: the live SDK→runtime IPC
  path is a known, tracked gap (**AAASM-3000**, xfail'd at the SDK level in
  **AAASM-3172**), so the agent degrades honestly to offline rather than failing.
- **Node** installs the published `@agent-assembly/sdk` from npm — no bundled
  native binding wired to a UDS, so it stays offline.
- **Go** `go install`s the pure-Go SDK — without the `aa_ffi_go` cgo
  `libaa_ffi_go`, the SDK uses a **simulated** UDS fallback that never dials the
  socket.

So the agents end up `transport=offline` and say so in `transport_note`, rather
than asserting a live connection that cannot exist. The harness **still brings up
the real runtime and waits for its socket**, so once the live IPC path lands
(AAASM-3000), the Python agent's existing `RuntimeClient` call flips to
`transport=live` — mirroring the live integration harness
`tests/live/test_e2e_python.py`.

## Sidecar startup — AAASM-3527 (fixed)

An early run of this harness surfaced a real defect: the `aa-runtime` image's
`ENTRYPOINT` path `/aa-runtime` was built as a **directory**, not the binary, so
the container failed with `exec: "/aa-runtime": is a directory` and the sidecar
never started. Filed and fixed as **AAASM-3527** (under Epic AAASM-3198) — the
Dockerfile now stages the binary through a path that cannot collide with the
copied-in source tree. A leg where the socket still doesn't bind is now treated
as a real failure (`SIDECAR_UNREACHABLE`), not a tolerated known-gap.

## Governed-call enforcement — AAASM-5886

Tier A/B above prove the base image's *own* SDK build runs and (where it ships a
native client) can dial the sidecar. Neither proves the sidecar actually
**enforces** anything — the gap AAASM-5886 (a follow-up to AAASM-3524) found.
Since the published base images don't yet ship the SDK's native `_core`
transport (AAASM-1202), waiting on the base image's own agent to prove
enforcement would leave Tier C permanently unprovable through no fault of the
sidecar. Instead, `governed_call_probe` (`aa-sdk-client/examples/`) is a
standalone client speaking the exact same handshake + `CheckAction` wire the SDK
uses (mirroring `aa-integration-tests/tests/e2e_runtime_gateway_deny.rs`), run as
a throwaway container against the compose stack's shared UDS. It sends a
`TOOL_CALL` (not in `policy.toml`'s `blocked_actions` — must come back ALLOW) and
a `PROCESS_EXEC` (the fixture's restricted action — must come back DENY); a
wrong decision on either fails the leg. This proves the **containerized
`aa-runtime` sidecar's own enforcement**, independent of what any particular
language's published SDK build currently ships.

The two product bugs that used to block this (**AAASM-3000** SDK⇄runtime IPC
deadlock, **AAASM-3021** SDK pre-execution check unwired) are both fixed; only
**AAASM-3172** (flipping the *SDK-level* python/node/go behavioral xfails to hard
asserts once a published SDK release carries the fix) remains open, and it does
not block this probe — the probe never goes through those SDKs' wrapper code.

## What was actually validated (and what is pending)

| Check | Status |
|---|---|
| `aa-runtime` sidecar image builds and starts | ✅ (AAASM-3527 fixed) |
| Base images build from `docker/Dockerfile.*` | ✅ exercised locally (go 1.26 confirmed end-to-end; the other 8 build the same two-stage way, gated only by Docker VM disk — see below) |
| `aasm --version` on the image (hygiene) | ✅ |
| Tier A — minimal agent runs with no manual config, clean exit | ✅ |
| Tier B — live `SDK → aa-runtime` transport from the base image's own agent | ⏳ base images ship no native client yet (AAASM-1202); honestly reported `transport=offline` |
| Tier C — governed-call enforcement by the containerized sidecar | ✅ real ALLOW + real DENY via `governed_call_probe` (AAASM-5886) |

The full 9-image sweep on a single machine is **disk-bound**: each base image's
stage 1 rebuilds the `aasm` Rust CLI from source (multi-GB target dirs), so the
Docker VM can hit `No space left on device` running all 9 back-to-back. In CI the
GHA build cache dedups the `aasm-builder` stage across the matrix, so this is a
local-only constraint — prune between legs (`docker buildx prune -af`) or run
languages one at a time.

## Running it

Prerequisites: `docker` (with the compose plugin), `jq`. The `aa-runtime` sidecar
is built from source the first time (a Rust release build — minutes), then reused.

```bash
# One image (build from docker/, the pre-publish path):
docker/smoke/run-smoke.sh --lang go --version 1.26-alpine

# All 9 images:
docker/smoke/run-smoke.sh --all

# Post-publish: pull the real GHCR tags instead of building (after a v* release):
IMAGE_MODE=pull GHCR_TAG=v0.0.1 docker/smoke/run-smoke.sh --all

# Keep the compose stack up for debugging:
KEEP_STACK=1 docker/smoke/run-smoke.sh --lang python --version 3.14-slim
```

Exit code is non-zero if any image fails Tier A, hygiene, the build, sidecar
startup, or the governed-call probe (AAASM-5886).

The `aa-runtime` sidecar is built once and **reused if already present** (so
`--all` and CI don't rebuild it per image). To force a fresh sidecar build after
changing `aa-runtime/` source, remove the cached tag first:
`docker rmi aa-runtime:smoke`.

## In CI

[`.github/workflows/docker-image-smoke.yml`](../../.github/workflows/docker-image-smoke.yml)
runs the 9-image matrix (read from `images.json`) on PRs touching `aa-runtime/**`
or `docker/**`. It builds `aa-runtime` once, shares it as an artifact, and runs
one matrix leg per image. A **post-publish GHCR pull-smoke** (the missing
AAASM-1226 job referenced by `docker.yml`) is the natural follow-up; the runner
already supports it via `IMAGE_MODE=pull`.

## Files

| Path | Role |
|---|---|
| `images.json` | The 9-image matrix (shared by the runner + CI) |
| `run-smoke.sh` | The runner: build/pull → compose up → run agent → assert → teardown |
| `docker-compose.smoke.yml` | Parameterized agent + `aa-runtime` sidecar stack |
| `policy.toml` | Allow/deny enforcement policy mounted into the sidecar |
| `agents/<lang>/agent.*` | Minimal per-language agent run ON the base image |
| `agents/<lang>/Dockerfile.agent` | Overlay that adds ONLY the agent onto the base image |
| `probe/Dockerfile.probe` | Builds `governed_call_probe` (AAASM-5886) — the real allow/deny assertion |
| `../../aa-sdk-client/examples/governed_call_probe.rs` | The probe's source — real handshake + `CheckAction` wire |

## Reproducibility — pinned vs moving sources

The base images install SDKs from **moving** sources (`python-sdk.git` HEAD,
npm `@beta`, go `@latest`), so a green run reflects those at build time. Where the
harness controls a version it pins it: the Go agent's `go.mod` pins the go-sdk to
`v0.0.1-beta.2` (the version `agent-assembly-examples/go` uses). The Python/Node
agents cannot pin the in-image SDK (the image chose the source); the harness
records the resolved versions in the run rather than pinning them.
