# Changelog

All notable changes to **AI Agent Assembly** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1-alpha.5] — 2026-06-03 (pre-release)

> **Not for production use.** Fifth pre-release in the v0.0.1 dry-run
> series. Validates the entire release pipeline end-to-end with all the
> alpha-4 recovery fixes baked into master.

### Why a fresh bump rather than recovering alpha-4

alpha-4 published successfully to 5 of 6 channels (GH Release,
Homebrew, npm, PyPI, ghcr.io). Only crates.io is partially-published:
`aa-core` landed at `0.0.1-alpha.4`, the other 8 crates never
published because `cargo workspaces publish` tripped on dirty-tree
before AAASM-2346's `--allow-dirty` fix.

`gh run rerun --failed` uses the workflow definition at the time of
the original tag push (pre-2346 fix), so re-running cannot pick up
the post-merged improvements. Bumping to alpha-5 with a fresh tag
validates the entire release flow end-to-end with all fixes applied.

### Recovery fixes verified by this tag

* **AAASM-2346 (PR #846)** — `cargo workspaces publish` invocation in
  `release.yml` now passes `--allow-dirty` so the topological publish
  step does not fail on the transient working-tree dirtiness caused by
  the `.ci/strip-for-publish.sh` step that runs right before it.
* **AAASM-2455 (PR #848)** — `smoke-curl-installer` channel `pip`
  invocation pinned to avoid the newest pip surfacing a transient
  dependency-resolver bug on the smoke job. (Superseded by AAASM-2457
  which restructured the smoke matrix.)
* **AAASM-2456 (PR #849)** — New `docs/release/RUNBOOK.md` operator
  playbook plus `scripts/release-readiness.sh` (10-check pre-tag gate)
  and `release-status-aggregator` workflow job that posts a single
  per-channel verdict comment on each GH Release.
* **AAASM-2457 (PR #867)** — Smoke matrix restructured: SDK smoke jobs
  dropped from `release.yml` (each SDK repo owns its own publish-time
  smoke) and a new `cargo install aasm --version <tag>` smoke channel
  added. Net 6 → 6 smoke channels with sharper accountability.
* **AAASM-2459 (python-sdk PR #75)** — `release-python.yml` now syncs
  `pyproject.toml` `version` AND `agent_assembly/__init__.py`
  `__version__` to the dispatched tag via a shared composite action
  (`.github/actions/sync-version/`); previously only `pyproject.toml`
  was bumped, leaving `__version__` stuck on the previous alpha.
* **AAASM-2460 (python-sdk PR #76)** — Deleted broken upstream
  Chisanan232 personal bumper workflows that were duplicating
  release-time version sync and racing the new composite action.

### Companion fixes in SDK repos

* **node-sdk PR #67 (AAASM-2344)** — `package.json` `repository.url`
  lowercased to satisfy npm registry strict-mode validation that
  alpha-4's mixed-case URL had tripped.
* **python-sdk PR #74 (AAASM-2345)** — Multiple `release-python.yml`
  Stage-step bugs fixed (artifact name collision, missing env var
  hoist, wheel-build job ordering).

### Install

```bash
# Native binaries (Homebrew + GH Release tarballs)
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
curl -L https://github.com/ai-agent-assembly/agent-assembly/releases/download/v0.0.1-alpha.5/aasm-aarch64-apple-darwin.tar.gz | tar xz

# crates.io — first end-to-end validated publish of all 9 crates
cargo install aasm --version 0.0.1-alpha.5

# Container images
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.5
docker pull ghcr.io/ai-agent-assembly/python:3.14-slim

# Language SDKs
pip install --pre agent-assembly==0.0.1a5
npm install @agent-assembly/sdk@0.0.1-alpha.5
go get github.com/ai-agent-assembly/go-sdk@v0.0.1-alpha.5
```

### Behaviour delta on the crates.io `aasm` binary

Unchanged from alpha-4. The published `aasm` binary omits the
`aasm run <tool>` and `aasm tools` subcommands while the dev-tool
subsystem is being finished. Local source builds
(`cargo build -p aa-cli`) expose the full surface unchanged. See
`docs/src/compatibility.md` for the restoration recipe.

### Refs

* This tag's prep: `AAASM-2461`
* Predecessor: `AAASM-2343` (alpha-4)
* Parent Story: `AAASM-1234` (F118 release-notes authoring)

---

## [0.0.1-alpha.4] — 2026-06-02 (pre-release)

> **Not for production use.** Fourth pre-release in the v0.0.1 dry-run
> series. Verifies the three release-infra fixes that landed since alpha-3,
> the most significant being that `cargo install aasm` now works for the
> first time.

### Release-infra fixes verified by this tag

* **AAASM-2340 (PR #843)** — `cargo install aasm` works for the first
  time. The workspace is published to crates.io in topological order
  via [cargo-workspaces](https://github.com/pksunkara/cargo-workspaces).
  Nine crates publish: `aa-core`, `aa-proto`, `aa-runtime`,
  `aa-ebpf-common`, `aa-ebpf`, `aa-proxy`, `aa-sandbox`, `aa-gateway`,
  `aa-cli`. Sibling content needed by the binary is bundled into crate
  tarballs through `_embedded/` mirrors — the dashboard SPA
  (`aa-cli/_embedded/dashboard/dist/`), the gRPC proto contract
  (`aa-proto/_embedded/proto/`), and the BPF probe source
  (`aa-ebpf/_embedded/aa-ebpf-probes/`, compiled at install time when
  nightly + `bpfel-unknown-none` are present, otherwise graceful stubs).
  New `aasm sandbox run` / `aasm sandbox info` subcommands expose the
  WASI tool-execution sandbox (highlight ④ of the product spec) to OSS
  users. The dev-tool surface (`aasm run` / `aasm tools` + the three
  `aa-devtool*` crates) is held back from this alpha via a build-time
  strip script (`.ci/strip-for-publish.sh`) driven by
  `strip-for-publish:begin` / `:end` markers; sources remain in the
  repo and re-publish is a one-line workflow change once the subsystem
  ships.

* **AAASM-2339 (PR #841)** — `smoke-curl-installer` channel gated with
  `if: false` until `get.agent-assembly.io` is provisioned. Smoke
  matrix now runs 6 green channels per release. Wiring preserved so
  re-enabling at v0.1+ is one flag flip.

* **AAASM-2336 (PR #842 + node-sdk#66)** — `release.yml` gains a
  `notify-downstream` job that fires `repository_dispatch` (event-type
  `agent-assembly-release-published`) to BOTH node-sdk and python-sdk
  after the GH Release object is published. node-sdk's `release-node`
  listens for the dispatch and drops its retry-with-backoff workaround
  (AAASM-2328 superseded). python-sdk's listener (AAASM-2342 / PR
  python-sdk#73) lands in the same release cycle.

### CI performance work (AAASM-2340 follow-up)

* `aa-integration-tests/tests/common/cli.rs` adds an `aasm_command()`
  helper that honours `AASM_BIN_PATH`; CI workflows pre-build `aasm`
  once and export the path to nextest, skipping per-test `cargo run`
  overhead. Cut the Test job from ~60 min → ~9 min, Coverage from
  ~60 min+ → ~18 min, SonarCloud from failing → ~22 min SUCCESS,
  and both Integration tests jobs from 20-min timeout → ~10–15 min.

### Install

```bash
# NEW — works for the first time
cargo install aasm --version 0.0.1-alpha.4

# Existing channels (homebrew, docker, language SDKs)
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.4
pip install --pre agent-assembly==0.0.1a4
npm install @agent-assembly/sdk@0.0.1-alpha.4
go get github.com/ai-agent-assembly/go-sdk@v0.0.1-alpha.4
```

### Behaviour delta on the published `aasm` binary

The crates.io-published `aasm` binary omits the `aasm run <tool>` and
`aasm tools` subcommands while the dev-tool subsystem is being
finished. Local source builds (`cargo build -p aa-cli`) expose the
full surface unchanged. See `docs/src/compatibility.md` for the
restoration recipe.

### Refs

* Verify: `AAASM-2343` (this tag's prep) + the standing AAASM-2340 ACs
  (clean-machine `cargo install aasm` smoke test, publish-crates
  pipeline observed on this real tag)
* Predecessor: `AAASM-2312` (alpha-3)
* Companion: `AAASM-2342` (python-sdk repository_dispatch listener)

---

## [0.0.1-alpha.3] — 2026-06-01 (pre-release)

> **Not for production use.** Third pre-release in the v0.0.1 dry-run
> series. Verifies the 3 release-infra fixes that landed since alpha-2.

### Release-infra fixes verified by this tag

* **AAASM-2188 (PR #832)** — Docker matrix parallel cargo cache race
  (`File exists (os error 17)` when unpacking same crate concurrently).
  Fixed by per-Dockerfile cache `id` + `sharing=locked` on all 6
  language Dockerfiles.
* **AAASM-2189 (python-sdk#68)** — `Release Python SDK` maturin wheel
  builds missing protoc. Fixed by downloading official protoc 32.1
  binary in `before-script-linux` with SHA256 verification + retry.
* **AAASM-2190 (node-sdk#59)** — `release.yml` `pnpm publish` E402
  for scoped package. Fixed by adding `--access public`.

### Still unfixed (separately tracked, not blocking this dry-run)

* `Publish to crates.io` — AAASM-2094 deeper issue (internal crates
  not on crates.io). Architectural decision pending under AAASM-1200.
* `node-sdk release-node` cross-repo race (release not found).
* `smoke-test.yml` Docker pull uses old namespace.
* 6× AAASM-1253 smoke-test findings.

### Install

```bash
cargo install aasm --version 0.0.1-alpha.3
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.3
```

### Refs

* Verify: `AAASM-2316`
* Predecessor: `AAASM-2107` (alpha-2)

---

## [0.0.1-alpha.2] — 2026-05-28 (pre-release)

> **Not for production use.** Second pre-release in the v0.0.1 dry-run series.
> Continues exercising the release CD pipeline while verifying the 6
> release-infra fixes that landed since alpha-1.

### Release-infra fixes verified by this tag

* **AAASM-2093** — `docker.yml` language images now push to the correct
  `ghcr.io/ai-agent-assembly/` namespace (was `ghcr.io/agent-assembly/`,
  which caused `denied: not_found: owner not found`).
* **AAASM-2094** — `aa-cli/Cargo.toml` workspace path-deps now carry
  explicit `version` literals so `cargo publish -p aa-cli` passes
  manifest verification (the deeper crates.io dep-resolution issue is
  tracked separately; the publish job will still fail at that step).
* **AAASM-2095** — `release.yml` now sets `prerelease: true` on the
  GitHub Release object for SemVer pre-release tags (`-alpha.*`,
  `-rc.*`).
* **AAASM-2096** — F119 smoke-test now chains off `release.yml` via
  `workflow_call` instead of `release: published` (which was blocked
  by the GITHUB_TOKEN downstream-trigger restriction).
* **AAASM-2097** (node-sdk) — `pnpm publish` now derives the npm
  dist-tag from the SemVer pre-release identifier (`--tag alpha` for
  `-alpha.*`, `--tag rc` for `-rc.*`, etc.) instead of hardcoded
  `--tag alpha`.
* **AAASM-2098** (node-sdk) — `pnpm-lock.yaml` no longer drifts when
  the workspace version bumps; `optionalDependencies` use the
  `workspace:*` protocol.

### What remains unfixed (still expected to surface on alpha-2)

* **crates.io publish** — still fails at dep resolution (internal
  crates not on crates.io). Architectural decision under AAASM-1200.
* **F119 smoke-test channel jobs** — the 6 AAASM-1253 findings (PyPI
  name, curl endpoint, Docker tag scheme, Homebrew tap GA, smoke-test
  PyPI name, curl pipefail) are still pending.

### Install

```bash
cargo install aasm --version 0.0.1-alpha.2
brew install ai-agent-assembly/homebrew-agent-assembly/aasm  # version-pinned to alpha.2 via tap formula
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.2
```

### Refs

* Verify ticket: `AAASM-2107` — alpha-2 cross-repo release verification
* Predecessor: `AAASM-1936` — alpha-1 release-pipeline verification

---

## [0.0.1-alpha.1] — 2026-05-25 (pre-release)

> **Not for production use.** This is the first pre-release of AI Agent Assembly,
> published to **dry-run the full v0.0.1 distribution pipeline** before cutting the
> v0.0.1 GA tag. Functional scope is identical to the upcoming v0.0.1 GA — this
> release does not add features beyond what GA will ship.

### Pre-release purpose

- Verify the cross-repo release workflows (`agent-assembly`, `python-sdk`,
  `node-sdk`, `go-sdk`) function end-to-end before cutting v0.0.1.
- Exercise the F119 smoke-test workflow (`.github/workflows/smoke-test.yml`)
  against real published artifacts.
- Surface any release-infrastructure bugs (Homebrew tap location, PyPI package
  name, curl installer endpoint, GHCR tag scheme, secret configuration) in a
  low-stakes channel before the GA release.

### Channel-specific dist-tag behaviour

Pre-release artifacts publish only under pre-release tags on each channel, so
unpinned `npm install` / `pip install` continue to resolve to the previous GA
version (or skip pre-releases entirely):

| Channel       | How to install the alpha-1 explicitly                         |
| ---           | ---                                                           |
| npm           | `npm install @agent-assembly/sdk@0.0.1-alpha.1` (or `@alpha`) |
| PyPI          | `pip install --pre agent-assembly-python==0.0.1a1`            |
| crates.io     | `cargo install aasm --version 0.0.1-alpha.1`                  |
| Docker (GHCR) | `docker pull ghcr.io/agent-assembly/python:0.0.1-alpha.1`     |
| Homebrew      | tap formula not auto-updated on pre-releases                  |

For the GA release scope, see the upcoming [0.0.1] entry, which will be authored
under AAASM-1247 once the alpha-1 dry-run passes and the GA tag is cut.

[0.0.1-alpha.1]: https://github.com/ai-agent-assembly/agent-assembly/releases/tag/v0.0.1-alpha.1
