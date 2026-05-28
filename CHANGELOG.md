# Changelog

All notable changes to **AI Agent Assembly** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.0.1-alpha.1]: https://github.com/AI-agent-assembly/agent-assembly/releases/tag/v0.0.1-alpha.1
