# Changelog

All notable changes to **AI Agent Assembly** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
