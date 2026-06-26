# ADR 0009: Versioned Base-Image Tags & Reproducible SDK Pinning

**Status**: Proposed
**Date**: 2026-06
**Ticket**: [AAASM-3766](https://lightning-dust-mite.atlassian.net/browse/AAASM-3766) (Story [AAASM-3765](https://lightning-dust-mite.atlassian.net/browse/AAASM-3765))

---

## Context

We publish nine "governed" language base images to GHCR — `python`, `node`, and `go`,
each in three runtime variants — built by `.github/workflows/docker.yml`. Each image
bundles the `aasm` CLI (built from this repo's source at the release tag) with the
matching language SDK, so a developer's agent runs governed out of the box.

Two properties make these images **non-pinnable** and **non-reproducible** today:

1. **The tag carries no product-version axis.** Language images are tagged only by
   language runtime — `python:3.14-slim`, `node:24-slim`, `go:1.26-alpine` — plus a
   moving `:latest`. Every release **overwrites the same tag in place**, so there is
   only ever *one* `python:3.14-slim` and it always reflects the newest release. A
   developer who wants "Python 3.14 + core `v0.0.1-beta.3`" cannot get it — they are
   forced onto whatever the latest release baked in. This is inconsistent with
   `aa-runtime`, which *is* product-versioned (`v0.0.1-beta.1 … rc.1` + `latest`).

2. **The SDK floats even within a single build.** Python installs from
   `git+…python-sdk.git` (master HEAD), Node from `@agent-assembly/sdk@beta`, Go from
   `…/go-sdk@latest`. Rebuilding an image yields a different SDK. The images are not
   reproducible to any release.

A complicating fact: the SDKs **version independently** of the core program and of
each other (at time of writing: core `~beta.4`/`rc.1`, python `0.0.1b5`/`0.0.2`, node
`@beta → 0.0.1-beta.5`, go `v0.0.1-beta.3`). So "install the SDK version that equals
the core tag" by string match is wrong — the core↔SDK mapping must be **explicit**.

## Decision

**1. Add an immutable product-version tag axis to the language images**, keeping the
existing moving tags. On a `v*` tag push, each language image is published as:

| Tag | Mutability | Purpose |
|---|---|---|
| `<lang>:<runtime>-<core-version>` (e.g. `python:3.14-slim-v0.0.1-beta.4`) | **immutable** | pin this for reproducible CI |
| `<lang>:<runtime>` (e.g. `python:3.14-slim`) | moving | newest release for that runtime |
| `<lang>:latest` (is_latest runtime only) | moving | newest runtime + newest release |

The `<core-version>` coordinate is the `aa-runtime`/release tag (`github.ref_name`),
so all governed images for a release share one version coordinate.

**2. Make the baked-in SDK reproducible — and require the pin.** Each Dockerfile takes
a **required** `ARG SDK_VERSION` and installs that exact released SDK from the language
registry (`pip install agent-assembly==<v>`, `npm install -g @agent-assembly/sdk@<v>`,
`go install …/go-sdk/...@<v>`). There is **no floating fallback** — a build with no
`SDK_VERSION` fails fast with a clear error. This is deliberate: the **core version is
the developer's selectable axis** (the image tag + the bundled `aasm` CLI) and the SDK
is a *dependent* value pinned to the compatible release, so every image is an explicit,
reproducible `(core, SDK)` pair. Dropping the fallback also makes the install path
**identical across Python, Node, and Go** — the earlier per-language defaults diverged
(git-master / `@beta` / `@latest`), partly because npm's `latest` dist-tag is stale; a
required pin sidesteps all of that. `docker.yml` and the smoke runner both resolve the
pin from the manifest and pass it.

**3. Resolve the SDK pin from an explicit source of truth.** A new
`docker/sdk-versions.json` maps each language to its pinned SDK release:

```json
{ "sdk": { "python": "0.0.1b5", "node": "0.0.1-beta.5", "go": "v0.0.1-beta.3" } }
```

`docker.yml` reads it with `jq` and passes `SDK_VERSION` via `build-args` for **both**
PR and tag builds (so CI validates the real pinned image). The seed values equal the
SDKs' current published releases, so pinning is **behaviour-neutral today** — it only
freezes what floating already resolves. The manifest is kept in step with
`docs/src/compatibility.md` (the human-facing matrix) and schema-validated in CI.

**4. Validate every image in CI.** On PRs touching `docker/**`, `docker.yml` builds the
**full nine-image matrix** (previously a reduced `is_latest`-only set on PR) and the
post-build smoke asserts each image's installed SDK version equals the pin (`go` is
validated by the build itself, which fails on a bad `@<version>`).

## Consequences

- **Positive:** developers can pin governed images to an immutable release coordinate;
  builds are reproducible; the language images become consistent with `aa-runtime`; CI
  proves all nine images build and carry the intended SDK.
- **Cost:** more tags in GHCR (runtime × release), and the full-matrix PR build is more
  expensive than the reduced set — mitigated by GHA layer caching (`type=gha`) and the
  `docker/**` path filter. The extra immutable tags are pushed only on release.
- **Maintenance:** `docker/sdk-versions.json` must be bumped when an SDK release that
  ships in the images changes; the compat-matrix CI gate is extended to enforce it.
- **Cross-repo ordering:** because images pin *published* SDK releases, the pinned SDK
  version must already be published before the core release builds its images
  (consistent with the existing release fan-out ordering).
- **Not addressed here:** automated derivation of the manifest from per-SDK release
  feeds (cross-repo CI) — left as a follow-up; today the manifest is hand-maintained
  alongside the compatibility matrix.
