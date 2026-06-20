# release-validate-channels — EXAMPLES

A complete worked run of the `release-validate-channels` skill against real
channel state, so the canonical filled-in shape of the output is on record.
The lean overview and boundaries live in [SKILL.md](SKILL.md); the full
per-channel probe commands live in [REFERENCE.md](REFERENCE.md).

## Contents

- [Worked example — v0.0.1-alpha.9 (2026-06-14)](#worked-example--v001-alpha9-2026-06-14)
  - [1. GitHub Release](#1-github-release)
  - [2. crates.io (sparse-index)](#2-cratesio-sparse-index)
  - [3. npm](#3-npm)
  - [4. PyPI](#4-pypi)
  - [5. Homebrew tap](#5-homebrew-tap)
  - [6. python-sdk fanout](#6-python-sdk-fanout)
  - [7. node-sdk fanout](#7-node-sdk-fanout)
  - [8. Docs sites](#8-docs-sites)
  - [9. GHCR](#9-ghcr)
  - [Final matrix (alpha-9)](#final-matrix-alpha-9)

## Worked example — `v0.0.1-alpha.9` (2026-06-14)

The concrete shape of a successful run, against the real channel state on
2026-06-14 for `v0.0.1-alpha.9` (`VERSION=0.0.1-alpha.9`, `PEP440=0.0.1a9`).

### 1. GitHub Release

```text
gh release view v0.0.1-alpha.9 --repo ai-agent-assembly/agent-assembly \
  --json name,assets,isDraft,isPrerelease
```

- `isDraft = false`, `isPrerelease = true`
- 6 assets (`release.yml` signs `SHA256SUMS` with a single self-contained
  `.cosign.bundle` — there are no detached `.sig`/`.pem` files):
  - `aasm-aarch64-apple-darwin.tar.gz`
  - `aasm-x86_64-apple-darwin.tar.gz`
  - `aasm-aarch64-unknown-linux-gnu.tar.gz`
  - `aasm-x86_64-unknown-linux-gnu.tar.gz`
  - `SHA256SUMS`
  - `SHA256SUMS.cosign.bundle`

### 2. crates.io (sparse-index)

All 9 published crates show `vers=0.0.1-alpha.9` on the last line of their
sparse-index file: `aa-core`, `aa-proto`, `aa-runtime`, `aa-ebpf-common`,
`aa-ebpf`, `aa-proxy`, `aa-sandbox`, `aa-gateway`, `aa-cli`. The wider
security/SDK split (`aa-security`, `aa-sdk-client`) is published as part of
the same workspace cut and pinned to the same `0.0.1-alpha.9`.

### 3. npm

5 packages present at `0.0.1-alpha.9`:

- `@agent-assembly/sdk@0.0.1-alpha.9`
- `@agent-assembly/runtime-darwin-arm64@0.0.1-alpha.9`
- `@agent-assembly/runtime-darwin-x64@0.0.1-alpha.9`
- `@agent-assembly/runtime-linux-arm64@0.0.1-alpha.9`
- `@agent-assembly/runtime-linux-x64@0.0.1-alpha.9`

Note: the Linux runtime sub-packages are named `runtime-linux-{arm64,x64}`
without a `-gnu` suffix, even though the corresponding GitHub Release
tarballs use the `unknown-linux-gnu` triple. Do not "correct" this — npm
sub-package naming follows `${platform}-${arch}`, not the Rust target
triple.

### 4. PyPI

- `agent-assembly==0.0.1a9` present, `yanked=false`, 4 wheels + 1 sdist:
  - `cp312-cp312-macosx_11_0_arm64`
  - `cp312-cp312-macosx_10_12_x86_64`
  - `cp312-cp312-manylinux_2_17_aarch64`
  - `cp312-cp312-manylinux_2_17_x86_64`
  - sdist tarball
- Higher-yanked shadow: `0.0.2` is yanked with reason
  `"have wrong to release"`. This is a known, well-understood artefact
  (see "Known quirks" §1 in [REFERENCE.md](REFERENCE.md)). Surface as a
  **soft red** annotation, not a hard fail — `pip install
  agent-assembly==0.0.1a9` resolves correctly.

### 5. Homebrew tap

`ai-agent-assembly/homebrew-agent-assembly` `master` carries
`Formula/aasm.rb` with `version "0.0.1-alpha.9"` and 4 `sha256` literals
that match the sums in the release's `SHA256SUMS` asset.

### 6. python-sdk fanout

`release-python.yml` on `ai-agent-assembly/python-sdk`,
`event=repository_dispatch`, most recent run **27474863938**:
`status=completed`, `conclusion=success`, `createdAt` after the
agent-assembly `release.yml` `createdAt` for the same tag.

### 7. node-sdk fanout

`release-node.yml` on `ai-agent-assembly/node-sdk`,
`event=repository_dispatch`, most recent run **27474863898**:
`status=completed`, `conclusion=success`, after the agent-assembly tag.

### 8. Docs sites

- agent-assembly `Docs` workflow run **27475103444**: completed / success.
- python-sdk `pages-build-deployment` run **27474963083**: completed / success.
- node-sdk: docs cut is the "Cut docs version snapshot" job inside the
  same `release-node.yml` run (#27474863898) above — successful.

### 9. GHCR

Container images are **deferred** for this iteration of `release.yml` —
the workflow may not publish the GHCR tags every cut. If the
`docker manifest inspect` probe fails for `ghcr.io/ai-agent-assembly/python:0.0.1-alpha.9`
or `ghcr.io/ai-agent-assembly/go:0.0.1-alpha.9` because the images were
not built this iteration, annotate the row as "deferred this cut", not as
a publish failure.

### Final matrix (alpha-9)

```text
Release validation for v0.0.1-alpha.9:

| Channel              | Status | Detail                                                            |
|----------------------|--------|-------------------------------------------------------------------|
| GitHub Release       | ✓      | 6 assets, isPrerelease=true                                       |
| crates.io (9 crates) | ✓      | all sparse-index vers = 0.0.1-alpha.9                             |
| npm (5 packages)     | ✓      | sdk + 4 runtime sub-packages (linux-{arm64,x64}, no -gnu)         |
| PyPI                 | ✓      | 0.0.1a9 active, 4 wheels + 1 sdist; soft note: 0.0.2 yanked shadow|
| Homebrew tap         | ✓      | Formula version 0.0.1-alpha.9, 4 sha256s match SHA256SUMS         |
| python-sdk fanout    | ✓      | release-python.yml run 27474863938 success                        |
| node-sdk fanout      | ✓      | release-node.yml run 27474863898 success                          |
| Docs sites           | ✓      | Docs 27475103444 + python pages 27474963083 + node-sdk snapshot   |
| GHCR                 | —      | deferred this cut (images not published in current release.yml)   |
```

Net result: 8/9 ✓, 1 deferred. Had GHCR shipped this iteration, the
matrix would be 9/9 ✓.
