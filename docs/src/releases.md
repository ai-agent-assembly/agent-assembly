# Releases

This page tells you where to find a published build, which channels it ships to,
and how the release is cut.

`agent-assembly` is in the **`v0.0.1` pre-release series**. The public API
and wire protocol are not yet stable.

> **Warning:** every published tag is a pre-release. Do not run `v0.0.1-*`
> in production — the wire protocol can change between pre-releases.

## Where releases live

- **GitHub Releases:** <https://github.com/ai-agent-assembly/agent-assembly/releases>
  — the source of truth for published tags and changelogs. The workspace is
  currently at pre-release `{{#include generated/version-tag.md:2}}`; see the
  GitHub Releases page for the exact publish date and per-tag notes.
- **Per-tag notes:** the source-controlled release notes live under
  `docs/release/` (one file per tag, e.g. `docs/release/v0.0.1-beta.4.md`).
- **Top-level changelog:** [`CHANGELOG.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/CHANGELOG.md).

## Distribution channels

A single coordinated tag push fans out to every channel:

| Channel | Artifact |
|---|---|
| GitHub Releases | `aasm-*.tar.gz` binaries + `SHA256SUMS` |
| crates.io | Workspace crates at the tag version |
| Homebrew tap | `aasm` formula ([`homebrew-tap`](https://github.com/ai-agent-assembly/homebrew-tap)) |
| PyPI / npm | SDK packages |
| GHCR | Container image |

## Release process

The mechanics (version bump, tag, changelog, multi-channel publish) are driven
by the automated release workflow. Operators follow the pre-tag checklist in the
release runbook at `docs/release/RUNBOOK.md`. See also the
[Versioning Policy](versioning.md) and [Compatibility Matrix](compatibility.md).
