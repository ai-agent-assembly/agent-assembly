# agent-assembly release runbook

> Step-by-step procedure for cutting an agent-assembly release.
> Companion to `scripts/release-readiness.sh` (pre-tag) and
> `scripts/check-release.sh` (post-tag). Tracked under AAASM-2456.

This runbook assumes the operator has push rights to
`ai-agent-assembly/agent-assembly` and merge rights on the
`ai-agent-assembly/homebrew-agent-assembly` tap.

---

## 1. Pre-release — bump PR

The bump PR sets the workspace version, refreshes path-dep version literals,
adds the `CHANGELOG.md` section, and creates `docs/release/v<version>.md`.

```bash
# in a feature worktree off master
$EDITOR Cargo.toml                 # workspace.package.version
$EDITOR aa-*/Cargo.toml            # all path-dep `version = "..."` literals
$EDITOR CHANGELOG.md               # prepend ## [<version>] section
$EDITOR docs/release/v<version>.md # release notes (copy structure from previous)
```

Open the bump PR, wait for green CI, merge to master. **Then run the
readiness check from a fresh master checkout:**

```bash
git checkout master
git pull --ff-only remote master
bash scripts/release-readiness.sh <version>      # e.g. 0.0.1-alpha.5
```

All 10 checks must report ✓ before continuing. Common failures and what to do:

- *Cargo.toml version mismatch* — bump PR not yet merged.
- *Workspace path-dep literals don't match* — at least one Cargo.toml was
  missed in the bump PR; open a follow-up patch and re-run.
- *Stale homebrew tap PR open* — close or merge it before tagging; otherwise
  the per-tag bot will open a parallel PR and reviewers will be unsure
  which one is current.

## 2. Tag push — IRREVERSIBLE

This is the point of no return. Tag pushes can be deleted but the bytes
they trigger downstream (crates.io, npm, PyPI) **cannot be unpublished**.

```bash
git tag -a v<version> -m "Release v<version>"
git push remote v<version>
```

Note: branches and tags push to `remote` (`ai-agent-assembly/agent-assembly`),
**not** `origin` (the operator's personal fork).

## 3. What runs automatically after tag push

Four workflows fire in parallel from the tag push. **None waits on the others.**
`release.yml` additionally opens two SDK FFI source-pin bump PRs as part of its
job set (see the source-sync rows below).

| Workflow                  | What it produces                              |
| ------------------------- | --------------------------------------------- |
| `release.yml`             | GH Release page, `aasm-*.tar.gz` x4 + SHA256SUMS, crates.io publish (9 crates), Homebrew tap PR |
| `docker.yml`              | ghcr.io images: `python:<version>`, `go:<version>` |
| `repository_dispatch` → node-sdk | Triggers `release-node.yml` which publishes 5 npm packages |
| `repository_dispatch` → python-sdk | Triggers `release-python.yml` which publishes `agent-assembly` to PyPI |
| `release.yml` → node-sdk FFI pin | Opens a bot PR on node-sdk bumping `native/aa-ffi-node/Cargo.toml` `aa-sdk-client` git-SHA pin to the tagged commit (source-sync, **not** a publish) |
| `release.yml` → python-sdk FFI pin | Opens a bot PR on python-sdk bumping all 3 pins (`aa-core`/`aa-proto`/`aa-sdk-client`) in `native/aa-ffi-python/Cargo.toml` to the tagged commit (source-sync, **not** a publish) |

The post-release artifact smoke test (`smoke-test.yml`) was deprecated and
removed (AAASM-2772). Post-release artifact verification is performed manually
per the "Post-release verification" section of `RELEASING.md`.

## 4. Manual gate — merge the Homebrew tap PR (within ~5 minutes)

`release.yml`'s `update-homebrew-tap` job opens a PR against
`ai-agent-assembly/homebrew-agent-assembly` with branch `bot/aasm-<version>`
and title `🤖 (formula): aasm <version>`.

**Until that PR is merged, `brew install aasm` will still resolve to the
previous version.** The formula file on the tap's master branch is what
Homebrew reads; the bot-created branch is invisible to `brew install`.

```bash
gh pr list --repo ai-agent-assembly/homebrew-agent-assembly --state open
gh pr merge <pr-number> --repo ai-agent-assembly/homebrew-agent-assembly --squash
```

## 5. Verification

Run the status probe and iterate until all channels are ✓:

```bash
bash scripts/check-release.sh v<version>
```

Expected first-run state immediately after tag push: GH Release ✓,
everything else still red (workflows haven't finished). Re-run every few
minutes. Most channels are green within 10-20 minutes; crates.io and PyPI
indexing latency can add 1-2 minutes. ghcr.io image push is usually
the last to complete.

## 6. Recovery — when a channel stays red

For each ✗ in `check-release.sh` output, the line beneath it shows the
re-trigger command. The workflow:

1. Open a ticket describing the failure (link the failed workflow run).
2. Open a fix PR against the affected repo (sources, not just CI config).
3. Merge the fix to master.
4. Re-trigger the relevant workflow via `workflow_dispatch` with the
   `release_tag` input. Each `release-*.yml` accepts this for re-trigger.
5. Re-run `check-release.sh v<version>` to verify.

**crates.io is immutable.** A crate version cannot be republished — if a
crate publishes broken, the only recovery is to bump to the next version
(e.g. alpha-5 → alpha-6) and re-tag. Get the source fix in **before**
re-triggering, not after.

PyPI and npm allow re-publish only within a short grace window and only
if no installs have happened. Treat them as immutable in practice.

## 7. Decoupling note — SDK versions are not required to match

The SDK repos (`python-sdk`, `node-sdk`, `go-sdk`) cut their own releases
on their own cadence. The SDK CI is the SDK's own quality gate.
`agent-assembly`'s release covers only what `agent-assembly` itself
publishes: Homebrew tap, ghcr.io images, crates.io tarballs, and the GH
Release tarballs.

The dispatcher in `release.yml` (`notify-downstream` job) fires a
`repository_dispatch` event to node-sdk and python-sdk after the GH Release
publishes. This is a coordination signal, not a gate. If an SDK publish
fails, the SDK's own follow-up release fixes it independently — the
`agent-assembly` tag is unaffected.

### SDK-only hotfixes — do not cut an agent-assembly tag

When an operator is asked to ship a fix that lives **only** in a Python
or TypeScript SDK surface (no change to the `aasm` binary, no change to
a shared Rust crate), do **not** cut a fresh `agent-assembly` tag for it.
Cutting an agent-assembly tag triggers crates.io publishes, ghcr.io image
builds, and a Homebrew tap PR — all wasted work for a fix that touches
none of those artifacts. Instead, dispatch the SDK's own release workflow
in SDK-only hotfix mode and reuse the existing `agent-assembly` tag as
`binary_source_tag`. See `node-sdk/docs/release/RUNBOOK.md` section 2 and
`python-sdk/docs/release/RUNBOOK.md` section 2 for the per-SDK procedure,
including the `.N` (semver) vs `.postN` (PEP 440) version-naming
asymmetry between the two ecosystems.

## 8. Operator gates — one-time-per-environment setup

These must be set up once, before the first release, and again whenever
the credential rotates. Not part of the per-release loop.

- **crates.io email verification.** The publishing token's owner account
  must have a verified email; otherwise `cargo publish` fails with
  "a verified email address is required".
- **npm 2FA + Trusted Publisher OIDC.** Each of the 5 `@agent-assembly/*`
  packages must have `@agent-assembly/release-bot` configured as a
  trusted publisher with the node-sdk repo+workflow path; otherwise OIDC
  publish fails with "OTP required".
- **PAT rotation.** `CRATES_IO_TOKEN`, `CROSS_REPO_DISPATCH_PAT`,
  `HOMEBREW_TAP_TOKEN` expire on the cadence configured at the GitHub /
  crates.io side. `release-readiness.sh` check 8 verifies all three exist
  in the repo; it does not verify they're still valid.

After rotation:
```bash
gh secret set CRATES_IO_TOKEN --repo ai-agent-assembly/agent-assembly
gh secret set CROSS_REPO_DISPATCH_PAT --repo ai-agent-assembly/agent-assembly
gh secret set HOMEBREW_TAP_TOKEN --repo ai-agent-assembly/agent-assembly
```
