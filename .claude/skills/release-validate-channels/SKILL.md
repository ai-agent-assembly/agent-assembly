---
name: release-validate-channels
description: Validate a published agent-assembly release across all distribution channels (GitHub Release, crates.io, npm, PyPI, Homebrew, SDK fanouts, docs sites).
---

# release-validate-channels

Executable contract for verifying that an agent-assembly tag has propagated
cleanly across every downstream distribution channel. The canonical prose
runbook (recovery procedure, immutability guarantees, SDK decoupling notes)
lives in [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md) section 5
("Verification"); this SKILL.md encodes the cross-channel matrix that Claude
Code itself runs after each tag push.

> This skill picks up where `/release-tag-cut` ends. It assumes `release.yml`
> has already fired and is responsible for confirming that what `release.yml`
> *intended* to publish actually landed on every channel it owns.

## When to use

Invoke this skill when **all** of the following are true:

- The operator has just cut a tag via `/release-tag-cut` (or the tag arrived
  via the equivalent CI path).
- `release.yml` on `ai-agent-assembly/agent-assembly` for that tag shows
  `status=completed` and `conclusion=success`.
- The operator wants a deterministic, paste-ready confirmation that every
  downstream channel (GitHub Release assets, crates.io, npm, PyPI, Homebrew
  tap, the python-sdk / node-sdk fanout dispatches, docs sites, and GHCR)
  caught up with the new tag.

The skill is the read-only counterpart to `/release-tag-cut`: tag-cut writes
the tag and lets the publish workflows fan out; this skill confirms the
fan-out landed.

## When NOT to use

Skip (or defer) this skill in any of the following cases:

- **`release.yml` has not finished yet.** The pre-condition check fails fast
  with the run URL. Wait for `conclusion=success` first, or accept that
  channels 2–9 will be mid-flight and the result is meaningless.
- **The tag is non-published or withdrawn.** Tags that never triggered
  `release.yml` (e.g. internal markers, mis-pushed branches) have no channel
  state to validate. There is nothing to probe.
- **The operator wants to fix a broken channel.** This skill is *read-only*
  by contract — it surfaces deviations and the exact commands that surface
  them, but it does NOT retry publishes, merge tap PRs, or yank versions.
  Retries and recovery live in [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md)
  section 6 ("Recovery"). Re-running this skill after a manual retry is
  fine; using it as the retry mechanism is not.

## How to use

**Invocation.**

```text
/release-validate-channels v<X>
```

Concrete example:

```text
/release-validate-channels v0.0.1-alpha.9
```

**Required inputs.**

| Input | Source | Notes |
|---|---|---|
| `<TAG>` | Operator argument | Published agent-assembly release tag (e.g. `v0.0.1-alpha.9`). The skill does not invent or guess tags. |
| `release.yml` run for `<TAG>` | `gh run list` (see Pre-conditions) | Must be `status=completed`, `conclusion=success`. The skill aborts fast if not. |

**Behaviour.** The skill is **read-only**. It runs the nine channel probes
in the order defined under "The channel matrix" below and emits a single
green / red Markdown table (see "Output — the green/red matrix"). It does
not mutate any registry, repository, tap, or workflow. Safe to re-run as
many times as needed; idempotent by construction.

**Typical operator flow.**

1. Cut the tag (`/release-tag-cut v<X>`).
2. Watch `release.yml` until it goes green.
3. Run `/release-validate-channels v<X>`.
4. Paste the resulting matrix into the post-release note or follow-up
   ticket. Any red row carries the literal failing command and its output
   so triage does not require re-running the probe.

## Pre-conditions

All of the following MUST hold before any probe below runs. If any fails,
stop and surface the failure with the exact command output and the run URL —
do not attempt to remediate from inside this skill.

1. **Target tag provided** — the operator supplies `<TAG>` (e.g.
   `v0.0.1-alpha.10`). The skill does not invent or guess tags.
2. **`release.yml` run for that tag is `completed/success`** — query via:

   ```bash
   gh run list --workflow release.yml \
     --repo ai-agent-assembly/agent-assembly \
     --branch "<TAG>" \
     --limit 1 \
     --json status,conclusion,url,databaseId
   ```

   The result must show `status=completed` and `conclusion=success`. If it
   does not, stop and report the run URL — channel propagation cannot have
   completed if `release.yml` did not finish successfully.

## The channel matrix

The skill probes nine channels in the order below, recording green / red per
channel. Every red entry MUST be reported with the exact command and its
literal output so the operator can paste back into a follow-up ticket.

`VERSION="${TAG#v}"` (strip the leading `v`).
`PEP440` conversion: `0.0.1-alpha.N` → `0.0.1aN`
(see `scripts/check-release.sh` `to_pep440()` for the canonical sed).

| # | Channel              | Check |
|---|----------------------|-------|
| 1 | GitHub Release       | `gh release view <TAG>` exposes the 6 expected assets and `isPrerelease=true` |
| 2 | crates.io            | Each workspace-published crate's sparse-index latest line `vers` matches `$VERSION` |
| 3 | npm                  | `@agent-assembly/sdk@$VERSION` + 4 platform runtime sub-packages exist |
| 4 | PyPI                 | `agent-assembly==$PEP440` exists with 4 wheels + 1 sdist; no yanked higher version shadows |
| 5 | Homebrew tap         | Tap `master` `Formula/aasm.rb` declares `version "$VERSION"` and its 4 `sha256` literals match release `SHA256SUMS` |
| 6 | python-sdk fanout    | Most recent `release-python.yml` (`event=repository_dispatch`) run succeeded |
| 7 | node-sdk fanout      | Most recent `release-node.yml` (`event=repository_dispatch`) run succeeded |
| 8 | Docs sites           | `Docs` workflow on agent-assembly + `pages-build-deployment` on python-sdk / node-sdk all succeeded post-tag |
| 9 | GHCR                 | `ghcr.io/ai-agent-assembly/{python,go}:$VERSION` manifests exist |

### 1. GitHub Release — 6 assets, isPrerelease

```bash
gh release view "$TAG" \
  --repo ai-agent-assembly/agent-assembly \
  --json name,assets,isDraft,isPrerelease,url
```

Pass criteria:

- `isDraft = false`
- `isPrerelease = true` (every `v0.0.1-alpha.*` tag is a pre-release)
- `assets` array has **6 entries**, exactly:
  - `aasm-aarch64-apple-darwin.tar.gz`
  - `aasm-x86_64-apple-darwin.tar.gz`
  - `aasm-aarch64-unknown-linux-gnu.tar.gz`
  - `aasm-x86_64-unknown-linux-gnu.tar.gz`
  - `SHA256SUMS`
  - `SHA256SUMS.cosign.bundle`

If asset count or names diverge, report the exact `assets[].name` list and
flag the release run URL.

### 2. crates.io — sparse-index probe per crate

The crates.io public REST API (`https://crates.io/api/v1/crates/<name>`) is
rate-limited and rejects sustained polling. Use the sparse-index instead —
it is the source of truth `cargo` itself reads, has no rate limit, and
guarantees consistency with the registry within seconds of publish.

The sparse-index URL is computed from the crate name (lowercase) prefix:

| Name length | Prefix layout       | Example                                        |
|-------------|---------------------|------------------------------------------------|
| 1           | `1/<name>`          | `1/a`                                          |
| 2           | `2/<name>`          | `2/ab`                                         |
| 3           | `3/<first>/<name>`  | `3/a/abc`                                      |
| ≥ 4         | `<c1c2>/<c3c4>/<name>` | `aa/-c/aa-core`, `aa/-g/aa-gateway`         |

So `aa-core` → `https://index.crates.io/aa/-c/aa-core`.

The published-crate set (9 crates, per `release.yml`):

```bash
CRATES=(aa-core aa-proto aa-runtime aa-ebpf-common aa-ebpf \
        aa-proxy aa-sandbox aa-gateway aa-cli)
for crate in "${CRATES[@]}"; do
  # Sparse index path: first two chars / next two chars / name
  c12="${crate:0:2}"; c34="${crate:2:2}"
  url="https://index.crates.io/${c12}/${c34}/${crate}"
  # Each line is one published version, newest last.
  latest_vers="$(curl -fsSL "$url" | tail -1 | python3 -c \
    'import sys,json; print(json.load(sys.stdin)["vers"])')"
  echo "${crate}: latest=${latest_vers} expected=${VERSION}"
done
```

Pass criteria: every crate's `latest_vers` (the last line of its sparse-index
file) equals `$VERSION`. Note that "latest" here means "most recent
published" — crates.io is immutable, so a green result also implies the tag
was not republished or yanked.

### 3. npm — sdk + 4 runtime sub-packages

```bash
NPM_PKGS=(
  "@agent-assembly/sdk"
  "@agent-assembly/runtime-darwin-arm64"
  "@agent-assembly/runtime-darwin-x64"
  "@agent-assembly/runtime-linux-arm64"
  "@agent-assembly/runtime-linux-x64"
)
for pkg in "${NPM_PKGS[@]}"; do
  v="$(npm view "${pkg}@${VERSION}" version 2>/dev/null || true)"
  echo "${pkg}: ${v:-MISSING} expected=${VERSION}"
done
```

Pass criteria: `npm view <pkg>@$VERSION version` prints `$VERSION` exactly,
for all 5 packages. A blank result means the version is missing on the npm
registry. If only the SDK package is present but the runtime sub-packages
are not, `release-node.yml` likely failed mid-matrix — surface its run URL
(see channel 7).

### 4. PyPI — wheels + sdist, distinguishing yanked from active

```bash
curl -fsSL "https://pypi.org/pypi/agent-assembly/${PEP440}/json" \
  | python3 -c '
import sys, json
d = json.load(sys.stdin)
info = d["info"]
yanked = info.get("yanked", False)
yanked_reason = info.get("yanked_reason") or ""
files = d["urls"]
wheels = [f for f in files if f["packagetype"] == "bdist_wheel"]
sdists = [f for f in files if f["packagetype"] == "sdist"]
print(f"version={info[\"version\"]} yanked={yanked} reason={yanked_reason!r}")
print(f"wheels={len(wheels)} sdist={len(sdists)}")
for f in wheels:
    print(f"  {f[\"filename\"]}")
'
```

Pass criteria for the target `$PEP440` version:

- HTTP 200 (version exists)
- `yanked = false`
- exactly **4 wheels** and **1 sdist**

Then check no **higher** version is yanked-but-shadowing:

```bash
curl -fsSL "https://pypi.org/pypi/agent-assembly/json" \
  | python3 -c '
import sys, json
from packaging.version import parse as v
d = json.load(sys.stdin)
target = "'"$PEP440"'"
shadows = []
for ver, releases in d["releases"].items():
    if not releases:
        continue
    if v(ver) > v(target) and any(r.get("yanked") for r in releases):
        reasons = sorted({r.get("yanked_reason") or "" for r in releases})
        shadows.append((ver, reasons))
for ver, reasons in shadows:
    print(f"YANKED-SHADOW {ver}: {reasons}")
if not shadows:
    print("no yanked higher versions")
'
```

**Known quirk (institutional knowledge).** PyPI may carry yanked higher
versions from a botched earlier release. The `v0.0.1-alpha.9` cycle, for
example, left `0.0.2` yanked on PyPI with reason
`"have wrong to release"`. A yanked higher version does *not* affect
`pip install agent-assembly==$PEP440` (yanked versions are excluded from
resolution unless explicitly pinned). It IS a documentation hygiene issue
and should be surfaced as a soft red, not a hard fail — annotate the report,
do not block.

### 5. Homebrew tap — formula version + matching SHA256SUMS

```bash
FORMULA="$(gh api repos/ai-agent-assembly/homebrew-agent-assembly/contents/Formula/aasm.rb \
  --jq '.content' | base64 -d)"
printf '%s\n' "$FORMULA" | grep -E '^[[:space:]]*version '
printf '%s\n' "$FORMULA" | grep -E 'sha256 '
```

Pass criteria:

- `version "<VERSION>"` line present (exact match).
- 4 `sha256 "..."` literals present.

Then verify the formula's `sha256` literals match the release's `SHA256SUMS`:

```bash
gh release download "$TAG" \
  --repo ai-agent-assembly/agent-assembly \
  --pattern SHA256SUMS --dir /tmp/aa-release-"$TAG" --clobber

# Map asset basename → formula expects this sha256
awk '{print $2,$1}' /tmp/aa-release-"$TAG"/SHA256SUMS
printf '%s\n' "$FORMULA" | grep -E '(url|sha256) '
```

For each tarball asset in `SHA256SUMS`, the formula MUST contain the same
sha256. A mismatch means the Homebrew tap PR (RUNBOOK section 4) was merged
against a stale or different artifact — surface the diff to the operator.

If the formula `version "..."` does not match `$VERSION`, the tap PR has not
been merged yet — check for the open PR (`bot/aasm-<VERSION>` branch) and
flag the merge gate per RUNBOOK section 4.

### 6. python-sdk fanout — `release-python.yml` repository_dispatch run

```bash
gh run list \
  --repo ai-agent-assembly/python-sdk \
  --workflow release-python.yml \
  --event repository_dispatch \
  --limit 1 \
  --json status,conclusion,createdAt,url,displayTitle
```

Pass criteria: `status=completed` and `conclusion=success`, with
`createdAt` after the `release.yml` run's `createdAt` for `$TAG`. If the
most recent dispatch is in `in_progress` or `queued`, this is not red —
report "in flight, re-check after completion".

### 7. node-sdk fanout — `release-node.yml` repository_dispatch run

```bash
gh run list \
  --repo ai-agent-assembly/node-sdk \
  --workflow release-node.yml \
  --event repository_dispatch \
  --limit 1 \
  --json status,conclusion,createdAt,url,displayTitle
```

Same pass criteria as channel 6. If `release-node.yml` succeeded but the
npm sub-package check (channel 3) shows missing runtime packages, the
publish job within the workflow failed silently — surface both run URL and
the missing-package list.

### 8. Docs sites — `Docs` + `pages-build-deployment` post-tag

```bash
# agent-assembly main docs site
gh run list --repo ai-agent-assembly/agent-assembly \
  --workflow "Docs" --branch master --limit 1 \
  --json status,conclusion,createdAt,url

# python-sdk and node-sdk publish docs via GitHub Pages directly
for repo in python-sdk node-sdk; do
  gh run list --repo "ai-agent-assembly/${repo}" \
    --workflow "pages-build-deployment" --limit 1 \
    --json status,conclusion,createdAt,url
done
```

Pass criteria: each of the three runs is `status=completed` /
`conclusion=success`, with `createdAt` after `release.yml`'s `createdAt`
for `$TAG`. A red here is a documentation-staleness issue, not an artifact
issue — soft red, annotate but do not block.

### 9. GHCR — container images for python + go

```bash
for image in python go; do
  if docker manifest inspect \
       "ghcr.io/ai-agent-assembly/${image}:${VERSION}" >/dev/null 2>&1; then
    echo "ghcr.io/ai-agent-assembly/${image}:${VERSION} : present"
  else
    echo "ghcr.io/ai-agent-assembly/${image}:${VERSION} : MISSING"
  fi
done
```

If `docker` is unavailable, fall back to the GH packages API per
`scripts/check-release.sh` `ghcr_check()`:

```bash
gh api "/orgs/ai-agent-assembly/packages/container/${image}/versions" --paginate
```

Pass criteria: both `python:$VERSION` and `go:$VERSION` manifests exist.

## Output — the green/red matrix

Emit a single Markdown table the operator can paste into a follow-up ticket
or post-release note. Use one row per channel; the `Detail` column carries
either the success summary or the literal red-flagging command output.

```text
Release validation for <TAG>:

| Channel              | Status | Detail                                          |
|----------------------|--------|-------------------------------------------------|
| GitHub Release       | ✓      | 6 assets, isPrerelease=true                     |
| crates.io (9 crates) | ✓      | all latest line vers = <VERSION>                |
| npm (5 packages)     | ✓      | sdk + 4 runtime sub-packages at <VERSION>       |
| PyPI                 | ✓      | <PEP440> active, 4 wheels + 1 sdist, no shadows |
| Homebrew tap         | ✓      | Formula version <VERSION>, sha256s match        |
| python-sdk fanout    | ✓      | release-python.yml run #N success               |
| node-sdk fanout      | ✓      | release-node.yml run #N success                 |
| Docs sites           | ✓      | Docs + 2× pages-build-deployment success        |
| GHCR                 | ✓      | python:<VERSION> + go:<VERSION> present         |

  All channels green for <TAG>.
```

Replace `✓` with `✗` for any red channel and append, on the line beneath,
the exact failing command and its literal output so the operator has
everything needed to triage without re-running the probe.

## What's expected when done

A successful invocation produces, in this exact order:

1. **A paste-ready Markdown matrix** — one row per channel, status column,
   detail column. The operator can paste it directly into a release-cut
   ticket, post-release note, or the parent Jira issue. The matrix format
   is the one shown under "Output" above; the worked example below is its
   canonical filled-in shape.

2. **Every anomaly is named with the literal command output that surfaced
   it.** The skill must not say "channel X looks off" without quoting the
   exact `gh`, `curl`, or `npm view` invocation and its actual stdout /
   stderr. Triage downstream relies on being able to re-run (or skip
   re-running) the same probe by hand.

3. **Specific follow-up recommendations per red row.** The skill names the
   next action; it does not perform it.

   | Red channel | Recommended follow-up |
   |---|---|
   | GitHub Release assets diverged | Re-check `release.yml` run logs for the `build-artifacts` / `sign-release` job — re-trigger per RUNBOOK § 6. |
   | crates.io row red | Inspect the `Publish workspace to crates.io` job log in the `release.yml` run for `<TAG>`; immutable registry, recovery is a fresh tag. |
   | npm row red | Inspect `release-node.yml` run on `ai-agent-assembly/node-sdk`. If only sub-packages are missing, the matrix publish failed silently. |
   | PyPI row red | Inspect `release-python.yml` run on `ai-agent-assembly/python-sdk`. Yanked shadow is a soft red — annotate, do not block. |
   | Homebrew tap row red, with open bot PR | Invoke `/homebrew-tap-merge` once the bot PR opens. |
   | Homebrew tap row red, no bot PR | Check the `update-homebrew-tap` job in `release.yml`. |
   | python-sdk / node-sdk fanout row red | Surface the run URL; let the operator re-trigger per RUNBOOK § 6. |
   | Docs sites row red | Soft red — documentation staleness only; surface and move on. |
   | GHCR row red | Confirm whether this `release.yml` iteration is expected to publish GHCR; if yes, surface the `docker.yml` run URL. |

4. **A definitive go / no-go statement.** The last line of the skill's
   output is one of:

   - `All channels green for <TAG>.` (every row ✓)
   - `<TAG> validated with <N> soft notes — see annotations.` (only soft
     reds, e.g. yanked PyPI shadow, deferred GHCR)
   - `<TAG> has <N> hard red channels — operator action required.` (one
     or more hard reds; follow the table above)

The operator should not have to read the rest of the SKILL.md to act on
the result — the matrix and the final line are the deliverable.

## Worked example — `v0.0.1-alpha.9` (2026-06-14)

The concrete shape of a successful run, against the real channel state on
2026-06-14 for `v0.0.1-alpha.9` (`VERSION=0.0.1-alpha.9`, `PEP440=0.0.1a9`).

### 1. GitHub Release

```text
gh release view v0.0.1-alpha.9 --repo ai-agent-assembly/agent-assembly \
  --json name,assets,isDraft,isPrerelease
```

- `isDraft = false`, `isPrerelease = true`
- 6 assets:
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
  (see "Known quirks" §1). Surface as a **soft red** annotation, not a
  hard fail — `pip install agent-assembly==0.0.1a9` resolves correctly.

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

## Known quirks to encode (load-bearing institutional knowledge)

These quirks have bitten real release cycles and are recorded here so the
skill does not relearn them every cut.

1. **PyPI yanked-version shadowing.** Higher yanked versions can persist on
   PyPI alongside the current active release. The `v0.0.1-alpha.9` cycle
   left `0.0.2` yanked with reason `"have wrong to release"`. Treat
   yanked-shadows as a soft red — annotate, do not block. `pip install
   agent-assembly==$PEP440` is unaffected because yanked versions are
   excluded from resolution unless explicitly pinned.

2. **go-sdk is out of scope by design.** The Go SDK cuts its own
   `goreleaser`-driven tag on its own cadence and is decoupled from the
   `agent-assembly` release. Per `docs/release/RUNBOOK.md` section 7, do
   NOT flag go-sdk as a missing channel. There is no `release-go.yml`
   fanout to probe.

3. **crates.io public REST is rate-limited.** Sustained polling of
   `https://crates.io/api/v1/crates/<name>` returns 429. Use the
   sparse-index (`https://index.crates.io/<prefix>/<name>`) instead — same
   data, no rate limit, this is the URL `cargo` itself uses.

4. **`release.yml` is parallel, not pipelined.** The four post-tag
   workflows (`release.yml`, `docker.yml`, `release-python.yml` via
   `repository_dispatch`, `release-node.yml` via `repository_dispatch`)
   fire concurrently from the tag push and DO NOT wait on each other. A
   probe that runs immediately after `release.yml` completes can still
   show npm or PyPI red simply because their workflow is mid-flight.
   Re-run the skill 2–5 minutes later before treating any red as
   actionable.

5. **Homebrew tap manual-merge gate.** The tap PR is opened by the
   `update-homebrew-tap` job but is *not* auto-merged. Until an operator
   merges it (RUNBOOK section 4), `brew install aasm` still resolves to
   the previous version. A red on channel 5 with an open tap PR is the
   operator's gate, not a publish failure.

## Cross-reference

`docs/release/RUNBOOK.md` section 5 ("Verification") contains the human
narrative of this loop — re-trigger commands per channel, the immutability
guarantees of crates.io / PyPI / npm, and the SDK decoupling rationale.
This SKILL.md and that section are the same procedure expressed for
different readers: this file for Claude Code, that section for the
operator.

## What this skill explicitly does not do

- Cut, edit, or push tags (that is `/release-tag-cut`).
- Re-trigger failed `release-*.yml` workflows (RUNBOOK section 6, operator-
  driven; the skill surfaces the run URL but does not call
  `gh workflow run`).
- Merge the Homebrew tap PR (RUNBOOK section 4, operator-gated).
- Yank PyPI / npm / crates.io versions (these are immutable in practice;
  recovery is a fresh tag, not a republish).
- Validate go-sdk channels (decoupled, RUNBOOK section 7).
- Touch repos other than `ai-agent-assembly/{agent-assembly,python-sdk,
  node-sdk,homebrew-agent-assembly}`.
