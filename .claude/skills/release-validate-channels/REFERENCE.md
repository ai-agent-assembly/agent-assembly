# release-validate-channels — REFERENCE

Full per-channel probe commands and the load-bearing institutional quirks for
the `release-validate-channels` skill. The lean overview, invocation, output
matrix format, and boundaries live in [SKILL.md](SKILL.md); this file is the
detailed Level-3 reference it links to.

## Contents

- [The channel matrix](#the-channel-matrix)
  - [1. GitHub Release — 6 assets, isPrerelease](#1-github-release--6-assets-isprerelease)
  - [2. crates.io — sparse-index probe per crate](#2-cratesio--sparse-index-probe-per-crate)
  - [3. npm — sdk + 4 runtime sub-packages](#3-npm--sdk--4-runtime-sub-packages)
  - [4. PyPI — wheels + sdist, distinguishing yanked from active](#4-pypi--wheels--sdist-distinguishing-yanked-from-active)
  - [5. Homebrew tap — formula version + matching SHA256SUMS](#5-homebrew-tap--formula-version--matching-sha256sums)
  - [6. python-sdk fanout — `release-python.yml` repository_dispatch run](#6-python-sdk-fanout--release-pythonyml-repository_dispatch-run)
  - [7. node-sdk fanout — `release-node.yml` repository_dispatch run](#7-node-sdk-fanout--release-nodeyml-repository_dispatch-run)
  - [8. Docs sites — `Docs` + `pages-build-deployment` post-tag](#8-docs-sites--docs--pages-build-deployment-post-tag)
  - [9. GHCR — container images for python + go](#9-ghcr--container-images-for-python--go)
- [Known quirks to encode](#known-quirks-to-encode-load-bearing-institutional-knowledge)

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
