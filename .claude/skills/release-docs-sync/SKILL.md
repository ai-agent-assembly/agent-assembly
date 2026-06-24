---
name: release-docs-sync
description: Sync every version-dependent doc/content reference to a new agent-assembly release version (alpha / beta / rc / official). Use right before or as part of cutting a release — after release-tag-cut bumps the Cargo version literals but before/while the docs are published — to update the compatibility matrix, install examples, sample CLI output, and SDK README version refs so docs never go stale. Version-type-agnostic: the same checklist applies to any pre-release or official version.
---

# release-docs-sync

`release-tag-cut` bumps every workspace **Cargo** version literal, regenerates
`Cargo.lock`, and pushes the tag. It does **not** touch **documentation /
content** version references. Those are a separate, manual, easily-forgotten
step — and forgetting it is exactly the drift bug
[AAASM-3372](https://lightning-dust-mite.atlassian.net/browse/AAASM-3372) found
(compatibility matrix stuck at `alpha.5`, install examples on a stale version,
hub badges wrong).

This skill is the **can't-forget checklist**: given a new version `X` (any of
alpha / beta / rc / official), it lists exactly which files in which repos to
update, and how. The mechanical backstop is
[`scripts/check-docs-versions.sh`](../../../scripts/check-docs-versions.sh),
which fails if the agent-assembly live install examples + compat-matrix row are
not on `X`.

> **This skill creates NO new release mechanics.** The docs **channel** cut
> (latest / pre-release / stable labels, version dropdowns) is already fully
> **release-workflow-driven** (AAASM-2741 / AAASM-2744). **Do NOT hand-edit
> channel labels or the channel dropdown** — only update the in-content version
> references listed below. (For **node-sdk**, `website/versions.json` and
> `website/versionChannels.json` are that channel config — auto-managed by the
> release docs-snapshot step; **do not hand-edit them**.)

> **Principle — three kinds of version reference; only one gets bumped.** Before
> changing any version string, classify it:
> - **Current / canonical** — install snippets, sample CLI output, "captured
>   against `vX`" provenance, the latest-release link, the *new* compat-matrix
>   row → **bump to `X`**.
> - **Historical** — CHANGELOG, `docs/release/*`, older compat-matrix rows,
>   `versioned_docs/` snapshots, a security "last full refresh" marker → **leave**.
>   They record the past; bumping a refresh marker without an actual re-review is
>   a lie.
> - **Forward-reference** — a dependency pin to the release that *ships a feature*
>   (an example for an adapter/feature added after the last published tag, pinned
>   `>=X`) → **correct, not stale; leave it / set to `X`**. Do NOT downgrade it to
>   the last *published* version. This is the AAASM-3695 trap — see Step 3.5.

> **Timing — consumer repos lag; the release repos lead.** Repos that **install
> from registries** (`agent-assembly-examples`, the docs-hub live badges) must
> reference the **currently-published** version. Do **not** bump them to `X`
> *before* `X` is published — `pip install` / `npm i` / `go get` of an unpublished
> `X` breaks. Bump those **after** the publish step. The release repos' own docs
> (this skill) *describe* the upcoming release and may lead.

## When to use

- Whenever a new agent-assembly version is being cut (pre-release **or**
  official). Run it as part of the release, alongside `release-tag-cut`.
- It is version-type-agnostic: alpha → beta channel promotion, beta forward-roll,
  rc, or the first official `v0.0.1` all use the same procedure. The version
  string is the only input that changes.

## Inputs

- `X` — the new version, in tag form (e.g. `v0.0.1-beta.3`, `v0.0.1`). The
  per-registry forms you will also need:
  - bare core/CLI form: `0.0.1-beta.3` (drop the leading `v`)
  - PyPI / PEP 440 form: `0.0.1b3` (alpha→`aN`, beta→`bN`, rc→`rcN`)
  - npm dist-tag: the channel name (`alpha` / `beta` / `rc` / `latest`)

## Procedure

Work in a worktree off fresh `remote/master` (see the project worktree rules).
Edit each file below, then run the verifier. Granular GitEmoji commits.

### Step 1 — agent-assembly `docs/` + README (the verifier covers these)

These are the references that ship in the core docs site and the repo front page.
The verifier (`scripts/check-docs-versions.sh X`) asserts every one of them.

1. **`docs/src/compatibility.md`** — the live tables. **Add a NEW row** (never
   overwrite an old one) for `X` to each of:
   - **Compatibility Matrix** — `| vX | python… | node… | go… | protocol/v1 |`
   - **Minimum Supported Runtime Version per SDK** — add the three SDK rows for
     `X` if the minimum changed (a channel promotion usually bumps it).
   - **Supported Protocol Versions per Runtime** — `| vX | protocol/v1 |`.
   Older rows stay — this is a cumulative matrix, not a replace.

2. **`docs/src/quick-start/installation.md`** — bump the live examples:
   - the **`AASM_VERSION=vX`** pin-a-version snippet,
   - the **`VERSION=vX`** manual pre-built-binaries snippet,
   - the **`aasm <bare X>`** `--version` sample output,
   - the **`| cli | <bare X> |`** `aasm version` table sample.

3. **`README.md`** (repo root):
   - the **`AASM_VERSION=vX`** quick-install snippet,
   - the **Project Status** "latest [`vX`]" release line (and its date).

4. **`docs/src/quick-start/configuration.md`** and
   **`docs/src/quick-start/first-run.md`** — these carry **captured sample
   output** that names a build version (e.g. `"version": "0.0.1-alpha.5"`,
   "captured from a real `v0.0.1-alpha.5` build"). Refresh the version string so
   samples don't advertise an ancient build. *(Not gated by the verifier — these
   are illustrative captures, not install instructions; update them when
   re-capturing, but a stale sample here is cosmetic, not a broken instruction.)*

5. **`docs/release/vX.md`** — the per-tag release notes file. `release-tag-cut`
   owns creating this; confirm it exists for `X` (do not duplicate its work).

> `agent-assembly.toml.example` carries **no** version literal today — nothing to
> bump there. Re-check with `grep -nE 'version|0\.0\.1' agent-assembly.toml.example`
> in case that changes.

### Step 2 — agent-assembly-docs hub (read-only sibling; separate PR/repo)

The hub `docs/src/compatibility.md` has the **highest drift risk** because it
uses **static** shields.io badges that do NOT self-update:

- **`badge/core-vX`** core badge and **`badge/go--sdk-vX`** Go badge — these are
  hard-coded `img.shields.io/badge/...` URLs. Bump the version segment to `X`.
- The **PyPI** and **npm** badges are **live** (`shields.io/pypi/v/...`,
  `shields.io/npm/v/.../<dist-tag>`) — they self-update; **do not** hand-edit
  them, but if the channel changed (alpha→beta), repoint the npm dist-tag.
- **Add a new matrix row** for `X` to the hub compatibility table, same as the
  core file. Fix any "tested @ <sha> (post-… unreleased)" line that is now
  superseded by a real published tag.

> The hub lives in the sibling `agent-assembly-docs` repo. Make these edits in
> that repo's own PR — do not edit it from the agent-assembly worktree.

### Step 3 — SDK READMEs (read-only siblings; mostly self-updating)

- **python-sdk** — all version badges are **live** (`pypi/v`, GitHub release,
  pyversions). Install snippets use `pip install agent-assembly` with **no
  pinned version**. **Nothing to bump** on a normal release. Only touch if a
  snippet ever hard-codes `==0.0.1bN`.
- **node-sdk** — the npm badge is **live** (`npm/v/.../beta`). Install snippets
  use the `@beta` dist-tag, not a pinned version. On a **channel promotion**
  (e.g. beta→rc→latest), repoint the dist-tag in the badge URL, the
  `pnpm add @agent-assembly/sdk@<tag>` snippet, and the "current release line is
  `0.0.1-beta.x`" prose. Otherwise nothing to bump.
- **go-sdk** — badges are static `docs-live` only; the install snippet is
  `go get github.com/<org>/go-sdk` with no version. **Nothing version-bump to
  do.** (Note: the canonical org id is lowercase `ai-agent-assembly`; if a
  README's `go get` path ever uses mixed case, that is a casing fix tracked
  separately, not part of version-sync.)

**Net for SDKs:** on a same-channel forward-roll, the SDK READMEs need **no**
edits (badges are live). Only a **channel change** requires the dist-tag /
prose edits in node-sdk above.

### Step 3.5 — example dependency pins for newly-added features (forward-refs)

**Easy to miss, and NOT covered by `check-docs-versions.sh`.** When a release adds
new SDK features/adapters, their example docs must pin the release that **ships**
them — not the last published version. Pinning the older version means a reader
installs a build that lacks the feature (`ImportError` / missing export). This is
the AAASM-3695 class: the LlamaIndex example correctly pins `>=0.0.1b5` while only
`b4` was published, because the adapter is **absent** from `b4`.

1. Grep every example/doc dependency pin:
   - python: `git grep -nE 'agent-assembly\s*[<>=]' docs/`
   - node:   `git grep -nE '@agent-assembly/sdk@' docs/`
2. For each pinned feature, check whether it exists in the **last published tag**:

   ```sh
   git cat-file -e <last-published-tag>:agent_assembly/adapters/<name>/__init__.py
   ```

   - **errors (absent)** → the feature is new in `X`; the pin **must** be the `X`
     registry form (`>=0.0.1b5`, etc.).
   - **succeeds (present)** → the existing lower pin is valid; **leave it**.
3. Fix any pin naming a version that does not actually contain its feature. (The
   beta.4 wave found four the QA pass missed: `agno` at `>=b4`, and `haystack` /
   `microsoft-agent-framework` / `smolagents` at `>=b2` — all adapters that only
   ship in `b5`.)

> Do this for **every** new feature's example, not just the canonical version
> files. A green `check-docs-versions.sh` does **not** catch these — it only
> checks the core install examples + the compat-matrix row.

### Step 4 — verify

From the agent-assembly worktree:

```sh
bash scripts/check-docs-versions.sh X     # e.g. v0.0.1-beta.3
```

It must exit `0`. If it flags a ref, fix that file and re-run. The check is
scoped to the **live install examples + the new compat-matrix row** — it
deliberately does **not** flag changelog/history rows that legitimately name
older versions.

Also run `markdownlint` on any edited `.md` and (if available) `shellcheck` if
you touched the script.

## Cross-references

- `release-tag-cut` — bumps Cargo literals + creates the tag and
  `docs/release/vX.md`. **Run this skill in the same release flow** so docs land
  with the version bump. *(Follow-up once
  [PR #1169 / AAASM-3449](https://github.com/ai-agent-assembly/agent-assembly/pull/1169)
  merges: add a one-line pointer to `release-docs-sync` in `release-tag-cut`'s
  flow index.)*
- `release-validate-channels` — post-tag channel propagation check (separate).
- [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md) — canonical
  release prose; this skill is the docs-content slice of it.

## Done when

- `scripts/check-docs-versions.sh X` exits 0 in agent-assembly.
- A new compat-matrix row for `X` exists in **both** the core and hub
  compatibility files.
- The hub's **static** core/Go badges read `X`.
- Every new-feature example pin points at the release that ships it (Step 3.5),
  verified absent from the prior published tag — not downgraded to the last
  published version.
- Consumer / registry-install repos were **not** bumped ahead of publish.
- Channel labels (incl. node-sdk `versions.json` / `versionChannels.json`) were
  **not** hand-edited (they're workflow-driven).
