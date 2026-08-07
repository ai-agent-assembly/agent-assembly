# Documentation inventory and migration map

[Content-layer ownership](content-ownership.md) says where a fact *belongs*.
[ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)
says which layer *wins* when two disagree. Neither says what is actually there.

This page is the census. It enumerates every tracked Markdown file across the
organisation's repositories, assigns each one a layer and a disposition, and
records the duplication and disagreement found while doing so. It is a
point-in-time measurement, not a specification: nothing here decides policy, and
where the measurement disagrees with `content-ownership.md` the specification is
right and this page is reporting a defect.

It exists to be consumed. The migration work that follows needs a page set it can
partition without two tickets editing the same file, and the legacy-URL work needs
the list of pages whose address will change. Those are the two tables at the end.

## What this page is not

It is **not** a second content-ownership specification. `content-ownership.md`
remains the instrument a contributor applies; this page only records what the
tree contains and what should happen to it.

It does not reproduce the contents of private repositories. Six of the eighteen
repositories below are private. For those, this page records that documentation
exists, how much, and where — which is a fact about the repository, not content
from inside it. No private page's text, structure below directory level, or
internal reasoning appears here.

## Method

### The repository set, and the rule that defines it

**Scope rule.** Every repository in the `ai-agent-assembly` organisation, plus
exactly one outside it: the L0 company site, which
[content-ownership.md](content-ownership.md#the-content-layers) names as a layer
of *this product's* content model. Nothing else outside the organisation is in
scope, whether or not it is checked out on a contributor's machine.

The rule is stated because the boundary is not self-evident and an inventory
that cannot be re-derived is not evidence. "Repositories in the organisation"
and "repositories this workspace checks out" are different sets, and the L0 site
is the one member of the second that the content model puts inside the first.

The organisation has **18** repositories:

```bash
gh repo list ai-agent-assembly --limit 100 --json name,isPrivate,isArchived
```

**Seventeen of those carry tracked Markdown**; `agent-assembly-spec` is archived
and empty. Adding the one external L0 site gives the **eighteen repositories
measured below**.

Nine of the eighteen are the surfaces this work was asked to inventory — the
company site, the product website, the Docs Hub, Core, the three SDKs, Arena and
Examples. The **other nine were not asked for**, and are included because
omitting them would have left a hole in the layer model this page measures
against:

- the four private product repositories — `cloud`, `agent-assembly-enterprise`,
  `internal-docs` and `e2e-private` — recorded at directory granularity only;
- `e2e-public`, whose evidence is 19 of its 26 files;
- the organisation's `.github` repository, which
  [owns the org-wide `SECURITY.md`](content-ownership.md#canonical-source-by-content-type)
  and the metadata registry
  [ADR 0014](../adr/0014-canonical-metadata-registry-and-drift-gate.md) assigns;
- `saas-infra`, `homebrew-tap` and `.github-private`, which carry 30 tracked
  Markdown files between them — including a second ADR tree in
  `saas-infra/docs/adr/` (11 files, 10 numbered decisions).

#### What is out of scope, and why

A silent exclusion is the defect this page exists to prevent, so every exclusion
is named and counted. None of the following is included in any total on this
page.

| Excluded | Files | Why |
|---|---:|---|
| `ai-agent-assembly/agent-assembly-spec` | 0 | Archived **and empty** — `git/trees/HEAD` returns HTTP 409 *"Git Repository is empty"*. Per project policy the spec stays in the Core monorepo. |
| `horonomy/.github` | 8 | Horonomy's own org profile |
| `horonomy/internal-docs` | 48 | Horonomy's own internal documentation |
| `horonomy/infra` | 5 | Horonomy's own infrastructure |
| `horonomy/GearMeshing-AI` | 13 | A separate Horonomy product |

The four `horonomy` repositories are excluded **by the scope rule, not by
oversight**: they are the company's own repositories, and none is a surface of
Agent Assembly's content model at any layer. `horonomy/official-website` is in
scope because `content-ownership.md` names it as L0 — the company's *product
portfolio* page is a layer of this product's content — and its four siblings are
not.

They are counted here anyway so the exclusion is quantified rather than
asserted. `horonomy/internal-docs` is the one worth knowing about: at 47
docs-bucket files it is a larger private surface than any of the six private
repositories that *are* recorded below. If a future decision brings Horonomy's
own documentation into this programme's scope, that is where the volume is.

### The counting rule

Counts are taken from `git ls-tree` against a **remote tracking ref**, never from
a directory walk and never from the local working tree. Three reasons, each of
which has produced a wrong number in this programme before:

- A directory walk counts untracked scratch files and anything a build step
  emitted, inflating the total.
- A walk cannot distinguish a checked-in generated file from a hand-authored one.
- Two of the checked-out repositories are on a feature branch, so the
  local `HEAD` is not the published state. Reading the remote ref sidesteps this.

Tracked-ness is tested with `git cat-file -e "${ref}:${path}"`, not with a
filesystem existence check.

Only `.md` and `.mdx` are counted. Images, `openapi/`, `proto/` and source files
carry documentation weight but are not pages, and the inventory is a page census.

The reproducible form, for any repository and ref in the table below:

```bash
git -C <repo> ls-tree -r --name-only <ref> | grep -Ec '\.(md|mdx)$'
```

### Four buckets

Total Markdown is not the documentation surface. Every file is sorted into
exactly one bucket by path:

| Bucket | Matches | What it is |
|---|---|---|
| **Docs** | `docs/**`, `website/**`, `blog/**`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md` | The reader-facing surface. This is what the inventory is about. |
| **Evidence** | `verification-reports/**`, `reports/**` | L6. Records of a measurement, written once and cited. |
| **Tool config** | `.claude/**`, `.github/**`, `CODE_OF_CONDUCT.md`, `SUPPORT.md` | Instructions to tools and contributors about process, not about the product. |
| **Other** | everything else | Enumerated in full below — it is small, and some of it is misfiled. |

### Per-repository counts

Measured at the refs shown. Public repositories first, private second.

| Repository | Ref | Total | Docs | Evidence | Tool config | Other |
|---|---|---:|---:|---:|---:|---:|
| `agent-assembly` (Core) | `remote/main` | 353 | 225 | 96 | 19 | 13 |
| `node-sdk` | `remote/main` | 330 | 319 | 5 | 6 | 0 |
| `python-sdk` | `remote/main` | 60 | 46 | 6 | 7 | 1 |
| `examples` | `origin/main` | 53 | 43 | 6 | 4 | 0 |
| `.github` (`dotgithub`) | `remote/main` | 41 | 9 | 0 | 30 | 2 |
| `arena` | `origin/main` | 38 | 25 | 7 | 5 | 1 |
| `docs` (Hub) | `origin/main` | 32 | 27 | 0 | 2 | 3 |
| `go-sdk` | `remote/main` | 27 | 23 | 1 | 3 | 0 |
| `e2e-public` | `origin/main` | 26 | 5 | 19 | 2 | 0 |
| `horonomy-official-website` | `origin/main` | 11 | 6 | 0 | 2 | 3 |
| `official-website` | `origin/main` | 9 | 8 | 0 | 1 | 0 |
| `homebrew-tap` | `HEAD` † | 3 | 1 | 0 | 2 | 0 |
| `internal-docs` *(private)* | `origin/main` | 66 | 40 | 24 | 2 | 0 |
| `cloud` *(private)* | `remote/main` | 43 | 21 | 18 | 1 | 3 |
| `agent-assembly-enterprise` *(private)* | `remote/main` | 25 | 17 | 7 | 1 | 0 |
| `saas-infra` *(private)* | `HEAD` † | 24 | 23 | 0 | 1 | 0 |
| `e2e-private` *(private)* | `origin/main` | 17 | 12 | 3 | 2 | 0 |
| `.github-private` *(private)* | `HEAD` † | 3 | 2 | 0 | 0 | 1 |
| **Total** | | **1161** | **852** | **192** | **90** | **27** |

† Three repositories are not checked out in this workspace, so their trees were
read from the GitHub API at the default branch rather than from a local remote
ref. The bucket rules applied are identical:

```bash
gh api "repos/ai-agent-assembly/<repo>/git/trees/HEAD?recursive=1" \
  --jq '.tree[]|select(.type=="blob")|.path' | grep -E '\.(md|mdx)$'
```

The bucket script that produced the four right-hand columns is a `grep -E` chain
over the same `ls-tree` output; it is reproduced in
[Appendix: the bucket script](#appendix-the-bucket-script) so the numbers can be
re-derived rather than trusted.

## How a row is classified

Every row carries two independent classifications, and the most common mistake
available here is to collapse them.

**The content layer, `L0`–`L6`**, comes from
[content-ownership.md](content-ownership.md#the-content-layers). It answers
*which audience is this page for, and what is it allowed to author?*

**The truth layer, `T1`–`T7`**, comes from
[ADR 0034 Decision 1](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#1-the-product-truth-hierarchy).
It answers *if this page and another disagree, which one changes?*

ADR 0034 states the correspondence and its limits directly: L4 (examples) and L5
(READMEs) have **no** truth layer at all, because they may only restate and never
author. A statement found in an example or a README that no truth layer supports
is a defect in that statement rather than a new source — which is why the
disposition column for those rows never reads *keep as canonical*, whatever the
page happens to say today.

The layer is a property of the surface, so it is assigned per directory. The
disposition is a property of the page.

### The disposition vocabulary

| Disposition | Meaning | Redirect obligation |
|---|---|---|
| **Keep** | Correct layer, correct owner. No migration ticket needs to touch it. | None |
| **Move** | Content is right, layer is wrong. Relocate unchanged. | Yes, if the page is published |
| **Merge** | Duplicates another page. Fold in, leave a link. | Yes, for the page that disappears |
| **Supersede** | A newer page states this better. Retire behind a pointer. | Yes |
| **Delete** | Not documentation, or no longer true, and nothing links to it. | Only if it was published |
| **Record** | Private or evidence. Counted, never migrated by this programme. | None |

*Move*, *Merge* and *Supersede* all imply a URL stops resolving. Every such page
appears in [Redirect obligations](#redirect-obligations), which is the table
[AAASM-3665](https://lightning-dust-mite.atlassian.net/browse/AAASM-3665)
consumes.

## The inventory

Rows are grouped by directory, because layer and audience are properties of the
surface. Where a page inside a group takes a different disposition from the
group, it is named underneath — so the groups plus their named exceptions
partition the surface exactly, and two migration tickets can take disjoint
slices without reading each other's diff.

Every group is expandable to its file list with:

```bash
git -C <repo> ls-tree -r --name-only <ref> -- <path> | grep -E '\.md$'
```

### L0 · Company site — `horonomy-official-website` (6 docs-bucket files)

### L1 · Product website — `official-website` (8 docs-bucket files)

These two are taken together because they share the finding that matters:
**neither publishes its content as Markdown.** Both are Docusaurus 3.10.2
classic-preset TypeScript sites whose reader-facing copy lives in `.tsx`
components as inline JSX.

| | L0 `horonomy-official-website` | L1 `official-website` |
|---|---|---|
| Published host | `horonomy.dev` | `agent-assembly.com` |
| Authored routes | 4 | 6 (× 2 locales) |
| Markdown pages published | **2** (`docs/intro.md`, 1 blog post) | **2** (both blog posts) |
| Docs plugin | enabled, 1 seed page | **`docs: false`** — no docs tree exists |
| Where the copy is | `src/pages/index.tsx` + 16 component modules | `src/pages/*.tsx` + `src/components/home/index.tsx` (563 lines) |
| Localisation | single locale | `en` + `zh-Hant`, translated via `i18n/zh-Hant/code.json` |

Of the 17 Markdown files across both repos, **4 are published**. The rest are
ADRs, design records, validation reports, PR templates and repo READMEs — three
of them saying so in their own text (`adr/README.md`: *"Reference material — not
published by the Docusaurus site."*).

**Disposition: Record.** There is almost nothing here for a Markdown migration
to move, and that is itself the finding — see
[D6](#d6--the-two-outermost-layers-are-not-markdown).

### L2 · Docs Hub — `docs` (22 pages + 4 root files)

mdBook, not Docusaurus, built at the site root of `docs.agent-assembly.com`,
with the five component doc sets mounted underneath at `/core/`,
`/python-sdk/`, `/node-sdk/`, `/go-sdk/` and `/arena/` by
`docs/scripts/aggregate.sh`. `docs/src/foo.md` publishes to
`https://docs.agent-assembly.com/foo.html`; `docs/src/README.md` becomes the
site index. A zh-Hant build is emitted under `/zh-Hant/`.

All 22 pages are listed in `SUMMARY.md`; there are no orphans.

| Group | Pages | Job | Disposition |
|---|---:|---|---|
| Routing and status — `documentation.md`, `docs-hub-aggregation.md`, `source-of-truth.md`, `README.md`, `compatibility.md` | 5 | Route to components; hold the status map | **Keep** — all five carry generated regions |
| Evaluation narrative — `comparison.md`, `product-promise.md`, `faq.md`, `risk-scenarios.md`, `open-core-boundary.md`, `glossary.md` | 6 | Help a reader decide | **Keep** |
| Managed service — `quickstart-saas.md`, `cloud-deployment.md`, `saas-claim-publication-checklist.md` | 3 | SaaS pages and the gate on SaaS claims | **Keep** |
| Operator — `docker-containers.md`, `self-host-observability.md`, `troubleshooting.md`, `security-model.md` | 4 | Run and debug the limited-function stack | **Keep** |
| Governance of the Hub itself — `page-standards.md`, `accessibility.md`, `localization.md` | 3 | The metadata contract and site policy | **Keep** |
| `policy-reference.md` | 1 | Field-by-field policy YAML reference, 464 lines | **Review** — see [D7](#d7--the-hubs-second-policy-reference-is-already-a-known-instance) |

Root files `README.md`, `CONTRIBUTING.md`, `AGGREGATION.md` and `MIGRATION.md`
are not book pages. `MIGRATION.md` is the AAASM-3665 plan and is quoted under
[Redirect obligations](#redirect-obligations).

One further page sits in the Hub repository's `docs/` tree but **outside**
`docs/src/`, so it is not in the book and not in `SUMMARY.md`:
`docs/sync-architecture.md`, a contributor-facing description of how
documentation reaches the hub. It says so itself, and records that the
cross-repo sync it describes is designed but not built (AAASM-302).
**Disposition: Keep** — the same category as Core's `docs/release/` and
`docs/superpowers/`: inside `docs/`, deliberately outside the book.

Five pages carry real generated regions (eight regions), fed by two generators
and two manifests:

| Page | Regions | Generator | Manifest |
|---|---:|---|---|
| `compatibility.md` | 3 (`matrix`, `notes`, `requirements`) | `docs/scripts/generate_compatibility.py` | `compatibility.toml` |
| `README.md` | 2 (`landing-badges`, `sdks-and-components`) | `docs/scripts/generate_hub_components.py` | `hub-components.toml` |
| `source-of-truth.md` | 1 (`source-of-truth-table`) | `generate_hub_components.py` | `hub-components.toml` |
| `docs-hub-aggregation.md` | 1 (`aggregation-table`) | `generate_hub_components.py` | `hub-components.toml` |
| `documentation.md` | 1 (`router`) | `generate_hub_components.py` | `hub-components.toml` |

Enforced by `.github/workflows/hub-metadata-check.yml`. Several further
occurrences of the marker text are prose or trailing explanatory comments and
are **not** generated content — the distinction was made by reading each match,
not by counting them.

### L3 · Core — `agent-assembly/docs/src` (143 pages)

This book. `T4` throughout: it authors architecture, ADRs, protocol and policy
semantics, and measured limitations.

| Group | Pages | Audience | Generated | Disposition |
|---|---:|---|---|---|
| `adr/` | 33 | Contributors, security researchers | Hand | **Keep** — canonical decision record; owned by other lanes |
| `cli/` | 24 | Operators | Hand | **Keep** |
| `devtools/` | 14 | Integrators, security researchers | Hand | **Keep** (one exception below) |
| `usage-guide/` | 11 | Operators, developers | Hand | **Keep** |
| `security/` | 8 | Security engineers | Hand | **Keep** |
| `operations/` | 7 | Operators | Hand | **Keep** |
| `architecture/` | 7 | Contributors | Hand | **Keep** |
| `generated/` | 6 | *(none — include fragments)* | **Generated** | **Keep** — see below |
| `development/` | 6 | Contributors | Hand | **Keep** — this page joins it |
| `quick-start/` | 4 | New users | Hand | **Keep** |
| `introduction/` | 4 | New users | Hand | **Keep** |
| `benchmarks/` | 4 | Operators, contributors | Hand | **Keep** |
| `migration/` | 2 | Upgraders | Hand | 1 Keep, 1 **Move** (below) |
| `protocol/`, `events/`, `governance/`, `reference/`, `research/` | 5 | Mixed | Hand | 4 Keep, 1 **Move** (below) |
| Root pages | 8 | Mixed | 7 Hand, 1 Generated | **Keep** |

Root pages are `README.md`, `SUMMARY.md`, `api-reference.md`, `compatibility.md`,
`policy-reference.md`, `policy-rbac.md`, `releases.md`, `versioning.md`.

#### The six `generated/` fragments are not pages

`generated/docs-url.md`, `install.md`, `protocol-version.md`, `repo-url.md`,
`version-tag.md` and `version.md` are single-value include fragments pulled in
with mdBook's `{{#include}}`, per
[Shared docs metadata](shared-docs-metadata.md). They are the **only** six pages
in the book absent from `SUMMARY.md`, and that absence is correct rather than an
oversight — they have no standalone reader.

This was verified rather than assumed: comparing the 136 `.md` targets in
`SUMMARY.md` against the 142 tracked pages leaves exactly those six, and the
reverse comparison is **empty** — every `SUMMARY.md` entry resolves to a tracked
file. The book's table of contents has no broken entries.

```bash
git show <ref>:docs/src/SUMMARY.md | grep -oE '\]\([^)]+\.md\)' \
  | sed 's/](//;s/)//' | sort -u > /tmp/in-summary
git ls-tree -r --name-only <ref> -- docs/src | grep -E '\.md$' \
  | sed 's|docs/src/||' | grep -v '^SUMMARY.md$' | sort -u > /tmp/all-pages
comm -13 /tmp/in-summary /tmp/all-pages   # orphans      -> the six fragments
comm -23 /tmp/in-summary /tmp/all-pages   # broken links -> empty
```

#### Named exceptions in Core

| Page | Why it is not *Keep* | Disposition |
|---|---|---|
| `migration/template.md` | A fill-in template, carrying literal `[FILL IN]` placeholders, listed in `SUMMARY.md` and therefore **published to readers** as if it were a guide. | **Move** — to a contributor-side location, out of the rendered book |
| `research/AAASM-5269-sensitive-data-provider-architecture.md` | 1,193 lines that state of themselves: *"This is a research report. It recommends; it decides nothing."* That is an L6 record of an investigation, and the decision it fed became [ADR 0032](../adr/0032-local-first-sensitive-data-provider-architecture.md). Publishing it as a book chapter puts a non-deciding document beside deciding ones. | **Move** — candidate for L6; requires a decision from AAASM-5594, not from this page |
| `events/cross_team_edge.md` | The sole page in its section, documenting one event. A section of one is a filing accident rather than a structure. | **Merge** — into a protocol/event reference |
| `devtools/product-brief.md` | 865 lines describing itself as *"the product-level source of truth"*. The content is measured integration capability, which is properly `T4`; the **phrase** claims an authority that [content-ownership.md](content-ownership.md#canonical-source-by-content-type) assigns product positioning to L1. | **Keep**, retitle — the page belongs here, its self-description does not |

### L3 · SDKs — live documentation

| Repo | Path | Pages | Renderer | Frontmatter | Disposition |
|---|---|---:|---|---|---|
| `python-sdk` | `docs/**` | 40 | mkdocs + mike | **0 of 40** | **Keep** |
| `node-sdk` | `docs/**` | 21 | Docusaurus | 19 of 21 (`sidebar_position`) | **Keep** |
| `go-sdk` | `docs/**` | 20 | Hugo | 20 of 20 (`title`, `weight`) | **Keep** |

Three renderers, three versioning mechanisms, and **no frontmatter key common to
all three** — the intersection is empty. Every key in use is a site-renderer
directive (ordering, TOC, search exclusion, slug); none is descriptive metadata.
No page in any SDK carries a `description`, `owner`, `status`, `last_reviewed`
or ticket reference. Any future metadata contract therefore starts from zero on
python-sdk's 40 pages and adds new keys to the other 41.

Each SDK generates exactly one bounded block, all in its quick-start:

| Repo | Page | Marker | Generator |
|---|---|---|---|
| `node-sdk` | `docs/02-quick-start/index.md` | `{/* BEGIN GENERATED: install-commands */}` and two more | `scripts/generate-docs-metadata.mjs` |
| `go-sdk` | `docs/quick-start.md` | `<!-- BEGIN GENERATED: quickstart-tabs -->` | `scripts/gen-quickstart-tabs.go` |
| `python-sdk` | `docs/quick-start.md` | `<!-- BEGIN GENERATED: quickstart-framework-tabs -->` | `scripts/generate_quickstart_tabs.py` |

The python-sdk block is the odd one out: it carries no `DO NOT EDIT` line, so a
contributor who opens it has no in-file warning that an edit will be overwritten.

#### `node-sdk/website/versioned_docs` — 294 pages, and none of them are source

294 of node-sdk's 330 tracked Markdown files — **89% of the repository's
Markdown** — are frozen Docusaurus release snapshots across 19 versions, listed
in `website/versions.json`. They are cut by `pnpm docusaurus docs:version` at
publish time, and `website/docusaurus.config.ts` instructs contributors not to
cut or edit one by hand.

They are **build output that is deliberately expected to drift**. Comparing each
snapshot page's blob against the live `docs/` page at the same relative path:
**288 differ, 3 are identical, and 3 have no live counterpart.** Only 93 unique
blobs back the 294 files, so two thirds are byte-duplicates of another snapshot.

```python
# Run from a node-sdk checkout. Prints 288 / 3 / 3 / 93 at remote/main.
import re, subprocess

def blobs(ref, sub):
    # check=True: a failed git call must raise, not return an empty set.
    out = subprocess.run(["git", "ls-tree", "-r", ref, "--", sub],
                         capture_output=True, text=True,
                         check=True).stdout.splitlines()
    d = {}
    for line in out:
        meta, path = line.split("\t", 1)
        if path.endswith((".md", ".mdx")):
            d[path] = meta.split()[2]        # blob SHA
    return d

REF = "remote/main"
snap = blobs(REF, "website/versioned_docs")
live = blobs(REF, "docs")
# An empty input would print a clean-looking row of zeros. Refuse to.
assert snap and live, "empty tree — run this from a node-sdk checkout"
same = diff = absent = 0
for path, sha in snap.items():
    rel = re.sub(r"^website/versioned_docs/version-[^/]+/", "", path)
    counterpart = live.get("docs/" + rel)
    if counterpart is None: absent += 1
    elif counterpart == sha: same += 1
    else:                    diff += 1
print(f"differ={diff} identical={same} no-counterpart={absent} "
      f"unique-blobs={len(set(snap.values()))} total={len(snap)}")
```

An earlier attempt at this in shell returned all zeros — every `sed` and `awk`
inside the loop had silently failed on a lost `PATH`, and "0 differ" is a
plausible-looking answer. The Python is published because the number is only as
trustworthy as the reader's ability to re-run it and see the same thing.

Treating them as a migration surface would be a category error, and treating
their drift as a duplication defect would be too.

**Disposition: Record.** No migration ticket should touch them. They are noted
here only so that the next person to run a repository-wide Markdown count is not
misled by node-sdk appearing to be the largest documentation surface in the
organisation, which it is not — its live surface is 21 pages, the smallest of
the three SDKs.

Neither sibling SDK pays this cost: `python-sdk` publishes versions to
`gh-pages` via mike, and `go-sdk` declares channels in
`website/data/versions.toml` with zero Markdown under `website/`.

#### Structural parity across the three SDKs

The three sets cover the same product, and most of their topics line up. The
asymmetries below are the ones that do not, and they are a content gap rather
than a migration item:

| Topic | node-sdk | python-sdk | go-sdk |
|---|---|---|---|
| Standalone architecture page | yes | yes | folded into core-concepts |
| Standalone allow/deny decisions guide | folded into guides index | yes | yes |
| Framework-integration guide | folded into guides index | split across two pages | yes |
| "Govern an agent's tools" task guide | — | — | yes |
| Release runbook page | yes | yes | — |
| Release-process page | yes | yes | folded into compatibility |
| Release-notes page | — | yes | — |
| Registry dist-tag policy | yes | — | — |
| ADRs inside docs | — | 1 | 1 |
| Contributor/development section | — | 3 pages | — |
| Framework examples | 5 | **12** | 1 |

Framework-example depth is the widest gap: python-sdk documents twelve
framework integrations, go-sdk one.

### L3 · Arena — `arena` (25 docs-bucket files)

The fifth L3 component, and the one most easily missed: its docs are **mounted
into the published Hub at `/arena/`** by `docs/scripts/aggregate.sh`, so these
are live reader-facing URLs, not repository-internal notes.

| Group | Pages | Job | Disposition |
|---|---:|---|---|
| `docs/*.md` | 13 | The component doc set — architecture, API reference, runners, behaviour profiles, report schema, glossary, submitting an agent | **Keep** |
| `docs/samples/**` | 2 | Two example match reports | **Keep** |
| `agents/**/README.md` | 6 | One per bundled agent | **Keep** — L5 signposts |
| `tests/fixtures/**/README.md` | 2 | Fixture scaffolding | **Record** — not a documentation surface |
| `README.md`, `CONTRIBUTING.md` | 2 | Repository signposts | **Keep** |

`docs/security-policy.md` is the instance
[content-ownership.md](content-ownership.md#canonical-source-by-content-type)
already anticipates when it notes that Arena "additionally scopes its own
trial-ground policy as a docs page". It is a scoped local policy, not a rival to
the org-wide `SECURITY.md`, and stays.

**All 15 `docs/**` pages are published**, so any move among them carries a
redirect obligation against `docs.agent-assembly.com/arena/`. None is proposed
here.

### L3 · Verification harness — `e2e-public` (5 docs-bucket files)

19 of this repository's 26 Markdown files are evidence, already counted under
L6. The remaining five are the harness's own contributor documentation.

| Page | Disposition |
|---|---|
| `docs/ci-profiles.md`, `docs/verification-modes.md`, `docs/production-validation-runbook.md` | **Keep** — how to run the harness |
| `docs/evidence-template.md` | **Keep** — a template, but a contributor-side one that is not published in any book, unlike Core's `migration/template.md` |
| `README.md` | **Keep** |

### L5 · Org profile — `.github` (9 docs-bucket files)

30 of its 41 files are tool config, noted below. The nine docs-bucket files:

| Page | What it is | Disposition |
|---|---|---|
| `SECURITY.md` | The **org-wide vulnerability reporting process** — canonical for every repository that has no `SECURITY.md` of its own | **Keep** — this is why the repository is in this inventory |
| `README.md`, `profile/README.md` | The org profile GitHub renders | **Keep** |
| `CONTRIBUTING.md` | Org-wide contribution guidance | **Keep** |
| `metadata/README.md`, `scripts/README.md` | Signposts for the ADR 0014 metadata registry and its tooling | **Keep** |
| `docs/onboarding-poc/AAASM-394{5,6,7}-*.md` | Scaffold-integration findings, dogfooding notes and a POC findings summary | **Move** — records of an investigation, not reader-facing pages |

Those last three are the same pattern as
[D5](#d5--nine-evidence-files-are-filed-in-the-source-tree): findings records
filed on a documentation path. They are **not** in D5's list of nine, which
covered only `agent-assembly`; counting them makes twelve misfiled evidence
files in total across the two repositories.

### L4 · Examples — `examples` (43 docs-bucket files)

One `README.md` per runnable integration, plus scenarios and a choosing guide.
The 43 docs-bucket files are **40 READMEs + 2 pages under `docs/`
(`choosing-an-example.md`, `concepts.md`) + `CONTRIBUTING.md`**.

The READMEs distribute as `python/` 17, `scenarios/` 9, `node/` 7, `go/` 5,
`snippets/` 1 and the repository root 1 — each language directory's count
including its own index README above the per-framework ones.

A 41st `README.md` exists at `.github/workflows/README.md`; it is **Tool config**
under this page's own bucket rules and is not part of the 43.

**Disposition: Keep**, with the standing constraint that L4 has **no truth
layer**. Under
[ADR 0034 Decision 1](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#1-the-product-truth-hierarchy),
an example may restate and never author, so no example README can be the
canonical source for anything it says.

### L5 · Repository READMEs — 151 in the docs bucket

Every one of the eighteen repositories has a root `README.md`. Across all
directory levels there are **158 tracked `README.md` files, of which 151 are in
the docs bucket** — the other seven are Evidence or Tool config by this page's
own rules and are counted there instead:

| | All levels | Docs bucket | The difference |
|---|---:|---:|---|
| `agent-assembly` | 45 | 44 | `verification-reports/README.md` |
| `examples` | 41 | 40 | `.github/workflows/README.md` |
| `saas-infra` | 12 | 12 | — |
| `arena` | 10 | 9 | `reports/README.md` |
| `cloud` | 9 | 6 | three under `verification-reports/` |
| `e2e-public` | 2 | 1 | `verification-reports/releases/README.md` |
| all others | 39 | 39 | — |
| **Total** | **158** | **151** | |

`agent-assembly`'s 44 are mostly crate READMEs; `examples`' 40 are the L4 example
pages counted above rather than L5 signposts.

**Disposition: Keep.** Like L4, L5 has no truth layer and may only restate.

#### The other repository signposts

`README.md` is not the only signpost, and the rest would otherwise fall between
the groups above. Every remaining docs-bucket file that is not under a `docs/`,
`website/` or `blog/` tree is one of these:

| File | Where | Disposition |
|---|---|---|
| `CONTRIBUTING.md` | 11 repositories | **Keep** — contributor process, correctly per-repo |
| `SECURITY.md` | `agent-assembly`, `node-sdk`, `python-sdk`, `.github-private`, and the org-wide one in `.github` | **Keep** — the [canonical-source table](content-ownership.md#canonical-source-by-content-type) assigns this per repository, falling back to the org default, which is exactly the arrangement present |
| `node-sdk/website/README.md` | 1 file | **Keep** — Docusaurus scaffolding, not a page |

That closes the docs bucket: every file in it is now either inside a named
`docs/`/`website/`/`blog/` group, a `README.md` counted above, or one of these.

`homebrew-tap`'s `README.md` is the exception worth naming: it is the tap the
install documentation points readers at, so it is a **published install surface**
rather than a repository signpost. It is 1 of that repository's 3 Markdown files,
the other two being tool config. **Disposition: Keep**, and it belongs in any
sweep that checks install instructions for agreement — see
[D9](#d9--four-confirmed-contradictions), where two of the four contradictions
are about installation.

Core's root `README.md` and its `aa-*/README.md` set are owned by
[AAASM-5672](https://lightning-dust-mite.atlassian.net/browse/AAASM-5672) and are
recorded here only.

```bash
git -C <repo> ls-tree -r --name-only <ref> | grep -Ec '(^|/)README\.md$'
```

### L6 · Evidence — 192 files across 11 repositories

`verification-reports/**` and `reports/**`. Per
[content-ownership.md](content-ownership.md#the-content-layers) these are
records of a measurement, written once and cited, never maintained as a
narrative. **Disposition: Record** for all 192.

Core holds half of them (96). The distribution is in the
[per-repository counts](#per-repository-counts).

#### Evidence filed outside the evidence directory

Nine files carry evidence but sit in the source tree, where neither an
evidence sweep nor a documentation sweep will find them:

| Path | Repo |
|---|---|
| `dashboard/docs/verification/aaasm-{94,1152,1341,1383,1384,1395,4080}-*.md` | `agent-assembly` |
| `aa-cli/AAASM-4457-error-message-audit.md` | `agent-assembly` |
| `aa-gateway/benches/REPORT.md` | `agent-assembly` |

**Disposition: Move** to `verification-reports/`. None is published, so none
carries a redirect obligation.

### Repo-internal Markdown that is not a documentation surface

87 files of tool configuration (`.claude/**`, `.github/**`,
`CODE_OF_CONDUCT.md`, `SUPPORT.md`) and the 26-file *Other* bucket. The `.github`
repository is 30 of the 87, which is what that repository is for.

**Disposition: Record**, with three exceptions already listed above
(`dashboard/docs/verification/**`, `aa-cli/…`, `aa-gateway/benches/REPORT.md`).

### Private repositories — recorded, not reproduced

Six repositories are private. This page records their documentation volume and
top-level shape, which is a fact about the repository rather than content from
inside it. **Disposition: Record** for all 115 docs-bucket files; none is in the
public migration scope, and no public page may restate their internals.

| Repo | Docs | Evidence | Shape |
|---|---:|---:|---|
| `internal-docs` | 40 | 24 | `docs/{architecture,adr,runbooks,enterprise,reference,onboarding,design}` |
| `saas-infra` | 23 | 0 | `docs/adr/` (11), `docs/runbooks/`, 12 READMEs |
| `cloud` | 21 | 18 | `docs/`, `docs/architecture/`, `design/` |
| `agent-assembly-enterprise` | 17 | 7 | `docs/`, `docs/generated/` (9) |
| `e2e-private` | 12 | 3 | `docs/`, `tests/`, `fixtures/` |
| `.github-private` | 2 | 0 | `README.md`, `SECURITY.md` |

#### Core's `adr/` is not the organisation's only decision record

There are **four decision-record trees**, three of them private:

| Tree | Files | Numbering |
|---|---:|---|
| `agent-assembly/docs/src/adr/` | 33 | `0001`… |
| `saas-infra/docs/adr/` *(private)* | 11 | `0001`… |
| `internal-docs/docs/adr/` *(private)* | 10 | `ADR-001`… |
| `internal-docs/docs/architecture/adr/` *(private)* | 8 | `ADR-001`… |

`internal-docs` therefore collides with **itself**, before any cross-repository
collision is considered.

Directory names and file counts are facts about a repository; what those
decisions say is not, and none of it appears here.

Two consequences follow, and both are directory-level observations that need no
private content to state:

**Numbering collides across the trees, and this page cites some of the colliding
identifiers bare.** Each tree numbers from `0001`, so a bare "ADR 0007" or
"ADR 0014" — both of which appear on this page — identifies a document only once
the reader already knows which tree is meant. This is exactly the hazard
[D2](#d2--three-numbering-schemes-two-of-which-are-spelled-l) records for the
`L0`–`L6` / `T1`–`T7` / `L0`–`L3` collision, and the remedy is the same:
qualify the identifier with its tree. Every ADR reference on this page is to
Core's tree.

**[D9's `tool.agent-assembly.dev` contradiction](#d9--four-confirmed-contradictions)
is adjudicated from Core's ADR set alone.** A private tree covers infrastructure
subject matter that may bear on it. That finding should therefore be re-checked
against the private trees before it is filed. The two may agree; this page has
not established that they do, and cannot show either way.

`internal-docs` and `cloud` both also carry a `docs/architecture/` tree. Whether
any of these overlap Core's `architecture/` cannot be assessed in a public page.
Flagged for a private-side review, not resolved.

## Findings

Duplication and disagreement are what an inventory is for. A count tells you how
much there is; these tell you what is wrong with it.

The two are graded differently. **Duplication** is often correct — the layer
model is built on outer layers restating inner ones, and
[content-ownership.md](content-ownership.md#duplication-rules) permits several
forms of it. **Disagreement** is never correct: two pages stating incompatible
things about one fact is a defect regardless of which layers they sit in.

**What is published here is what was verified here.** Each finding below was
established by reading both sides at a named ref, or by running the gate that
decides the question and reading its exit code. A wider cross-repository sweep
produced further contradiction *candidates* — around the compatibility matrix's
per-release SDK pairings, container base-image version pins, SDK auto-start
defaults, and how the interception layers are described relative to
[ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md).
Those are not listed here, because a governance page that publishes an
unverified defect has committed the error it exists to prevent. They were handed
to defect triage as leads.

### D1 · Seventeen internal links in Core point at a path that does not exist

Ten pages in the Core book link to `../architecture/index.md` (13 links),
`architecture/index.md` (2) or `introduction/index.md` (2). Neither target is
tracked; the real files are `architecture/README.md` and
`introduction/README.md`.

```bash
git grep -o -e '\.\./architecture/index\.md' -e 'architecture/index\.md' \
             -e 'introduction/index\.md' <ref> -- docs/src \
  | sed 's/.*://' | sort | uniq -c
```

This is confirmed by the repository's own gate rather than by inspection —
`scripts/check-doc-links.sh` **exits 1** on the current tree:

```bash
git ls-tree -r --name-only <ref> -- docs/src | grep -E '\.md$' \
  | xargs bash scripts/check-doc-links.sh
# 17 × "::error::broken internal link", exit 1
```

The severity is bounded, and stating it precisely matters. mdBook maps
`README.md` to `index.html`, so the **rendered book is correct**: the emitted
href is `../architecture/index.html`, and that file exists in `docs/book/`. The
links fail for a reader browsing the source on GitHub, and they fail the gate.

That the gate is red on `main` means it is not run across the whole book in CI —
it takes explicit file arguments, so a pull request that touches none of these
ten pages never sees the failure. **Report as a defect**; the fix is out of this
page's scope.

### D2 · Three numbering schemes, two of which are spelled `L`

A reader who meets `L2` in this repository has to work out which of three
vocabularies it belongs to:

| Scheme | Range | Means | Defined in |
|---|---|---|---|
| Content layers | `L0`–`L6` | Publication surface, by audience distance | [content-ownership.md](content-ownership.md#the-content-layers) |
| Truth layers | `T1`–`T7` | Evidential authority | [ADR 0034 §1](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#1-the-product-truth-hierarchy) |
| Governance capability tiers | `L0`–`L3` | How much a dev-tool adapter can enforce | `governance/capability-matrix.md` |

ADR 0034 already warns that conflating the first two is "the first mistake
available" and supplies a mapping table. It does not mention the third, which
collides with the first in both letter and range: `L0`–`L3` are valid values in
two unrelated schemes, and `governance/capability-matrix.md` is itself an L3
page.

Not a contradiction — the schemes are independently coherent. **Report as a
naming hazard** for AAASM-5594 to resolve, most cheaply by renaming the
governance tiers.

**The same hazard applies to bare ADR numbers, and this page is not exempt.**
There are [four decision-record trees](#cores-adr-is-not-the-organisations-only-decision-record),
each numbering from `0001`, so "ADR 0007" identifies a document only once the
reader knows which tree is meant. This page cites several such identifiers bare;
all of them refer to Core's tree. Qualifying the identifier with its tree is the
same remedy as renaming the governance tiers, and is worth applying wherever an
ADR is cited across repositories.

### D3 · Every SDK example page has an examples-repo twin

23 pairs, established by set comparison rather than sampling:

| SDK | Example pages | With an `examples/` counterpart | SDK-only |
|---|---:|---:|---:|
| `python-sdk` | 13 | **13** | 0 |
| `node-sdk` | 6 | **6** | 0 |
| `go-sdk` | 4 | **4** | 0 |

The overlap is total in all three directions: no SDK documents a framework
example that the `examples` repository does not also ship.

This is **permitted duplication, not a defect** — the SDK page is `T4` and
canonical; the example README is L4 with no truth layer and may only restate.
But it is 23 pairs of pages that must be changed together, which is a
maintenance obligation nobody has written down, and the direction of authority
is not stated on any of the 46 pages.

**Disposition: Keep both**; record the canonical direction explicitly on the L4
side.

Three python frameworks — AutoGen, Semantic Kernel and Strands Agents — ship a
runnable example with **no dedicated SDK example page**. They are not
undocumented: all three appear as tabs in `python-sdk/docs/quick-start.md`
(verified by `git grep`, with `agno` as a known-present control). It is an
asymmetry inside the SDK's own examples section, not a claim without a source.

### D4 · The three SDKs share no documentation metadata

Three renderers (mkdocs+mike, Docusaurus, Hugo), three versioning mechanisms,
and an **empty intersection** of frontmatter keys: `title` exists only in
go-sdk, `sidebar_position` only in node-sdk, and python-sdk's 40 pages carry no
frontmatter at all.

Every key in use is a renderer directive. **No page in any SDK carries
descriptive metadata** — no `description`, `owner`, `status`, `last_reviewed`,
or ticket reference. Core is the same: zero of its 143 pages carry frontmatter,
verified with a `BEGIN GENERATED` control proving the search would have found a
match.

**Report as a gap**, not a defect. It is the precondition anything resembling a
metadata contract would have to establish first, and it is a larger job than it
looks: 40 pages from nothing, plus new keys on 41 more, plus 143 in Core.

### D5 · Nine evidence files are filed in the source tree

Listed under
[Evidence filed outside the evidence directory](#evidence-filed-outside-the-evidence-directory).
`dashboard/docs/verification/**` in particular is seven acceptance and
design-fidelity records sitting under a `docs/` path, where a documentation
sweep will pick them up as pages and an evidence sweep will miss them entirely.

**Disposition: Move** to `verification-reports/`.

### D6 · The two outermost layers are not Markdown

`content-ownership.md` assigns L0 company positioning and L1 product positioning
to two repositories that publish essentially no Markdown. Between them they
track 17 Markdown files, of which **4 are published**: one seed docs page and
three blog posts. Everything a reader actually sees on `horonomy.dev` and
`agent-assembly.com` is inline JSX inside `.tsx` components — 563 lines of it in
`official-website/src/components/home/index.tsx` alone — and `official-website`
sets `docs: false`, so it has no docs tree at all.

Three consequences, none of which is visible from a page count:

**A Markdown-based governance sweep cannot see L0 or L1.** Any check that
enumerates `.md` files — including this inventory, and including
`check_absolutes_unwaivable.py` — passes over the product website trivially,
because the claims are in TypeScript.

**The `zh-Hant` locale on L1 has no translated Markdown.** Translations live in
`i18n/zh-Hant/code.json`. The two blog posts occupy `zh-Hant` routes while
serving English content.

**L1 is the layer with the strongest commercial incentive to overstate**, and it
is the layer least reachable by the tooling built to catch overstatement.

**Report as a structural gap.** It is not a defect in any page; it is a gap in
what the governance model can reach, and AAASM-5594 should know it before
planning migration work that assumes Markdown.

### D7 · The Hub's second policy reference is already a known instance

The Docs Hub publishes `policy-reference.md` (464 lines) and so does Core. They
are independent prose, neither generated from the other.

This is **not a new finding**. `content-ownership.md` records it as
[the reference instance](content-ownership.md#worked-example-two-hand-written-policy-references)
of the failure that page exists to prevent, including a specific contradiction
in the Hub page's opening, and assigns the fix to
[AAASM-5586](https://lightning-dust-mite.atlassian.net/browse/AAASM-5586) and
[AAASM-5609](https://lightning-dust-mite.atlassian.net/browse/AAASM-5609).

It is repeated here only so that the inventory's disposition column is
consistent with the specification's: the Hub page is **Review**, owned
elsewhere, and no migration ticket arising from this map should touch it.

### D8 · The metadata contract exists, and one page in the organisation satisfies it

`docs/src/page-standards.md` in the Docs Hub defines a real, detailed contract:
an `AA-PAGE-META` block, written as an HTML comment as the first construct in
the file before the `H1` — mdBook has no YAML frontmatter — carrying eight
required keys (`schema_version`, `page_type`, `audience`, `user_job`, `owner`,
`canonical_source`, `describes_capability`, `disclosure_levels`), conditional
keys, and fifteen cross-field rules. Unknown keys are a hard error.

Conformance today:

| Surface | Pages | Conforming |
|---|---:|---:|
| Docs Hub (`docs/src`) | 22 | **1** — `page-standards.md` itself |
| Core (`agent-assembly/docs/src`) | 143 | **0** |
| `python-sdk` / `node-sdk` / `go-sdk` (`docs/`) | 81 | **0** |

The contract's `owner` enum includes `L3:agent-assembly` and eight further `L3:`
surfaces, so it is designed to span repositories. Adoption has not started
outside the page that defines it. The backfill is
[AAASM-5610](https://lightning-dust-mite.atlassian.net/browse/AAASM-5610); the
validator that would enforce it is
[AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601) and
does not exist yet.

**This page does not carry an `AA-PAGE-META` block, and that is deliberate.**
Adding one would make it the only page in Core with one, inventing a local
convention in a repository that has not adopted the contract, with no validator
to check it was written correctly. The adoption decision belongs to AAASM-5610,
not to a page that is only supposed to be counting. Recorded here so the
omission is a visible choice rather than an oversight.

### D9 · Four confirmed contradictions

These are pages stating incompatible things about one fact. Each was verified by
reading both sides at the named ref, and each is a **defect** — the resolution
belongs to defect triage, not to this page, which deliberately does not pick a
winner.

Every entry names the layer that should change under
[ADR 0034 Decision 1](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#1-the-product-truth-hierarchy).

#### `:8080` has three mutually exclusive definitions

| Where | What it says `8080` is |
|---|---|
| Core `quick-start/first-run.md` | The gateway's own HTTP API — *"`aasm status`, `aasm agent`, and `aasm topology` talk to the gateway's **HTTP API on `http://localhost:8080`**"* |
| Core `usage-guide/overview.md`, `usage-guide/troubleshooting.md` | The **SaaS** control-plane API, *"not part of the open-source local runtime"*; the local gateway *"serves its API on `7391`, not `8080`"* |
| Hub `troubleshooting.md` | *"Port `8080` is a **different** endpoint — the aa-runtime health/metrics server (`AA_METRICS_ADDR`) — not the gateway REST API."* |

The first two are both in **this book**, so this is an intra-repository
contradiction before it is a cross-repository one. `T1` settles the behaviour:
`aa-cli/src/config.rs` defaults the CLI to `http://localhost:8080` while
`aa-cli/src/commands/start.rs` defaults the local gateway's port to `7391`. The
mismatch the second row describes is real, which makes the first row's account
of where operator commands land wrong in local mode.

#### The compatibility matrix carries a row for a release that does not exist

Core's `compatibility.md` states `| v0.0.1 | v0.0.1 ✓ | v0.0.1 ✓ | v0.0.1 ✓ |`.
There is no `v0.0.1` tag: `git tag -l "v0.0.1"` returns nothing, while the
control `git tag -l "v0.0.1-rc.6"` returns the tag. The Hub's matrix has no such
row. A ✓ against an unreleased version is a claim with no artifact behind it.

#### The installer's default directory

Core's `README.md` states the binary installs to `~/.local/bin`.
`quick-start/installation.md` states `/usr/local/bin` first, falling back to
`~/.local/bin`. `scripts/install-cli.sh` implements the second. `T1` wins and
the README is the defect; it is owned by
[AAASM-5672](https://lightning-dust-mite.atlassian.net/browse/AAASM-5672) and is
recorded here, not touched.

#### An installer host is advertised and retired at the same time

[ADR 0007](../adr/0007-public-domain-and-url-contract.md) states that
`tool.agent-assembly.dev` is *"**retired**"* and *"no longer an advertised
installer alternate"*. Core's `README.md` advertises it — *"The alternate host
`https://tool.agent-assembly.dev` serves the same script"* — and
`quick-start/installation.md` calls it *"a kept alternate"*.
`infra/redirects/README.md` §2 also treats it as live and forbids redirecting
it. An Accepted ADR states the intended contract, so under ADR 0034's carve-out
the ADR wins and the three pages are the defect.

### D10 · The claim vocabulary has no enforcing check

`development/claim-vocabulary.md` is a 1,263-line specification: twelve
`CLAIM-ABS-*` rules plus a verb rule and a quotation rule, with severities,
PCRE patterns, five silent exemption classes and a documented scan pipeline.

**No script implements it and no workflow runs it.** Searching `scripts/` and
`.github/workflows/` for `CLAIM-ABS`, `claim_vocab` and `claim-vocab` returns
nothing; the control — `check_absolutes` — is found, in `docs.yml`.

The gate that does exist, `scripts/check_absolutes_unwaivable.py`, is a
different and much narrower instrument. It does not look for the vocabulary at
all: it fails when a governance page asserts that one of those rules is
*waiver-eligible*. Both are needed, and only the second one runs.

**Report as a gap.** The distinction matters because a green CI run on a
documentation change currently proves the second property and says nothing about
the first, which is the one most readers would assume it covers.

### D11 · Two Core `docs/` trees are outside the book by design, and one is stale

`docs/release/` (27 files) and `docs/superpowers/` (13 files) sit in Core's
`docs/` tree but not in `docs/src/`, so they are neither book pages nor
evidence. `scripts/check-doc-orphans.sh` names both as deliberate exclusions.

`docs/release/` is 19 per-tag release notes, a runbook and 7 security
sign-offs, referenced by `docs/src/releases.md`. **Disposition: Keep**, except
the 7 `security-signoff/` files, which are records of a measurement and belong
with the other evidence. **Disposition: Move.**

`docs/superpowers/` is described by the orphan script as "planning/spec scratch
space, never published". All 13 files are dated 2026-04-27 to 2026-04-29 and
cover tickets whose work has long since shipped and, where it produced a
decision, been recorded in the ADR set.

**Disposition: Delete — recommended, requires sign-off.** Nothing links to
them, they were never published, and they carry no redirect obligation. This
page recommends; it does not act, and no migration ticket should remove them
without an explicit decision.


## Redirect obligations

This section is the hand-off to
[AAASM-3665](https://lightning-dust-mite.atlassian.net/browse/AAASM-3665).
`infra/redirects/README.md` §3 states that the per-repo path mapping is owned
there and that the file records "the **intent and the rule shape**, not the
final per-repo table". This is the input to that table.

### How a Core path becomes a URL

`.github/workflows/docs.yml` builds the book with mdBook and assembles a
versioned site: the current build lands in `_site/latest/` and each release
under `_site/<version>/`, published with `actions/deploy-pages`. So
`docs/src/<path>.md` resolves to `<host>/latest/<path>.html`, and
`docs/src/<dir>/README.md` resolves to `<host>/latest/<dir>/index.html` — the
`README` → `index` mapping that [D1](#d1--seventeen-internal-links-in-core-point-at-a-path-that-does-not-exist)
turns on.

Two consequences shape the obligation:

**Archived versions are frozen and must not be rewritten.** A page that moves
today keeps its old URL in every previously published version, correctly. Only
`latest/` breaks. A redirect rule that matched all versions would falsify the
archive.

**The Core book has no redirect mechanism configured.** `docs/book.toml` has no
`[output.html.redirect]` section — mdBook supports one and it is absent — so a
moved page currently 404s inside `latest/` with nothing to catch it. Adding that
section is the cheapest fix for in-book moves and does not require the
owner-gated Cloudflare path.

### The legacy-URL table already exists, and is unimplemented

`MIGRATION.md` in the `docs` repository is the AAASM-3665 plan. It carries the
five legacy host mappings:

| Legacy URL | Canonical target |
|---|---|
| `ai-agent-assembly.github.io/agent-assembly-docs/` | `docs.agent-assembly.com/` |
| `ai-agent-assembly.github.io/agent-assembly/` | `docs.agent-assembly.com/core/` |
| `ai-agent-assembly.github.io/python-sdk/` | `docs.agent-assembly.com/python-sdk/` |
| `ai-agent-assembly.github.io/node-sdk/` | `docs.agent-assembly.com/node-sdk/` |
| `ai-agent-assembly.github.io/go-sdk/` | `docs.agent-assembly.com/go-sdk/` |

The chosen strategy is a `rel=canonical` plus redirect stub in each repository,
not deletion, rolled out hub-first and core-last.

**None of the five is implemented.** A sweep for `rel="canonical"`,
`http-equiv="refresh"` and `location.replace` across the four repositories
returns only the illustrative stub inside `MIGRATION.md`'s own fenced code
block, plus two unrelated hits in Core. So
`ai-agent-assembly.github.io/agent-assembly/` serves live content today and does
not point at its canonical home.

### Exactly one redirect is deployed

`agent-assembly/docs/site-root-index.html`, published as the Pages site root by
`docs.yml` and reused by the Hub at `/core/index.html`. It resolves a **version
channel**, not a legacy URL: site root → `stable`, else `pre-release`, else
`latest/`, read client-side from `versions.json`, with a `<meta refresh>` to
`latest/` as the no-JavaScript fallback. It carries `noindex`.

Everything else in `infra/redirects/README.md` is host-level and **Proposed,
owner-gated, and not applied by CI** — the file says so in its own first
paragraph. No page-level redirect is configured in any of the four repositories.

Mechanically confirmed absent, each with a positive control in the same sweep:
`_redirects`, `netlify.toml`, `vercel.json`, `.htaccess`, nginx config, and
`@docusaurus/plugin-client-redirects` (control: `preset-classic`, found).

One consequence is worth stating because it looks like a working mechanism and
is not: Core's mdBook theme references a `fragment_map` at
`docs/theme/index.hbs`, which mdBook populates **only** when
`[output.html.redirect]` is configured. It is not, so the map is always empty
and the anchor-remapping code it feeds is inert.

| Source | Target | Status | Declared in |
|---|---|---|---|
| `www.agent-assembly.com/*` | `agent-assembly.com/*` (301, query preserved) | Proposed, owner-applied | `infra/redirects/README.md` §1 |
| `tool.agent-assembly.dev` | *(no redirect — co-serves the installer)* | Decided, ADR 0007 | `infra/redirects/README.md` §2 |
| other `*.agent-assembly.dev` | `.com` equivalent (301) | Proposed | `infra/redirects/README.md` §2 |
| `ai-agent-assembly.github.io/<repo>/*` | `docs.agent-assembly.com/*` (301) | Intent only — mapping owned by AAASM-3665 | `infra/redirects/README.md` §3 |

### Obligations created by this map

Every page this inventory marks *Move*, *Merge* or *Supersede* and that is
published:

| Page | Current URL under `latest/` | Disposition | Obligation |
|---|---|---|---|
| `docs/src/migration/template.md` | `/latest/migration/template.html` | Move | 301 to the contributor location, or remove from `SUMMARY.md` and accept the 404 — it should never have been a reader page |
| `docs/src/research/AAASM-5269-sensitive-data-provider-architecture.md` | `/latest/research/AAASM-5269-sensitive-data-provider-architecture.html` | Move to L6 | 301 to the `verification-reports/` location |
| `docs/src/events/cross_team_edge.md` | `/latest/events/cross_team_edge.html` | Merge | 301 to the merged protocol/event reference, with a fragment |

The nine misfiled evidence files
([D5](#d5--nine-evidence-files-are-filed-in-the-source-tree)) are **not**
published — they are outside `docs/src/` and so never enter the book — and
therefore carry no redirect obligation.

The 294 `node-sdk` snapshots carry none either: they are archived versions,
which are frozen by design.

## Disposition summary

The overwhelming majority of the 852-file documentation surface is **Keep**.
That is the correct outcome for an inventory of a documentation set that is
broadly well-placed, and it is worth stating plainly so the exceptions below are
read as exceptions rather than as a sample of a larger problem.

Everything that is **not** Keep or Record, in full:

| Disposition | Files | What |
|---|---:|---|
| **Move** | 2 | Core: `migration/template.md`, `research/AAASM-5269-…md` |
| **Move** | 9 | Evidence in Core's source tree: `dashboard/docs/verification/**` (7), `aa-cli/AAASM-4457-…md`, `aa-gateway/benches/REPORT.md` |
| **Move** | 7 | Core: `docs/release/security-signoff/*.md` |
| **Move** | 3 | `.github`: `docs/onboarding-poc/AAASM-394{5,6,7}-*.md` |
| **Merge** | 1 | Core: `events/cross_team_edge.md` |
| **Review** | 1 | Hub: `policy-reference.md` — owned by AAASM-5586 / 5609, not by this map |
| **Delete** *(recommended, needs sign-off)* | 13 | Core: `docs/superpowers/**` |
| **Keep, retitle** | 1 | Core: `devtools/product-brief.md` |

**Record** covers 192 evidence files, 90 tool-config files, the 115 docs-bucket
files in the six private repositories, node-sdk's 294 frozen snapshots, and
`arena`'s 2 test-fixture READMEs.

Every docs-bucket file in every counted repository falls under exactly one group
in [The inventory](#the-inventory) or one row above.

That is a file-level claim, and it needs a check that can fail. Two earlier
attempts at this could not, and the way they failed is worth recording because
both looked more rigorous than the thing they replaced:

- Asserting the coverage. It was wrong — 25 files had no group.
- Arguing it from the buckets summing to each repository's total. That shows the
  *bucketing* is exhaustive, which is a weaker and different claim: it holds
  even if the disposition map covers nothing.
- Subtracting `^docs/|^website/|^blog/` and the signposts from the docs bucket.
  The [Appendix](#appendix-the-bucket-script) **defines** that bucket as exactly
  those patterns, so the check tested the definition against itself and returned
  an empty remainder no matter what was in the tree.

The check below subtracts **the disposition groups' own globs**, listed per
repository, rather than the bucket definition:

```python
GROUPS = {   # the globs this page's groups actually name
  "agent-assembly": [r"^docs/src/", r"^docs/release/", r"^docs/superpowers/", SIGNPOST],
  "docs":           [r"^docs/src/", r"^docs/sync-architecture\.md$",
                     r"^(AGGREGATION|MIGRATION)\.md$", SIGNPOST],
  "node-sdk":       [r"^docs/", r"^website/versioned_docs/",
                     r"^website/README\.md$", SIGNPOST],
  # …one entry per repository; private repos are Record in full
}
SIGNPOST = r"(^|/)(README|CONTRIBUTING|SECURITY)\.md$"

for repo, globs in GROUPS.items():
    for path in docs_bucket(repo, REF[repo]) + sys.argv[1:]:
        if not any(re.search(g, path) for g in globs):
            leaks.append(f"{repo}: {path}")
sys.exit(1 if leaks else 0)
```

Because `agent-assembly`'s entry names three subtrees rather than `^docs/`, a
page added at `docs/anything-else/` leaks. That is the property the previous
version lacked.

**Result: 828 docs-bucket files checked, remainder empty, exit 0.** And the
check demonstrably fails — passing three paths that no group names
(`docs/totally/unlisted-nobody-dispositioned-this.md`,
`website/orphan-page-not-in-any-group.md`, `some/deep/dir/GUIDE.md`) reports 25
leaks and exits 1.

It earned its keep on first run: it found `docs/sync-architecture.md`, a Hub
page inside `docs/` but outside `docs/src/` that none of the three earlier
checks could see. It is now [dispositioned](#l2--docs-hub--docs-22-pages--4-root-files).

### Partitioning this for implementation tickets

The groups in [The inventory](#the-inventory) are disjoint path globs, so a
ticket can take a slice by naming its glob and no two tickets will collide. Four
natural slices, in dependency order:

1. **Misfiled evidence** — the 19 *Move* files above that are evidence: 9 in
   Core's source tree, 7 release sign-offs, 3 in `.github`. None is published,
   so there is no redirect obligation, no reader impact, and no dependency on
   anything else. This slice spans two repositories.
2. **Core book hygiene** — the 3 published *Move*/*Merge* pages, plus adding
   `[output.html.redirect]` to `docs/book.toml` so the moves do not 404. The
   redirect section must land first or with them.
3. **The broken-link defect ([D1](#d1--seventeen-internal-links-in-core-point-at-a-path-that-does-not-exist))**
   — 17 links across 10 pages, and the CI change that would have caught them.
   Independent of the others.
4. **Metadata adoption ([D8](#d8--the-metadata-contract-exists-and-one-page-in-the-organisation-satisfies-it))**
   — blocked on AAASM-5601 delivering a validator; should not start before it.

Slices 1–3 do not overlap and can run concurrently.

## What this page hands off

| To | What it takes from here |
|---|---|
| [AAASM-5594](https://lightning-dust-mite.atlassian.net/browse/AAASM-5594) | The disposition table and the four partitions above |
| [AAASM-3665](https://lightning-dust-mite.atlassian.net/browse/AAASM-3665) | [Redirect obligations](#redirect-obligations) — the per-page list `MIGRATION.md` says it does not carry |
| [AAASM-5610](https://lightning-dust-mite.atlassian.net/browse/AAASM-5610) | The conformance census in [D8](#d8--the-metadata-contract-exists-and-one-page-in-the-organisation-satisfies-it): 1 of 22, 0 of 143, 0 of 81 |
| Defect triage | [D1](#d1--seventeen-internal-links-in-core-point-at-a-path-that-does-not-exist) (broken links, gate red on `main`) and [D2](#d2--three-numbering-schemes-two-of-which-are-spelled-l) (colliding `L` vocabularies) |

### Re-running this census

Every number on this page comes from `git ls-tree` against a named ref, and the
commands are inline beside the tables that use them. The refs move; the counts
will drift the day after this page merges. That is expected, and it is why the
commands are published rather than only their output — a number nobody can
re-derive is not evidence, and a page that reports one is asking to be believed
rather than checked.

## Appendix: the bucket script

```bash
ref=<ref>; repo=<repo>
L=$(git -C "$repo" ls-tree -r --name-only "$ref" | grep -E '\.(md|mdx)$')
EV='(^|/)verification-reports/|(^|/)reports/'
TC='^\.claude/|^\.github/|(^|/)CODE_OF_CONDUCT\.md$|(^|/)SUPPORT\.md$'
DC='^docs/|^website/|^blog/|(^|/)README\.md$|(^|/)CONTRIBUTING\.md$|(^|/)SECURITY\.md$'
echo "total    $(echo "$L" | grep -c .)"
echo "evidence $(echo "$L" | grep -Ec "$EV")"
echo "toolcfg  $(echo "$L" | grep -Ec "$TC")"
echo "docs     $(echo "$L" | grep -Ev "$EV" | grep -Ev "$TC" | grep -Ec "$DC")"
```

`Other` is the remainder. The three regexes are evaluated in that order and are
mutually exclusive by construction, so the four buckets sum to the total — which
is the check that the classification is complete.
