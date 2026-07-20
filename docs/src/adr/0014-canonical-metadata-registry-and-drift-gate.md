# ADR 0014: Canonical Metadata Registry & Drift Gate

**Status**: Proposed
**Date**: 2026-07
**Ticket**: [AAASM-4912](https://lightning-dust-mite.atlassian.net/browse/AAASM-4912) (Epic [AAASM-4908](https://lightning-dust-mite.atlassian.net/browse/AAASM-4908))

This ADR records **one decision**: where the shared, non-version metadata that is
hand-copied across the OSS repos — repo names/slugs, canonical URLs, product/org
display names, cross-repo & governance links, and Jira project/field IDs — has its
*canonical registry*, how consumers *reference* it, and the drift-gate contract that
keeps them in sync. It mirrors the boundary of [ADR 0013](0013-version-metadata-source-of-truth-and-drift-gate.md)
(version metadata) for the *metadata* axis, and it treats the URL *values* decided
in [ADR 0007](0007-public-domain-and-url-contract.md) / [ADR 0008](0008-saas-host-routing-auth-cookie-boundaries.md)
as inputs it stores, **not** values it re-decides. It is deliberately **not** a
catalog of every consumer doc — see Non-goals.

---

## Context

A 2026-07 audit (Appendix A) inventoried the shared metadata that drifts across the
public repos. As with version metadata, the picture is a **proven-but-partial**
source-of-truth (SoT): the `.github` repo already has a working "registry →
generator → bounded generated block → `--check`" pattern for badges and install
channels, but the widest-fanned values (canonical URLs, repo names, Jira IDs) sit
outside it as hand-copied literals, and post-rename residue from Epic AAASM-4341
persists in several files.

**The existing seam (to widen — named here, not forked).**

- **Registry:** `.github` repo — `metadata/org-profile.yaml`.
- **Generator:** `.github` repo — `scripts/generate_org_profile.py` (stdlib-only;
  rewrites two bounded `<!-- BEGIN/END GENERATED: repo_table -->` /
  `install_channels` regions in `profile/README.md`; ships a `--check` drift mode).
- **Gate:** `.github` repo — `.github/workflows/org-profile-drift.yml`.
- **What it holds today:** `org` slug; a `repos[]` list (`slug`, `repo` = "org/name",
  `default_branch`, `role`, `badge{…}`, `version[]`, `activity_*[]`); an
  `install_channels[]` list.
- **What it does NOT hold (the widen candidates):** canonical URLs
  (docs/app/api/marketing/installer), product & org **display** names, published
  security/contact addresses, `.github` governance-branch, cross-repo doc deep-link
  bases, and the Jira project/field IDs — plus a per-repo **visibility** flag.

**A second, docs-scoped partial registry already exists:** this repo's
`metadata/docs.yaml` (established by AAASM-4310) holds `protocol_version`,
`repo_url`, `docs_url`, and the installer URLs for the mdBook site. So two
canonical URLs (`repo_url`, `docs_url`) are *already* SoT'd here — for the docs site
only — while every other consumer hand-copies them. This overlap is exactly the
kind of dual ownership the decision below resolves.

**The drift surface (Appendix A).** The largest cluster is **canonical URLs** —
`docs.agent-assembly.com/*`, `agent-assembly.com/install.sh`, `app`/`api` hosts —
hand-copied across all six code/doc repos with deep per-SDK paths, none sourced from
a registry. Second is **post-rename repo-name/casing residue** (Epic AAASM-4341):
`.github`'s `05-context-boundary.md` still says `agent-assembly-cloud` (now `cloud`),
profile prose links "agent-assembly-examples" (now `examples`), `onboarding-poc/*`
says `agent-assembly-docs` (now `docs`), and `python-sdk/pyproject.toml`'s
Homepage/Repository use the old `AI-agent-assembly` casing. Third is **Jira field-ID
drift**: `onboarding-poc/*` still cites `customfield_10041` for Components even
though the ticket-authoring skill now records that field as null (native
`components` is authoritative). Governance links also drift on the `.github` default
branch (`blob/main/…` vs the actual `master`).

## Decision

1. **The `.github` repo's `metadata/org-profile.yaml` is the single canonical
   registry for org-shared metadata, widened (not forked) to add these sections:**

   - `urls` — canonical docs/marketing/app/api/installer hosts and per-SDK docs base
     paths. **Values are owned by ADR 0007/0008**; the registry only *stores* them so
     they exist once (it does not re-decide them).
   - `product` — the product **display** name, org display name, org slug, and the
     **publicly published** contact/security addresses.
   - `governance` — the `.github` default branch and baseline-doc link bases
     (CONTRIBUTING/SECURITY/CODE_OF_CONDUCT), so cross-repo links stop drifting
     (`main` vs `master`).
   - `jira` — the public coordination constants: site, project key, board id, and the
     custom-field IDs, with the recorded fact that **Components is the native field,
     not `customfield_10041`**.
   - a per-repo **`visibility: public | private`** flag on each `repos[]` entry.

2. **One value has exactly one owner.** No value the registry owns may be
   independently declared elsewhere. This repo's `metadata/docs.yaml` keeps only
   genuinely docs-scoped values (e.g. `protocol_version`) and **derives** the shared
   ones (`repo_url`, `docs_url`, installer URLs) from the registry rather than
   re-declaring them.

3. **The reference mechanism is two-mode, chosen by the consumer's shape:**
   - **Generation** — for artifacts that can host a bounded generated region or
     include a generated snippet (README badge/link tables, install channels,
     structured docs). Consumers embed a `BEGIN/END GENERATED` block or an
     `\{{#include generated/…}}` snippet; the literal is never hand-typed.
     (This is the existing `org-profile.yaml`→`profile/README.md` and
     `docs.yaml`→`docs/src/generated/*` pattern.)
   - **Lint-flag-on-hardcoded-value** — for free prose and scattered deep-links where
     a generated block is impractical. A drift audit greps for the registry's
     canonical literals appearing **outside** the registry, its generated outputs,
     and an explicitly-listed set of historical locations, and **fails CI**. This is
     the metadata analogue of ADR 0013's orphan-literal audit.

4. **The drift-gate contract.** Whichever mode a consumer uses, the guard is a
   **blocking** CI job that either (a) regenerates from the registry and fails on any
   diff (`git diff --exit-code`), or (b) runs the hardcoded-value lint and fails on a
   stray literal. A non-blocking (issue-only) or presence-only check does not satisfy
   the contract.

5. **The public/private boundary is enforced by the registry, not by reviewers.**
   The `visibility` flag means a generated **public** artifact (the org profile, a
   public repo's README/docs) MUST NOT emit any `private` repo's slug, name, or
   internal metadata. Generators filter on visibility; the lint treats a private slug
   appearing in a public generated artifact as a failure.

## Decision-scope

This ADR fixes, for the OSS repos: (a) the canonical registry location
(`.github` `metadata/org-profile.yaml`) and the schema sections it is widened to
hold; (b) the single-owner-per-value rule (incl. reconciling `docs.yaml`); (c) the
two-mode reference mechanism (generation vs hardcoded-value lint); (d) the blocking
drift-gate contract; and (e) the visibility-flag boundary. The concrete per-repo
build/rollout work it implies is **AAASM-4914** (Appendix B).

## Accepted risks

- **Registry lives in the public `.github` repo.** It therefore may hold only
  values that are already public (public repo names, published URLs, the Jira
  coordination constants that already appear in every ticket). Assumption: nothing
  in the registry is a secret or a private-repo internal. Reconsideration trigger: a
  need to share a *private* value across repos — that must not enter this public
  registry (see Forbidden designs).
- **URL values are duplicated from ADR 0007/0008 into the registry.** Accepted
  because the registry is storage, not a competing decision; the reconsideration
  trigger is any change to those ADRs, which must update the registry in the same
  change.

## Explicitly forbidden designs

- **Centralizing any private-repo internal, slug, or private-only metadata into the
  public registry** — forbidden by the context-boundary rules
  (`.github/.claude/rules/05-context-boundary.md`). A generated public artifact must
  never surface a `private` entry.
- **A second independent copy of a registry-owned value** — e.g. a canonical URL or
  repo name hand-typed in prose that the registry already owns (the current
  `agent-assembly-examples` / `AI-agent-assembly`-casing / `customfield_10041`
  drifts are exactly this failure).
- **Re-deciding URL values here** — ADR 0007/0008 own the host contract; this ADR
  only stores the agreed literals.
- **A non-blocking or presence-only drift gate** as the sole guard for a
  registry-owned value.

## Non-goals (explicitly out of scope)

- **Re-spec of every consumer doc** — this ADR fixes the registry + reference + gate;
  it does not rewrite or enumerate every page that consumes a value.
- **CI platform choice details** — how each repo runs its gate is the rollout's
  concern, not this decision.
- **Centralizing private-repo internals** — respecting the context-boundary rules is
  a hard boundary, not a deferred nicety.
- **Version metadata** — owned by ADR 0013; a version literal is not registry-owned
  metadata under this ADR.
- **Historical values** — past release notes, per-tag references, and archival
  onboarding-poc records that must preserve what they shipped with stay literal
  (their stale repo-names are corrected by the rollout, not templated).

## Consequences

- **Maintainers** get one place to change a URL, repo name, or Jira ID, and a build
  that fails on a stray copy — replacing hand-copied constants that drift silently.
- **The public/private boundary becomes mechanical** — the visibility flag stops a
  private slug leaking into a public artifact by construction, not by review
  vigilance.
- **The rollout (AAASM-4914)** has fixed boundaries: widen `org-profile.yaml` +
  generator + lint; reconcile `docs.yaml` to derive shared values; and clear the
  AAASM-4341 residue (Appendix A) as the first values brought under the registry.
- **Cost:** the `.github` generator and each consuming repo's gate must be built and
  maintained; a metadata edit becomes an edit-plus-regenerate change. Accepted — it
  is the cure for the drift the audit found.

## Operational guidance

- To change a shared value: edit `metadata/org-profile.yaml`, run
  `generate_org_profile.py`, commit the regenerated blocks; never hand-type a
  registry-owned literal. URL changes flow from ADR 0007/0008 → registry → consumers.
- Adding a repo: add its entry **with** a `visibility` flag; private repos never
  appear in a public generated artifact.

## Validation requirements

- `.github` has a **blocking** drift job (model: `org-profile-drift.yml`) that
  regenerates and fails on diff, plus a hardcoded-value lint for prose/deep-links.
- A reviewer can confirm enforcement by checking that (a) no registry-owned value is
  independently declared outside the registry or a generated/`DO NOT EDIT`
  artifact or a listed historical location, and (b) no `private` slug appears in any
  public generated artifact. These are the acceptance surface for AAASM-4914.

## Reconsideration triggers

- A shared value must be **private** (cannot live in the public `.github` registry) —
  reopen to decide a separate private-side mechanism (do **not** widen this one).
- **ADR 0007/0008** change the URL/host contract (registry must be updated in step).
- The **Jira** project/field IDs change, or the tracker is migrated.
- A **new OSS repo** or a new class of shared metadata is added (extend the schema +
  rollout list).

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-4912](https://lightning-dust-mite.atlassian.net/browse/AAASM-4912) | This spike — audit + author the ADR |
| [AAASM-4908](https://lightning-dust-mite.atlassian.net/browse/AAASM-4908) | Parent Epic (drift elimination) |
| [AAASM-4914](https://lightning-dust-mite.atlassian.net/browse/AAASM-4914) | Rollout the registry + reference mechanism + gate per repo (Appendix B) |
| [AAASM-4341](https://lightning-dust-mite.atlassian.net/browse/AAASM-4341) | The org-wide repo rename whose residue is the rollout's first cleanup |
| [AAASM-4902](https://lightning-dust-mite.atlassian.net/browse/AAASM-4902) | Baseline-doc fixes; its deferred siblings are Appendix A drift items |
| [ADR 0013](0013-version-metadata-source-of-truth-and-drift-gate.md) | Sibling — same SoT/generator/`--check` pattern for the version axis |
| [ADR 0007](0007-public-domain-and-url-contract.md) / [ADR 0008](0008-saas-host-routing-auth-cookie-boundaries.md) | Own the URL *values* this registry stores (not re-decided here) |
| Implementation PRs | _(docs-only spike; no implementation PR — AAASM-4914 carries the wiring)_ |

---

## Appendix A — Hardcoded-metadata inventory (2026-07 audit)

Root: `.github` repo = the `dotgithub/` workspace checkout. "generated" = inside a
sanctioned generated block; otherwise a hand-copied literal.

### Repo names + slugs
| Site | Metadata | Form |
| --- | --- | --- |
| `.github` `metadata/org-profile.yaml` | every `slug` + `repo` "ai-agent-assembly/`<name>`" | **canonical SoT** |
| `.github` `profile/README.md` | repo names/badges | generated block (fine) EXCEPT prose |
| `.github` `profile/README.md:29` | link text "**agent-assembly-examples**" → `/examples` | literal — **stale pre-rename name** (4902-deferred) |
| `.github` `CLAUDE.md` / `AGENTS.md` / `README.md` | repo map tables | literal (fixed to current slugs in 4902) |
| `.github` `.claude/skills/ticket-authoring/references/fields.md:47-51` | Components vocabulary repo-name list | literal (mixes private slugs — see boundary note) |
| `node-sdk/package.json` | `@agent-assembly/sdk`, repository/bugs/homepage | literal package fields |
| `python-sdk/pyproject.toml:6,81,82` | name + Homepage/Repository | literal — **casing drift** (§ 4893) |
| `go-sdk/go.mod:1` | `module github.com/ai-agent-assembly/go-sdk` | literal |
| `agent-assembly/Cargo.toml:48-49` | repository/homepage | literal |
| `homebrew-agent-assembly/Formula/aasm.rb` | tap slug `ai-agent-assembly/tap/aasm` | literal (mirrored in org-profile install snippet) |

### Canonical URLs (largest cluster)
| Site | Metadata | Form |
| --- | --- | --- |
| `.github` `metadata/org-profile.yaml` + `profile/README.md` | docs site, arena docs, installer alias, curl installer | SoT / generated |
| `.github` `SUPPORT.md:5,20` | docs + marketing URLs | literal |
| `agent-assembly/**` | installer `agent-assembly.com/install.sh` (×26), docs `docs.agent-assembly.com/` (×22, incl. per-SDK `…/stable/`), `app.agent-assembly.com/` | literal, high fan-out |
| `docs/**` | `api.`/`app.` hosts, `agent-assembly.com/early-access`, per-SDK docs | literal |
| `python-sdk`,`node-sdk`,`go-sdk`,`examples`,`arena`,`official-website`,`e2e-public` | `docs.agent-assembly.com/<sdk>/…` deep links + `install.sh` | literal, high fan-out |

### Product / org display names
| Site | Metadata | Form |
| --- | --- | --- |
| `.github` `CLAUDE.md`, `profile/README.md:1,8` | "AI Agent Assembly" | literal (no shared source) |
| `python-sdk/pyproject.toml:9` | "Agent Assembly Team", `team@agent-assembly.dev` | literal |
| `.github` `profile/README.md:126` | `security@agent-assembly.dev` | literal prose |
| `official-website/**` | marketing display names | literal |

### Cross-repo + governance links
| Site | Metadata | Form |
| --- | --- | --- |
| `agent-assembly/CONTRIBUTING.md`, `docs/.claude/CLAUDE.md`, `examples/.claude/CLAUDE.md`, `arena/.claude/CLAUDE.md`, `official-website/.claude/CLAUDE.md` | link to `.github/blob/**main**/…` | literal — **branch drift** (`.github` default is `master`) |
| `.github` `profile/README.md:120-131` | governance links + security email | literal prose (correct `blob/master/`) |

### Jira project / field IDs
| Site | Metadata | Form |
| --- | --- | --- |
| `.github` `.claude/skills/ticket-authoring/references/fields.md` | site, project `AAASM` (10006), **board id 7**, Team `customfield_10001`, Story points `10016`, Sprint `10020`, Start date `10015`; **Components = native field, `customfield_10041` is NULL — do not use** | **canonical (skill-local) literal** |
| `.github` `.claude/skills/ticket-authoring/SKILL.md`, `CLAUDE.md:78`, `AGENTS.md:82` | same constants | literal |
| `.github` `docs/onboarding-poc/AAASM-3947-…:222-224`, `AAASM-3946-…:204` | **`customfield_10041` for Components** | literal — **stale/drifted** (contradicts fields.md) |

### org-profile.yaml seam (widen target)
- **SoT** `.github` `metadata/org-profile.yaml`; **generator** `.github`
  `scripts/generate_org_profile.py` (stdlib-only, bounded `BEGIN/END GENERATED`
  blocks, `--check` mode); **gate** `.github/workflows/org-profile-drift.yml`.
- **Holds:** `org`; `repos[]` (slug/repo/default_branch/role/badge/version/activity);
  `install_channels[]`. **Does not hold:** canonical URLs, display names, security
  email, governance branch, cross-repo deep-links, Jira IDs, per-repo visibility.

### AAASM-4341 rename residue (rollout's first cleanup; 4902-deferred siblings)
- `.github` `.claude/rules/05-context-boundary.md` — `agent-assembly-cloud` (now
  `cloud`); also defines the public/private split the ADR must respect.
- `.github` `profile/README.md` prose — `agent-assembly-examples` (now `examples`),
  governance links + security email.
- `.github` `docs/onboarding-poc/AAASM-3945-…` — `agent-assembly-docs` (now `docs`).
- `.github` `docs/onboarding-poc/AAASM-3946/3947-…` — `customfield_10041` for
  Components (stale) + Jira field-ID list.
- `python-sdk/pyproject.toml:81-82` — Homepage/Repository `AI-agent-assembly` casing
  (old redirecting casing; inferred **AAASM-4893** item — the ticket id itself is not
  present in the tree, flagged as inference).

### Context-boundary note
All inventoried items are in **public** repos. Two would pull **private** internals
into public artifacts and are Non-goals: (a) `05-context-boundary.md`'s private-repo
names (`cloud`, `agent-assembly-enterprise`, `e2e-private`, `internal-docs`,
`saas-infra`), and (b) `fields.md`'s Components vocabulary mixing private slugs into
a public `.github` doc. The **visibility flag** in the Decision is what keeps a
generated public artifact from ever emitting these.

## Appendix B — Per-repo rollout list implied (for AAASM-4914)

1. **.github (registry owner)** — widen `org-profile.yaml` with `urls`, `product`,
   `governance`, `jira`, and a per-repo `visibility` flag; extend
   `generate_org_profile.py` to emit the new generated blocks (visibility-filtered);
   add the hardcoded-value lint; keep `org-profile-drift.yml` blocking.
2. **.github (rename residue)** — `05-context-boundary.md` `agent-assembly-cloud` →
   `cloud`; `profile/README.md` prose `agent-assembly-examples` → `examples`;
   `onboarding-poc/*` `agent-assembly-docs` → `docs` and `customfield_10041` → native
   `components`.
3. **python-sdk** — `pyproject.toml` Homepage/Repository casing `AI-agent-assembly` →
   `ai-agent-assembly` (inferred AAASM-4893).
4. **Governance-branch drift** — `main` → `master` in the `.github` baseline-doc
   links across `agent-assembly/CONTRIBUTING.md`, `docs`, `examples`, `arena`,
   `official-website` `.claude/CLAUDE.md`.
5. **URL consumers** — bring `docs.agent-assembly.com/*` and `install.sh` references
   under a generated snippet (where the file allows) or the hardcoded-value lint
   (prose/deep-links), across the six code/doc repos.
6. **agent-assembly** — reconcile `metadata/docs.yaml` to **derive** `repo_url`,
   `docs_url`, and installer URLs from the registry (single-owner), keeping only
   docs-scoped values (e.g. `protocol_version`) locally.
