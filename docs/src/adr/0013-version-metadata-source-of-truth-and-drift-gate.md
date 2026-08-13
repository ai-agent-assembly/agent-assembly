# ADR 0013: Version Metadata Source-of-Truth & Drift Gate

**Status**: Proposed
**Date**: 2026-07
**Ticket**: [AAASM-4909](https://lightning-dust-mite.atlassian.net/browse/AAASM-4909) (Epic [AAASM-4907](https://lightning-dust-mite.atlassian.net/browse/AAASM-4907))

This ADR records **one decision**: where a version-bearing value's *truth* lives
across the OSS repos, how that truth *propagates* to every consumer, and the
`--check` drift-gate contract that keeps them in lockstep. It complements
[ADR 0003](0003-cross-repo-dependency-pinning.md) (which pins the core *crate*
dependency by git SHA) and [ADR 0009](0009-versioned-base-image-tags-and-sdk-pinning.md)
(which fixed that core and SDK versions move on *independent* axes and must be
mapped explicitly, never by string match). It is deliberately **not** a release
manual — see Non-goals.

---

## Context

A 2026-07 audit (Appendix A) inventoried every version-bearing reference across
the public repos — package manifests, install snippets, compatibility matrices,
README version prose, mdBook/tool pins, the e2e harness matrix, and the docs
version selectors. The picture is a **partial, siloed** source-of-truth (SoT)
model: several repos have already adopted a "metadata file → generator → checked-in
artifact → `--check` gate" pattern, but each did so independently, and a cluster of
hand-maintained literals sits outside any of them.

**What is already wired (per-repo SoT + generator + gate).** These are real and
proven; the decision below generalizes them rather than inventing a new mechanism:

- `examples/metadata/sdk-versions.yaml` → `generate_example_metadata.py` →
  install snippets; gated by `example-metadata-check.yml` (regenerate → `git diff
  --exit-code`, plus a `--check` orphan-literal audit).
- `e2e-public/metadata/harness.yaml` → `generate_harness_metadata.py`; gated by
  `harness-metadata-check.yml`.
- `homebrew-agent-assembly/metadata/versions.rb` → generated `Formula/*.rb`.
- `node-sdk/metadata/sdk.json` → `generate-docs-metadata.mjs` (install commands,
  dist-tag).
- `go-sdk/VERSION` → `version.go` (`const Version`, "DO NOT EDIT") via
  `gen-metadata.go`; lockstep gated by `docs-metadata.yml`.
- `agent-assembly/metadata/docs.yaml` + `Cargo.toml [workspace.package].version`
  → `generate_docs_metadata.py` → `docs/src/generated/*.md`; gated by the
  `docs.yml` drift check (established by AAASM-4310).

**The core version anchor.** `agent-assembly/Cargo.toml [workspace.package].version`
(currently `0.0.1-rc.6`) is the authoritative core/runtime version — every core
crate inherits it, and it is the coordinate the release tag carries.

**What is hand-maintained (the drift surface).** Four *independent* package-version
literals — core `Cargo.toml`, `python-sdk/pyproject.toml`, `node-sdk/package.json`,
`go-sdk/VERSION` — stay aligned only because the release skills edit them by hand;
README version *prose* (the Homebrew README is already visibly drifted, stating
`beta.1` while the formula ships `rc.4`); the mdBook/toolchain pins; and assorted
sample-output lines. Two existing gates are weak: `agent-assembly`'s
`compatibility.md` is guarded only by a *presence* check (a row exists), not a
value check, and the docs-hub `generate_compatibility.py --check` is documented as
CI-run but is **not actually wired** into any workflow; the cross-repo
`sdk-sha-drift` gate only *opens an issue* (non-blocking).

**The release seam (named here to locate it — not redefined).** Two skills own the
*writing* of version truth on a release and are the integration seam this ADR's
contract plugs into:

- `agent-assembly/.claude/skills/release-tag-cut` **writes** the version anchors
  (bumps the `[workspace.package] version` literals, regenerates `Cargo.lock`,
  cuts and pushes the `v<X>` tag that triggers the release fan-out).
- `agent-assembly/.claude/skills/release-docs-sync` **consumes** that anchor to
  propagate doc/content version refs (compat-matrix row, install snippets, sample
  CLI output), with `scripts/check-docs-versions.sh` as its mechanical backstop.

How, when, and through which channels a release is cut and fanned out is owned by
those skills and the release workflow — **out of scope here** (Non-goals). This ADR
only fixes the *contract* those skills and the per-repo gates read and write.

## Decision

1. **Every version-bearing value has exactly one SoT; nothing outside the SoT (and
   its generated outputs) may carry a version literal.** The SoT is one of a small,
   enumerated set of anchors, per the tier it belongs to:

   - **Core/runtime version anchor** = `agent-assembly/Cargo.toml
     [workspace.package].version`. All core crates inherit it; it is the coordinate
     the release tag carries. `release-tag-cut` is the only sanctioned writer.
   - **Each SDK's own version anchor** = a single file per SDK repo
     (`go-sdk/VERSION`, `node-sdk/package.json`, `python-sdk/pyproject.toml`).
     SDKs version **independently** of the core and of each other (ADR 0009);
     their versions are **not** derived from the core by string equality.
   - **The core↔SDK (and channel) mapping** is itself explicit metadata in a SoT
     file (e.g. `e2e-public/metadata/harness.yaml`, `examples/metadata/
     sdk-versions.yaml`), never reconstructed by matching version strings.
   - **Repo-scoped derived values** (install snippets, protocol version, canonical
     URLs referenced by version-bearing pages, sample output) live in that repo's
     single metadata SoT file (the `metadata/*.yaml|json` pattern already in use),
     read only from the anchors above.

2. **Propagation is generator-driven, one direction only: SoT → generator →
   checked-in artifact → consumer via include/templating.** A consumer page/manifest
   references a *generated* snippet; it never restates the literal. Generated
   artifacts are committed (so `mdbook build` and package builds need no toolchain
   at build time), carrying a `DO NOT EDIT` banner naming their generator.

3. **The `--check` drift-gate contract.** Every generator ships a check mode, wired
   as a **blocking** CI job in its repo, that:
   1. regenerates all outputs deterministically from the SoT and **fails on any
      diff** (`git diff --exit-code`); and
   2. runs an **orphan-literal audit** — greps the tree for version strings that
      appear outside the sanctioned SoT, generated outputs, and explicitly-listed
      historical locations, and fails if any are found.
   A gate that only *opens an issue*, or only asserts a row/field *exists* without
   validating its value, does **not** satisfy this contract (it is why the current
   `sdk-sha-drift` and `compatibility.md` presence checks are called out for
   upgrade in the rollout).

4. **The release seam is a consumer of this contract, not a replacement for it.**
   `release-tag-cut` writes the anchors; `release-docs-sync` propagates to content
   refs; the per-repo `--check` gates are the safety net that fails the build when
   either misses a site. This ADR fixes that contract; it does not redefine the
   skills' internals.

## Decision-scope

This ADR fixes, for the OSS repos: (a) the enumerated set of canonical version
anchors and the rule that no version literal exists outside a SoT + its generated
outputs; (b) the one-directional generator propagation model; (c) the blocking
`--check` gate contract (regenerate-and-diff **plus** orphan-literal audit); and
(d) the named integration seam with `release-tag-cut` (writes anchors) and
`release-docs-sync` (propagates content). The concrete per-repo build/rollout work
it implies is **AAASM-4911** (Appendix B).

## Accepted risks

- **Aligned-but-independent versions.** The four package anchors happen to be
  aligned today (`0.0.1-rc.6`); keeping them independent (per ADR 0009) means the
  mapping metadata, not equality, is authoritative. Assumption: the explicit
  core↔SDK map is maintained on every release. Reconsideration trigger: a proposal
  to collapse to a single global version (revisit ADR 0009 first).
- **Generated artifacts are committed.** They can go stale between a SoT edit and a
  regenerate; the blocking `--check` gate is what makes that a failed build rather
  than a shipped drift. Accepted because it keeps the docs/package builds
  toolchain-free.

## Explicitly forbidden designs

- **A second hand-maintained copy of any version literal** — e.g. version prose in
  a README that restates a value the generated block already carries (the current
  Homebrew README `beta.1` drift is exactly this failure).
- **Deriving an SDK version from the core version by string match** — forbidden by
  ADR 0009; the mapping is explicit metadata.
- **A non-blocking (issue-only) drift gate, or a presence-only check, as the sole
  guard** for a version-bearing site.
- **Templating historical values** — changelog entries, past release-notes, and
  per-tag compatibility rows stay literal (see Non-goals).

## Non-goals (explicitly out of scope)

Owned by the release workflow and the existing `release-*` skills, **not** re-decided
or re-documented here:

- Release **cadence**, and tag / publish **mechanics**.
- Channel **fan-out** (npm dist-tags, GHCR tags, PyPI pre-release promotion,
  Docusaurus/`mike`/tap snapshots) as a *process*.
- **SaaS / private** release surfaces and any private-repo version state.
- The **internals** of `release-tag-cut`, `release-docs-sync`, `release-runbook`,
  `sdk-only-release`, `release-security-gate`, `release-validate-channels`.
- **Historical** version references (CHANGELOG, per-tag release notes, past
  compatibility-matrix rows) — these must stay literal for historical accuracy.
- Base-image version **tagging** (owned by ADR 0009) and the core-crate **SHA pin**
  (owned by ADR 0003) — this ADR governs the *version-metadata* SoT, not those.

## Consequences

- **Maintainers** gain one rule ("edit the SoT, regenerate, commit; never touch a
  generated literal") and a build that fails loudly on drift instead of shipping it.
- **The rollout (AAASM-4911)** has fixed boundaries: wire the two known gate gaps
  (docs `generate_compatibility.py --check`; upgrade `sdk-sha-drift` /
  `compatibility.md` from issue-only/presence-only to blocking value checks),
  convert the remaining hand-maintained literals (README prose, sample output) to
  generated snippets or bring them under an orphan-literal audit, and confirm each
  repo's generator exposes a blocking `--check`.
- **Cost:** each repo must own a generator and a blocking gate; a SoT edit is now a
  two-step (edit + regenerate) commit. Accepted — it is the cure for the drift the
  audit found.

## Operational guidance

- To change a version-bearing value: edit the **anchor/SoT**, run the repo's
  generator, and commit the regenerated outputs in the **same** change. Never edit a
  `DO NOT EDIT` generated file or restate a version literal in prose.
- On a release, the version write is the release skills' job; a contributor's only
  obligation is that the per-repo `--check` gate is green.

## Validation requirements

- Each repo with version-bearing consumers has a **blocking** CI job that
  regenerates from the SoT and fails on any diff **and** runs an orphan-literal
  audit (model: `examples/.github/workflows/example-metadata-check.yml`).
- A reviewer can confirm the ADR is enforced by checking that (a) no version literal
  exists outside a SoT or a generated/`DO NOT EDIT` artifact or a listed historical
  location, and (b) the two named gate gaps are closed. These checks are the
  acceptance surface for AAASM-4911.

## Reconsideration triggers

- Core and SDKs move to a **single shared version** (would revisit ADR 0009 and this
  anchor set).
- The crates reach **1.0 / crates.io** publication (ADR 0003's stabilization
  trigger) — the core anchor's relationship to a published version may change.
- A **new OSS repo** with version-bearing surfaces is added (extend the anchor set +
  rollout list).
- The **release skills** are re-architected such that the write-side seam moves.

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-4909](https://lightning-dust-mite.atlassian.net/browse/AAASM-4909) | This spike — audit + author the ADR |
| [AAASM-4907](https://lightning-dust-mite.atlassian.net/browse/AAASM-4907) | Parent Epic (drift elimination) |
| [AAASM-4911](https://lightning-dust-mite.atlassian.net/browse/AAASM-4911) | Rollout the SoT + `--check` gates per repo (Appendix B) |
| [AAASM-4310](https://lightning-dust-mite.atlassian.net/browse/AAASM-4310) | Established the docs `metadata/docs.yaml` → generator → drift-check pattern |
| [ADR 0003](0003-cross-repo-dependency-pinning.md) | Complements — governs the core-*crate* SHA pin, not version metadata |
| [ADR 0009](0009-versioned-base-image-tags-and-sdk-pinning.md) | Complements — core↔SDK versions are independent, mapped explicitly (not string-matched) |
| Implementation PRs | _(docs-only spike; no implementation PR — AAASM-4911 carries the wiring)_ |

---

## Appendix A — Version-bearing site inventory (2026-07 audit)

Tag key: **[A]** already-SoT-wired (metadata file → generator → `--check`/`git diff`
gate); **[B]** hand-maintained literal.

### mdBook / tool pins — all [B]
| Site | Value | Tag |
| --- | --- | --- |
| `docs/.github/workflows/aggregate.yml` | mdBook 0.5.2, mdbook-mermaid 0.17.0, mdbook-i18n-helpers 0.4.0 (pinned URL+sha256) | B |
| `agent-assembly/.github/workflows/docs.yml` | mdBook 0.5.2, mdbook-mermaid 0.17.0 (`cargo install --locked --version`) | B |
| `agent-assembly/aa-ebpf-probes/rust-toolchain.toml` | Rust `nightly` channel | B |
| `go-sdk/go.mod` (`go 1.26.0`) → `go-sdk/metadata/sdk.yaml` (`goMinVersion`) | Go toolchain floor | go.mod = B (source); sdk.yaml badge = A (generated) |

### e2e harness matrix — [A]
| Site | Value | Tag |
| --- | --- | --- |
| `e2e-public/metadata/harness.yaml` | `sdk_versions` (py `0.0.1rc6` / node `0.0.1-rc.6` / go `v0.0.1-rc.6`), `release_channels.stable_tag`, install commands | A (gen `generate_harness_metadata.py`, gate `harness-metadata-check.yml`) |

### README version-state prose
| Site | Value | Tag |
| --- | --- | --- |
| `homebrew-agent-assembly/README.md:20` | prose "pinned to `v0.0.1-beta.1`" — **drifted** (formula ships `rc.4`); outside the generated Formula block | B (drift) |
| `node-sdk/README.md:20` prose "`0.0.1-rc.x`" | hand prose | B |
| `node-sdk/README.md:33` install line (`@0.0.1-rc.6`) | inside `BEGIN GENERATED: install-dist-tag` block | A |
| `python-sdk/README.md:96` sample output `aasm 0.0.1rc6` | hand-typed (install uses `--pre` + dynamic PyPI badge) | B |
| `go-sdk/README.md:19` protocol prose; `:52` protocol table cell | line-19 prose hand; table cell generated by `gen-metadata.go` | B (prose) / A (table) |
| All three SDK badges | shields.io dynamic (self-updating) | n/a |

### Compatibility matrices
| Site | Value | Tag |
| --- | --- | --- |
| `docs/compatibility.toml` → `docs/src/compatibility.md` | core↔SDK matrix SoT; rendered by `generate_compatibility.py --check` | A-intended — **`--check` appears UNWIRED in any docs workflow** (gap) |
| `agent-assembly/docs/src/compatibility.md` | separate repo-local matrix, not manifest-generated | B — guarded only by `.ci/check-compatibility-matrix.sh` **presence** check (no value validation) |
| `go-sdk/docs/compatibility.md`, `go-sdk/README.md:52` | protocol table | B / generated |

### Install snippets
| Site | Value | Tag |
| --- | --- | --- |
| `examples/metadata/sdk-versions.yaml` | pip/uv/pnpm/npm/yarn/go-get snippets | A (gen `generate_example_metadata.py`, gate `example-metadata-check.yml` incl. `--check` orphan-literal audit) |
| `node-sdk/metadata/sdk.json` | install commands, `distTag: rc` | A (gen `generate-docs-metadata.mjs`, `publish-docs.yml`) |
| `e2e-public/metadata/harness.yaml install_commands.*` | install commands | A |
| `agent-assembly/README.md:30` install snippet; `:198` Project Status | `v0.0.1-rc.6` | B — backstopped by `scripts/check-docs-versions.sh` (release-docs-sync skill; not a standalone CI job) |

### Versioned-docs / channel config
| Site | Value | Tag |
| --- | --- | --- |
| `node-sdk/website/versions.json` + `versionChannels.json` | Docusaurus version list (`lastVersion 0.0.1-rc.6`) | A — release-workflow managed, do-not-hand-edit |
| `python-sdk/mkdocs.yml` (`mike`) | master→latest / release→stable promotion | A — release-driven |
| `docs/docs/book.toml` | hub mdBook, no per-release selector (i18n only) | n/a |

### Package manifest pins (single anchors)
| Site | Value | Tag |
| --- | --- | --- |
| `agent-assembly/Cargo.toml` `[workspace.package].version` | `0.0.1-rc.6` — **core anchor** (release-tag-cut writes) | B (anchor) |
| `python-sdk/pyproject.toml:7` | `0.0.1rc6` — SDK anchor | B (anchor) |
| `node-sdk/package.json:3` | `0.0.1-rc.6` — SDK anchor | B (anchor) |
| `go-sdk/VERSION` → `assembly/version.go` (`DO NOT EDIT`) | `0.0.1-rc.6` — SDK anchor | VERSION = B (anchor) → version.go = A (generated, gate `docs-metadata.yml`) |
| `{go,node,python}-sdk/native/aa-ffi-*/Cargo.toml` | core-crate `rev = 670e0a1…` git SHA | B — bot-bumped; gates: per-repo `native-pin-consistency.yml` (ADR 0003) + `agent-assembly/sdk-sha-drift.yml` (**issue-only, non-blocking** — gap). *Governed by ADR 0003, listed for completeness.* |

## Appendix B — Per-repo rollout list implied (for AAASM-4911)

1. **agent-assembly** — close the `compatibility.md` gap (upgrade presence check to a
   value-validating generate-and-diff, or fold into a SoT); confirm
   `generate_docs_metadata.py --check` is blocking; bring README install/Project-Status
   lines under an orphan-literal audit rather than only the release-skill backstop.
2. **docs (hub)** — **wire `generate_compatibility.py --check`** into a workflow
   (currently documented but unwired).
3. **homebrew-agent-assembly** — bring `README.md` version prose under the
   `versions.rb` generator (or delete the literal); fix the `beta.1` drift.
4. **python-sdk** — generate the sample-output line from the `pyproject.toml` anchor
   (or orphan-literal audit it).
5. **node-sdk** — bring the `README.md:20` prose into the generated block.
6. **go-sdk** — bring `README.md:19` protocol prose under `gen-metadata.go`.
7. **examples / e2e-public** — already conformant; use as the reference gate shape.
8. **cross-repo** — upgrade `sdk-sha-drift` from issue-only to a blocking check (or
   record why it stays advisory under ADR 0003).
