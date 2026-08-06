# Truth adoption record — template

Every participating repository in the organisation carries one
`TRUTH-ADOPTION.md` at its root. The record is how a repository adopts
[ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)
— the canonical product-truth and cross-repository governance decision — **without
carrying a copy of it**. Copying the ADR is forbidden design 1; this record is the
sanctioned alternative.

This page is the template and its field reference. It is contributor
documentation, not a decision: the decision that a record is required, what it
must contain and where it lives is ADR 0034's
[Decision 4](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md).
Where this page and the ADR disagree, the ADR wins and this page is the thing that
changes.

## Does this repository need one?

> A repository requires an adoption record **iff** it publishes reader-facing
> content about the product **or** hosts a claim-bearing artifact — a manifest, a
> registry, a claim-bearing test fixture, or a generated page.

ADR 0034's **adoption matrix** has already applied that test to every repository
in the organisation, so look the repository up there rather than re-deriving the
answer. Note what the test is *not*: visibility. Two private repositories require
a record and two public ones do not.

## Where it goes

`TRUTH-ADOPTION.md`, at the repository root — the same fixed path in every
repository, so a cross-repository validator needs no per-repository
configuration. A path that has to be configured is a path that silently skips the
repository whose configuration is missing.

## The template

Copy this whole block into `TRUTH-ADOPTION.md` and fill it in. Delete no field:
a field that does not apply takes an explicit empty value (`[]`, `none`) so a
reader can tell "considered and empty" from "forgotten".

````markdown
---
adr: "0034"
adr_url: "https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md"
adr_revision: "AAASM-5621"
repository: "ai-agent-assembly/<repo>"
truth_layers: []          # e.g. ["T1", "T4"] — ADR 0034 Decision 1
content_layers: []        # e.g. ["L3", "L5"] — content-ownership.md
claim_namespaces: []      # capability/claim id prefixes this repo may claim in
owners:
  # reviewer CLASS -> the team or group that fills it. Never an individual.
  truth-owner-core: "@ai-agent-assembly/<team>"
enforcement:
  pull_request: "none"    # name the check, or "none"
  release_gate: "none"    # name the gate, or "none"
  note: ""                # required when either is "none"
local_adrs: []            # repo-specific ADRs that cite ADR 0034
exceptions: []            # waivers — see "Exceptions" below
last_reviewed_version: ""
last_reviewed_date: ""    # YYYY-MM-DD
---

# Truth adoption record

This repository adopts [ADR 0034][adr] as the canonical product-truth and
cross-repository documentation governance decision. The full decision lives in
`ai-agent-assembly/agent-assembly` and is **not** reproduced here.

## Responsibilities

What this repository authors, and what it may only restate.

| Content type | This repository | Canonical owner |
| --- | --- | --- |
| <type> | Authors / Restates | <owner> |

## Claim namespaces

Claims in these namespaces may be authored here. A claim outside them belongs to
another repository.

- `<namespace>`

## Owners and reviewers

| Reviewer class | Filled by | Reviews |
| --- | --- | --- |
| `<class>` | `@<team>` | <what> |

A material truth change requires at least one approval from the owning class. A
waiver additionally requires a `waiver-approver` who is not the author.

## Enforcement

Where a violation of ADR 0034 is caught in this repository. If neither a pull
request check nor a release gate exists, say so — an unrecorded gap reads as a
gate that is present.

| Scope | Mechanism |
| --- | --- |
| Pull request | <check name, or "none — reason"> |
| Release gate | <gate name, or "none — reason"> |

## Exceptions

Waivers in force. Each is a string-scoped, approved, expiring permission — never
a topic or a page. An expired waiver fails closed.

| id | rule | text | scope | justification | evidence | approver | issued | expires |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

## Local ADRs

Repository-specific implementation decisions that cite ADR 0034. A local ADR may
not restate or redefine global precedence.

- <none>

## Last reviewed

Against ADR 0034 revision `AAASM-5621`, at `<version>`, on `<YYYY-MM-DD>`.

[adr]: https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md
````

## Field reference

### `adr`, `adr_url`, `adr_revision`

The canonical identifier and the durable link. `adr_url` uses the `blob/HEAD`
form rather than a branch name, per the *Linking to another repository* rule in
[`CONTRIBUTING.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/CONTRIBUTING.md)
— a rename's redirect does not cover every link form.

`adr_revision` is the ticket of the most recent `## Update — AAASM-NNNN` section
in the ADR, or `AAASM-5621` when there is none. It is what makes a record's
staleness detectable: a record naming an older revision has not been reviewed
against the current decision.

### `truth_layers`, `content_layers`

Two different axes, and both are wanted. `truth_layers` are ADR 0034's `T1`–`T7`
— evidential authority. `content_layers` are
[content-ownership.md](content-ownership.md)'s `L0`–`L6` — publication surface.
A repository can hold a content layer and no truth layer: `examples` (L4) and a
README (L5) restate and never author, so they never win a precedence contest.

### `claim_namespaces`

The capability and claim identifier prefixes this repository may author claims
in. This is what makes a change-propagation sweep bounded — given a changed
manifest row, the namespaces say which repositories can possibly carry a claim
that resolves to it, so the sweep is a lookup rather than a search of every
repository.

Before the Approved Claims Registry exists, list the capability-id prefixes from
the [AAASM-5527 manifest](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/verification-reports/AAASM-5527-capability-coverage-matrix.yaml)
that apply.

### `owners`

Reviewer **classes** mapped to teams, never to individuals — an individual's
record goes stale when people change. The classes are ADR 0034's Decision 9;
which humans fill them, and the rota, are
[AAASM-5603](https://lightning-dust-mite.atlassian.net/browse/AAASM-5603)'s.

### `enforcement`

Where a violation is actually caught here. This field exists to stop an
unrecorded gap reading as a gate that is present: a repository whose CI cannot
run the check states `none` with a reason, and that honest gap is visible to
anyone assessing coverage. **A record that claims an enforcement scope the
repository does not have is itself a violation.**

### `exceptions`

Waivers in force, with the nine fields ADR 0034's Decision 10 requires. Three
constraints are easy to get wrong:

- A waiver covers **an exact string**, never a page or a topic.
- `expires` is at most 90 days from `issued`, or the next release tag, whichever
  is sooner.
- Renewal is a **new approval with fresh evidence**, not an edited `expires`.
  Editing the date is forbidden design 9.

Three things may not be waived at all: an ADR 0033 forbidden design, evidence
freshness or tracked-ness, and the absence of any resolvable row for a governed
claim.

### `local_adrs`

Repository-specific implementation decisions that cite ADR 0034. The test for
"genuinely repository-specific" is whether a reader of another repository would
need the decision to act correctly — if they would, it is not local.

### `last_reviewed_version`, `last_reviewed_date`

The release version and date at which the record was last checked against the
ADR. A version alone is ambiguous once a version is re-cut; a date alone does not
say what was shipping. Both.

## Two failure modes worth naming

**`markdownlint` does not validate front matter.** A record whose YAML is
malformed — a value beginning `[`, an unquoted `:` — passes both `markdownlint`
and a link check while parsing to something other than what it reads as. Do not
treat a green Markdown lint as evidence the record is valid; the
[AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601)
validator parses the front matter itself and fails on a parse error.

**An empty field and a missing field are different.** `claim_namespaces: []` says
the question was asked and the answer is none. An absent key says nobody looked.
The validator treats the second as an error, which is why the template ships every
key rather than only the applicable ones.

## Worked example — a restate-only repository

`examples` publishes runnable integrations (L4) and a README (L5). It authors no
product claim and holds no claim-bearing artifact of its own — but it *needs* a
record precisely because it publishes reader-facing content, and the record is
what fixes that it may only restate.

```yaml
adr: "0034"
adr_url: "https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md"
adr_revision: "AAASM-5621"
repository: "ai-agent-assembly/examples"
truth_layers: []                      # restates only; authors no truth layer
content_layers: ["L4", "L5"]
claim_namespaces: []                  # may author no claim
owners:
  truth-owner-core: "@ai-agent-assembly/pioneer"
enforcement:
  pull_request: "none"
  release_gate: "none"
  note: "No AAASM-5599 check wired here yet; review-enforced until it lands."
local_adrs: []
exceptions: []
last_reviewed_version: "v0.0.1-rc.7"
last_reviewed_date: "2026-08-06"
```

The two empty lists are the substance of this record, not a gap in it: they say
that a governed claim appearing in `examples` is a defect wherever it came from.

## Related

| Reference | Relation |
| --- | --- |
| [ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md) | The decision this record adopts; owns what the record must contain |
| [Content-layer ownership](content-ownership.md) | The `L0`–`L6` layers, the reuse patterns and the correction routing the record's *Responsibilities* section refers to |
| [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md) | Owns the claim vocabulary a claim namespace resolves against, and the forbidden designs a waiver may not cover |
| [AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601) | Validates these records |
| [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605) · [AAASM-5607](https://lightning-dust-mite.atlassian.net/browse/AAASM-5607) | Roll the records out across the organisation |
