# The capability and evidence manifest

`capability-manifest.yaml` records, one row per governed capability, what Agent
Assembly actually does to an action: where it is intercepted, under what
preconditions, with what failure posture, on which channels and platforms it
ships, whether anything reaches it by default, and what evidence backs all of
that.

It exists so that generated documentation and UI **cannot silently overstate
protection**. AAASM-5588, AAASM-5600 and AAASM-5609 build public surfaces from
these rows, so a wrong field here becomes published output.

| | |
|---|---|
| Manifest | [`capability-manifest.yaml`](capability-manifest.yaml) |
| Schema | [`../schemas/capability-manifest/v1/capability-manifest.schema.json`](../schemas/capability-manifest/v1/capability-manifest.schema.json) |
| Semantic validator | [`../scripts/validate_capability_manifest.py`](../scripts/validate_capability_manifest.py) |
| Rule fixtures | [`testdata/`](testdata/) |
| CI gate | [`../.github/workflows/capability-manifest.yml`](../.github/workflows/capability-manifest.yml) |
| Ticket | [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) |

This manifest is ADR 0034's **T2** layer, and it is what ADR 0034's validation
requirement **W7** asks for. It is *not* a source of truth for the architecture
— [ADR 0033](../docs/src/adr/0033-canonical-governance-and-enforcement-architecture.md)
is — and it does not own any vocabulary. See
[Three axes, three owners](#three-axes-three-owners).

## Running the gates

```bash
# 1. the schema is self-consistent, and the manifest conforms to it
npx ajv-cli@5 compile  --strict -s schemas/capability-manifest/v1/capability-manifest.schema.json
npx ajv-cli@5 validate --strict --all-errors \
  -s schemas/capability-manifest/v1/capability-manifest.schema.json \
  -d governance/capability-manifest.yaml

# 2. the rules JSON Schema cannot express
python3 scripts/validate_capability_manifest.py

# 3. the rules can still fail — a positive control plus one fixture per rule
bash governance/testdata/run-validator-tests.sh
```

All three run in CI on every PR touching this area, on every push to `main`,
and weekly. The weekly run is not decoration: a PR-only gate never runs on the
merge that breaks it, and evidence ages past the freshness limit with nobody
editing a file.

`--no-git` exists for editing outside a checkout and **must never be used in
CI** — the git-backed checks are precisely the ones that distinguish a cited
path from a real one.

## Three axes, three owners

[ADR 0034 hand-off 7](../docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)
fixes three vocabularies over three different subjects, with the rule that **no
axis may be applied to another's subject**. The manifest carries the first two
and must never carry the third.

| Axis | Field here | Vocabulary owner | Subject it ranges over |
|---|---|---|---|
| Behaviour on evidence | `coverage`, `coverage_qualifiers` | ADR 0033 §6 — eleven terms, closed | One **action** on one host, at one time |
| Protection state | `protection_state` | ADR 0030 §4.1 ladder | One **developer-tool integration** on one host |
| Adapter ceiling | `governance_level_ceiling` | ADR 0030 §4.3 `GovernanceLevel` | What an adapter *could* ever reach — a build-time ceiling, not a measurement |
| Documentation-area maturity | *(never in this file)* | Docs Hub `source-of-truth.md` | One **area of documentation** |
| Portfolio lifecycle | *(never in this file)* | The company site's product registry | One **product in the portfolio** |

`degraded` is deliberately spelled the same on the claim axis and among ADR
0030's overriding states; ADR 0033 §6 says so explicitly. It is the one shared
spelling and it is ratified, not a defect.

### Reconciliation: the ticket's proposed `State` enum

AAASM-5531 was written before ADR 0033 and ADR 0034 merged, and its "Proposed
model" lists a nine-value `State` enum. **That enum is not shipped.** Coining a
term on the claim axis that ADR 0033 §6 does not define is
[ADR 0034 forbidden design 12](../docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md).
Each proposed value is resolved below, and the validator's rule R7 names the
axis for the four that were cross-axis rather than merely failing an enum.

| Ticket value | What it actually is | Where it lands in the manifest |
|---|---|---|
| `Configured` | Neither a claim term nor a ladder rung — an **activation** fact | `default_state` (`on`/`off`/…) plus `reachability`. Dropped as a state |
| `Detected` | **ADR 0033 §6 claim term**, kept verbatim | `coverage: detected` |
| `Evaluated` | **ADR 0033 §6 claim term**, kept verbatim | `coverage: evaluated` |
| `EnforcedManagedPath` | Not a §6 term. Two facts fused: an outcome and a launch precondition | `coverage: denied_before_execution` **plus** `launch_path` and `preconditions[]`. Dropped as a term |
| `GatewayVerified` | An **ADR 0030 protection rung** (`GatewayProtected`) — a different axis, subject = a tool integration | `protection_state: gateway_protected`. Dropped from the claim axis |
| `HostConstrained` | An **ADR 0030 protection rung** (`HostEnforced`) | `protection_state: host_enforced`. Dropped from the claim axis |
| `BypassResistantMeasured` | Not a term on any axis. ADR 0030 §4.1 already says `HostEnforced` "is the only state that claims bypass resistance", so the measurement is the rung plus its evidence | `protection_state: host_enforced` with `evidence[]`. Dropped entirely |
| `Unsupported` | **ADR 0033 §6 claim term**, kept verbatim | `coverage: unsupported` |
| `Unmeasured` | **ADR 0033 §6 claim term**, kept verbatim | `coverage: unmeasured` |

The ticket's enum also **omits six** of ADR 0033 §6's terms — `Observed`,
`Redacted`, `Approval required`, `Degraded`, `Experimental` and `Planned`. All
six are in the manifest's `coverage` enum; four are in use today (`observed`,
`redacted`, `degraded`, `experimental`), and `approval_required` and `planned`
are available but unused, which is itself a finding worth carrying: no row in
this survey reaches *Approval required*.

A distinct, smaller reconciliation applies inside ADR 0030 itself. The AAASM-5527
survey carried one `current_level` field holding **both** ladder rungs (nine
rows) and a `GovernanceLevel` value (one row, L5). ADR 0030 §4.3 forbids
conflating a ceiling with a measurement, so the field is split into
`protection_state` and `governance_level_ceiling`, and validator rule R7 rejects
either one carrying the other's values.

## Distribution: names, and their correspondence elsewhere

The manifest uses [ADR 0034 §6.1](../docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)'s
field names verbatim — `released_channels`, `released_platforms`,
`released_matrix` — so no second spelling is coined here.

`docs`' page-metadata contract (AAASM-5595) models the same fact as a
`platforms[]` list of `{channel, platform, status}` in **kebab-case**, and that
page defers to this manifest: when 5531 lands, its `platforms[]` becomes
derivable from `released_matrix`. The correspondence is recorded here so a
third spelling never appears:

| This manifest | `docs` page metadata | Note |
|---|---|---|
| `released_channels[]` + `released_matrix{}` | `platforms[].channel` | `github_release` ↔ `github-release`, `install_script` ↔ `install-sh`, `crates_io` ↔ `crates-io`, `ghcr` ↔ `ghcr`, `homebrew` ↔ `homebrew` |
| `released_platforms[]` | `platforms[].platform` | `linux_x86_64` ↔ `linux-x86_64`, `linux_aarch64` ↔ `linux-aarch64`, `macos`, `windows` |
| *(no equivalent — this manifest states presence, not a verification grade)* | `platforms[].status` | The page's grade is page metadata; the manifest's equivalent evidence lives in `evidence[]` |
| `meta.evidence_tree` + `meta.evidence_date` | `last_verified.ref` + `.date` | Both reject `main`/`master`/`HEAD` |

The manifest additionally carries `pypi`, `npm` and `go_modules`, because the
SDK rows ship through those registries and the core's five channels do not
cover them.

## The three questions

A capability can pass the first and fail the third; three dead capabilities
were found in this programme exactly that way. Collapsing any two into one
field is [ADR 0034 forbidden design 5](../docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md),
and validator rule R10 rejects a `released` / `shipped` / `available` /
`reachable` key outright.

| Question | Fields | Why it is not the others |
|---|---|---|
| **Distributed?** | `released_channels`, `released_platforms`, `released_matrix` | A crate on crates.io but absent from the GitHub Release assets reads as shipped or unshipped depending on which channel the reader had in mind |
| **Buildable?** | `buildable`, `buildable_conditions` | A `cfg(target_os = "linux")` dependency ships in the source tarball and in no macOS binary |
| **Activated?** | `default_state`, `reachability` | Code that ships, builds, and no route reaches (`reachability: dead_code`), or that a default config routes past (`stubbed_default`) |

Two reasoning rules that have each produced a wrong answer here before:

- **Absence from `RELEASE_BINARIES` or from `release.yml`'s asset list is not
  evidence of absence from crates.io.** `cargo workspaces publish` ships every
  workspace member that does not set `publish = false`. Verify the **published
  artifact** — the registry, the tap, the release asset list — never the
  workflow that was expected to produce it.
- **`scripts/check-release-completeness.sh` is not a channel oracle.** It
  substring-matches package names, so a platform-conditional packaging step
  satisfies it. A green completeness gate is evidence about the workflow, not
  about the artifact.

## Evidence

Every row carries at least one `evidence[]` item, of exactly one of three
kinds:

| Kind | Required keys | Checked how |
|---|---|---|
| `test` | `path` | `git cat-file -t <evidence_tree>:<path>` must exit 0 and report `blob` |
| `test_unlocated` | `describes` | Not machine-checkable. A test asserted to exist with no path cited |
| `gap` | `reason` (`control` where an absence was probed) | Nothing to check; the honest statement that no test exists |

`test_unlocated` exists because the AAASM-5527 survey recorded real evidence in
two shapes. Collapsing "aa-proxy unit tests" into `test` would mean inventing a
path; collapsing it into `gap` would mean deleting an evidenced fact, which
[ADR 0034 forbidden design 10](../docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)
names as a defect in the same table as overstatement. Twelve items are in this
kind and each is a candidate for promotion to `test` once someone locates it.

Two rules about the tree the evidence names:

- **Existence is not tracked-ness** (ADR 0034 §6.4). A generated, gitignored
  file passed one audit on a dirty tree and failed the next on a clean one.
  `testdata/invalid-r5-untracked-evidence.yaml` is that exact file.
- **Nor is "tracked somewhere" the same as "in this tree."** Round 1 used
  `git ls-files --with-tree=<tree> --error-unmatch`, which reads like "tracked
  in this tree" and in fact queries **index ∪ tree** — so a test written today
  could be cited as evidence at a tree from before it existed, and the gate
  certified it. A real command and a real exit code were not enough; the
  predicate was wrong. When a gate shells out, **fixture the command's
  semantics, not merely its failure**: list the predicates the command might
  plausibly implement and pick an input on which they disagree.
  `testdata/invalid-r5-evidence-newer-than-tree.yaml` is that input, and its
  header explains why its path must not be "tidied".
- **Evidence derived on a branch does not describe a published ref**
  (ADR 0034 §6.3). `main`, `master` and `HEAD` are hard errors in
  `evidence_tree`. Set `meta.describes_ref` when the manifest is asserted to
  describe a release, and `git merge-base --is-ancestor` must hold — a row
  failing it is `Unmeasured` for that ref, not "probably still true".

## Prose may not restate a structured fact

An environment fact has exactly one home: `preconditions[]`.

- **R8** — an environment token in any prose field must be declared in this
  row's `preconditions[].name`. The namespace is `AA_*` **plus** a short
  allow-list of externally-owned variables our own claims turn on:
  `NODE_EXTRA_CA_CERTS`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`,
  `SSL_CERT_FILE`, `NODE_TLS_REJECT_UNAUTHORIZED`. `NODE_EXTRA_CA_CERTS` is
  the reason L1 can intercept TLS and its absence is the reason L2 and L3
  cannot, so leaving it outside the namespace left the load-bearing fact in
  prose with nothing checking it.
- **R8b** — the `NAME=value` **assignment** spelling in a prose field is
  rejected. The value belongs in `preconditions[].required_value`.

This is not a style rule. The AAASM-5527 YAML's M1 `notes` said the only
supported route "forces `AA_PROXY_LLM_ONLY=false`", which the companion
Markdown retracts in bold and which finding F7 contradicts — one fact, two
homes, and they disagreed (AAASM-5666).

**What R8b does and does not do.** It blocks one spelling. A sentence phrased
"set to 0" or "forces false" still passes, and a regex chasing English always
will. R8 is the durable half: forcing the token into `preconditions[]` is what
puts prose and structure side by side where a reviewer can compare them.

Where a variable is named because it is **absent** — L2, L3 and L8 all turn on
something not being injected — still declare it, with `optional: true` and the
polarity in `note`. An absence that matters is a fact, and facts live in the
structure.

Where two routes reach the same capability, write **two optional
preconditions**, each carrying its own consequence in `note`. M1 is the worked
example.

## Adding or changing a row

1. **Find the row before writing the sentence.** Ordering the work the other
   way is how overstatements get authored.
2. Copy `testdata/valid-minimal.yaml` — it carries one of every required field.
3. Pick `coverage` from ADR 0033 §6's eleven terms. If none fits, the answer is
   `unmeasured`, not a twelfth term.
4. Answer all three of distributed / buildable / activated. `unmeasured` is an
   honest value for `buildable`; leaving a field out is not — an omitted
   dimension reads as the **broadest** admissible value
   ([forbidden design 8](../docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)),
   which is rarely what an author means.
5. Cite evidence at a named tree. If the only evidence you have is from a
   branch, the honest record is a `gap`, not a `ref` that overstates.
6. Run all three gates above.

**Quoting gotcha:** YAML 1.1 parses bare `on` and `off` as booleans, so
`default_state` values **must** be quoted (`'on'`, `'off'`). An unquoted value
becomes `true`/`false`, fails the string enum, and the gate goes red — which is
the gate working, but the error message points at a type, not at the quoting.

### Ids are a public interface

Row ids (`S1`, `M1`, `G7`, …) are stable claim identifiers cited by other
repositories and by generated public pages. **Never reuse an id.** When a row
is removed, move its id to `meta.retired_ids`; rule R2 then rejects any attempt
to reissue it.

### When implementation behaviour changes

A change that alters any of a row's dimensions must update the row **in the
same PR**. Mechanically, per ADR 0034 §7: match your changed paths against
`interception_component` and `evidence[].path` across the manifest, update
every row you hit, then re-run the gates. `owner.repository` (and
`also_repositories`) says where the behaviour change lands and therefore who
owns the update.

## Migration from the AAASM-5527 survey

The manifest was seeded from
[`../verification-reports/AAASM-5527-capability-coverage-matrix.yaml`](../verification-reports/AAASM-5527-capability-coverage-matrix.yaml)
— all 80 rows, at evidence tree `299de3883`. That file remains the
point-in-time verification report it was written as, together with its
companion Markdown; **this manifest is the maintained artifact from here on**,
and the survey should not be edited to track code changes.

Field-by-field, what changed and why:

| Survey field | Manifest | Reason |
|---|---|---|
| `current_level` | `protection_state` **+** `governance_level_ceiling` | ADR 0030 §4.3 — one field held two axes; L5 was the divergent row |
| `evidence: [string]` | `evidence: [{kind, …}]` | AC 5 could not be checked while tracked paths and prose shared one list |
| *(absent)* | `buildable`, `buildable_conditions` | ADR 0034 §6.1's second question had no field; 52 rows honestly answer `unmeasured` |
| *(absent)* | `preconditions[]` | Gives every environment fact one structured home (R8/R8b) |
| *(absent)* | `owner{repository, component}` | The ticket's "component and repository owner"; also names who owns the update obligation |
| `tickets: [AAASM-…, F1]` | `tickets[]` **+** `findings[]` | Jira refs and AAASM-5527 finding ids are different namespaces resolving through different systems |
| `boundary_class: null` (36 rows) | `boundary_class: not_applicable` | A deliberate null is indistinguishable from an unfilled one |
| `known_bypasses: []` (S9, G1, G8) | an explicit "not enumerated" entry | Silence is not a bound |
| `deny_signal: <scalar>` | `deny_signal: [<enum>]` | S6 carries two signals and a scalar cannot say so |
| `default_state: on` (unquoted) | `default_state: 'on'` | YAML 1.1 parsed 38 rows' values as booleans |
| `transport`, `language`, `identity_source`, `released_channels`, … mixed scalar/list | consistent types | Consumers could not rely on a shape |
| `coverage` enum (already ADR 0033 §6) | unchanged | The survey got this right; it is kept verbatim |

### Rows corrected on content, and how they were found

An earlier revision of this page named **M1** as the only row where the seed
YAML and the companion Markdown disagreed. That was wrong, and the way it was
wrong matters more than the row it missed: it came from grepping for one
retracted phrase, finding M1, and stopping — proving a positive without ever
bounding the population. Two rows had escaped.

The claim is replaced by a repeatable method. **Enumerate the retractions
first, then attribute them to rows**, so the population is bounded before any
conclusion is drawn:

1. Grep the Markdown for a *list* of retraction markers, recording the hit
   count for each — **including the zeros**, since a silent zero and a broken
   probe look identical. At the pinned commit: `Correction` 3, `corrected` 3,
   `withdrawn` 2, `inverted` 2, `Withdrawn` 1, `on re-reading` 1,
   `that is false` 1, `earlier revision` 11; and `Retract`, `retracted`,
   `Superseded`, `no longer`, `revised`, `Amended`, `mistake` all **0**.
   18 hits at 18 distinct lines.
2. Read each hit in context and map it to the row ids it governs — a Markdown
   table groups rows (`**I1** · **I2** · **I3**`), so one retraction can bind
   several. 38 of 80 rows are governed by at least one.
3. For each row compare seed, manifest and Markdown across `notes`,
   `known_bypasses[]`, `evidence[].reason`, `target_level`,
   `interception_component` and `released_note` — not `notes` alone. I1's
   defect was in `notes`; S13's was `known_bypasses` against `evidence[].reason`
   **inside one row**.
4. Sweep every retracted phrase across **all 80 rows**, not only the attributed
   ones, since an escape that landed on an unattributed row is exactly what the
   attribution would miss. Scope the sweep to *claim-bearing* fields: an
   `evidence[].reason` recording `WITHDRAWN: "<phrase>"` is the audit trail of
   a retraction being honoured, and flagging it would report the fix as the
   defect.
5. Where the two documents disagree, **settle it from source**, not by assuming
   the later document wins, and cite the file:line that settled it.

Result, every row in exactly one bucket:

| Bucket | Count | Rows |
|---|---|---|
| **Corrected** — manifest follows the retraction | 38 | C2 C3 C4 C5 C6 G3 G6 G7 G10 G11 H2 H3 H4 I1 I2 I3 I4 I7 L1 L5 L6 L7 L8 M1 N3 N5 N13 P1 P2 P3 S1 S2 S4 S5 S6 S8 S9 S13 |
| **Divergent** — still carries a retracted claim | 0 | — |
| **Self-contradictory** — two fields of one row disagree | 0 | — |
| **Not applicable** — no retraction touches the row | 42 | the remainder |

The two rows that failed the first pass, and how source settled them:

- **I1** recorded a *closed* vulnerability as partly open, citing
  `run_registration.rs:583,668` as a residual smell. Read at the evidence tree,
  both call sites are inside that module's test block (opens at `:462`): `:583`
  mints a deliberately foreign key to assert the binding check refuses it, and
  `:668` **is** the AAASM-5332 regression assertion. Both prove the
  vulnerability is closed, so the citation inverted their meaning. Understatement
  is a defect in the same table as overstatement.
- **S13** asserted refusal "lives in the out-of-repo FFI shims" in
  `known_bypasses` while its own `evidence[].reason` recorded that as withdrawn,
  the Node shim being hard-coded fail-open. `known_bypasses[]` is AAASM-5588's
  publication surface, so it was one generator away from being published.

Also corrected on content: **M1** (the `AA_PROXY_LLM_ONLY` divergence, plus
`AA_PROXY_MITM_HOSTS` promoted to a first-class optional route), **C2** and
**G3** (assignments moved into `required_value`), **L1/L2/L3** (`AA_TEAM_ID`
named in `transport` and declared nowhere — R8 caught it on its first run),
**N2** (a locatable test found), **N4/G8/S6/S9/G5** (coverage weakened), and
**L7** (moved off `host_enforced`).

## Known gaps

Stated here rather than left for a reader to infer, because an omission in a
manifest reads as the broadest admissible value.

1. **Docker/GHCR is unsurveyed.** ADR 0034 §6.2 names five core channels; the
   AAASM-5527 survey enumerated four of them and never asked about GHCR, which
   publishes `aa-runtime` and `aa-gateway` images. `ghcr` is in the schema's
   channel enum so the answer is *expressible*, and
   `meta.channels_not_surveyed` records that a row's silence about it means
   **Unmeasured, never Unsupported**. Rule R9 refuses a `ghcr` claim until the
   channel is surveyed and moved into `meta.channels_surveyed`.
2. **`buildable` is `unmeasured` on 52 of 80 rows.** The survey did not ask the
   question separately. The field exists so the answer cannot be inherited from
   a neighbour; filling it is per-row verification work.
3. **Three rows carry a mid-strength claim term on gap-only evidence** — S13
   and I7 (`evaluated`), M9 (`redacted`). The validator warns rather than
   fails, because the survey may legitimately have derived those from reading
   code. Each needs either a located test or a weaker term.
4. **Eleven `test_unlocated` items** name a test suite without a path.
5. **`public_wording` is unset on every row.** Consumers must generate from the
   structured fields until a row carries approved prose.
6. **The evidence describes `main`, not a release.** `meta.evidence_tree`
   `299de3883` is **2788 commits** ahead of `v0.0.1-rc.6` and is an ancestor of
   no released tag, so ADR 0034 §6.3's own command
   `git merge-base --is-ancestor 299de3883 v0.0.1-rc.6` exits 1 (rc.5 and rc.4
   likewise). Every row is therefore `Unmeasured` **for any released ref** until
   re-derived. `meta.describes_ref` is deliberately unset for exactly this
   reason — setting it to rc.6 would correctly turn the gate red — which also
   means **rule R4 does not execute on the real manifest** and fires only in its
   fixture. A consumer publishing a release-scoped surface (AAASM-5609's "What
   Ships Today" especially) must either re-derive at the tag or label the
   surface as describing `main`.
7. **Five rows were weakened for unverifiability, not for absence.** N4 and G8
   have no located test in this repo, measured. S6, S9 and G5 assert tests in
   the `node-sdk`, `go-sdk` and all three SDK repositories respectively, and
   rule R5 resolves paths only against *this* repo's evidence tree, so they
   cannot be checked here at all. All five now read `evaluated` rather than
   `denied_before_execution`. Recording *why* matters: for the three SDK rows
   this weakening may itself be an understatement, and cross-repo evidence has
   no mechanism yet.
8. **P3 sits at `host_enforced` with `coverage: unsupported`, and is escalated
   rather than mechanically fixed.** Its two cited tests are Claude Code launch
   tests, and its own `interception_component` says of macOS host enforcement
   "NO TEST PINS IT ... a pass-through tautology". R14 clause 1 passes it
   because the tests are locatable, and clause 2 passes because
   `protection_state_scope: tool_governance_only` is set — but a rung that ADR
   0030 §4.1 reserves for bypass resistance, on a row whose coverage is
   `unsupported`, needs a human decision about which of the two is wrong.

## Interfaces this manifest provides

Generation of public tables is **not** this ticket's — AAASM-5600 owns it. What
is provided is the interface:

- **AAASM-5600** (validate capability ids, generate support/maturity/protection
  tables) — resolve an id against `capabilities[].id`; render support from
  `released_channels`/`released_platforms`/`released_matrix`, protection from
  `protection_state`, and behaviour from `coverage`. Never mix the three in one
  column. `reachability` and `default_state` must be visible wherever
  distribution is, or the table asserts a capability is available that nothing
  reaches.

  **`protection_state_scope` must render in the same cell as the rung** — never
  omitted, never relegated to a separate column a layout can drop. A row at
  `host_enforced` whose scope is `tool_governance_only` reached that rung by
  writing a tool's own settings file and carries **no data-path claim**;
  published as a bare "Host Enforced" it reads as ADR 0030 §4.1's bypass-resistance
  guarantee. The schema and rule R14 both require the field wherever `coverage`
  is not itself an enforcement term, so a row that needs the qualifier cannot
  reach a generator without one — but rendering it is the generator's half.

  A row whose evidence is entirely `gap` must be presented as a gap, on **every**
  surface and not only AAASM-5588's.
- **AAASM-5588** (Trust, Evidence and Known Limitations) — `evidence[]`,
  `known_bypasses[]`, `boundary_class` and `boundary_attained` are the
  limitations surface. A row whose evidence is entirely `gap` must be presented
  as a gap.
- **AAASM-5609** (What Ships Today / Choose Your Enforcement Path) —
  `preconditions[]` is the enforcement-path input. M1's two optional
  preconditions are the worked example of a targeted route and a wide one.

## Versioning

`manifest_version` is semantic and its major matches the schema directory
(`schemas/capability-manifest/v1/`). Adding an optional field or an enum value
is a minor bump. Removing a field, tightening a rule, or renaming a value is a
**major** bump and needs a new `vN` schema directory plus a migration section
here — consumers in other repositories pin to the major.
