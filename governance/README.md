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
| `test` | `path` | `git ls-files --with-tree=<evidence_tree> --error-unmatch -- <path>` must exit 0 |
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
  file passed one audit on a dirty tree and failed the next on a clean one; the
  `--error-unmatch` exit code is the discriminator and a file-existence test is
  not. `testdata/invalid-r5-untracked-evidence.yaml` is that exact file.
- **Evidence derived on a branch does not describe a published ref**
  (ADR 0034 §6.3). `main`, `master` and `HEAD` are hard errors in
  `evidence_tree`. Set `meta.describes_ref` when the manifest is asserted to
  describe a release, and `git merge-base --is-ancestor` must hold — a row
  failing it is `Unmeasured` for that ref, not "probably still true".

## Prose may not restate a structured fact

An environment fact has exactly one home: `preconditions[]`.

- **R8** — an `AA_*` token in any prose field must be declared in this row's
  `preconditions[].name`.
- **R8b** — an `AA_*=value` **assignment** in any prose field is rejected. The
  value a variable must hold belongs in `preconditions[].required_value` and
  nowhere else.

This is not a style rule. The AAASM-5527 YAML's M1 `notes` said the only
supported route "forces `AA_PROXY_LLM_ONLY=false`", which the companion
Markdown retracts in bold and which finding F7 contradicts — one fact, two
homes, and they disagreed (AAASM-5666). R8b makes that unstatable.

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

Rows corrected on content, not shape:

- **M1** — the `notes`/Markdown divergence about `AA_PROXY_LLM_ONLY`
  (AAASM-5666), plus `AA_PROXY_MITM_HOSTS` promoted to a first-class optional
  route. **C2** and **G3** — assignments moved out of prose into
  `required_value`.
- **L1, L2, L3** — `AA_TEAM_ID` was mentioned in `transport` and declared
  nowhere; rule R8 caught it on its first run.

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
4. **Twelve `test_unlocated` items** name a test suite without a path.
5. **`public_wording` is unset on every row.** Consumers must generate from the
   structured fields until a row carries approved prose.

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
