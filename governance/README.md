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

### The container channel, and rule R17 (AAASM-5680)

`ghcr` was in the schema's enum and in `meta.channels_not_surveyed`, so **no row
could claim it** while `.github/workflows/docker.yml` had been pushing to
ghcr.io since AAASM-4480. A matrix generated faithfully from the manifest
therefore shipped without a GHCR column, and its omission read as a deliberate
"not distributed there". It had already cost something: AAASM-5591's audiences
page dropped Docker/GHCR by hand, was corrected in review, and the fix replaced
the hand-written list with a reference to *this* vocabulary — deferring to a
source that omitted the channel the review had just restored.

**Surveyed against the registry, not the workflow** (`GET
https://ghcr.io/v2/ai-agent-assembly/<name>/tags/list`, 2026-08-07). Five
repositories answer and two do not:

| Image | Delivers | Built by |
|---|---|---|
| `aa-gateway` | the `aa-gateway` binary | `aa-gateway/Dockerfile:61,67`, pushed `docker.yml:160-161` |
| `aa-runtime` | the `aa-runtime` binary | `aa-runtime/Dockerfile:58,64`, pushed `docker.yml:111-112` |
| `python` ×3 | `agent-assembly` **and** `aasm` | `Dockerfile.python-3.14-slim:79,81-82` + `:89`, asserted `:93`,`:96` |
| `node` ×3 | `@agent-assembly/sdk` **and** `aasm` | `Dockerfile.node-24-slim:69,74` + `:52`, asserted `:84`,`:85` |
| `go` ×3 | `go-sdk` **and** `aasm` | `Dockerfile.go-1.26-alpine:73,75` + `:61`, asserted `:87`; the module is in the image's module cache |
| `aa-proxy` | — | no pull token issued |
| `aasm` | — | no pull token issued, **but the binary ships inside all nine language images** |

> On `go:88`. `RUN go list -m …@latest` is a GOPROXY query, and it resolves a
> *different* version than `:73` installs — the published layer
> `sha256:0c89b228fea4a…` holds both `go-sdk/@v/v0.0.1-beta.3.zip` (installed)
> and `v0.0.1-rc.5.info` (what `@latest` resolved). The module zip and
> `go/bin/minimal` genuinely are in the image; `:88` is not what proves it.

24 rows carry the channel: 5 `aa-gateway`, 3 `aa-runtime` (G1, G2, G11), 2
`aa-cli` (L8, C5), the 13 SDK rows, and `I3`. Linkage is deliberately *not* the
predicate: `aa-cli` links `aa-proxy` as a library, yet `aasm proxy start` spawns
the separate `aa-proxy` binary (`aa-cli/src/commands/proxy/start.rs:85-114`), so
a linkage rule would have put `ghcr` on 17 proxy rows that ship in no image.

**`I3` was added in review round 2.** Its `owner.component` is `aa-core`, but
its capability is *derived server-side* at
`aa-gateway/src/service/lifecycle_service.rs:477-497` — gateway code in the
published gateway image, exactly like I5/I7/G8/G9/G10. Round 1 filed it under
`owner.component`, which is not the predicate this page states; where the two
disagree, the delivering artifact wins.

**`G6` and `G7` do not carry it, and round 1 recorded the wrong reason.** They
were filed `not_published` on the premise that "their subject is the eBPF loader
daemon". Their own fields say otherwise: `G7` carries no `aa-ebpf` in
`framework_or_tool`, and both rows' cited code (`ebpf_control.rs:204-213` and
`:190-201`, the latter a plain `std::fs::read_to_string`) is compiled into every
`aa-runtime` binary — `aa-runtime/src/lib.rs:15` has no `#[cfg]` — and shipped in
the image. They are now `not_surveyed`: what is absent is the loader daemon their
*degradation trigger* concerns, and nobody measured these two rows from inside
the image.

**What `released_channels` means, stated because the addition must not inherit a
looser reading.** It is read as *the channels through which the artifact that
delivers this row's capability is obtained*. On the SDK family the field does
not already hold to that: all 13 rows carrying `pypi`/`npm`/`go_modules` carry
the same four values regardless of their own `language`, so `S1`
(`language: [python]`) claims `npm` and `go_modules` while `S8`
(`language: [go]`) claims `pypi` — a product-family union, wrong in both
directions per row. **That predates this ticket and is not fixed here; it needs
its own.** `ghcr` is true under both readings, because each language image
installs its own language's SDK and asserts it at build time, so no row's claim
is broadened by adding it.

**Rule R17** has three clauses:

| Clause | What fails |
|---|---|
| Vocabulary partitioned | A channel the schema admits that is neither surveyed nor explicitly not surveyed, or one recorded as both |
| Publishing implies surveyed | A channel a workflow in `.github/workflows/` publishes to that `channels_surveyed` omits — the clause that fails on the pre-ticket state |
| No silent row | For a channel classified exhaustively, a row that neither names it, nor is `released_channels: [not_applicable]`, nor appears in `meta.channel_absences` |

**Both of R17's tables are constants in the validator, not manifest fields**: a
rule whose evidence lives in the artifact it gates can be switched off by editing
the artifact. Each is keyed by the whole channel enum and asserted against it, so
a sixth channel forces a decision instead of a silent omission.

Round 1 got that right for the publish markers and wrong for clause 3, which
iterated the channels appearing *in* `meta.channel_absences` — so deleting that
one key deleted the check, exit 0, with the denominator vanishing alongside it.
`EXHAUSTIVE_ROW_CLASSIFICATION` now drives it. Only `ghcr` is enforced there, and
the other eight channels carry a written reason rather than an omission: AAASM-5527
surveyed them at document level, leaving 23 to 60 rows per channel silent, and
enforcing exhaustiveness would demand a measured absence for each of them that
nobody derived. **A rule must not be satisfied by inventing a measurement.**

`meta.channel_absences` carries a `status` separating the two kinds of absence.
`not_published` (32 rows: 26 aa-proxy-subject, 5 owned by `aa-ebpf`/`aa-ebpf-probes`
and delivered by the crates.io-only `aa-ebpf-loaderd`, and `C3`, whose `aa-api`
crate no published binary depends on) means the delivering artifact is in no
image, measured. `not_surveyed` (17 rows: 15 library and devtool rows whose code
*is* inside the `aasm` binary the language images carry, plus `G6`/`G7`) means the
code is on the channel and nobody measured the capability against a container.
The second is `unmeasured`, never `unsupported` — ADR 0034 forbidden design 8.

```
count: [R17] vocabulary: 9 channels = 9 surveyed + 0 not surveyed + 0 unclassified; 16 workflow files scanned, 4 publish here (['crates_io', 'ghcr', 'github_release', 'homebrew'])
count: [R17] ghcr: 80 rows = 24 carry it + 7 not_applicable + 49 recorded absent + 0 unaccounted
```

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

A `test` item may also carry **`pins`**, naming which of the row's claims it
actually substantiates. At least one test must declare `pins: [protection_state]`
wherever `protection_state` is an ADR 0030 enforcement rung (rule R14 clause 1).

The field exists because *"the row has a locatable test"* and *"a test pins this
rung"* are different assertions, and the first is satisfied by **any**
sufficiently-tested row. P3 passed the untightened rule on two Claude Code launch
tests while its own text said of macOS host enforcement "NO TEST PINS IT". Applied
retroactively to the manifest as it stood before this fix, the tightened rule
flags all three rows then at an enforcement rung — L1, L7 and P3 — where the
untightened rule flagged only L7.

**Honest limit:** `pins` is an author assertion. Nothing machine-checks that the
named test truly substantiates the claim. What the gate buys is that somebody had
to state it, in a field a reviewer can challenge, rather than the rule inferring
it from mere presence — and the note beside L1's pin is what that statement looks
like when it is doing its job.

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
- **And a document-level caveat about that is not a per-row statement.** Rule
  **R15**: where the evidence tree is not inside the newest `v*` tag and a row
  cites a path present at the tree and absent at the tag, the row must name the
  tag. See [Known gaps](#known-gaps) 6 for its scope and its limits — it is one
  more author-declared statement forced into a reviewable field, not a proof.

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
| `coverage` enum (already ADR 0033 §6) | vocabulary unchanged; **five rows weakened** | The survey chose the right vocabulary and it is kept verbatim. Five values are not: `G5`, `G8`, `N4`, `S6` and `S9` moved to `evaluated` because R12 refuses the stronger term on `test_unlocated` evidence — see rule R16 below |

### The three representations, and rule R16 (AAASM-5678)

Three documents describe the same 80 rows: this manifest, the seed YAML, and
the seed's companion Markdown. On five rows — `G5`, `G8`, `N4`, `S6`, `S9` —
they disagreed about `coverage`, the ADR 0033 §6 field the entire public claim
vocabulary rests on, and **nothing compared them**.

**The manifest is not the outlier by accident; it is weaker on purpose.** Each
of the five carries exactly one evidence item, of `kind: test_unlocated`, and
rule R12 refuses `denied_before_execution` on a row with no locatable test. Set
any of the five to the seed's value and the gate exits non-zero — the weakening
is *forced*, not editorial. Positive control that the correlation is exact:
`S1` holds `denied_before_execution` on two `kind: test` items and does not
diverge. `G5`, `S6` and `S9` assert tests in the SDK repositories, which R5
cannot resolve because it reads only this repository's evidence tree; `G8` and
`N4` have located negative evidence with recorded restoration conditions.

So the residual defect was never the divergence. It was that a deliberate,
rule-driven weakening and a genuine drift looked identical, because neither was
written anywhere a machine could read.

**Rule R16** compares and requires a declaration:

| Clause | What fails |
|---|---|
| Contract present | A document sharing an id with its seed and declaring no `meta.cross_representation` |
| Populations match | A row in one representation and not the other |
| Partition total | A field the schema allows that is neither compared nor named as excluded, or one named twice |
| Per-field agreement | Any divergence with no declaration naming that row, that field and that exact pair of values |
| Declarations live | A declaration matching no divergence — a standing excuse for a change nobody reviewed |

The compared set is read out of the **seed's own `schema.enums`** plus a named
list of additions, never hand-picked here: 29 fields of the 51 the two schemas
allow between them. The remaining 22 are named with their reason in
`meta.cross_representation.seed.excluded_fields`. The defect that produced this
ticket was a comparison over three fields reported as covering "every mechanical
field", so a partial comparison that does not say what it left out is itself a
failure.

Every count is printed on each run and the pair arithmetic is asserted, so a
population smaller than the one claimed shows up as a sum that does not close:

```
count: [R16] ids: 80 in the manifest, 80 in …-matrix.yaml, 80 shared, 0 manifest-only, 0 seed-only
count: [R16] fields: 51 in the union of the two schemas = 29 compared + 22 excluded with a named reason + 0 unclassified
count: [R16] seed: 80 ids x 29 fields = 2320 pairs; 1357 agree, 32 diverge, 931 one-side-silent; 0 skipped
count: [R16] seed_companion: 80 coverage cells read, 0 ragged rows skipped; 80 of 80 shared ids compared, 75 agree, 5 diverge
count: [R16] divergences: 37 found; declarations claim 37 (row, representation) pair(s) across 4 entries, 37 matched
```

The 32 seed divergences are 8 + 24. The 8: the five `coverage` rows above, plus
`L7` and `P3` demoted off `host_enforced` by R14, plus `L5`, where the seed's
`current_level` enum admitted the GovernanceLevel `l1_observe` on the
ProtectionState axis and R7 rejects it. **Each names the rule that forces it**,
which is what makes conservatism distinguishable from drift: the manifest could
not hold the other representation's value without a different rule failing.

The other 24 are the `released_channels` rows AAASM-5680 added `ghcr` to. They
are declared with `manifest_adds: [ghcr]` rather than a value pair, because the
full list differs per row while the delta does not, and the AAASM-5527 survey
never enumerated the channel — its own `schema.enums` has eight channel values
and `ghcr` is not among them. R16 flagged all of them as undeclared on the first
run of that change, which is the rule doing its job on work written after it.

**Scope, stated rather than overclaimed.**

- Prose is excluded, and that is a real limit. The manifest's prose was
  rewritten during the AAASM-5531 review rounds while the seed keeps the
  sentence as first compiled — measured at the current tree, `known_bypasses`
  differs on 10 of 80 rows, `transport` on 6, `notes` on 4, `launch_path` and
  `target_level` on 2 each, `identity_source` on 1 — and every one is a
  correction, not a disagreement about a fact. Equality there would report the
  fix as the defect. The fields that carry a fact are all compared.
- `evidence` is excluded because the two shapes differ on 80 of 80 rows by
  design: bare path strings against typed items. That migration is what makes
  R5, R12 and R14 possible, and it is the reason the manifest can be weaker
  than the seed at all.
- The companion is compared on `coverage` alone. It is the only column stated
  for all 80 ids in a fixed position; `Bnd` is present for 69 and annotates the
  class in prose (`B3 (conditional)`), `Timing` for 58, and `Mode` and `Failure
  posture` are two structured fields written as one sentence. Only terms inside
  a `**bold**` run count — reading the whole cell picks up prose that names a
  term to deny it, which is what `H2` ("explicitly *not* Denied before
  execution") and `C2` do.
- One-side-silent is neither agreement nor divergence. It is counted and
  printed — 931 of the 2320 pairs — because a field one representation never
  carried says nothing about the other, and folding it into "agree" would
  inflate the gate's apparent reach by 40%.

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
   probe look identical. At the pinned commit: `earlier revision` 11,
   `Correction` 3, `corrected` 3, `withdrawn` 2, `inverted` 2, `was wrong` 2,
   `Withdrawn` 1, `on re-reading` 1, `that is false` 1; and `Retract`,
   `retracted`, `Superseded`, `no longer`, `revised`, `Revised`, `Amended`,
   `mistake`, `Corrected`, `Inverted`, `not true`, `in fact` all **0**.
   Positive control `AAASM` = 109, so the probe is live. 26 line-hits at **18
   distinct lines**.

   `was wrong` was **missing from the round-2 list** and is live. Its two hits:
   `:172`, already inside the rc.6 preamble, and `:1087`, a schema-design note
   retiring the boolean `reachable_in_release`, already reflected in the
   `reachability` enum and governing no row.

   **Two retractions carry no marker at all** and were found only by reading:
   `:618-632` (the launch-env defect class — fixed for one adapter, open for
   L2 and L3) and `:890-899` (*"three corrections upward"*, I1 · L1 · C2).
   Recorded because it bounds what a marker list can do: the list finds hits,
   reading finds retractions.

   **And the list is case-sensitive, which is a third limit, not a detail.**
   `:890` is *"three corrections upward"*: `Correction`, `Corrected` and
   `corrected` all return **0** on that line, while a case-insensitive
   `correction` returns **1** (control: `Question 4` = 1 on the same line, so
   the probe is live). So "carries no marker" is true of *this* list and a
   slightly different list would have caught it — which is the honest way to
   read every zero above. Grepping is a way to bound a population, never a way
   to prove one is empty.
2. Read each hit in context and map it to the row ids it governs — a Markdown
   table groups rows (`**I1** · **I2** · **I3**`), so one retraction can bind
   several. **Key the result on (row, retraction) pairs, not rows.** A row
   governed by two retractions can be Corrected for one and Divergent for the
   other, and a per-row bucket cannot express that — which is exactly how L1
   held "Corrected" for the R8/`AA_TEAM_ID` retraction while the rc.6 scoping
   retraction that also names it went unapplied. **15 retractions govern at
   least one row, producing 40 (row, retraction) pairs over 32 distinct rows;
   5 rows appear in more than one pair.**

   Each retraction carries an explicit **obligation** — what the row must
   actually say — so a pair is Corrected only when the manifest says it, never
   because the row was attributed. Where a Markdown table cell groups ids but
   the retraction's substance concerns only some of them, the others are
   bucketed **Not binding with the reason recorded**, never silently dropped.

   **Grouping rule, published because 18 marker lines do not become 15
   retractions without one** — an independent reconstruction reached 16, and
   the difference is rule 3:

   1. A retraction is a **unit of withdrawal, not a line**. Marker hits on
      adjacent lines inside one blockquote or one table cell are one
      retraction: `:171`+`:172` are the rc.6 preamble, `:456`+`:457` the
      `deny_signal` counts. 18 lines → 16 units.
   2. Units governing **no capability row** are counted, but separately:
      `:1087` (a schema-design note) and `:1098` (a method note). 16 → 14.
   3. **`:913` restates `:786-795` and is not a second retraction.** Its marker
      (*"corrected and retitled"*) is on the gap-to-ticket mapping's AAASM-5640
      line, and that line binds the **identical nine rows** —
      H2 · H3 · H4 · N13 · I4 · G6 · G7 · P1 · P2 — as the retraction at
      `:786-795`. Counting it separately double-counts one withdrawal over one
      row set. 14 → 13. **This single step is the 15-vs-16 difference**; the
      mapping block is swept separately below instead.
   4. Marker-**less** retractions found by reading count: `:618-632` and
      `:890-899`. 13 → **15**.

   The population itself, so the attribution is reproducible rather than only
   its arithmetic checkable:

   | # | Markdown | Retraction | Rows | Pairs |
   |---|---|---|---|---|
   | 1 | `:167-187` | rc.6 scoping — three named rows must read *fixed on `main`, still live in rc.6* | I1 · L1 · C6 | 3 |
   | 2 | `:439` | *"refusal lives in the out-of-repo FFI shims"* is false — the Node shim is fail-open | S13 | 1 |
   | 3 | `:455-459` | *"six sentinel / five raise"* and *"seven underived"* both withdrawn; 5 raise / 3 sentinel / 4 underived | S1 · S2 · S4 · S5 · S6 · S8 · S9 · G3 · N3 | 9 |
   | 4 | `:529` | N13 — the uncovered-TLS-library list is longer than earlier revisions reproduced | N13 | 1 |
   | 5 | `:585` | M1 — *"the only supported route"* corrected; the targeted `mitm_hosts` route exists | M1 | 1 |
   | 6 | `:616` | L8 — the ambient-proxy strip applies exactly on `--no-proxy`, not *"on this path"* | L8 | 1 |
   | 7 | `:618-632` | the launch-env defect class is fixed for one adapter and open for two *(no marker)* | L2 · L3 | 2 |
   | 8 | `:670` | C6 — the residual is pinned at `scanner.rs:3960-4005`; the earlier `:1071-1092`/`:3012-3030` citation was unrelated | C4 · C5 · C6 | 3 |
   | 9 | `:684` | I7 — a tokenless call does **not** keep its client-supplied tenancy | I7 | 1 |
   | 10 | `:690` | I1/I2/I3 — `run_registration.rs:583,668` is the AAASM-5332 regression test, withdrawn on re-reading | I1 · I2 · I3 | 3 |
   | 11 | `:786-795` | AAASM-5640 corrected and retitled — host interception is Linux + crates.io + nightly only | H2 · H3 · H4 · N13 · I4 · G6 · G7 · P1 · P2 | 9 |
   | 12 | `:819` | D-g — closed on `main` by AAASM-5368, still live in the published rc.6 | C6 | 1 |
   | 13 | `:890-899` | Question 4 answered in the product's favour — three corrections upward *(no marker)* | I1 · L1 · C2 | 3 |
   | 14 | `:950` | F7 — there is no CLI route to targeted MCP adjudication, but the mechanism exists | M1 | 1 |
   | 15 | `:1046` | I1 — the `aa-cli` half is withdrawn; the `aa-gateway` half is a fixture smell only | I1 | 1 |
   | | | | **32 distinct rows** | **40** |

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

Result. Every **pair** in exactly one bucket — 40 pairs:

| Bucket | Pairs | |
|---|---|---|
| **Corrected** — the row says what the retraction requires | 37 | |
| **Divergent** — the row still carries the retracted claim, or is silent where a statement is required | 0 | was 1 — L1 × the rc.6 retraction, fixed below |
| **Not binding** — the Markdown cell groups this id, the retraction's substance does not reach it | 3 | C4 × `:670`, C5 × `:670`, I2 × `:690` |
| **Self-contradictory** — two fields of one row disagree | 0 | round 2's within-row detector, re-run unchanged, across all 80 rows |

Projected back onto rows, from the **same** attribution so the two cannot
disagree:

| Bucket | Rows | |
|---|---|---|
| **Corrected** | 29 | C2 C6 G3 G6 G7 H2 H3 H4 I1 I3 I4 I7 L1 L2 L3 L8 M1 N3 N13 P1 P2 S1 S2 S4 S5 S6 S8 S9 S13 |
| **Divergent** | 0 | — |
| **Not binding** | 3 | C4 C5 I2 |
| **Not applicable** | 48 | the remainder |

The row counts differ from round 2's (38 / 42) because the attribution was
re-derived, in both directions, and the differences are stated rather than
reconciled away:

- Round 2's `:616` key bound L5 · L6 · L7 · L8. The marker at `:616` is inside
  **L8's** table cell (the ambient-proxy strip correction); the blockquote that
  follows at `:618-632` is the launch-env defect class and binds **L2 and L3**,
  the two adapters still injecting one variable. L5/L6/L7 are re-attributed out
  and L2/L3 in.
- Round 2's `:913` key bound P3 · C3 · N5 · G10 · G6 · G11 — rows read off the
  **gap-to-ticket mapping** table. That table maps gaps to follow-up issues; it
  is not a retraction population, and its one marker (*"corrected and
  retitled"*) sits on the AAASM-5640 line, which binds the eBPF nine. The block
  is swept separately below rather than folded in.

**Adjacent sweep — the gap-to-ticket mapping block (`:908-925`).** Not
retractions, so not in the pair table, but swept because round 2 folded part of
it in and because the escape it exposes has the same shape: a **lone omission**
inside a line whose siblings all comply. Per mapping line, rows citing the
mapped ticket:

| Mapping line | Rows citing it | Shape |
|---|---|---|
| AAASM-5653 — `aa-proxy` absent from the macOS release channels | **14 / 14** | was 13/14; **L1 was the lone omission**, fixed below |
| AAASM-5640 — eBPF absent from every channel except crates.io | 6 / 9 | I4, G6, G7 carry the packaging fact in `released_note` but not the ticket id — the claim is stated, the reference is not |
| AAASM-5535 — degraded-state reporting | 1 / 2 | G6's own `target_level` delegates: *"the reporting half is G11"*, and G11 carries it |
| AAASM-5533 — MCP transport mediation | 5 / 7 | M7 and M9 route to a different follow-up (F2) in their own `target_level` |
| AAASM-5631 · 5637 · 5626 · 5532 | 1 / 1 each | complete |
| AAASM-5534, AAASM-5529 | 0 / 5, 0 / 9 | **uniform** absence — a scoping decision that gap→ticket mapping is the Markdown's job, not a per-row escape |

A uniform zero and a lone omission are different findings, and only the second
is an escape. That distinction is why the sweep reports coverage per line
rather than a single compliance number.

The rows that failed a pass, and how source settled them:

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
- **L1**, twice, and it is what the pair keying was for. The rc.6 retraction
  names I1 · L1 · C6; I1 and C6 carried the statement and L1 had no `notes`
  field at all — on the manifest's **only** `host_enforced` row, ADR 0030
  §4.1's sole bypass-resistance rung. Settled at the tag with controls in the
  same probe: `aa-cli/src/commands/run_registration.rs` and **all four** of
  L1's evidence items — including the pinning test
  `cli_run_claude_governed_launch.rs` — are absent at `v0.0.1-rc.6`, while
  `aa-cli/src/main.rs` and `aa-devtool-claude-code/src/lib.rs` resolve there.
  R14 clause 1 could not be satisfied at rc.6 at all, so the rung is *unearned*
  for the release, not merely unmeasured. Separately, L1 was the lone omission
  in the AAASM-5653 mapping line, and there the Markdown's attribution needed
  checking rather than copying: `aasm proxy start` spawns the **separate**
  `aa-proxy` binary from `PATH` or `~/.cargo/bin` only
  (`aa-cli/src/commands/proxy/start.rs:85-114`) and `resolve_launch_proxy`
  (`run.rs:372-388`) refuses to launch without a live verified endpoint — so on
  this macOS-only row the packaging gap denies the capability outright.
- **L5** — surfaced by rule R15 rather than by the comparison.
  `aa-devtool/src/registry.rs` does not exist at `v0.0.1-rc.6` (control:
  `aa-devtool-saas/src/adapter.rs` and `aa-api/src/routes/devtools/mod.rs` both
  resolve at the tag), so the row cited a mechanism the release lacks. The
  direction is the opposite of L1's and the row now says so: L5's claim is a
  *negative* one — the SaaS surface is not a governed integration — and it
  holds more strongly at rc.6, where no adapter registry existed at all. Only
  the citation was main-scoped.

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

   **This caveat is now backed by a per-row check, because on its own it was
   not enough.** Being true of all 80 rows, it distinguishes none of them: a
   reader cannot tell from it whether a given row differs *materially* in the
   release. That is exactly how L1 — the only `host_enforced` row — omitted the
   rc.6 statement its two named siblings carry and still read as release truth.
   **Rule R15** requires the tag to be named on any row citing a path that
   exists at the evidence tree and not at the newest `v*` tag. Its limits,
   stated rather than left to be discovered. It fires on a *missing* citation,
   never a *changed* one. Re-derived by comparing blob oids at the two refs —
   over **this manifest's** citations, not the Markdown preamble's, which
   counts a different population — of the **72** cited paths tracked at the
   evidence tree, **10 are absent** at `v0.0.1-rc.6`, **29 are present with
   different content**, and 33 are byte-identical.

   **Those 29 are the honest limit of this rule, and they are the larger
   number.** A row may cite any of them, describe behaviour the release does
   not have, and R15 will not object — the path resolves at both refs, so
   nothing distinguishes "same file, changed behaviour" from "same file, same
   behaviour" without reading the diff. R15 buys the 10 sharpest cases, where
   the cited artifact does not exist in the release at all. It does not make a
   row release-true, and no consumer should read a silent R15 as saying it did.

   **The sentence R15 forces is author-declared, and the failure mode is an
   inverted sentence, not a vague one.** The check is a substring search for
   the tag, so `notes: "Behaviour is unchanged since rc.6; no divergence
   between main and the release"` — false of every row R15 fires on — passes,
   because it contains `rc.6`. The gate buys that a row cannot silently *omit*
   the statement. It buys nothing about the statement being true. Reviewing
   these sentences is a human job and R15 does not replace it.

   **Field coverage is part of the rule, because it was a defect once.** R15's
   read set is `evidence[].path` plus every field `prose_values` walks — the
   same set the scope statement may be written in. An earlier revision read
   only `evidence[].path` and `interception_component` while accepting the
   statement anywhere, and three rows fell in that gap: I7 (cited in `notes`),
   L6 (`evidence[0].reason`) and I5 (`known_bypasses[2]`), the last two on
   AAASM-5588's publication surface. **A rule whose read set is narrower than
   its write set has a hole exactly that wide.**
   `testdata/invalid-r15-path-cited-in-notes.yaml` is the input on which the
   two read sets disagree, and its header carries that truth table.

   Two further limits: the rule retires itself once a tag containing the
   evidence tree is cut; and where no `v*` tag resolves it **warns** rather
   than passing — a shallow clone and a repository with no releases are
   indistinguishable from inside the validator. Those two branches, plus
   `--no-git` and a positive control, are asserted by
   `testdata/r15_branch_probes.py`, which the fixture harness runs.
7. **Five rows were weakened — two for measured absence, three for
   unverifiability.** The distinction is the point, so the heading has to carry
   it. N4 and G8 have no located test in this repo, measured. S6, S9 and G5
   assert tests in the `node-sdk`, `go-sdk` and all three SDK repositories
   respectively, and
   rule R5 resolves paths only against *this* repo's evidence tree, so they
   cannot be checked here at all. All five now read `evaluated` rather than
   `denied_before_execution`. Recording *why* matters: for the three SDK rows
   this weakening may itself be an understatement, and cross-repo evidence has
   no mechanism yet.
8. **P3 was demoted from `host_enforced` to `integrated`** — resolved, not
   outstanding. `host_enforced` beside `coverage: unsupported` is contradictory
   on its face: ADR 0030 §4.1 reserves that rung for bypass resistance and ADR
   0033 §6 defines `unsupported` as *not available on this platform or
   configuration*, and a capability cannot be bypass-resistant for something it
   does not provide. The row's own `interception_component` settles which half
   is wrong — "E4: NONE … NO TEST PINS IT … a pass-through tautology" — and
   neither cited test pins the rung either: both gate their macOS lane on
   `require_claude`, and the real binary is absent from CI, so those lanes skip
   rather than measure. `integrated` is what the managed-settings write plus its
   read-back earns, and ADR 0030 §4.1 notes that rung "still says nothing about
   traffic". **The two directions are gated differently, and the row says so:**
   demoting further needs only evidence, because claiming less than the evidence
   supports is the safe direction; *restoring* the rung needs a test that pins
   macOS host enforcement **and** an owner decision, because no wrapper makes an
   unsupported claim true.

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

  **Do not render `pins: [protection_state]` as machine-proven.** R14 clause 1
  requires the declaration, and R5 still checks that the named test's path is
  real and in the evidence tree — but *nothing checks what the test asserts*. A
  future row satisfies the clause by adding four characters. The field is
  **reviewable, not verified**: its value is that a human had to write the
  claim somewhere a reviewer can challenge it, instead of the rule inferring the
  rung from mere presence. Today L1 is its only user and its declaration has
  been read against the test; a generator must not turn that into a badge.

  **`protection_state: integrated` carries no evidence guarantee from any
  rule.** R14 gates only the top two rungs, while ADR 0030 §4.2 rule 1 says file
  existence is never sufficient for *"`Integrated` **or above**"*. Seven rows
  sit at `integrated` — H8, M10, L2, L3, L4, L7 and P3 — and **six of the seven
  carry `gap`-only evidence** (P3 is the exception, with a located test). That
  is defensible: §4.1 notes `Integrated` *"still says nothing about traffic"*,
  and a managed-settings write plus its read-back plausibly satisfies its
  fingerprint limb where AASM wrote the file. But it is not *enforced*, so a
  future row could take `integrated` on pure file existence and nothing would
  object. Render it as the weak rung it is.

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

**The bump obligation binds from first release, not from introduction.** What a
major bump protects is a consumer that already pins the major; before this
manifest has been published there is no such consumer, so a new `vN` directory
would be a migration path from nothing to nothing. Concretely: **R14 and R15
were both added at `1.0.0` without a bump**, under this reading, while the
manifest was still unreleased. That is stated here rather than left for a
reader to notice, because a page whose own repository contradicts it is the
defect this manifest exists to remove.

**The release trigger, concretely, because the artifact cannot express the
window.** The schema pins `manifest_version` to `^1\.[0-9]+\.[0-9]+$` — no
`0.x`, no prerelease suffix — so the file reads `1.0.0` in both states and a
future author cannot tell from it which one applies. The trigger is therefore
named rather than inferred:

> **This manifest becomes released when AAASM-5600 merges a generator that
> reads it.** That is the first moment another repository's output depends on
> these rules. Until then, tightening a rule is a free edit. From then on,
> **tightening a rule is a `2.0.0` plus a `schemas/capability-manifest/v2/`
> directory and a migration section here, with no pre-release exemption to
> appeal to.**

Merging this file to `main` does not trip the trigger; being consumed does.
