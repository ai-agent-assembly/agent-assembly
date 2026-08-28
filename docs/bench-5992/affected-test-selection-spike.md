# Spike: affected-test selection for PR CI (AAASM-6007)

**Status: spike report only. No CI behavior change. No required-gate semantics
affected by this document.** Produced under AAASM-6007, a subtask of the
AAASM-6002 CI-performance epic. This is a design + risk assessment, not an
implementation, and it does not authorize one — see "Recommendation" below
for what would have to happen first.

## Question this answers

Can `agent-assembly`'s PR CI safely run a *reduced* test suite — computed from
"which crates changed" plus a dependency/reverse-dependency closure over the
Cargo workspace graph — instead of the full `cargo nextest run --workspace`,
without creating **false-green PRs**: a PR that passes the reduced suite but
would have failed the full one?

**Verdict: not viable as a required-gate replacement without a nontrivial,
currently-unbuilt correctness harness underneath it.** The workspace's crate
graph is exactly the kind of shape where naive closure computation looks
sound and is not: real coupling exists that no `Cargo.toml` edge encodes,
multi-hop reverse-dependency chains that must be walked correctly, and
feature-flag-gated dev-dependency edges that a `--no-deps` or shallow
`cargo metadata` reading would miss outright. None of this rules the idea
out — it rules out shipping v1 as a required check. See the falsification
plan below for what would change the verdict.

## The real dependency graph

Built from `cargo metadata`/`Cargo.toml` inspection of every workspace member
(34 crates plus `conformance` and `examples/*`), not a hypothetical one.
Intra-workspace edges only (external crates.io deps omitted):

| Crate | Depends on (workspace) |
|---|---|
| `aa-core` | `aa-security` |
| `aa-security` | — (leaf) |
| `aa-storage` | `aa-core` |
| `aa-storage-memory` | `aa-core`, `aa-storage` |
| `aa-storage-redis` | `aa-core`, `aa-storage`, `aa-storage-memory` |
| `aa-cache` | `aa-core` |
| `aa-storage-postgres` | `aa-core`, `aa-storage` |
| `aa-storage-sqlite-buffer` | `aa-core` |
| `aa-proto` | — (leaf) |
| `aa-ebpf-common` | — (leaf) |
| `aa-ebpf` | `aa-core`, `aa-ebpf-common` |
| `aa-runtime` | `aa-core`, `aa-devtool`, `aa-devtool-claude-code`, `aa-devtool-codex`, `aa-ebpf`, `aa-ebpf-common`, `aa-policy`, `aa-proto`, `aa-security`, `aa-storage-sqlite-buffer` |
| `aa-proxy` | `aa-core`, `aa-proto`, `aa-runtime`, `aa-security` |
| `aa-sdk-client` | `aa-proto`, `aa-security` |
| `aa-wasm` | `aa-core` |
| `aa-sandbox` | `aa-core` |
| `aa-isolation` | `aa-core`, `aa-security` |
| `aa-isolation-sandlock` | `aa-core`, `aa-isolation` |
| `aa-isolation-native` | `aa-core`, `aa-isolation`, `aa-security` |
| `aa-isolation-vm-proto` | `aa-isolation-native` |
| `aa-isolation-macos-vm` | `aa-core`, `aa-isolation`, `aa-isolation-native`, `aa-isolation-vm-proto` |
| `aa-policy` | `aa-core`, `aa-security` |
| `aa-gateway` | `aa-auth`, `aa-core`, `aa-policy`, `aa-proto`, `aa-runtime`, `aa-sdk-client`, `aa-security`, `aa-storage-postgres` |
| `aa-api` | `aa-auth`, `aa-core`, `aa-devtool`, `aa-devtool-saas`, `aa-gateway`, `aa-proto`, `aa-runtime`, `aa-sandbox`, `aa-sdk-client`, `aa-security`, `aa-storage-postgres` |
| `aa-cli` | `aa-core`, `aa-devtool`, `aa-devtool-claude-code`, `aa-gateway`, `aa-isolation`, `aa-isolation-macos-vm`, `aa-isolation-native`, `aa-isolation-sandlock`, `aa-policy`, `aa-proto`, `aa-proxy`, `aa-runtime`, `aa-sandbox`, `aa-sdk-client`, `aa-security`, `aa-storage`, `aa-storage-memory`, `aa-storage-redis` |
| `aa-devtool-contract` | `aa-core` |
| `aa-devtool` | `aa-devtool-claude-code`, `aa-devtool-codex`, `aa-devtool-contract`, `aa-devtool-copilot`, `aa-devtool-sample-myeditor`, `aa-devtool-windsurf` |
| `aa-devtool-claude-code`, `-codex`, `-copilot`, `-saas`, `-windsurf` | `aa-devtool-contract` |
| `conformance` | `aa-core`, `aa-proto`, `aa-security` |
| `aa-integration-tests` | `aa-api`, `aa-core`, `aa-devtool`, `aa-devtool-claude-code`, `aa-devtool-codex`, `aa-devtool-contract`, `aa-ebpf`, `aa-ebpf-common`, `aa-gateway`, `aa-isolation`, `aa-proto`, `aa-proxy`, `aa-runtime`, `aa-sandbox`, `aa-sdk-client`, `aa-security`, `aa-storage-postgres`, `aa-storage-sqlite-buffer` |

Two structural observations that shape the whole rest of this report:

1. **`aa-core` and `aa-security` sit at the bottom of nearly everything.** A
   one-line change to either has a forward-reverse-dependency closure that is
   effectively the entire workspace (`aa-core` alone is a transitive
   dependency of 25 of the 34 members, including every crate `aa-cli` and
   `aa-integration-tests` touch). For the highest-traffic crates, "affected
   test selection" degenerates to "run everything" — the win is concentrated
   in leaf/near-leaf crates (`aa-storage-redis`, `aa-wasm`, `aa-sandbox`,
   the `aa-devtool-*` adapters, `aa-isolation-*` backends), which is a
   meaningfully smaller set of PRs than "most PRs."
2. **`aa-integration-tests` and `conformance` are the crates whose *tests*
   actually assert the cross-crate contracts**, but they are themselves leaf
   nodes with no reverse dependents. A naive "closure of crates reachable
   from the changed crate" correctly includes `aa-integration-tests` whenever
   any of its 18 workspace dependencies changes — but only if the closure
   walk is a true reverse-dependency graph traversal, not a shallow
   "immediate dependents" lookup. See the multi-hop case below.

## False-green risk catalog (concrete, from this codebase)

Each item below is a real construct in this repo, not a hypothetical.

### 1. Feature-gated dev-dependency edges invisible to a plain `Cargo.toml` scan

`aa-runtime/Cargo.toml` declares:

```toml
[features]
test-fixtures = []  # AAASM-5280: exposes devint::fixture, the configurable
                     # DevToolIntegration the DI-API's end-to-end tests drive.
```

and `aa-cli/Cargo.toml` pulls `aa-runtime` in **twice** — once as an ordinary
`[dependencies]` entry, and again under `[dev-dependencies]` with
`features = ["test-fixtures"]`, specifically so `aa-cli`'s own command tests
exercise the same `DevToolIntegration` fixture `aa-runtime`'s own tests use
rather than a second copy that would drift.

A dependency-closure computation that reads only `[dependencies]` (the
common shortcut, since `cargo metadata --no-deps` and most "what does this
crate depend on" tooling defaults to the runtime graph) would correctly flag
`aa-cli` as a reverse dependent of `aa-runtime` — but would not know that a
change gated behind `test-fixtures` only manifests in `aa-cli`'s *test*
build, not its release build, and would not know to distinguish "changed a
`test-fixtures`-gated path" (must re-run `aa-cli`'s command tests) from
"changed a path outside that feature" (does not affect `aa-cli`'s tests via
this edge). Getting this right requires resolving the feature-unification
graph per build target (`--tests` vs. default), not just the crate graph.

The same shape recurs at `aa-gateway`'s `redis-cache` feature (off by
default, gates `dep:redis` and the `PolicyCache::Redis` variant) and
`aa-runtime`'s `integration-test` / `aa-ebpf`'s `integration-test` features
(root-only, Linux-only, explicitly excluded from the default feature set and
from the crates' own default test run — `cargo test -p aa-runtime --features
integration-test --test layer_integration` is a separate, manually-invoked
command). A selection algorithm that doesn't model *which* CI job enables
*which* features per crate will either under-select (miss a
feature-activated regression) or over-select (always include the
integration-test-gated crates, defeating the purpose).

### 2. Cross-process boundaries with no Cargo edge at all

`aa-integration-tests/tests/e2e_sdk_python.rs` drives fixture scripts under
`tests/fixtures/agents/python/{single_agent,agent_team,root_sub_agents}/` by
spawning a `python3` subprocess (`Command::new("python3")`) and asserting on
its stdout JSON event stream (`AA_SELFTEST=1` mode). The coupling this test
protects — that the Python SDK's selftest JSON event shape matches what
`agent-assembly` expects — has **no Cargo dependency edge whatsoever**: the
crate under test (the Python SDK's `agent_assembly` package) isn't a Rust
crate, isn't in this workspace, and isn't reachable from any `cargo metadata`
walk. A change to `aa-sdk-client`'s wire types or `aa-security`'s finding
schema that also needs a corresponding Python-SDK-repo change would not
select this test via crate-graph closure at all — it already doesn't today,
and "affected test selection" computed purely from `Cargo.toml` edges cannot
close this gap, only preserve or widen it depending on whether
`aa-integration-tests` (which legitimately depends on `aa-sdk-client` in
Cargo terms) is included by the closure for the *other* reason it changed.

### 3. Protocol coupling documented only in test comments, not encoded anywhere machine-readable

`aa-integration-tests/tests/e2e_mcp_interceptor.rs`'s module doc states the
test exercises `aa_proxy::intercept::mcp::parse_mcp_request` to verify the
structured fields (`tool_name`, `arguments`) that `aa-gateway`'s policy
engine needs (`FieldRef::Tool` / `ToolCallContext.args_json`) are extracted
correctly — a coupling between `aa-proxy`'s parser output shape and
`aa-gateway`'s policy-engine input shape that today is asserted **only** by
this one test's hand-written assertions, with the rest of the wiring
(gateway client in `aa-proxy`, enforcement on the wire, structured audit
emission) explicitly not yet implemented (`#[ignore]`d ST-Q-1..5 in the same
file). `aa-integration-tests` does have a genuine Cargo edge to both
`aa-proxy` and `aa-gateway`, so a naive closure computed today would
correctly select this test for either crate — the risk here is forward-
looking: as this coupling deepens (the wiring the comment describes as
"not yet implemented" lands), whether the crate-graph edge continues to be a
faithful proxy for "this test should run" depends entirely on that future
code also flowing through a declared Cargo dependency and not, say, a shared
JSON schema file, a wire constant duplicated in both crates, or a NATS
subject string convention (as `aa-gateway`'s `audit-consumer` feature
already does for `assembly.audit.<tenant>.<agent>` — a string contract
between the publisher and the consumer that no compiler or dependency graph
checks).

### 4. Multi-hop reverse-dependency closure through a `Box<dyn Trait>` registry

`aa-cli/Cargo.toml` names `aa-devtool-claude-code` and `aa-devtool-codex` as
direct dependencies (not merely transitively via `aa-devtool`) specifically
because the registry's `Box<dyn DevToolAdapter>` "cannot carry" the extra
surfaces (lifecycle implementation, plan renderer, launch-environment
executor) those two adapters need — see the `AAASM-5281`/`AAASM-5918`
comments in that manifest. `aa-devtool-windsurf` and `aa-devtool-copilot`,
by contrast, register *only* through `aa_devtool::registry`'s dynamic
dispatch and are reached by `aa-cli` only transitively, via `aa-devtool`.

A change to `aa-devtool-windsurf`'s adapter implementation is invisible to
`aa-cli`'s own test suite by direct edge — the effect is real (the registry
`aa-cli` consumes changes behavior) but only reachable by walking
`aa-devtool-windsurf → aa-devtool → aa-cli`, a two-hop reverse-dependency
traversal. This isn't a case the Cargo graph fails to encode (the edges are
real and present) — it's a case that demonstrates the closure computation
must be a correct full transitive reverse-dependency walk, not a
one-hop "who directly depends on the changed crate" lookup, which is the
kind of implementation shortcut a first-pass tool is likely to take under
time pressure.

## Existing CI routing infrastructure (context for a future implementation, not touched by this ticket)

`.github/workflows/ci.yml` already has a two-layer routing model documented
in this repo's `.claude/CLAUDE.md`: `on.push.paths` / `on.pull_request.paths`
gates whether the workflow runs at all, and a `dorny/paths-filter` `changes`
job (`.github/workflows/ci.yml`, `filter` step) computes named boolean
outputs (`rust`, `dashboard`, `proto`, `schema`, `openapi`, `storage`,
`conformance`, `devint_client`, `backend_license`, `isolation_backend`,
`isolation_native`, `governance`, `benchmarks`, plus several governance
satellite gates) that downstream jobs consume via `needs.changes.outputs.*`
to decide whether *that job* runs.

This existing router is **glob/directory-based, not dependency-graph-based**:
the `rust` filter fires on any `aa-*/**/*.rs` (or `.toml`/`.sql`/…) change
across the *entire* workspace — i.e. today, changing any one crate already
selects the same single `rust` job umbrella that every other crate change
selects. There is no per-crate job splitting today; "affected test
selection" as scoped by this ticket would be a materially different
mechanism (crate-graph closure → per-crate/per-test selection within what is
currently one monolithic `rust` job), not an extension of the existing
`changes` job's granularity. A future implementation would need to either
compose with this router (e.g. add a *finer* selection step downstream of
`needs.changes.outputs.rust == 'true'`) or replace part of it — either way,
it must not remove or weaken the existing glob-based gate, since (per the
`AAASM-5738`/`AAASM-5714`/`AAASM-5677` comments already in `ci.yml`) this
repo has repeatedly had to add router-filter entries by hand after
discovering "dead trigger" gaps, and a crate-graph-only router would
reintroduce that exact class of bug for anything not expressed as a Cargo
edge (see risk catalog items 2 and 3 above).

## Falsification-test plan

Before a reduced-suite selector could gate anything required on `main`, it
would have to survive a plan structured to actively try to prove it wrong,
not just demonstrate it usually works:

1. **Shadow-run period, not a switchover.** For a minimum of 6 weeks (chosen
   to span multiple release cycles and catch low-frequency crate
   combinations, not a magic number — should be revisited once real PR
   volume data is available) every PR runs *both* the full
   `cargo nextest run --workspace` (continues to be the actual required
   check, unchanged) and the candidate reduced-suite selector, in parallel,
   with the reduced suite's result recorded but never gating merge.
2. **Divergence metric.** For each PR, record whether
   `reduced_suite_result != full_suite_result`. The case that matters is
   specifically **reduced=pass, full=fail** (the false-green case this whole
   spike exists to prevent) — track it separately from
   reduced=fail/full=pass (over-selection; wastes time but is safe) and from
   agreement.
3. **Numeric acceptance threshold.** Zero observed false-greens over the
   full shadow period, for at least the volume of PRs needed to reach a
   pre-agreed statistical confidence level appropriate to a required-gate
   decision (e.g., zero-false-green across ≥300 PRs as a starting proposal —
   this number needs sign-off from whoever owns the CI-correctness bar, not
   a unilateral pick). A single observed false-green during shadow-run does
   not just fail that PR's shadow check — it restarts the clock and requires
   root-causing which of the risk-catalog categories above (or a new one)
   produced it, with a fix to the selector before shadow-running resumes.
4. **Adversarial seeding, not just organic traffic.** Alongside organic PR
   traffic, deliberately construct PRs that target each risk-catalog item
   above (a `test-fixtures`-gated change in `aa-runtime` with no other
   crate touched; a `aa-devtool-windsurf`-only change; a change to the
   `assembly.audit.<tenant>.<agent>` NATS subject string on the publisher
   side without touching the consumer side) and confirm the selector's
   result against the full-suite result for each, specifically because
   organic PR traffic may never happen to exercise these low-frequency
   combinations within the shadow window.
5. **Kill switch and ownership.** The selector must have a documented,
   fast (single-config-flag) way to fall back to full-suite-always, and an
   owning team that reviews shadow-run divergence weekly during the shadow
   period — this is process, not code, but its absence is itself a
   viability blocker per this Epic's stated governance rule (a wrong
   implementation silently weakening CI correctness).
6. **Exit criteria are a decision point, not an automatic promotion.** Even
   a clean shadow-run result should be presented as a recommendation for a
   human governance decision to promote the selector to required-gate
   status, not auto-promoted by the shadow-run tooling itself.

None of this plan is built. It is scoped here so a future implementation
ticket has a concrete bar to design against, per this ticket's acceptance
criteria.

## Recommendation

**Pursue only as a scoped, explicitly-bounded future ticket — not reject
outright, but not viable to build directly from this spike either.**

Reasoning:

- The workspace's shape means the win is real but smaller than "affected-test
  selection" suggests at first glance: `aa-core`/`aa-security` centrality
  means a large share of realistic PRs (anything touching the shared
  wire-type or credential-scanning layer) would still need the full suite,
  so the achievable wall-clock win is concentrated in the leaf/near-leaf
  crates (storage backends, isolation backends, devtool adapters, WASM
  sandbox) — worth scoping precisely before committing engineering time.
- The false-green risk is not hypothetical noise; this repo has four
  concrete, present-day constructs (feature-gated dev-dependency edges,
  a cross-language subprocess boundary with zero Cargo coupling, a
  protocol contract currently enforced only by one test's hand-written
  assertions, and a `Box<dyn Trait>` registry requiring correct multi-hop
  closure) that a naive implementation would get wrong in ways that
  directly produce the false-green outcome this Epic's governance rule
  forbids trading away for speed.
- A **future ticket** should scope narrowly: (a) build the crate-closure
  computation and feature-unification-aware selection as a *non-gating*
  shadow job first — never skip the real required check on day one; (b) run
  the falsification plan above to completion before any promotion
  discussion; (c) explicitly decide, as a design question rather than an
  implementation default, whether the selector composes with or replaces
  part of the existing `dorny/paths-filter` router, given that router's own
  history of dead-trigger bugs from incomplete coverage.
- This ticket makes no CI behavior change and does not alter the full
  workspace suite's required-gate status, consistent with its acceptance
  criteria.
