# ADR 0023: Is `aa-api` Meant to Carry a Policy Cascade?

**Status**: Proposed — **requires architecture sign-off before any implementation; product sign-off additionally required if Option C is chosen**
**Date**: 2026-07
**Ticket**: [AAASM-5106](https://lightning-dust-mite.atlassian.net/browse/AAASM-5106) (Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082))

This ADR frames a decision about where the multi-document policy cascade is
supposed to live. **It changes nothing.** No loader, route, projection, schema, or
enforcement path is modified by merging it. Every option below is a proposal; none
is authorised by this document.

The question is narrow and answerable: **`aa-api` serves every REST surface that
reports on the policy cascade, and `aa-api` has no way to load one.** Whether that
is a wiring bug (as the directly analogous
[AAASM-3499](https://lightning-dust-mite.atlassian.net/browse/AAASM-3499) was
judged to be for `aa-gateway`) or a correct reflection of a single-policy design
that the projections mis-modelled, is the decision this ADR asks for.

It complements ADR 0004 (governance enforcement flow), ADR 0017 (which ratified the
Capability Matrix and Topology surfaces that read the cascade) and ADR 0018 (whose
"honestly-null until sourced" discipline the interim mitigation below extends).

All line references were re-verified at `main` @ `7174c640`.

---

## Context

### Two loaders, one of which nothing in `aa-api` can reach

`PolicyEngine` has two families of constructor:

| Constructor | Line | Populates `scope_index`? |
|---|---|---|
| `load_from_file` | `aa-gateway/src/engine/mod.rs:318` | **No** — `scope_index: ScopeIndex::new()` at `mod.rs:383` |
| `load_from_file_with_budget` | `aa-gateway/src/engine/mod.rs:673` | **No** — `scope_index: ScopeIndex::new()` at `mod.rs:695` |
| `load_cascade_from_dir` | `aa-gateway/src/engine/mod.rs:438` | **Yes**, via `read_cascade_dir` |
| `load_cascade_from_dir_with_budget` | `aa-gateway/src/engine/mod.rs:474` | **Yes**, via `read_cascade_dir` |

`read_cascade_dir` (`mod.rs:508-599`) is the only code anywhere that fills the
index — `scope_index.insert(doc)` at `mod.rs:586`.

`aa-api` builds its engine with `load_from_file`
(`aa-api/src/state.rs:302`), so its `scope_index` is empty from construction and
stays that way for the life of the process.

### `aa-gateway` has a working operator mechanism; `aa-api` has none at all

`aa-gateway` routes on the shape of the path it is given:

```rust
// aa-gateway/src/server.rs:223-233 (fn load_policy_engine)
if policy_path.is_dir() {
    PolicyEngine::load_cascade_from_dir_with_budget(policy_path, tracker)
} else {
    PolicyEngine::load_from_file_with_budget(policy_path, tracker)
}
```

Operators reach it through `aa-gateway --policy <FILE|DIR>`, or through
`aasm gateway start`, which resolves `--policy` → `$AA_POLICY` →
`~/.aasm/policy.yaml` and forwards the value verbatim
(`aa-cli/src/commands/gateway/start.rs:209-213`, forwarded at `:94`). This is the
capability documented in `docs/src/operations/policy-cascade-loader.md` — a
document that names `aa-gateway` and `aasm gateway start` only (`:38-53`) and
never mentions `aa-api`.

`aa-api` has **no equivalent**. Grepping its entire source for environment reads
returns `AA_API_ADDR` (`aa-api/src/bin/aa-api-server.rs:41`, `config.rs:36`),
`AASM_API_AUTH` (`state.rs:202`), `AASM_API_KEY` (`state.rs:205`), and
`ALLOW_PRIVATE_EGRESS_ENV` (`destinations/validate.rs:109`). There is no policy
path, no cascade directory, no config file key, and no CLI flag. **The ticket's
claim that no such setting is read anywhere in `aa-api` is confirmed.**

Worse than "not operator-settable": `aa-api` does not accept an operator policy at
all. It *synthesises* one — a hard-coded, budget-only envelope written to a
per-process temp file (`state.rs:266-290`) — and loads that. The durable
entrypoint `local_hardened_at` (`state.rs:454`) delegates to the same builder and
adds no policy source of its own.

### The two processes are disjoint, and the projections are in the wrong one

This is the structural fact the ticket does not state, and it is the crux.

- `aa-gateway` does **not** depend on `aa-api` (no `aa-api` entry in
  `aa-gateway/Cargo.toml`); the dependency runs the other way
  (`aa-api/Cargo.toml:21`).
- `aa-gateway`'s own HTTP surface is three routes — `/healthz`,
  `/api/v1/health`, `/api/v1/admin/status` (`aa-gateway/src/local_mode.rs:268`,
  `:277`, `:287`) — plus the dashboard's static assets
  (`aa-gateway/src/dashboard_server.rs:36`).
- Every cascade-derived projection lives in `aa-api`:
  `routes/policies.rs:121`, `routes/topology.rs:426`, `routes/capability.rs:608`.
- `aasm start --mode local` spawns `aa-api-server`; `--mode remote` spawns
  `aa-gateway` (`aa-cli/src/commands/start.rs:157-161`).

So: **the process that can load a cascade serves none of the endpoints that report
on one, and the process that serves all of them cannot load one.** No deployment
topology in the repository puts a populated `scope_index` behind
`GET /api/v1/agents/{id}/capabilities`, `GET /api/v1/topology`, or
`GET /api/v1/policies/team/{team_id}`.

### `apply_yaml` does not close the gap, and could not today

`apply_yaml` (`mod.rs:783`) validates, writes history, and swaps the primary slot
(`self.policy.store(...)`, `mod.rs:796`). It never touches `scope_index`. That is
already recorded in-tree at `aa-api/src/routes/policies.rs:484-486`.

Two further facts constrain any fix here:

1. `POST /api/v1/policies` **rejects every non-Global-scoped document**
   (`policies.rs:453-461`), because the primary slot is global by nature and a
   narrower scope "would be silently globalised". The handler's own comment
   defers scoped installation "until scoped installation is wired into the
   `scope_index` cascade (AAASM-4933 follow-up)". So the API cannot install an
   Org/Team/Agent policy at all — the tiers the cascade exists to express.
2. The one API that *does* insert into the index, `load_policy`
   (`mod.rs:1873`), takes `&mut self`. `AppState.policy_engine` is
   `Arc<PolicyEngine>` (`state.rs:45`); the test code that uses `load_policy`
   has to reach for `Arc::get_mut` (`state.rs:691`) at construction time. It is
   structurally unusable from a live request handler.

### Enforcement is genuinely unaffected — but not for the reason the ticket gives

`evaluate` falls back when the cascade is empty:

```rust
// aa-gateway/src/engine/mod.rs:845-846
if cascade.is_empty() {
    return self.evaluate_primary(ctx, action);
}
```

(The ticket cites `mod.rs:813-816`; at `7174c640` the fallback is at `:845-846`.)

The sharper point: **`aa-api` never calls `evaluate` at all.** Searching
`aa-api/src` for `.evaluate(` returns zero hits. Its `PolicyEngine` is used purely
as a projection source. Enforcement happens in `aa-runtime`/`aa-gateway`, in a
different process, against a policy loaded by a different code path.

That refines the ticket's framing — "the gateway denies and the dashboard says
there is nothing to deny with" is true, but the two are not the same engine
disagreeing with itself. They are two processes with independent policy inputs,
only one of which the operator can configure.

### Was the cascade ever intended for `aa-api`?

The evidence is mixed, and this is precisely why it needs a human decision.

**Points to "gateway-only by design":**

- [AAASM-951](https://lightning-dust-mite.atlassian.net/browse/AAASM-951)
  introduced the scope index for cascading *evaluation* — a runtime concern.
- [AAASM-2023](https://lightning-dust-mite.atlassian.net/browse/AAASM-2023) is
  titled "**Gateway** multi-document cascade loader" and motivates it entirely by
  `evaluate_with_cascade` versus `evaluate_primary`. Reporting is not mentioned.
- `docs/src/operations/policy-cascade-loader.md` documents only gateway
  entrypoints.

**Points to "`aa-api` was in scope and was skipped":**

- [AAASM-3499](https://lightning-dust-mite.atlassian.net/browse/AAASM-3499) — the
  bug that the cascade was "unreachable from any shipped binary" — **explicitly
  enumerated `aa-api` as one of the four affected paths**, quoting the very
  `state.rs` comment still present today. Its fix commit (`dadd6061`) touched
  `aa-gateway/src/main.rs` and `aa-gateway/src/server.rs` and nothing else.
  `aa-api` was named, diagnosed, and left unfixed — with no recorded rationale.
- The projections that read the cascade
  ([AAASM-5090](https://lightning-dust-mite.atlassian.net/browse/AAASM-5090),
  [AAASM-5099](https://lightning-dust-mite.atlassian.net/browse/AAASM-5099),
  [AAASM-5096](https://lightning-dust-mite.atlassian.net/browse/AAASM-5096)) were
  all specified against surfaces ratified in ADR 0017, and all were built in
  `aa-api`. Somebody expected a cascade to be there.
- The doc comment asserting `load_from_file` "is the only public loader"
  (`state.rs:243`) **is false** and has been since AAASM-2023: both
  `load_cascade_from_dir` (`mod.rs:438`) and `load_cascade_from_dir_with_budget`
  (`mod.rs:474`) are `pub`. The comment is a stale premise that has been
  load-bearing for the `aa-api` wiring ever since.

**Not verified:** no ticket, commit message, or design note was found that states
a deliberate decision to keep `aa-api` single-policy. The absence of such a record
is itself part of why this ADR exists.

---

## Blast radius

All three are shipped, all three read an index that is empty in every deployment.

### 1. Capability Matrix (AAASM-5090) — a fail-open on the page whose job is "what can this agent do"

`capability.rs:608` collects the cascade; `collect_merged_capabilities` folds an
empty slice into an empty `CapabilitySet`. `decide` (`capability.rs:480-488`) then
reads:

```rust
if aa_core::capability_is_denied(&caps.deny, cap) { return Decision::Deny; }   // empty deny → false
if caps.allow_is_restricted() && !caps.allow.contains(cap) { return Decision::Deny; }
Decision::Allow
```

`allow_is_restricted()` is `self.allow_restricted || !self.allow.is_empty()`
(`aa-core/src/capability.rs:70-72`) — `false` on an empty set. Both guards fall
through and **every cell renders `allow`**.

This is confirmed as the ticket states, with one nuance worth recording: `decide`
is individually correct. It is fail-closed *given* a cascade
(`capability.rs:475-479` documents exactly that). The fail-open is entirely a
property of being handed an empty input, which is why no unit test catches it.

### 2. Topology permission chain (AAASM-5099)

`topology.rs:427` sets `node.policy_count = Some(cascade.len() as u32)` — i.e.
`Some(0)`, not `None`. `Some(0)` is a positive claim ("zero policies govern this
agent"); `None` would have been "not known". Every tier of
`effective_permissions` renders empty for the same reason.

The crate already knows this distinction matters and applies it elsewhere: the
field's own documentation states that the list / tree / team endpoints "leave it
`null` rather than emitting a misleading `0`"
(`aa-api/src/models/topology.rs:287-291`). The graph endpoint is the one place
that emits the `0` — and it is the only place where the `0` is always wrong.

### 3. Policy `affects[]` and team active-policies (AAASM-5096)

`affects` is already absent-not-empty (`policies.rs:230`), and the create path
returns `affects: None` with an accurate explanation (`policies.rs:484-488`).

**Contradiction with the ticket, worth stating plainly:** the ticket's "worst UI
consequence" — the Teams card asserting *"No policy is in force for this team"*
while a policy is enforced — **is already fixed.** AAASM-5096 made
`TeamPoliciesResponse.policies` required-but-nullable (`policies.rs:633-634`) and
the dashboard renders the `null` case as a distinct `unknown` state reading
*"Policy data unavailable — the policy cascade is not currently loaded"*
(`dashboard/src/features/teams/TeamActivePoliciesCard.tsx:73-77`), with the count
shown as `—` rather than `0` (`:59`). A regression test asserts the unknown state
does not render the "no policy" copy
(`TeamActivePoliciesCard.test.tsx:48`). The ticket describes a state of affairs
that the PR which surfaced the ticket had already remedied on that one surface.

The other two surfaces have **not** been given that treatment. That asymmetry —
one surface honest, two surfaces asserting — is the concrete harm today.

---

## Options

### Option A — Wire `aa-api` to `load_cascade_from_dir` with an operator-settable directory

Mirror what AAASM-3499 did for `aa-gateway`: accept a policy path, route on
`is_dir()`, and load the cascade when it is a directory. `aa-api` already writes
its bootstrap policy *into a directory* (`state.rs:266`), so the mechanical change
is small — `load_cascade_from_dir(&policy_dir, budget_alert_tx)` is signature-
compatible (`mod.rs:438-441`) with the existing call at `state.rs:302`.

- **Fixes:** all three projections, at the source, for operators who supply a
  cascade directory. Restores the symmetry the docs already promise.
- **Does not fix:** deployments that supply no directory — the synthesised
  budget-only bootstrap would load as a one-document Global cascade, making the
  index non-empty and the projections *technically* correct but reporting a stub
  policy nobody authored. **The interim mitigation is therefore still required
  under this option**, to distinguish "cascade loaded, genuinely permissive" from
  "cascade absent".
- **Does not fix:** `POST /api/v1/policies` — an API-created policy still lands in
  the primary slot only, so it remains unreportable (see Option B).
- **Migration/compat:** additive. Needs a new operator input (flag and/or env,
  named consistently with the gateway's `$AA_POLICY`), a decision on the default
  when unset, and documentation in `policy-cascade-loader.md`. No wire-contract
  change; no schema change.
- **Open question it forces:** if `aa-api` and `aa-gateway` are run together
  (`--mode remote`), both would read the same directory independently. That is
  fine for a read-only projection but means two watchers and two parse paths over
  one directory — acceptable, but it should be a conscious choice, not a
  side-effect.

### Option B — Make `apply_yaml` also populate the scope index

So that a policy created through the API is visible to the projections that report
on policy.

- **Fixes:** the "I applied a policy and the dashboard still shows nothing" path,
  which is the *only* way to get a real policy into `aa-api` today.
- **Does not fix:** anything for Org/Team/Agent tiers, because
  `POST /api/v1/policies` rejects non-Global documents outright
  (`policies.rs:453-461`). Option B on its own makes the cascade a one-element
  Global list — enough to un-blank the projections, not enough to make the
  Org/Team tiers of the Topology chain mean anything. It is **necessary but not
  sufficient**, and it presupposes the AAASM-4933 follow-up on scoped
  installation.
- **Migration/compat — the real cost:** this changes `PolicyEngine` semantics, not
  just `aa-api` behaviour. A non-empty index flips `evaluate` from
  `evaluate_primary` to `evaluate_with_cascade` (`mod.rs:845-846`) for *any*
  embedder. Today that risk is latent, not active — the only non-test caller of
  `apply_yaml` is `aa-api/src/routes/policies.rs:469`, and `aa-api` never calls
  `evaluate`. But it converts a reporting fix into an engine-semantics change, and
  it needs an answer to "when the engine was loaded from a cascade directory, does
  an applied Global document *replace* the directory's Global tier or stack on top
  of it?"
- Also requires resolving the `&mut self` constraint on the insert path
  (`mod.rs:1873`) versus the `Arc<PolicyEngine>` the state holds — `apply_yaml` is
  `&self` and swaps through `ArcSwap`, so the cascade's `ArcSwap` (`mod.rs:1870-1872`)
  is the natural mechanism, but that is a real change to `load_policy`'s contract.

### Option C — Accept that `aa-api` is single-policy by design; re-point the projections at the primary document

Declare the primary slot the authoritative "active policy" for `aa-api`, treat the
cascade as a file-based *gateway* deployment feature, and rewrite the three
projections to read `self.policy` instead of `collect_cascade_with_lineage`.

- **Fixes:** the blank/fail-open projections, with no new operator surface and no
  engine change. Honest about what `aa-api` actually holds.
- **Does not fix:** anything about tiers. The Topology "permission chain" is a
  four-tier Global/Org/Team/Agent visualisation ratified in ADR 0017; against a
  single document it degenerates to one tier. `affects[]` and the team mapping
  become "every visible agent" for a Global doc, which is true but uninformative.
  **This is the option that changes what the UI promises**, which is why it needs
  product sign-off and not only architecture's.
- **Migration/compat:** contradicts `docs/src/operations/policy-cascade-loader.md`
  unless that document is amended to state the cascade is gateway-only and
  invisible to the dashboard — an odd thing for a governance product to say. It
  would also leave AAASM-3499's own analysis (which named `aa-api`) standing as an
  unexplained loose end.
- **Note:** if C is chosen, `collect_cascade_with_lineage`'s three `aa-api` call
  sites should be removed rather than left dormant, so the next reader does not
  re-derive this ticket.

---

## Recommendation

**Option A, with the interim mitigation as a hard prerequisite that lands first
and independently.** Option B is worth doing afterwards, but only behind the
AAASM-4933 scoped-installation decision. Option C is not recommended.

The reasoning:

1. **The precedent is exact.** AAASM-3499 asked the identical question about
   `aa-gateway` — loader exists, no shipped caller — and answered it by wiring the
   binary, not by deleting the capability. Its bug report named `aa-api` in the
   same breath. Answering the same question the opposite way for the second half
   of the same defect needs an affirmative reason, and none is recorded anywhere
   in the repository.

2. **Option C loses a promise the product has already made.** The cascade is
   documented, tested, and reachable in `aa-gateway`. Making it structurally
   invisible to the only UI the product ships means an operator can deploy
   Org/Team/Agent policies and have the governance dashboard show no trace of
   them. For a governance product that is a worse end state than the current bug,
   because it would be intentional.

3. **Option B is the wrong first move** even though it is the most obviously
   "correct-feeling" one. It changes shared engine semantics to fix a reporting
   gap, it cannot express the tiers that make the cascade worth having, and it is
   blocked behind a scoped-installation decision that nobody has taken.

4. **The mitigation matters more than the option.** Whichever way this goes, the
   window between now and the fix is the dangerous part, and the capability matrix
   is currently rendering `allow` for capabilities that a gateway-side policy
   denies. That is fixable this week; the wiring decision is not.

**What I am *not* recommending:** that Option A be implemented under this ADR, or
that a `--policy` flag be designed here. The naming, the default-when-unset, and
the dual-watcher question above are all open, and Option A is a proposal.

---

## Consequences

**If Option A is accepted:** `aa-api` grows an operator input it has never had,
and the documented cascade becomes visible in the dashboard for the first time.
Cost: a new configuration surface to name, document, and default safely; a second
watcher over the policy directory in co-deployed topologies; and the interim
mitigation is still needed for the no-directory case.

**If Option B is accepted (alone):** API-created Global policies become
reportable, the Org/Team/Agent tiers stay permanently empty, and `PolicyEngine`
acquires a semantics change whose blast radius is currently latent but not
theoretical. Accept only with the cascade-versus-primary precedence question
answered in writing.

**If Option C is accepted:** the projections become honest immediately and cheaply,
the four-tier Topology permission chain ratified in ADR 0017 needs an addendum
recording that it renders one tier in practice, and
`docs/src/operations/policy-cascade-loader.md` needs a prominent statement that
the cascade is a gateway-side enforcement feature with no dashboard
representation.

**Under every option:** enforcement is unchanged. `evaluate` has always fallen
back to `evaluate_primary` on an empty cascade (`mod.rs:845-846`), and `aa-api`
has never evaluated anything. Nothing in this ADR's option space makes the product
more or less permissive at runtime; the entire dispute is about what operators are
*told*.

---

## Interim mitigation — do this regardless of the outcome

**Every cascade-derived surface must distinguish "the engine carries no cascade"
from "this agent/team genuinely has no policy", and must render *unknown* rather
than *none*.** This is not contingent on any option above and should not wait for
sign-off on one.

The pattern already exists in-tree. AAASM-5096 applied it to
`TeamPoliciesResponse.policies`: required-but-nullable
(`aa-api/src/routes/policies.rs:633-634`), documented so a client cannot shrug the
absence off with `?? []`, and rendered by the dashboard as a distinct unknown
state (`TeamActivePoliciesCard.tsx:73-77`). ADR 0018 established the same
"present in the schema, honestly `null` until sourced" discipline for the enriched
decision record.

Two surfaces have **not** been given it:

- **Capability Matrix (AAASM-5090)** — the higher-severity of the two, because it
  does not merely blank: it asserts `allow`. `decide` (`capability.rs:480-488`)
  cannot distinguish an empty cascade from a genuinely permissive one, and the
  `Decision` vocabulary has no unknown member (`na` means "no such cell", per
  ADR 0018). Some signal has to be added — a nullable cascade-loaded flag on the
  response, or a distinct cell state — so the page can decline to answer instead
  of answering wrongly.
- **Topology permission chain (AAASM-5099)** — `policy_count` is
  `Some(cascade.len() as u32)` at `topology.rs:427`, so an absent cascade reports
  the affirmative `0`. `policy_count` and `effective_permissions` are already
  `Option`-typed (`aa-api/src/models/topology.rs:291`), so `None` is expressible
  on the wire today; the handler simply always populates them.

Whether that mitigation is a schema change (and therefore an `openapi/v1.yaml`
regeneration plus dashboard codegen) is an implementation question for the
follow-up ticket, not for this ADR.

---

## Decision required from: architecture (+ product if Option C)

1. **Is `aa-api` meant to load a policy cascade at all?** A/B (yes) or C (no).
   Given that AAASM-3499 named `aa-api` and did not fix it, is there a recorded or
   remembered reason, or was it an omission?
2. **If yes: what is the operator input?** A directory path by flag, by
   environment variable, or by reusing the gateway's `$AA_POLICY`? And what
   happens when it is unset — keep synthesising the bootstrap policy, or refuse
   to start?
3. **Should `apply_yaml` populate the scope index (Option B)?** This is a
   `PolicyEngine` semantics change, not an `aa-api` change. If yes: when the
   engine was loaded from a cascade directory, does an applied Global document
   replace that directory's Global tier or stack on it?
4. **Does the scoped-installation follow-up named at `policies.rs:448-452`
   (AAASM-4933) get opened now**, or does `POST /api/v1/policies` stay
   Global-only indefinitely?
5. **Product, only if Option C is on the table:** is the Topology four-tier
   permission chain ratified in ADR 0017 still the promise, given it would render
   a single tier in every `aa-api` deployment?
6. **Is the interim mitigation approved to proceed immediately**, decoupled from
   items 1–5? (Recommended yes — the capability matrix fail-open is live.)

Until items 1 and 2 are answered, **no implementation ticket should be opened
against Options A or B.** Merging this ADR authorises no implementation and
changes no behaviour.

## Reconsideration triggers

- Any decision to merge `aa-api` and `aa-gateway` into one process, which would
  dissolve the disjointness this ADR is really about.
- AAASM-4933's scoped-installation follow-up landing, which makes Option B able to
  express Org/Team/Agent tiers and materially strengthens it.
- A SaaS control-plane policy source (`cloud`) becoming the cascade's origin
  instead of a local directory, which would make Option A's directory input the
  wrong shape.
- Enforcement moving into `aa-api` — today it never calls `evaluate`, and the
  whole "reporting-only" framing depends on that staying true.

## Traceability

- Frames the decision blocking
  [AAASM-5106](https://lightning-dust-mite.atlassian.net/browse/AAASM-5106);
  surfaced during review of
  [AAASM-5096](https://lightning-dust-mite.atlassian.net/browse/AAASM-5096)
  (PR #1703).
- Direct precedent:
  [AAASM-3499](https://lightning-dust-mite.atlassian.net/browse/AAASM-3499) (same
  defect class, fixed for `aa-gateway`, `aa-api` named but not fixed); origin of
  the loader:
  [AAASM-2023](https://lightning-dust-mite.atlassian.net/browse/AAASM-2023);
  origin of the scope index:
  [AAASM-951](https://lightning-dust-mite.atlassian.net/browse/AAASM-951).
- Affected projections:
  [AAASM-5090](https://lightning-dust-mite.atlassian.net/browse/AAASM-5090)
  (capability matrix),
  [AAASM-5099](https://lightning-dust-mite.atlassian.net/browse/AAASM-5099)
  (topology permission chain),
  [AAASM-5096](https://lightning-dust-mite.atlassian.net/browse/AAASM-5096)
  (`affects[]` / team active-policies).
- Surfaces ratified in ADR 0017; the "honestly-null until sourced" discipline is
  ADR 0018's; enforcement-flow context is ADR 0004.
- Operator documentation for the cascade:
  `docs/src/operations/policy-cascade-loader.md`.
