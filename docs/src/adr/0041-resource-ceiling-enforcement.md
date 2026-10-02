# ADR 0041: Resource ceiling enforcement, round 1 (rlimits-first)

- Status: Accepted
- Date: 2026-10-02
- Ticket: AAASM-6165 (Epic AAASM-6159, "Agent Execution Runtime 2.0")

## Context

AC1 of AAASM-6165 asks for a backend-neutral resource-ceiling spec. That
already existed on `main` before this ticket: `ResourceLimits` (memory, CPU
seconds, PIDs, wall-clock, file size, open files),
`RequirementScope::Limits(ResourceLimits)`,
`CapabilityDomain::Resource`, `ResourceCeilingOrder` (lease-scope ordering)
and `limits_cover` (lease containment) all existed with **zero live
producers**. `aa-isolation::lowering::lower_policy` hard-coded
`CapabilityDomain::Resource` to an unrepresentable gap (`RESOURCE_GAP`) on
every policy document, no CLI flag built a `Resource` requirement, and
`aa-isolation-native` refused the domain outright. `aa-isolation-sandlock`
already implemented `--max-memory`/`--max-processes` rlimits-adjacent
ceilings, but nothing ever produced a requirement that reached them either.

This ADR records what round 1 actually closes — reachability — and the
decisions that shape how it does so.

## Decision 1 — Resource ceilings are not a new type

`ResourceLimits`/`RequirementScope::Limits` **is** the backend-neutral spec.
Round 1 does not introduce a parallel `ResourceSpec`/`ResourceCapability`
type. It makes the existing type reachable: `aasm run` gains six `--max-*`
CLI flags that build `ControlRequirement`s against `CapabilityDomain::Resource`,
the AASM-native backend gains an `RLIMIT_NOFILE`/`RLIMIT_FSIZE` lowering and a
capability report, and the sandlock backend's pre-existing memory/PID
lowering becomes reachable from the same producer with no sandlock code
change at all.

## Decision 2 — Lowering is all-or-nothing per *requirement*, not per domain

Each stated ceiling becomes its **own** `ControlRequirement`, never a bundled
`ResourceLimits` with several fields set in one requirement. A backend's
lowering (`lower_requirement`/`resource()` in both `aa-isolation-native` and
`aa-isolation-sandlock`) evaluates the *whole* `ResourceLimits` value a
requirement carries; if any one field in that bundle is unsupported, the
*entire requirement* gaps, even if the backend could have honoured another
field in the same bundle. Per-ceiling requirements mean each ceiling lowers,
or is refused, independently — and the refusal reason names the specific
ceiling (`max_memory_bytes: no cgroup subtree available…`), not a generic
"Resource unsupported".

Corollary: a post-effect signal (`max_wall_clock_seconds`, `max_cpu_seconds`)
must travel as its own `RequirementIntent::Observe`/`RequirementPosture::Optional`
requirement, never bundled with a `Required`/`Prevent` one — bundling it would
let the whole requirement's lowering depend on a field that is never a
prevention mechanism on any backend in this version.

`aasm run`'s producer (`aa-cli::commands::run::resource_requirements`) follows
this: six flags, each becomes its own requirement with its own posture.

## Decision 3 — `CapabilityDomain` is deliberately not split per ceiling

`CapabilityDomain` is `#[non_exhaustive]`, so splitting `Resource` into
`ResourceMemory`/`ResourcePids`/`ResourceOpenFiles`/… is technically
possible. It is rejected. Decision 2's per-requirement rule already delivers
the honesty property a split would buy — a precise refusal reason per
ceiling — at a much lower cost. A domain split would touch
`CapabilityDomain::ALL`, every backend's `discover()`, the capability-
manifest schema's token mapping, and `ResourceCeilingOrder`'s lease-scope
ordering, for no additional enforcement precision over decision 2.

One consequence recorded rather than "fixed": per-ceiling requirements do
**not** let a supported sibling ceiling survive alongside an unsupported one
in the *same launch*. `aa_isolation::capability::narrow_for` replaces the
one per-domain `CapabilityReport` as a whole, and `negotiate` resolves every
requirement against that one report — so a single gapping `Resource`
requirement in a launch makes every *other* `Resource` requirement in that
same launch also see an `Unsupported` domain report, and the launch refuses
if any of them is `Required`. This is the correct reading of "a `Required`
ceiling this backend cannot enforce refuses the launch" — decision 2's gain
is a *precise reason*, not independent per-ceiling survival within one
launch. Splitting `CapabilityDomain` would not even fix this without
duplicating `negotiate`'s whole per-domain resolution model.

## Decision 4 — rlimits first, not cgroup v2 first, for the native backend

cgroup v2 needs a writable delegated subtree, which is absent on most CI
runners and on an unprivileged host generally — it would have to be *skipped*
on measurement, not enforced, defeating the point of a round-1 ceiling.
`setrlimit`/`prlimit64` need no delegation, work on every Linux host, are
inherited unchanged across `fork`/`execve`, and `libc` (which exposes them)
is already a Linux-only dependency of `aa-isolation-native`. Round 1 adds
`aa-isolation-native::limits` (`RLIMIT_NOFILE`/`RLIMIT_FSIZE`, soft == hard)
rather than a cgroup v2 integration. A native cgroup v2 ceiling (which would
additionally let `max_memory_bytes`/`max_pids` be expressed natively, not
only by sandlock) is a stated follow-up, not round-1 scope.

### `RLIMIT_NPROC` is explicitly rejected as a tree-scoped PID ceiling

`RLIMIT_NPROC` counts processes **per real UID across the whole host**, not
within the confined process tree. Setting it on the launcher would risk
starving the supervisor itself (same UID, same counter) and would not be a
correct tree-scoped PID ceiling even if it didn't. `aa-isolation-native`
never lowers `max_pids`; the sandlock backend's own tree-scoped mechanism is
the only PID ceiling this round offers, and `resource_limitations()`/the
native `resource()` lowering gap both state this reason explicitly rather
than silently refusing.

### `prlimit64` and soft == hard

`prlimit64` is already in `aa-isolation-native::seccomp::STARTUP_BASELINE`
(a confined child needs to be able to call it on itself for ordinary libc
behaviour). A confined child that was only given a lowered *soft* limit
could call `prlimit64` to raise its own soft limit back toward the (unset,
`RLIM_INFINITY`) hard limit. Both `RLIMIT_NOFILE` and `RLIMIT_FSIZE` are
therefore installed with **soft == hard**, closing that self-raise. This is
documented as a stated limitation on the capability report, not left to be
discovered.

### `max_cpu_seconds` and `max_wall_clock_seconds`

Both are post-effect signals on every backend in this version — `SIGXCPU`/a
supervisor-side deadline fire only after the ceiling is exceeded, never
before. Neither is lowered as a `RequirementIntent::PreventBeforeEffect`
mechanism anywhere. `max_wall_clock_seconds` is enforced today by `aasm
run`'s own supervisor (`aa_isolation::deadline::requested_wall_clock_ceiling`,
pre-existing); `max_cpu_seconds` has no enforcement mechanism in this round
at all and is deferred to a follow-up ticket (`RLIMIT_CPU` is a reasonable
candidate, left unimplemented here to keep round 1's scope to ceilings this
PR could falsify end-to-end with a tiny, safe bound).

## Decision 5 — Ceiling provenance is the CLI flag, round 1; not policy

`lower_policy`'s `RESOURCE_GAP` for `CapabilityDomain::Resource` is
unchanged — round 1 does not touch policy lowering. This is true of the
policy **schema**: no YAML node names a resource ceiling, so
`PolicyCannotExpress` remains the honest answer for a launch with no
`--max-*` flag. The `--max-*` flags are CLI-operator provenance, attached
directly to the `ExecutionSpec` (`IsolationPlan::resource_requirements` in
`aa-cli`), never routed through `aa_isolation::PolicyLowering`. A real
`aa-security` policy node that *mandates* a ceiling centrally (so an operator
cannot omit `--max-open-files` and get an unbounded launch) is a stated
follow-up, not round-1 scope — round 1 only makes the ceiling reachable when
an operator asks for it.

One mechanical consequence: `PolicyLowering::apply_to` refuses with
`NoRequirementsLowered` when the *policy document* lowered to nothing, which
would otherwise refuse a launch that asked for a ceiling and nothing else
(the CLI-attached requirement is invisible to that check, by design, since
it is not policy-derived). `aa-cli`'s `resolve_boundary` special-cases this:
when the policy-document lowering is empty but the spec already carries its
own (CLI-provenance) requirements, the launch proceeds with those rather
than refusing.

`crate::report::RequestedControl::Stated`'s doc comment is corrected from
"Policy stated a requirement" to "the resolved spec stated a requirement" —
round 1's provenance is the CLI flag, not governed policy, and the field was
already spec-sourced (`IsolationReport::from_plan` reads
`planned.requirement`, which is the resolved `ExecutionSpec`'s own list, not
`PolicyLowering`'s) — this is a doc-only correction of a pre-existing
imprecision, not a behavior change.

## Decision 6 — the evidence vocabulary distinguishes cause, never fabricates a Decision

`aa_isolation::spec::ExitDisposition` is `Code(i32) | NoCode { detail: String }`
— no structured signal field, and this round does not add one (the crate's
own doctrine: never parse a backend-authored string as a signal). Each
backend's own `evidence()` instead reads its own `std::process::ExitStatus`
directly and emits its own cause record:

- `EvidenceKind::Installed` always, stating which ceilings (if any) were
  applied before `execve` — silence here must not read as a permissive run,
  the same rule `aa-isolation-native`'s filesystem/syscall records already
  follow.
- `EvidenceKind::Exercised`/`ClaimTerm::Detected` when the run ended by a
  nameable signal attributable to a ceiling this backend installed:
  `SIGXFSZ` → "the file-size ceiling was reached".
- `SIGKILL` is reported as **explicitly non-attributable**
  (`ClaimTerm::Unmeasured`) rather than guessed as the ceiling — it is
  equally consistent with an OOM kill or an operator `terminate()`.
- **`EvidenceKind::Decision` is never emitted for `Resource`.** EMFILE
  (open-descriptor denial) and EFBIG (file-size denial) are delivered to the
  **child** process, the same structural position as every Landlock/seccomp
  denial this backend already reports as observation rather than decision.
  `supports_prevention_claim(CapabilityDomain::Resource)` stays `false` after
  every native-backend run. This is the single most important honesty
  property of this round (AC7: "unsupported domains cannot appear as
  Prevention") and is directly tested
  (`a_lowered_resource_ceiling_never_produces_a_decision_record`).

A subtlety that is correct, not a bug: a native backend's *discovery-time*
`CapabilityReport::can_prevent()` for `Resource` can be `true` once the
descriptor-ceiling probe observes a real denial on this host — this is a
claim that the host is *capable* of enforcing some ceiling, structurally
separate from a per-run claim. `BackendAvailability` is not reachable from
`EnforcementEvidence`; the crate already keeps discovery-time capability and
per-run evidence apart by construction for every other domain, and `Resource`
follows the same rule.

## Decision 7 — shared vocabulary with `aa-sandbox`/AAASM-1965, no code edge

AC4 ("WASM maps to AAASM-1965") is a documentation decision, not a code
change. AAASM-1965/2018's mechanisms live in `aa-sandbox` (not `aa-wasm`,
which is a stub): `SandboxError::{CpuTimeout, WallClockTimeout,
MemoryExhausted}`, wasmtime fuel/`StoreLimits`/epoch deadline, and audit
variants `SandboxCpuTimeout`/`SandboxOomKilled`. This ADR records that both
halves of the product should name the same causes identically in their own
evidence/audit vocabularies — "the CPU ceiling was reached", "the memory
ceiling was reached" — without introducing a dependency edge between
`aa-sandbox` and `aa-isolation`. They are different execution models (a
process boundary vs. a WASM store), and a cross-crate edge here would buy no
enforcement gain for a real coupling cost.

`AAASM-6163`'s `EgressCeilings` (`aa-isolation::egress`) already closes the
network-ceiling slice of AC2/AC5; round 1 does not touch it.

## Residual: AC5, orphan-freedom

rlimits inherit across `fork`/`exec` (structural tree coverage), and the
descriptor-ceiling probe measures a **grandchild**, not just the immediate
child, so the claim is not "this process is bounded" but "a process this one
forks is too". There is no `cgroup.kill`-equivalent group-kill in this
round: a confined tree whose immediate process ignores a `terminate()`
relies on the pre-existing best-effort termination semantics, nothing
stronger. The real fix (cgroup v2's atomic group-kill) is deferred to the
cgroup v2 follow-up ticket; this round's AC5 claim is honestly partial.

## Explicitly out of scope for this round

No new `aa-security` policy node for ceiling provenance. No
`CapabilityDomain` split. No `aa-sandbox`↔`aa-isolation` code edge. No
`EgressCeilings` change. No `ExitDisposition` contract change. No cgroup v2
anywhere (native memory/PID ceilings, or a native alternative to sandlock's
existing mechanism). No `RLIMIT_CPU`/`max_cpu_seconds` enforcement (deferred;
this PR left it unimplemented rather than force a stretch). No disk/temp
growth ceiling (no mechanism exists; stated as truthful-unsupported). No
macOS VM-backend resource ceilings (not touched this round).

## Follow-up ticket (to be filed, not implemented here)

cgroup v2 integration for the native backend (would add native
`max_memory_bytes`/`max_pids`, plus the atomic group-kill AC5 needs);
`RLIMIT_CPU`/`max_cpu_seconds` enforcement; disk/temporary-storage growth
ceilings; macOS VM host+guest resource ceilings; a real `aa-security` policy
node for ceiling provenance so an operator cannot omit a ceiling flag and
get an unbounded launch by default.
