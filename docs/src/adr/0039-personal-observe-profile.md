# ADR 0039: Personal-Observe Deployment Profile

**Status**: Accepted
**Date**: 2026-09
**Ticket**: [HORO-1375](https://lightning-dust-mite.atlassian.net/browse/HORO-1375) ([AASM DogFood] Provide durable personal observe profile and verify local audit wiring), sub-tasks tracked under HORO-1369

## Context

Personal, unmanaged use of Agent Assembly's local single-process
`aa-api-server` entrypoint wants a deployment posture where a policy denial
is recorded — audited — without blocking the agent's action, for an agent
that has not been given an explicit per-agent `enforcement_mode`. Nothing in
the codebase before this ticket exposed that posture as a supported,
documented feature.

Two structural properties were also found broken by inspection of the
codebase before any new code was written (§2 of the design amendment this
ADR formalizes):

1. `AgentRegistry::set_enforcement_mode_persisted` had no guard against
   persisting `(Some(Observe), None)` — an uncapped, permanently-shadow
   record structurally invisible to the shadow-expiry reconciler (which
   requires `enforcement_mode_expires_at.is_some()`).
2. `aa-api`'s local audit hash chain was rooted under
   `std::env::temp_dir()` and reseeded to `[0u8; 32]` / `seq = 0` on every
   process boot — silently forking the audit trail from itself across every
   restart, the exact failure AAASM-5959 argued against for the gateway's
   own audit sink.

Both are fixed as part of this ticket, independent of whether
personal-observe is ever enabled, because a feature whose entire purpose is
"denies are still recorded" cannot ship on top of a durability defect that
can silently lose that same record.

## §0: The spine — one invariant, everything else falls out

**personal-observe supplies the policy-default slot only, and NEVER writes
`AgentRecord.enforcement_mode` or `AgentRecord.enforcement_mode_expires_at`.**

Structural consequences that fall out of this one invariant, not asserted
independently of it:

* The 72h-capped per-agent override column always wins:
  `resolve_enforcement_mode` is `agent_override.unwrap_or(policy_default)`.
* personal-observe never time-expires: the shadow-expiry reconciler
  (`shadow_expiry_watcher::tick` / `agents_with_expired_shadow`) only ever
  selects records with `enforcement_mode = Some(Observe)`; a `None` record —
  the only thing personal-observe affects — is invisible to it by
  construction, not by a special-case check.
* personal-observe does not reuse the 72h enterprise shadow-renewal path; it
  never touches the expiry column at all.

## Decision

### §4: The structural anti-bypass mechanism

Two newtypes gate the two ends of the policy-default slot, in a
**deliberately submodule-free leaf file**, `aa-gateway/src/engine/effective_mode.rs`
— NOT declared in `engine/mod.rs`. A private field is module-scoped in Rust;
declaring these types in `mod.rs` would let every descendant module
(`engine::decision`, `engine::cache`, …) construct them freely. Putting them
in a leaf module with no `mod` declarations of its own makes "this module"
and "the exact scope of the invariant" the same one file — this ADR
deliberately does **not** claim a crate-wide guarantee, only a
one-file-scoped one.

* `PolicyDefaultMode` gates **construction** of the default. Its only
  `Observe`-yielding constructor, `personal_observe(&PersonalObserveGrant)`,
  requires a grant that is itself only mintable by
  `aa_core::observation::authorize_personal_observe` — the boot gate below.
* `EffectiveMode` gates **consumption** of the resolved result.
  `transform_for_observe_mode` now takes an `EffectiveMode`, not a bare
  `aa_core::EnforcementMode`; the only producer of one is
  `resolve_enforcement_mode`, which always consults the capped per-agent
  column first.

Gating only the input would leave
`transform_for_observe_mode(eval, EnforcementMode::Observe)` directly
callable — exactly the "future code path added carelessly" this is meant to
close off. Narrowing the consumer closes it: there is no `EffectiveMode`
constructor, no `From<EnforcementMode>`, and no `Default` that yields
`Observe`.

### §4.2: Closing the two real uncapped-Observe holes found in the registry

Inspection found two producers below the request-validation layer that could
already create an uncapped `Observe`, independent of this ticket's new
feature:

* `AgentRegistry::set_enforcement_mode_persisted` now rejects
  `(Some(Observe), None)` — and, for symmetry, `(Some(Disabled), None)` —
  with a new `RegistryError::UncappedShadowWindow`, before any mutation.
* `storage_bridge::storage_to_runtime` now rehydrates a persisted
  `("observe", NULL expiry)` row **fail-closed to `Some(Enforce)`** (not
  `None` — under personal-observe, `None` itself resolves to `Observe`, so
  falling through to `None` would silently reproduce the exact outcome this
  guard exists to prevent) and logs a warning naming the agent.

### §5: Audit durability fix

`LocalDurablePaths::resolve()` roots the registry DB, the audit JSONL
directory, and the audit/retention SQLite file under durable paths
(`~/.aasm/local.db`, `aa_gateway::server::default_audit_dir()`,
`~/.aasm/audit.db` respectively) instead of a per-process temp directory,
and `local_hardened_at` resumes the hash chain from the last persisted entry
(`AuditWriter::read_last_hash` / `read_last_seq`) instead of reseeding to
zero. The audit JSONL directory is **deliberately unified** with
`aa-gateway`'s own `default_audit_dir()`: `AuditReader` globs every
`*.jsonl` file in its directory, so this is one governance trail per host,
not two that could silently fork — the same reasoning AAASM-5959 already
established for the gateway's own sink. `hermetic_temp()` preserves the
pre-ticket temp-path behaviour for tests.

### §6: Boot-refusal gate

Two layers, described in full on the
[personal-observe documentation page](../security/personal-observe-profile.md#boot-refusal-behaviour):
Layer 1 (`GatewayConfig::validate()`) is advisory only — three of six
non-test `GatewayConfig::load()` call sites in this codebase discard its
error. Layer 2 (`aa_core::observation::authorize_personal_observe`) is
authoritative: it re-derives every config-shaped signal directly and adds
nine runtime/env signals Layer 1 cannot see, and is the only place that can
mint a `PersonalObserveGrant`.

`aa-gateway` refuses unconditionally when the key is set — it does not
implement personal-observe (tracked as gap G5) — so an operator can never be
left believing the key applies there while a co-located `aa-gateway`
continues to enforce under `Standard`.

### §2.6: Explicitly out of scope

`aa-core/src/integration/plan.rs`'s `ObserveOnly` is a different axis — the
devtool-integration plan's own mode, not the gateway's `CheckAction`
decision path — and is untouched by this work. `PolicyDocument.enforcement_mode`
remains dead on the hot path; wiring it is explicitly deferred (gap G4) and
must not happen without routing through this same gate. `SHADOW_MAX_HOURS`,
`resolve_enforcement_transition`, and `shadow_expiry_watcher`'s own
behaviour are unchanged.

## Consequences

* Every existing deployment is a no-op: `ObservationProfile::default()` is
  `Standard`, and `GatewayConfig::default()`'s behaviour is bit-for-bit
  unchanged.
* `local_hardened_at`'s signature changes (`registry_db_path: PathBuf` →
  `paths: LocalDurablePaths`), with four call sites updated. Chosen over an
  env var so the durable path is explicit and testable, and because the
  audit-durability fix needed a place to carry three related paths together
  rather than three new individual parameters.
* `resolve_enforcement_mode` / `transform_for_observe_mode`'s public
  signatures in `aa-gateway`'s engine API change. Chosen because the founder
  asked for a structural, not test-level, invariant — nothing weaker
  (a runtime assertion, a lint, a code-review checklist item) gives that.
* The detector is best-effort. It buys a cheap block on obvious enterprise
  coupling at the cost of a false sense of coverage if the wording
  discipline in `docs/src/security/personal-observe-profile.md#wording-discipline`
  erodes — mitigated by an automated wording test (N4) in addition to
  review, and by the always-visible known-gaps table (G1-G7).
* aa-api's local audit reads widen to include gateway-written entries on the
  same host. Chosen over a second, forkable trail.

## Alternatives considered

* **A single bare `bool` "personal mode" flag on `GatewayConfig`.** Rejected:
  it would not have forced the two-layer gate or the newtype anti-bypass
  mechanism, and a boolean invites exactly the "future code path added
  carelessly" this ADR's §4 mechanism exists to prevent.
* **Wiring `PolicyDocument.enforcement_mode`** as the mechanism for
  personal-observe instead of a new `ObservationConfig` section. Rejected:
  it is dead on the hot path today, both production callers hardcode a
  default, and wiring it without the same gate would create a second,
  ungated `Observe` source (gap G4) — a strictly worse outcome than adding
  one new, gated config section.
* **Implementing personal-observe in `aa-gateway` too.** Deferred (gap G5):
  the local single-process entrypoint is where personal, unmanaged use
  actually happens; `aa-gateway` refusing outright is safer than an
  under-scoped implementation shipped to satisfy symmetry.
