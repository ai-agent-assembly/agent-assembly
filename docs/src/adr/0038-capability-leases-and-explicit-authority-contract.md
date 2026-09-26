# ADR 0038: Capability Leases & the Explicit-Authority Contract

**Status**: Proposed
**Date**: 2026-09
**Ticket**: [AAASM-6160](https://lightning-dust-mite.atlassian.net/browse/AAASM-6160), [AAASM-6161](https://lightning-dust-mite.atlassian.net/browse/AAASM-6161) (Epic [AAASM-6159](https://lightning-dust-mite.atlassian.net/browse/AAASM-6159), *Agent Execution Runtime 2.0*)

This ADR cross-references and amends nothing in
[ADR 0035](0035-agent-execution-isolation-and-pluggable-enforcement-backends.md); it
extends the contract 0035 established with a question 0035 never asked. It reuses the
capability-domain vocabulary [ADR 0030](0030-developer-integration-boundaries-and-trust-model.md)
§3.1 settled, rather than defining a competing one.

## Context

AAASM-5709 (done, Epic AAASM-5702) made launch-time process-tree inheritance and ambient
authority minimization checkable: `EnvironmentPlanner` distinguishes a credential
*removed* from the child from one that *could not be* removed
(`CredentialPosture::ambient_unremoved`), and that distinction now travels correctly
through `IsolationReport`.

What AAASM-5709 did not do — and what nothing in `aa-isolation` does today — is answer a
different question: **was this run ever explicitly authorized to touch a given
capability domain at all?** `crate::plan::negotiate` answers a narrower one: "can the
*backend* mechanically enforce or observe this domain, given a `ControlRequirement`". A
backend can be perfectly capable of enforcing `CapabilityDomain::Credential` while
nothing about a specific run's authorization to touch that domain has ever been checked.
`negotiate`'s own module documentation states the resulting gap plainly: it inspects
`spec.requirements()` only, so a domain no requirement names simply never enters its
loop — there is no arm of `negotiate` that can refuse a domain by omission, because
omission never reaches it in the first place.

AAASM-5533 (Epic AAASM-6159, not started) will eventually bind MCP transport identity
cryptographically and design a capability-token scheme for that transport. This ticket
does not wait on it and does not implement any of it: `IdentityRef` remains
asserted-only, exactly as `aa-isolation/src/spec.rs` already documents it — "asserted,
not verified... nothing in this crate authenticates it". What this ADR borrows from
AAASM-5533's eventual design is the *shape* of a capability lease (subject, scope,
lifetime, revocation), not its cryptography, so that the two do not converge on
incompatible vocabularies later.

## Decision

### 1. A versioned, backend-neutral `CapabilityLease` (`aa-isolation/src/lease.rs`)

A lease binds: a `LeaseId` and `LEASE_SCHEMA_VERSION`; a subject (`IdentityRef`, reused
verbatim — no second identity type); a `CapabilityDomain` (reused from
`aa_isolation::capability`, per ADR 0030 §3.1's rule against renaming a settled axis);
a scope (`RequirementScope`, reused verbatim — a lease's scope is the same "what within
the domain" question `ControlRequirement` already answers, with a lifetime and an issuer
attached, not a new concept); `issued_at`/`not_before`/`expires_at` (the last one
*required* at construction — a lease with no bound is not representable); optional
`ResourceLimits` where quantitative ceilings are meaningful; a `DelegationRule`
(`NotDelegable` or `DelegableWithNarrowerScope`); a `RevocationState` carrying a
generation counter; and a `LeaseBasis` (issuer, policy rule, approval reference, reason —
names only, never a credential value, matching `CredentialPosture`'s own discipline).

No backend implementation detail is representable in this schema — a lease is
policy-facing, and a backend lowers it into its own enforcement mechanism exactly as it
already lowers a `ControlRequirement` into an opaque `Lowering`.

### 2. The explicit-authority contract (`aa-isolation/src/authority.rs`)

Three mechanisms establish the invariant this Epic names:

> *Effective runtime authority is derived only from explicit ExecutionSpec/policy
> grants, validated leases and documented compatibility residuals — never merely from
> supervisor/host possession.*

1. **`EffectiveAuthority`** — a domain-total map, constructible only via
   `EffectiveAuthority::deny_all()`. Every `CapabilityDomain` starts explicitly denied;
   there is no code path from `crate::capability::BackendCapabilities` or from the host
   process environment into this type, which is the structural proof that supervisor
   possession cannot leak into a grant.
2. **`AuthorityWitness`** — an unforgeable-by-construction token. Its only field is
   private and its only constructor lives inside `authority_gate`, so a call site that
   requires one as a parameter cannot be satisfied by building authority some other way.
3. **`authority_gate`** — runs *before* `crate::plan::negotiate`, checking every
   `ControlRequirement` in a spec against the `EffectiveAuthority` built from that same
   spec's own leases. A domain with no covering, valid lease and no compatibility
   residual is refused before backend capability is ever consulted. `authority_gate`
   does not duplicate or bypass `negotiate` — it composes with it strictly ahead of it,
   holding a distinct question (was this authorized) apart from `negotiate`'s own
   (can the backend do it).

### 3. The rc.7 compatibility residual, precisely bounded

No rc.7 spec has ever carried a `CapabilityLease` — the type did not exist. A spec that
carries **no lease at all** is read, spec-wide, under the pre-lease contract: every
domain a `ControlRequirement` names is recorded as `AuthorityState::CompatibilityResidual`,
which `authority_gate` treats as granted. The moment a spec carries even **one** lease,
this residual stops applying spec-wide: every domain a requirement names must then have
its own valid, covering lease, or `authority_gate` refuses it. A `ControlRequirement`
alone is no longer read as an implicit grant once a caller has opted into the lease
system at all. This is the exact edge `aa-isolation/src/authority.rs`'s
`adding_any_lease_switches_the_whole_spec_out_of_the_legacy_path` test pins down.

The rule is deliberately spec-wide rather than per-domain: a per-domain fallback (some
domains lease-backed, others silently reverting to policy-grant-implies-authorization)
would let a caller who lease-covers the domain they are thinking about that day
accidentally leave every other domain on the old, weaker contract with no signal that
they had done so. A spec-wide switch means "I am using leases" is a single, auditable
fact about the whole spec.

### 4. A monotonic delegation *hook*, not a delegation *policy*

`CapabilityLease::derive_child` takes a `&dyn ScopeOrder` — a per-domain comparator
returning `Narrower`/`Equal`/`Wider`/`Incomparable` for a parent and candidate child
scope. This ticket ships exactly one implementation, `UndefinedScopeOrder`, which
returns `Incomparable` unconditionally. The consequence is intentional: **no lease in
this codebase can be delegated today**, because nothing here can yet prove a child scope
is no wider than its parent's for any real domain (a path-prefix comparator for
filesystem domains, a CIDR-containment comparator for network domains, etc.). Real
per-domain comparators are AAASM-6161's scope, not this ticket's — the hook exists so
that ticket plugs in without a redesign of `derive_child`'s signature or of
`DelegationRule`.

### 5. One real enforcement point: `aa-cli`'s `IsolationPlan`

`ExecutionSpec` gains `with_lease`/`leases()`, threaded through
`IsolationPlan::base_spec`'s `BoundLaunchFields` using the same exhaustive-destructuring
discipline AAASM-6038 established there for the identical reason: an added field that
is not consumed in the `let BoundLaunchFields { .. } = fields` pattern is a compile
error, not a silent drop. `IsolationPlan::resolve_boundary` calls `authority_gate` on the
fully-lowered spec, immediately before `backend.plan(&spec)` (which internally calls
`negotiate`) — composing the two questions in the order this ADR requires. No leases are
issued by any policy path in this ticket; the wiring exists and is exercised end to end
by this crate's own tests, ready for a future ticket to source real leases from policy
without changing this call site's shape.

### 6. Truthful reporting, additive only

`IsolationReport` gains `DomainAuthoritySummary` (domain, granted, a stable state token,
and a lease id when the grant came from a lease — never a lease's basis reason or scope
selectors, which is what keeps this type free of anything an operator would consider
sensitive) and an `authority_refused` constructor mirroring `from_refusal`'s shape for a
gate-level refusal. `REPORT_SCHEMA` is not bumped: both are purely additive fields/methods
that render nothing when unset, so an existing report — and every existing golden-output
test — is byte-identical to before this ticket.

## What this ADR does not decide

- **No crypto identity binding.** `IdentityRef` stays asserted-only. AAASM-5533 owns
  when and how that changes.
- ~~No real per-domain scope comparator.~~ **Decided by the AAASM-6161 amendment
  below.**
- **No revocation-latency claim.** `RevocationState` records a generation counter a
  lease issuer can bump; nothing here measures or bounds how quickly a revocation
  reaches every holder of a cached lease value. No text in `aa-isolation/src/lease.rs`
  or `authority.rs` may claim otherwise. AAASM-6161's `DelegationLedger` serializes
  *observation* of a revocation against a concurrent derivation — it still makes no
  claim about how fast a revocation *propagates* to a holder that is not asking.
- **No new policy DSL.** Leases are attached to an `ExecutionSpec` programmatically in
  this ticket. Exposing lease issuance through the policy schema is future work, listed
  in the ticket's own scope note as deferred rather than ruled out.
- **No change to `negotiate`'s own logic**, and no new capability domain — this ticket
  reuses `CapabilityDomain` entirely as it stood before it, so none of `aa-isolation`'s,
  `aa-isolation-sandlock`'s, or `aa-integration-tests`'s existing
  `CapabilityDomain::ALL` totality call sites need updating.

## Amendment (AAASM-6161): monotonic capability attenuation across ancestry

AAASM-6161 fills the hole this ADR reserved above and answers the question §4
explicitly deferred: once a real per-domain comparator exists, does a child launch's
lease actually stay inside the ceiling its parent held? Three findings from reading
the AAASM-6160 code as merged, rather than as designed, shaped the answer:

1. **`derive_child`/`ScopeOrder` had zero production call sites.** Every reference
   was inside this crate's own tests. "Logical sub-agent delegation" was not a new
   concept this ticket introduces — `IdentityRef.lineage` (asserted, populated from
   `aasm run --root-agent`) and the gateway registry's `parent_agent_id`/`depth`
   model (measured, backend-held) already existed — but nothing carried a parent's
   *effective authority* into a child launch. This amendment makes ancestry a
   **parameter of the existing authority decision point**, not a new launcher.
2. **The comparators this ticket needed already existed elsewhere.** Filesystem
   containment is `aa_security::policy::filesystem::PathScope` (`from_paths`,
   `permits`, `intersect`); host-pattern containment is
   `aa_core::policy::is_host_allowed_by_egress_allowlist`. Both are reused rather
   than reimplemented, so this comparator can never silently disagree with
   `aa-proxy`/`aa-gateway`/the eBPF probes about the same question.
3. **`aa-isolation/src/descendant.rs` is a separate, already-settled residual-risk
   disclosure and is not touched by this amendment.** Adding scope comparison to
   `authority_widening` would have broken its own
   `a_wider_selector_set_is_not_detected_and_this_is_the_known_gap` regression test,
   which is a different ticket's decision to revisit, not this one's.

### 7. Real per-domain `ScopeOrder` comparators (`aa-isolation/src/scope_order.rs`)

`order_for(domain)` is a domain-total, exhaustively-matched registry: `PathPrefixOrder`
(filesystem, delegating to `PathScope`), `HostPatternOrder` (network/DNS, delegating to
the canonical egress matcher for literal hosts and a direct wildcard-containment rule
for a wildcard child pattern — a wildcard is never fed to the host matcher as if it were
a hostname), `ExactTokenOrder` (syscalls/credential names, exact-set containment), and
`ResourceCeilingOrder` (numeric ceilings). `ProcessCreation`, `Ipc` and
`WorkspaceTransaction` — the three domains lowering only ever emits `RequirementScope::Whole`
for — get `UndefinedScopeOrder`: there is nothing to narrow, so `Incomparable` is the
honest answer, not a comparator pretending to reason about a scope shape that never
occurs. Every comparator fails closed (`Incomparable`) the moment any selector on either
side does not carry the `permit-only:` grammar `crate::lowering::permitted_selector`
checks for — a selector without that prefix is reachable in practice, and a fallback to
raw-string prefix matching would reintroduce the exact widening bug `PathScope` exists
to prevent.

### 8. `Ancestry` and witness-gated `ParentAuthority` (`aa-isolation/src/attenuation.rs`)

`authority_gate` gains a second parameter, `ancestry: &Ancestry`, with three states:
`Root` (no parent), `Parent(Box<ParentAuthority>)` (a resolved parent), and
`UnresolvedParent { .. }` (a claimed-but-unresolved parent). The third state exists
because "we could not resolve the claimed parent" must be distinguishable from "there
is no parent" — collapsing them into `Root` would read a claimed-but-unverified
ancestry as license to launch with full, unattenuated authority, which is the fail-open
outcome this amendment exists to rule out.

`ParentAuthority::from_gated_spec(spec, witness)` is constructible only from a spec and
an `AuthorityWitness` — and `AuthorityWitness`'s only constructor is inside
`authority_gate` itself. This is the whole mechanism behind nested attenuation being
monotonic *by construction*, not merely by convention: a grandchild's `ParentAuthority`
is built from the **child's own** already-attenuated spec and witness, never from the
grandparent's, so the ceiling a grandchild is checked against can only ever have
shrunk on the way down the tree.

`attenuation_applies(spec, ancestry)` gates when the new checks run at all: both a
non-empty `IdentityRef.lineage` *and* `EffectiveAuthority::is_lease_aware(spec)` must
hold. `aasm run --root-agent` sets lineage today, but no policy path issues a lease yet
— so this predicate is false for every real launch until a lease-issuing policy source
exists, and `--root-agent`'s CLI behavior is unchanged by this amendment. This is
stated explicitly so a reader does not infer the CLI has started attenuating.

### 9. Delegation provenance and the `with_delegation` re-widening hole
(`aa-isolation/src/lease.rs`)

`CapabilityLease::derive_child` now takes a `ChildLeaseRequest` (replacing its previous
seven positional arguments) and attaches a `DelegationProvenance` to every lease it
produces: the parent lease's id and subject, the `InheritanceMode` used, the
`DelegationRule` the child was actually issued with, and the parent's revocation
generation observed at derivation. `derive_child` also now floors a child's
`not_before` at `max(issued_at, parent.not_before)` — closing a gap where a child
derived with an early `issued_at` could become valid before its own parent does, the
same direction `expires_at` capping already closed for the other end of the window.

`authority_gate`'s provenance-integrity check compares a child lease's *current*
`delegation()` against the `DelegationRule` recorded in its own provenance at
derivation time. This is what closes the hole a public, non-clamping
`derive_child(...).with_delegation(DelegableWithNarrowerScope)` call could otherwise
reopen: the builder itself is deliberately not made to clamp (a silently-clamping
builder would read stronger than the caller meant, the same failure
`CapabilityLease::new`'s own builder discipline exists to prevent), so the check moves
to the one place a widened field can be caught against a value the widening call
cannot also rewrite.

### 10. Escalation requires independent attribution

A child lease that is wider than, or absent from, its parent's authority is refused
(`AuthorityRefusal::EscalationNotIndependentlyApproved`) unless
`LeaseBasis::is_independently_attributable` holds: the basis carries an
`approval_ref` or `policy_rule`, **and** its issuer is neither the child's own subject
nor the parent's. A parent cannot self-approve its child's escalation, and a child
cannot self-approve its own, regardless of how the reference string is worded — both
are ruled out by identity comparison, not by trusting the string's content.

### 11. `DelegationLedger`: the one shared mutable state a concurrent derivation touches

`CapabilityLease` values are otherwise immutable and travel by clone; the one
exception is revocation. `DelegationLedger` serializes a parent lease's revocation
generation under one lock, so two racing calls to `derive_child` agree on whether a
revocation had already taken effect before either produced a child — every returned
child records the generation observed **inside** the critical section, and a parent
found revoked inside that same section yields `DelegationDenied::ParentRevoked`, never
a child lease.

### 12. Quantitative limits stay per-child, not aggregate — the pinned, documented gap

`aa-isolation` measures no live resource consumption, so an aggregate sibling budget
would be a claim about runtime the crate cannot make. Limits are enforced as
per-child ceilings against the parent's own ceiling
(`crate::lease::limits_narrower_or_equal` — deliberately **not** a reuse of
`limits_cover`, which answers a different question: whether a lease's own grant
satisfies what a *requirement* asked for, where a field the requirement never
mentions is vacuously satisfied. Delegation narrowing asks the opposite question of
the *child*'s own field — a child that states no ceiling at all is wider than any
bounded parent ceiling, not narrower — so reusing `limits_cover` here would have
silently admitted a child that dropped a ceiling its parent enforced). Because limits
are per-child, sibling children may each hold the parent's full ceiling simultaneously;
this is a known, pinned gap
(`sibling_children_may_each_hold_the_parents_full_ceiling_and_this_is_the_known_gap`),
in the same shape as `descendant.rs`'s own
`a_wider_selector_set_is_not_detected_and_this_is_the_known_gap` — a deliberate
disclosure to be revisited if aggregate accounting is ever implemented, not an
oversight.

### 13. Reporting stays additive (`aa-isolation/src/report.rs`)

`DomainAuthoritySummary` gains three fields — `derived_from_lease_id`,
`inheritance_mode`, `issuer_kind` — populated from a lease's own
`DelegationProvenance` when it carries one. `REPORT_SCHEMA` is **not** bumped: every
existing report renders every new field as empty, so every pre-existing golden-output
test remains byte-identical.

### What this amendment does not decide

- No cross-process parent-authority handoff. Serializing a `ParentAuthority` from one
  `aasm run` into a child `aasm run`'s process requires a wire contract this ticket
  does not add (`EffectiveAuthority` carries no `serde` derive today); the `Ancestry`
  parameter is the seam a future ticket populates.
- No lease sourcing from the policy schema (already deferred by §4 above).
- No crypto identity binding (AAASM-5533, unchanged by this amendment).
- No change to `aa-isolation/src/descendant.rs` — see finding 3 above.

## Consequences

- A spec that opts into the lease system gets a strictly stronger guarantee than rc.7
  policy alone provided: every domain it exercises must be backed by a lease that is
  in-scope, unexpired, unrevoked, and schema-current, or the launch is refused before
  any backend is consulted.
- A spec that does not opt in is unaffected — this is the compatibility residual, and it
  is regression-tested (`legacy_spec_with_no_leases_passes_on_policy_grants_alone`).
- The negative control this Epic's own review standard asks for —
  "supervisor/parent authority does not appear in the child absent a grant" — is now a
  falsifiable, passing test
  (`supervisor_possession_without_a_lease_is_denied_once_leases_are_in_play`): a backend
  that fully possesses a domain (`Mediation::Enforce`, `DecisionTiming::Pre`,
  `Synchrony::Sync`) still yields a refusal when the spec is lease-aware and that domain
  carries no lease of its own, because `EffectiveAuthority` never reads
  `BackendCapabilities` at all.
