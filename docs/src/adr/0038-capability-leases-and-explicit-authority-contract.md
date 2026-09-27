# ADR 0038: Capability Leases & the Explicit-Authority Contract

**Status**: Proposed
**Date**: 2026-09
**Ticket**: [AAASM-6160](https://lightning-dust-mite.atlassian.net/browse/AAASM-6160), [AAASM-6161](https://lightning-dust-mite.atlassian.net/browse/AAASM-6161), [AAASM-6163](https://lightning-dust-mite.atlassian.net/browse/AAASM-6163) (Epic [AAASM-6159](https://lightning-dust-mite.atlassian.net/browse/AAASM-6159), *Agent Execution Runtime 2.0*)

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

**Cross-reference (AAASM-6166):** the durable execution receipt this ticket's
sibling amendment adds to [ADR 0035](0035-agent-execution-isolation-and-pluggable-enforcement-backends.md)
applies this section's own rule to a persisted artifact rather than introducing a
new one — a receipt's `LeaseBinding` records a lease's id and a digest of its
redaction-safe projection, never the lease's basis reason or its scope selectors.
No field of `aa-cli/src/commands/execution_receipt` holds either.

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

**One deliberate deviation from the original design sketch, worth stating plainly:**
`DelegationProvenance::parent_delegation` records the `DelegationRule` the *child*
was actually issued with at derivation (`request.child_delegation`), not the parent
lease's own `delegation` field verbatim. The two coincide in most cases, but only the
former makes the re-widening check reachable at all: since `derive_child` requires
the parent's own rule to already be `DelegableWithNarrowerScope` (the enum's
maximum value) before it will produce anything, recording the *parent's* value as
the ceiling would make "current `delegation()` exceeds the recorded ceiling"
unsatisfiable by construction — there would be no value greater than the maximum to
exceed it with. Recording what the child itself was issued with is what makes
`a_derived_lease_re_widened_via_with_delegation_is_refused_at_the_gate` a real,
passing falsification test rather than a dead branch.

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

## Amendment (AAASM-6163): the identity-bound, policy-governed egress contract

AAASM-6163 asked for "an identity-bound policy-governed egress broker for isolated
runs". Reading the merged AAASM-6160/6161 code and `aa-proxy` as they actually stand
today (not as first sketched) found that a broker-like mediation mechanism already
exists and is substantial: `aa-proxy/src/proxy/mod.rs`'s CONNECT-time SSRF literal
guard, operator denylist, gateway-authoritative `policy.network` check, in-tunnel
re-check (defeats a `Host`-header bypass) and DNS-rebinding defense (re-validates
every resolved answer, not just the first). This amendment does not rebuild that
mechanism. It binds a launch's *requirement* of it to this run's explicit authority,
and makes the mismatch between what a launch requires and what the mechanism
truthfully provides a pre-launch refusal instead of a silent fallback.

### 14. `CapabilityDomain::NetworkEgress` and `CapabilityDomain::NameResolution`, not a new domain

The egress contract (`aa-isolation/src/egress.rs`) binds to the existing pair of
domains `authority.rs` already carries in `EffectiveAuthority`/`AuthorityState`,
rather than introducing a third. `CapabilityDomain::ALL` is hand-maintained with a
count assertion checked at multiple sites across the workspace; a same-campaign
predecessor ticket (AAASM-6162) already paid the cost of adding a domain and
touching every one of those sites, and this amendment does not repeat that for a
property (egress mediation) the two existing domains already name.

### 15. Witness-gated `EgressAuthority`/`EgressWitness`, the same mechanism as §8/§2

`EgressAuthority::from_gated_spec` is constructible only from an `ExecutionSpec` plus
an `AuthorityWitness` — the same single-private-field, no-other-public-constructor
pattern §2's `AuthorityWitness` and §8's `ParentAuthority::from_gated_spec` already
use. A call site that requires an `EgressAuthority` cannot be satisfied by a direct
socket that never went through `authority_gate`, because nothing outside
`aa-isolation` can produce the witness the constructor requires. `egress_gate` itself
returns its own `EgressWitness` under the identical rule, so a caller downstream of
it (there is none yet, by design — see "What this amendment does not decide" below)
would have the same unforgeable proof.

### 16. `MediationDepth` lives on the egress report, not as a new `ClaimTerm` or a `CapabilityReport` field

`CapabilityReport::can_prevent`/`claim_ceiling` read only mediation, timing and
synchrony — no axis distinguishes a destination-only (L3/L4) refusal from a
payload-aware (L7) one. A destination-only guard that refuses before dialling is
`Enforce`/`Pre`/`Sync` exactly like a payload-aware one, so a report built from
either reads identically strong to a caller that only reads those two methods. This
amendment adds `MediationDepth`/`MediationDepthScope` to `EgressBrokerReport`
specifically, not to `CapabilityReport` (which would need the same axis added to
every domain's report, most of which have no payload to be aware of) and not as a
new `ClaimTerm` (`aa_core::attestation::ClaimTerm` and `EvidenceKind` are policed by
`scripts/check_claim_vocabulary.py`, and no existing term names this axis).
`EgressBrokerReport::supports_payload_aware_claim` is the one predicate a caller must
check before reading a destination-only prevention as evidence of payload-aware
mediation — false for every `MediationDepth::DestinationOnly` report regardless of
anything else, including a `FailClosed`, fully-available broker.

### 17. Ceilings stated and reported unsupported, never silently ignored

`EgressCeilings` states a quantitative connection/byte/rate ceiling; no accounting
mechanism for any of them exists in `aa-proxy` today. `check_ceilings` refuses a
launch whose contract states a ceiling against a broker report whose
`ceiling_support` is `SupportLevel::Unsupported` — the AC's "enforced where claimed,
or reported unsupported" arm satisfied by refusing rather than by pretending an
unenforced number was honored.

### What this amendment does not decide

- **`aa-proxy` still evaluates every egress decision under the synthetic,
  unregistered `PROXY_AGENT_ID` at Global policy tier.** `aa-proxy/src/network_enforce.rs`
  already states this and rules out threading a real credentialed agent identity
  into that per-connection path as a materially new trust boundary, out of scope for
  this ticket. `EgressAuthority` is a **pre-launch** decision in `aa-isolation` — "is
  this run authorized for brokered egress at this scope" — checked once, before any
  backend is consulted; it is not a per-connection identity on the proxy path, and
  nothing in this amendment changes what identity `aa-proxy` itself reasons under.
  This is the residual most likely to be misread later, so it is stated plainly here
  rather than left implicit.
- No quantitative connection/byte/rate *enforcement* — see §17. Only the truthful
  statement and the refusal-on-mismatch exist after this amendment.
- No credential injection (a separate ticket) — no type in `aa-isolation/src/egress.rs`
  holds or names credential material.
- No lease sourcing from the policy schema — already deferred by §4. Every real
  launch today constructs `EgressContract::not_required()`, so this amendment ships
  inert: `RUNTIME_REQUIREMENTS_SCHEMA` and `REPORT_SCHEMA` are unbumped, and every
  pre-existing golden-output test remains byte-identical.
- No second network-enforcement mechanism — see [ADR 0035](0035-agent-execution-isolation-and-pluggable-enforcement-backends.md)'s
  own cross-reference note for this ticket, added alongside its existing
  network-enforcement bullet.

## Amendment (AAASM-6164): the identity-bound credential-brokerage contract

AAASM-6164 asked for "a secretless-by-default credential broker for governed runs".
Reading `aa-proxy` and `aa-cli/src/commands/run.rs` as they actually stand today
found the same shape §14's egress amendment found: a broker mechanism already
exists and works. `aa-proxy/src/credentials.rs`'s `CredentialStore` already MitMs a
provider host, strips the agent's own `Authorization`/`x-api-key` header and
appends the operator's real key at egress (AAASM-3578/AAASM-5926) — the source
secret never enters the agent through that path. The actual defect: `aasm run`'s
`inheritable_ambient_env` still copies the operator's whole environment, including
that same provider key, into the child anyway, so the strong mechanism sits right
next to a launch path that undermines it. `governance/capability-manifest.yaml`
capability C2's own `known_bypasses` already named this. This amendment does not
add a fourth credential mechanism. It binds a launch's *requirement* of brokerage
to this run's explicit authority, and makes a launch that would otherwise still
hand the child a name a real brokerage mechanism covers a pre-launch refusal.

### 18. `CapabilityDomain::Credential`, not a new domain

`aa-isolation/src/credential_broker.rs` binds to `CapabilityDomain::Credential`,
which `capability.rs` already carries (ADR 0035 §9's "the authority the child
inherits"). No domain is added, for the same reason §14 gave for egress: adding one
means touching every hand-maintained `CapabilityDomain::ALL` call site across the
workspace, for a property an existing domain already names.

### 19. Witness-gated `CredentialAuthority`/`CredentialWitness`, the same mechanism as §8/§15

`CredentialAuthority::from_gated_spec` is constructible only from an
`ExecutionSpec` plus an `AuthorityWitness` — the identical single-private-field,
no-other-public-constructor pattern §2, §8 and §15 already use. `credential_gate`
itself returns its own `CredentialWitness` under the same rule.

### 20. Two-value requirement axis, three-value achieved axis — not a forbidden third "preferred" value

`BrokeragePosture` has exactly two values (`NotRequired`/`BrokerRequired`), for the
same reason `EgressPosture` does (§ "Two-value posture, deliberately" in
`egress.rs`'s own module documentation): a third, "broker preferred, raw secret
acceptable as a fallback", would *be* the silent raw-credential exposure this
contract exists to forbid, wearing the shape of a middle ground.

`BrokerageMode`, by contrast, is a three-value **achieved** fact, and the three
values are not ranked against each other: `BrokerPerformsRequest` (the source
secret never enters the child — what `aa-proxy` already does), a future
`EphemeralScopedCredential` (a different, run-bound, expiring value reaches the
child instead), and `RawInjectionFallback` (the source secret itself reaches the
child). These are different *mechanisms*, not different qualities of one
mechanism, so `RequiredMode::AnySecretlessMode` is a set-membership floor, not a
comparison on an `Ord`. Adding a third *requirement*-axis value would collapse
back into the same silent-fallback failure the two-value posture already refuses;
keeping the *achieved*-axis three-valued is what lets a contract require "any
secretless mechanism" without pretending the two secretless mechanisms are the
same one.

### 21. Raw fallback: default `Refuse`, admitted only when justified, recorded as `ClaimTerm::Degraded`

`RawFallbackPolicy::default()` is `Refuse` — mirrors `RangePolicy::default()`
(§17's sibling discipline in `egress.rs`): a launch that never states otherwise
cannot silently accept residual exposure. `RawFallbackPolicy::PermittedWhenJustified`
is the only opt-in, and `check_raw_fallback` still refuses an empty justification
under it — "permitted when justified" is not satisfied by an unstated reason.
`residual_exposure_record` files the admitted residual as `EvidenceKind::Installed`
+ `ClaimTerm::Degraded`. `Degraded` is not among `ClaimTerm::asserts_coverage`'s six
terms and ranks lowest in `aa-isolation/src/evidence.rs`'s internal ordering, so
this record can never raise `EnforcementEvidence::claim_for` for
`CapabilityDomain::Credential` — the residual is visible in the report without
ever being misread as coverage.

### 22. Conditional withholding at `aasm run`: the four conditions, and why unconditional removal would break tools rather than secure them

`aa-cli/src/commands/run.rs`'s `effective_child_env` now withholds a brokered
provider credential's env name from the child by default, with **no operator
env-var escape hatch**, when — and only when — all four hold: a dedicated proxy is
bound for this launch, `--no-proxy` was not passed, the host is actually MitM'd
under this launch's `llm_only`/`mitm_hosts` scope, and a provider key is
configured for that exact host (`AA_PROXY_PROVIDER_KEYS`). Withholding
unconditionally — for every credential-shaped name regardless of whether a
mechanism actually covers it — would not be stricter, it would be wrong: a tool
whose own provider key is for a host this launch does not MitM would simply lose
its credential with nothing else providing it, which is a broken launch, not a
secured one. The four-condition test is what keeps withholding tied to an actual
brokerage mechanism rather than to a name pattern. An operator whose tool needs a
key for a non-MitM'd host already has a coherent control: remove that host from
`AA_PROXY_PROVIDER_KEYS`.

### 23. Ceilings stated and reported unsupported, never silently ignored

`CredentialCeilings` states a quantitative use/byte ceiling; no per-run accounting
mechanism for either exists today. `check_ceilings` refuses a launch whose
contract states one against a broker report whose `ceiling_support` is
`SupportLevel::Unsupported` — the identical discipline §17 already established for
egress, applied here.

### What this amendment does not decide

- **Cross-process credential recovery from a supervisor's own `/proc` entry is not
  measured — a stated gap, not a discharged property.** This backend's own
  sibling scenario `another_processs_environ_is_outside_a_scoped_proc_grant`
  already records that a Yama host refuses a descendant reading an ancestor's
  `environ` unconditionally, before any backend is consulted. An attempted
  cross-process arm for this amendment's own negative control — a confined child
  reading its supervisor's `/proc/<pid>/environ` — ran into the identical wall:
  its own mandatory unscoped control (no backend, `/proc` granted whole) failed
  for the same ptrace-direction reason on every real CI runner, so the scenario
  could never attribute the denial to this backend and always declined. It was
  removed rather than shipped declining, per the `isolation-backend-native-linux`
  lane's own "fail on any decline" discipline (a decline there is a broken lane,
  not an honest opt-out). The negative control this amendment's AC actually needs
  — that a brokered credential's source name is absent from the child's own
  environment, descriptors and `/proc/self` — is still measured, by
  `linux_confinement_native.rs`'s sibling scenario, with a paired raw-fallback
  positive control. Whether a confined process can ever recover a credential from
  a *different* process's `/proc` entry on a Yama host remains open and is not
  this backend's property to close.
- **`SecretsService.DispatchTool`'s fate is untouched and stays AAASM-5631's own
  decision.** `proto/secrets.proto`'s `SecretsService.DispatchTool` and
  `aa-api/src/routes/dispatch.rs` remain dead code — both production constructions
  still instantiate a fresh, empty `InMemorySecretsStore` and no route registers
  anything into it. Nothing in `aa-proxy/`, `proto/secrets.proto`,
  `aa-api/src/routes/dispatch.rs`, `aa-gateway/src/secrets.rs` or any
  `aa-storage*` credential store changed for this amendment. "No child-facing
  credential-*request* channel exists" is held structurally, by adding nothing,
  not by asserting it.
- **Mode 2 (`BrokerageMode::EphemeralScopedCredential`) has vocabulary, not a
  mechanism.** No OSS minting path for a run-bound ephemeral credential exists
  anywhere in this repository. `check_required_mode` refuses, rather than
  silently passing, when a contract requires `RequiredMode::RunBoundEphemeralOnly`
  and no reported service offers it — see §20.
- **Per-request/per-connection proxy identity attribution is unchanged.**
  `aa-proxy/src/network_enforce.rs` still evaluates every decision under the
  synthetic `PROXY_AGENT_ID` at Global policy tier, exactly as this document's
  "What this amendment does not decide" for AAASM-6163 already states for egress.
  Authority here is launch-level only: this
  run's own `IdentityRef` and credential lease subject, never a per-request
  identity on the proxy path.
- **No revocation-latency claim.** `RevocationState`'s own existing documentation
  already reserves that ground for the lease system generally; this amendment adds
  nothing to it. "Measurable" here means the gate-level expiry/revocation
  fail-closed path `authority_gate`'s existing `lease.validate_at` already
  provides, plus `aa-proxy`'s own pre-existing `CredentialStore` TTL/rotate unit
  tests, unmodified and still passing.
- **No identity-verification claim.** `IdentityRef` remains *asserted*, not
  *verified* — the same AAASM-5533 residual every other amendment in this document
  already carries forward, unaffected here.
- **No secrets-vault/storage backend.** `aa_core::storage::CredentialStore`/
  `MemoryCredentialStore`/`PgCredentialStore` are untouched — explicitly out of
  this ticket's own acceptance criteria.
- No lease sourcing from the policy schema — already deferred by §4, applied here
  identically to §"No lease sourcing" for egress. Every real launch today
  constructs `CredentialContract::not_required()`, so this amendment ships inert:
  `RUNTIME_REQUIREMENTS_SCHEMA` and `REPORT_SCHEMA` are unbumped (both additive
  fields default empty/`not_required`), and every pre-existing golden-output test
  remains byte-identical except where a real launch's env now omits a brokered
  provider key it previously inherited — see §22's one genuinely user-visible
  behavior change.

## Amendment (AAASM-6171): the typed host-capability broker for native Xcode/Simulator operations

AAASM-6171 asked for "a typed host-capability broker for Xcode, Simulator, signing
and other native host operations". The ticket's own Context paragraph assumed the
macOS VM backend gives a strong host-confinement boundary this broker could punch
narrow holes through. Reading the actual code found that assumption false on four
independent counts: the macOS VM's own guest is **Linux**, not macOS
(`aa-isolation-macos-vm/src/lib.rs` delegates to `aa-isolation-native`/Landlock
inside a Virtualization.framework Linux guest), so `xcodebuild`/`simctl`/`codesign`
could never run inside it regardless of completeness; that backend reports
`Unavailable` on essentially every host today (AAASM-5840 tracks artifact-shipping
separately); there is no guest-initiated request channel at all
(`aa_isolation_vm_proto::Message` carries only host→guest launch variants); and no
OS confinement backend exists on macOS at all (`aa-isolation-native`/
`aa-isolation-sandlock` are both Linux-only; `auto_select` refuses on macOS). The
accepted resolution, settled before implementation rather than during it: ship the
broker as a **supervisor-side mediation boundary with no OS confinement underneath
it on macOS today**, and record that plainly rather than implying a sandbox this
build does not have. See "What this amendment does not decide" below for the full
list of what stays out.

### 24. Composite domain binding — `ProcessCreation` (lease-bearing) plus `FilesystemRead`/`FilesystemWrite`/`Credential` (non-lease-bearing), not a new domain

`aa-isolation/src/host_capability.rs` binds to `CapabilityDomain::ProcessCreation`
as `HostCapabilityAuthority`'s single lease-bearing state — spawning
`xcodebuild`/`simctl` *is* process creation — and separately checks
`FilesystemRead`/`FilesystemWrite`-shaped path scoping and a `Credential`-shaped
signing-identity reference, without introducing a fourth new domain. Same
reasoning as §14/§18: `CapabilityDomain::ALL`'s own test keeps the array in sync
with the enum, but every other reader of `ALL` (~80 call sites across this
workspace, by grep) would need re-auditing for a new variant, and
`execution_receipt::validate`'s own domain-count check would invalidate every
already-stored receipt. A composite binding over existing domains costs neither.

### 25. Witness-gated `HostCapabilityAuthority`/`HostCapabilityWitness`, the same mechanism as §8/§15/§19

`HostCapabilityAuthority::from_gated_spec` is constructible only from an
`ExecutionSpec` plus an `AuthorityWitness` — the identical pattern §8, §15 and §19
already use. `host_capability_gate` returns its own `HostCapabilityWitness` under
the same rule, and `aa-cli`'s `perform()` is the only function in that crate
permitted to spawn a `Command` for a `HostOperation` — it requires that witness as
a parameter to do so, so no call site can reach a real host process without
having passed the gate first.

### 26. The closed `HostOperation` enum plus typed-field validation is the actual privilege boundary — and why an argv array alone does not close argument injection

`HostOperation` is `#[non_exhaustive]` but deliberately carries no `Exec { command:
String }` variant, and none may ever be added — that absence, not a sandbox, is
what keeps this module from becoming a generic host-shell-execution surface. Each
variant's fields are validated newtypes (`SchemeName`, `ConfigurationName`,
`SimulatorUdid`, `SigningIdentityRef`) and a closed `Destination` enum, and
`to_argv` is the one function anywhere in this codebase that turns a
`HostOperation` into a host process argv.

Using `std::process::Command`'s argv array (never `sh -c`) already rules out shell
metacharacter injection. It does **not** rule out *argument* injection, and this
was verified empirically rather than assumed: `xcodebuild -scheme X -destination
'...' -derivedDataPath D SWIFT_ACTIVE_COMPILATION_CONDITIONS=INJECTED build` is a
real, legal `xcodebuild` invocation, and the trailing `KEY=value` element is
honored as a build-setting override — a bare positional argv element, reachable
the moment any validated field's raw value is allowed to contain `=` or start with
`-`. `ArgumentRejected::ContainsEquals`/`LeadingDash` close exactly this vector;
`aa-integration-tests`' positive control
(`positive_control_raw_key_value_argument_would_take_effect_if_not_blocked`)
deliberately bypasses the newtypes to prove the vector is real, rather than only
asserting the newtypes reject it.

### What this amendment does not decide

- **No guest→host IPC channel.** This broker's front door is a new `aasm host` CLI
  subcommand — the same shape as `aasm sandbox`/`aasm proxy` — invoked by the
  operator or by `aasm run`'s own launch pipeline, never a socket a confined child
  calls into. Building an actual guest-initiated request channel would require
  changes to `aa-isolation-vm-proto`'s `Message` enum and the Swift VM helper that
  this ticket does not make; that is separate, much larger, currently-unstarted
  infrastructure (AAASM-5840, AAASM-6170).
- **No new socket, daemon, crate, or dependency.** `aa-isolation`'s existing
  witness-gated-authority pattern and `aa-cli`'s existing subcommand shape are
  reused as-is.
- **No privilege-separated broker process.** There is no setuid/entitlement/XPC
  privilege separation anywhere in this repository relevant to this ticket. The
  broker runs as the caller's own UID — required, since `xcodebuild` needs that
  UID's own Xcode/DerivedData access — and "least host privilege practical" is
  satisfied by `env_clear()` plus a fixed three-variable environment
  (`PATH`/`HOME`/`DEVELOPER_DIR`), a null stdin, an argv from `to_argv` only, and
  no shell invocation ever. This is a mediation boundary, not a privilege drop —
  claiming otherwise would overstate what this build does, in the same way
  AAASM-5528 already named as an incident class for this repository's public copy.
- **No `codesign` invoker.** `HostOperation::Codesign` and `CodesignRequest` exist
  as vocabulary — `check_invoker_exists` always refuses this kind via
  `NoInvokerForOperation`. Automating `security unlock-keychain` to make a real
  invoker work would put a keychain secret on the agent's own path, which this
  repository's secret-handling policy forbids; the vocabulary exists so a future,
  deliberately-designed invoker has a typed request to extend rather than a new
  one to invent. Mirrors §"Mode 2 has vocabulary, not a mechanism" in the AAASM-6164
  amendment above.
- **No claim that a macOS OS-confinement backend exists.** `aa-isolation-native`/
  `aa-isolation-sandlock` remain Linux-only; `auto_select` still refuses on macOS.
  This is the real, current state of this repository — this ticket does not
  introduce that gap and does not claim to close it.
- **No `simctl boot`/`install`/`launch`.** A real simulator boot is minutes of wall
  clock; only `SimulatorList` (device discovery) ships with a real invoker.
- **TOCTOU symlink races are not closed.** `scoped_path` canonicalizes and checks
  at call time only; a symlink swapped between that check and the actual host
  invocation is not prevented — macOS has no `openat2(RESOLVE_BENEATH)`
  equivalent, and `xcodebuild` reopens paths itself after the check returns.
- **The `--lease-file` format is not cryptographically bound.** `aasm host`'s
  minimal hand-parsed JSON lease projection carries no seal or signature — the
  same residual class AAASM-6166's execution-receipt seal already documents for
  its own content digest (tamper-since-write detection, not proof of origin).
- **No OS confinement boundary exists on macOS today, full stop.** This broker is
  the *only* mediation standing between a governed launch and a real `xcodebuild`
  invocation on this platform. A determined unconfined agent can invoke
  `xcodebuild`/`simctl` directly, entirely outside this broker, on every macOS host
  this repository runs on today — see `governance/capability-manifest.yaml`'s
  `known_bypasses` entry for this capability, which states this in exactly these
  terms rather than as an implied assumption.

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
