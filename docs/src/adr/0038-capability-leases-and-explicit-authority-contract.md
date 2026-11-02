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

---

## Amendment (AAASM-6187): cross-process `/proc` credential recovery closes as structurally unmeasurable, not as a fix

**Scope of this amendment: it closes the open item the AAASM-6164 amendment's "What
this amendment does not decide" list left open — "whether a confined process can ever
recover a credential from a different process's `/proc` entry on a Yama host remains
open." It records a conclusion for that question. It decides nothing else, reverses
no prior decision, and does not touch ADR 0035.**

### What was tried, and why it was removed rather than shipped declining

A cross-process companion to `another_processs_environ_is_outside_a_scoped_proc_grant`
(`aa-isolation-native/tests/adversarial_boundary_native_linux.rs`) was attempted for
this ticket: the confined child reading its own supervisor's
`/proc/<supervisor-pid>/environ`, the reverse of the direction that scenario already
measures (parent reading child). Its own mandatory unscoped control — launched with
`/proc` granted whole and **no backend confinement installed at all** — failed to read
the target `environ` identically on every real CI runner this was tried against. A
scenario whose zero-confinement control cannot demonstrate the read succeeding cannot
attribute the control's own failure to this backend, so it was removed rather than
shipped `#[ignore]`d or declining — the latter would trip the
`isolation-backend-native-linux` lane's "fail on any decline" gate, which treats a
decline as a broken lane, not an honest opt-out.

### The mechanism, verified against the current kernel source rather than assumed

Before concluding anything, the actual kernel path was read, not inferred from this
ticket's own prior framing. `/proc/<pid>/environ` is opened by `environ_open()`
(`fs/proc/base.c`) via `__mem_open(inode, file, PTRACE_MODE_READ)`, which reaches
`mm_access(task, mode | PTRACE_MODE_FSCREDS)`. The actual permission decision is
`__ptrace_may_access()` (`kernel/ptrace.c`): a same-thread-group early-out, then a
same-credential check (caller's fsuid/fsgid against the target's full uid/gid triple,
or `CAP_SYS_PTRACE`), then `task_still_dumpable()`, and finally
`security_ptrace_access_check()` — the active LSM stack's hook, called for **every**
mode, READ included.

This matters because it is **not** what this ticket's own framing, or the existing
`another_processs_environ_is_outside_a_scoped_proc_grant` scenario's doc comment,
says: Yama's own hook (`yama_ptrace_access_check`, `security/yama/yama_lsm.c`) opens
with `if (mode & PTRACE_MODE_ATTACH) { ... }` — its descendant-only `ptrace_scope`
switch (the "a descendant may ptrace an ancestor, not the reverse" rule) **only
executes for `PTRACE_MODE_ATTACH`**. `PTRACE_MODE_READ` (`0x01`) and
`PTRACE_MODE_ATTACH` (`0x02`) are distinct bits (`include/linux/ptrace.h`), and
`environ_open` passes `READ`, never `ATTACH`. For this one specific access, Yama's
scope switch does not run at all, and Yama's hook returns `0` regardless of the
host's `ptrace_scope` value. So "Yama's `ptrace_scope` refuses a descendant reading an
ancestor's `environ` unconditionally" overstates what is true of Yama's own code for
this access — the real gate for `environ` (and for `auxv`/`stack`/`wchan`, which use
the identical `PTRACE_MODE_READ_FSCREDS` path) is the generic, **credential-and-
dumpability** check in `__ptrace_may_access()`, plus whatever the host's full LSM
stack's `security_ptrace_access_check()` hook additionally decides — not an
ancestry-direction rule. (`/proc/<pid>/mem`, by contrast, genuinely does pass
`PTRACE_MODE_ATTACH` and so genuinely is subject to Yama's descendant-only switch;
`environ` is not in that set.)

This leaves the CI-observed failure real but its exact cause host-specific and not
externally attributable: the runners this was tried against report
`lockdown,capability,landlock,yama,apparmor,ima,evm` active simultaneously, and
`__ptrace_may_access()` offers several non-ancestry predicates — uid/gid mismatch,
`task_still_dumpable()`, or any one LSM's own `security_ptrace_access_check()` — any
of which could be the one returning `-EPERM` on a given host. Which predicate fired is
not decidable from outside the kernel without instrumenting the specific runner, and
the ticket's "unmeasurable" conclusion does not require deciding it: **every one of
those predicates sits in the generic ptrace-access path, reached before any
Landlock/seccomp rule this (or any) `IsolationBackend` installs is even consulted.**
That is the fact the mandatory unscoped control exists to establish, and it held on
every runner tried, regardless of which predicate inside that path was responsible.

### No alternate measurement technique avoids the same gate

Every `/proc/<pid>/X` entry that can carry live memory content — `environ`, `mem`,
`maps`/`smaps`, `auxv`, `stack`, `wchan` — is reached through `mm_access()`/
`__ptrace_may_access()`, the identical gate `environ` sits behind (whether the
specific entry additionally trips Yama's `ATTACH`-only switch or not, as above). The
entries that are *not* gated this way — `cmdline`, `stat`, `status`, `comm`, the
`cwd`/`exe` symlink targets — are exactly the ones this Epic's existing scenarios
(`another_processes_proc_entry_is_unreadable_without_a_proc_grant`'s `cmdline` probe)
already use successfully, and none of them carries an environment value or other
live memory content. `cmdline` is already named and rejected for this reason in this
ticket's own problem statement; the rest are weaker still. Core dumps, shared memory,
and inherited file descriptors were also considered: each requires the supervisor to
have deliberately placed the secret somewhere the child's grant reaches, or a
misconfigured, unrelated subsystem (`core_pattern`) to leak it — a different attack
surface than "`/proc` credential recovery," and not a `ptrace`-free route to the same
measurement.

### Resolution: won't fix / structurally unmeasurable, not closed by kernel design

The confined-child-reads-supervisor-`environ` direction is **not shipped as a test**,
in any form — not `#[ignore]`d, not declining. This amendment is the documented
conclusion in place of that test: on every CI runner tried, the generic
ptrace-access path refuses this read before this backend's own Landlock/seccomp rules
are reached, so no denial can be credited to, or demanded of, this backend or any
future `IsolationBackend` implementor. No credential is exposed via this path today —
something in the host's existing ptrace-access stack already closes it, independent of
any AASM backend. This is **not** a claim that the direction is closed by kernel
design the way the `mem`/`ATTACH` case is: `environ`'s gate is credential-and-
dumpability-based, not ancestry-based, so a same-uid, dumpable supervisor is not
excluded by Yama's own logic, and a host whose full LSM stack and process credentials
differ from the runners tested here could plausibly behave differently. The
conclusion is "not measurable on the class of host this Epic's CI and target
deployments run today," not "provably impossible on every host" — a future
measurement attempt remains legitimate if a different host's observed behavior, or a
backend that doesn't rely on this kernel path for its own evidence, changes the
premise.

### Consequence for existing text

The AAASM-6164 amendment's "What this amendment does not decide" bullet on this topic
is now closed by this amendment rather than left open; its own wording stands
unchanged as the historical record of what was attempted. This amendment also narrows
no claim about `/proc/<pid>/mem` (still genuinely `ATTACH`-gated and ancestry-direction
restricted by Yama) — only about `environ` and the `PTRACE_MODE_READ`-class entries.
No other recorded text in this ADR, or in ADR 0035, changes.

---

## Amendment (AAASM-6272): production sourcing for leases, egress and ancestry, and three defects it surfaces

**Scope of this amendment: it replaces the "No new policy DSL... deferred rather
than ruled out" bullet in "What this ADR does not decide" above, and the "No lease
sourcing from the policy schema... this amendment ships inert" bullets repeated in
the AAASM-6163 and AAASM-6164 amendments' own "What this amendment does not decide"
lists, with the real policy-sourced design below — and it records four fixes the
design work found necessary — one a deliberate,
owner-approved narrowing of this ADR's own §3 compatibility promise (D4), three
ordinary defect fixes (D-b, D1, D2) the sourcing work forced into the light because
it needed to reason about ancestry and lease identity for the first time against a
real launch. Parent Epic AAASM-6159, Story AAASM-6272. Status of this ADR and of
ADR 0035 stays `Proposed` — see "Sequencing: promotion, not yet" below.**

### Why "ships inert" was true, and what changes

Every prior amendment to this ADR that touches lease sourcing — the top-level "No
new policy DSL" bullet, and the "No lease sourcing from the policy schema" bullet
repeated verbatim in the AAASM-6163 and AAASM-6164 amendments' own "What this
amendment does not decide" lists — says the same true thing: a real
`aasm run` constructs `IsolationPlan` with `leases: Vec::new()`, `Ancestry::Root`
unconditionally, and `EgressContract::not_required()`, at all 7 call sites in
`aa-cli/src/commands/run.rs`. `authority_gate`, the per-domain `ScopeOrder`
comparators, `Ancestry`/`ParentAuthority`, and the egress-contract types are all real
and exercised by this crate's own tests — but nothing an operator does can reach any
of them, because nothing sources a lease, a resolved ancestry, or an egress
requirement from policy for a real launch. AAASM-6272 adds that sourcing path:

1. **`authority.leases`**, a new policy node across `aa-policy`'s raw/document/
   canonical/validator layers and `schemas/policy/v1`, lets a policy author declare
   capability leases for a run.
2. **A new `aa-isolation` module** — deliberately **not** folded into `lower_policy`
   — lowers the canonical node into `Vec<CapabilityLease>`. `lower_policy`'s own
   documentation states it is deterministic/pure over restriction nodes only; a
   lease carries a lifetime and an issuer (`LeaseBasis`), neither of which is a
   restriction-node concept, so giving it its own lowering path keeps `lower_policy`'s
   existing purity contract intact rather than widening it to a case it was never
   designed for.
3. **The 7 `IsolationPlan` call sites in `run.rs` collapse onto one resolved
   authority sub-struct**, populated from that lowering and from ancestry
   resolution, mirroring the existing `resource_requirements` pattern already used
   in the same function for an analogous resolved sub-struct.
4. **An egress-contract policy node** lowers to `EgressContract::broker_required()`,
   replacing the hardcoded `EgressContract::not_required()` the AAASM-6163 amendment's
   own "ships inert" bullet already named. This node is sequenced to land **after**
   PR #2592 (AAASM-6261, open at the time of this amendment) merges, since that PR
   changes `check_name_resolution_grant`'s signature in `aa-isolation/src/egress.rs`
   — authoring against the pre-#2592 signature would need rework once it merges.

None of this changes `authority_gate`'s, `negotiate`'s, or the egress/credential
gates' own logic — it is exactly the sourcing path the bullets named above already
said was deferred, now built.

### D4: closing the compatibility-residual escape hatch under a resolved parent — an owner-approved narrowing of §3

§3 above states the rc.7 compatibility rule precisely: a spec with no lease at all is
read, spec-wide, under the pre-lease contract (`AuthorityState::CompatibilityResidual`,
which `authority_gate`'s `covered()` treats as granted). That rule was written, and is
still correct, for a **root** launch with no ancestry claim. Building AAASM-6272's
sourcing path exposed a case §3 did not anticipate: `attenuation_applies` —
```rust
fn attenuation_applies(spec: &ExecutionSpec, _ancestry: &Ancestry) -> bool {
    !spec.identity().lineage.is_empty() && EffectiveAuthority::is_lease_aware(spec)
}
```
— requires **both** non-empty lineage **and** `is_lease_aware(spec)` before any
ancestry check runs at all. A child launch with a genuinely resolved
`Ancestry::Parent` but **zero leases of its own** fails the second conjunct, so
`attenuation_applies` returns `false` **without ever inspecting `ancestry`**, and the
child is read under the same spec-wide compatibility residual a root launch gets —
granted in full, with no reference to the parent's ceiling whatsoever. A lease-aware
parent's attenuation is trivially shed by a child that simply declines to carry any
lease itself, while still claiming to be that parent's descendant via non-empty
lineage.

This was escalated to the product owner as decision D4, because closing it is a
**narrowing of this ADR's own §3 promise**, not a bug fix under the rule as written:
**decision — close it.** A child launch under a *resolved* `Ancestry::Parent` is now
required to be lease-aware itself. Zero leases under a resolved parent refuses, via a
new, additive `AuthorityRefusal` variant (non-breaking: the enum is `#[non_exhaustive]`)
— it does not fall through to `CompatibilityResidual`. The compatibility rule in §3 is
otherwise unchanged: it still applies in full to a root launch, or to a launch whose
ancestry could not be resolved at all (`Ancestry::UnresolvedParent`, already refused
on a different ground — `AuthorityRefusal::AncestryUnresolved`).

**Effect on the two tests §3 names.** Both `adding_any_lease_switches_the_whole_spec_
out_of_the_legacy_path` and `legacy_spec_with_no_leases_passes_on_policy_grants_alone`
call `authority_gate` under `Ancestry::Root` in every assertion they make today.
`adding_any_lease_switches_the_whole_spec_out_of_the_legacy_path` is **structurally
unaffected** by this narrowing — it is, and remains, a statement about root/no-parent
launches only, and D4 has nothing to say about that case.
`legacy_spec_with_no_leases_passes_on_policy_grants_alone` **remains true exactly as
written** — it is still a correct statement about the root case — but it is now
incomplete as the sole regression pin for the compatibility residual: it never
exercised a resolved parent, so it could not have caught this escape hatch in the
first place. This amendment's implementation adds a **new companion test** asserting
the opposite outcome — refusal — for the identical zero-lease spec under a resolved
`Ancestry::Parent`, which is the test that actually pins D4's closure.

**D1, the same function, a distinct defect.** `attenuation_applies`'s second
parameter is named `_ancestry` and the body never reads it — this is independent of
D4's `is_lease_aware` conjunct, and is the mechanism that makes D4 reachable in the
first place: because `ancestry` is never consulted, a resolved `Ancestry::Parent` and
an unresolved claim are indistinguishable to this predicate, and the only reason
`authority_gate`'s separate match on `ancestry` still fails closed for an unresolved
parent today is that it happens to run its own ancestry match *after*
`attenuation_applies` already decided, using only `lineage`/`is_lease_aware`. D1
(AAASM-6280) and D4 (AAASM-6282) are tracked as two Jira bug subtasks under
AAASM-6272 because they are two distinct, independently testable claims, but both
fixes land at this one call site, and fixing D1 (make `attenuation_applies` actually
read `ancestry`) is what gives D4's fix somewhere to hook its new refusal.

### D2 (AAASM-6281): parent lease validity is unchecked on the ancestry path

`check_attenuation` (the function `authority_gate` calls once a resolved parent
applies) compares a child lease's scope, expiry and limits against its parent's, and
was described as catching a parent revoked *after* the child's derivation via
`DelegationProvenance::parent_generation`; that description was wrong, see the
AAASM-6307 amendment below — the generation is compared against the generation of
the `ParentAuthority` snapshot's own lease value, never against the live ledger. It never calls `parent_lease.validate_at
(now)` — so a parent lease that has since expired, or whose `not_before` the current
`now` has not yet reached, passes silently as long as the child's own fields and
recorded generation stay consistent. `authority_gate`'s main loop already validates
the **child's** own lease at `now` for the ordinary `AuthorityState::Leased` case;
this amendment extends the identical validity check to the **parent's** lease on the
ancestry path, so a child cannot continue deriving authority from a parent whose own
lease has simply lapsed.

### D-b (AAASM-6279): a lease's subject is never checked against the launch's actual identity

Separately from the ancestry path, `aasm host --lease-file` (`aa-cli/src/commands/
host.rs`) builds its `ExecutionSpec` with a fixed `identity = IdentityRef::root
("aasm-host-operator")` and loads a lease whose `subject_agent_id` comes from the
lease file — but nothing compares the two. Neither `authority_gate`'s `covered()`
nor anything else in `aa-isolation` checks a lease's own subject against the spec it
is attached to. A lease issued for one subject is therefore usable to authorize a
launch under a different claimed identity, reachable today via `aasm host
--lease-file`. This amendment fixes that at the gate: a lease whose subject does not
match the spec's own identity is refused.

### D-a: `covered()`'s scope check diverges from the egress/name-resolution checks, and why

`authority_gate`'s internal `covered()` helper and `check_egress_grant`/
`check_name_resolution_grant` (`aa-isolation/src/egress.rs`) today all call the same
comparator — `CapabilityLease::covers`, whose own doc comment states it is
"deliberately coarse": `Whole` covers only `Whole`, and a `Selectors` list covers
another only when every requested selector is present **verbatim**. That is correct
and unchanged for `check_egress_grant`/`check_name_resolution_grant`, which this
amendment leaves exactly as they are — AAASM-6261/#2592's own stated security
rationale for egress and name-resolution grants is that a narrower-but-not-identical
match is a different, riskier question than "does this lease's exact scope cover
this exact requirement," and that strictness is deliberate there, not an oversight to
fix.

`authority_gate`'s own `covered()` is a different question: once a policy-sourced
lease is lowered from an authored node (rather than hand-built verbatim to match a
requirement, as every existing fixture does), a lease that is legitimately broader —
`whole: true`, or a selector set that contains a narrower lowered requirement without
being identical to it — should still be able to cover that requirement. §7's real
per-domain `ScopeOrder` comparators already answer exactly this "is X narrower than or
equal to Y" question for `check_attenuation`'s parent/child comparison; `covered()`
reuses the same comparator rather than inventing a second one. Concretely, `covered()`
changes from

```rust
AuthorityState::Leased(lease) => {
    if lease.covers(scope) { Ok(()) } else { Err(..LeaseScopeInsufficient..) }
}
```

to accepting the **union** of the existing strict check and the `ScopeOrder`-based
one — `lease.covers(scope) || matches!(scope_order::order_for(domain).compare(lease.
scope(), scope), ScopeOrdering::Narrower | ScopeOrdering::Equal)` — rather than a
straight replacement. A straight replacement would regress today's passing case:
`ProcessCreation`, `Ipc` and `WorkspaceTransaction` get `UndefinedScopeOrder` (§7),
whose `compare` returns `Incomparable` **unconditionally**, including for `Whole`
vs. `Whole` — exactly the shape `aasm host --lease-file` uses today via
`HostCapabilityContract`. Swapping `covers()` out entirely would make that currently-
working, verbatim-matching case refuse. The union preserves every case `covers()`
already accepts and additionally accepts a narrower-or-equal match on a domain with a
real comparator — so `covered()` and the egress/name-resolution checks are allowed to
diverge: they are answering different questions (a lease's scope *strictly matching*
a requirement, versus a lease's scope *containing* one), not the same question
answered inconsistently.

### Sequencing: promotion, not yet

This amendment's design — together with ADR 0035, which this amendment does not
otherwise edit — is accepted by the product owner to be **promoted to `Accepted`
together**, as a pair, once ready. "Ready" is not "this amendment is written": per
this Epic's own standing review discipline (see the AAASM-6160/6161/6163/6164/6171
amendments above, each of which earned its place by reading the merged code rather
than the design sketch), both ADRs stay `Proposed` until AAASM-6272's implementation
lands and demonstrates `authority_gate`/`egress_gate` genuinely refusing a real
authored workload — not merely passing this crate's own test fixtures. AAASM-6272's
own `Verify ...` subtask records that demonstration; the Jira tracking note for the
joint promotion lives on that Story rather than being restated here as a second
source of truth.

### What this amendment does not decide

- **No change to `authority_gate`'s, `negotiate`'s, or `egress_gate`'s own control-
  flow** beyond the four fixes (D4, D1, D2, D-a) and the sourcing path described
  above — no new gate, no new ordering between `authority_gate` and `negotiate`.
- **No crypto identity binding.** `IdentityRef` stays asserted-only; D-b fixes a
  *consistency* check (does the lease's claimed subject match the spec's claimed
  identity), not an *authentication* one — AAASM-5533 still owns verification.
- **No change to `aa-isolation/src/descendant.rs`** — unaffected by any fix here, for
  the same reason the AAASM-6161 amendment above gave for leaving it alone.
- **No cross-process parent-authority handoff.** `ParentAuthority::from_gated_spec`
  remains constructible only in-process, from a spec and a witness minted by the same
  process's `authority_gate` call. A real multi-process sub-agent tree's attenuation
  guarantee therefore stays partial after this amendment — tracked separately as its
  own Jira Story (AAASM-6273) rather than folded into this amendment's scope, because
  every route considered (serializing `ParentAuthority` directly; a
  `--parent-authority-file` flag analogous to `aasm host --lease-file`) reopens the
  exact forgery hole witness-gating exists to close, and the one architecturally
  correct route — re-deriving from the execution receipt — needs a `LeaseBinding`
  schema bump (`aa-cli/src/commands/execution_receipt/schema.rs` records only
  `lease_id`, a digest, `domain`, `derived_from_lease_id` and `inheritance_mode` — no
  scope, expiry, or subject) that this ADR's own §6 — whose cross-reference note
  explicitly scopes a receipt's `LeaseBinding` to "a lease's id and a digest of its
  redaction-safe projection, never the lease's basis reason or its scope selectors"
  — and ADR 0035's AAASM-6166 amendment (the receipt schema itself) deliberately
  avoided taking on here. §13 is the same additive-only discipline applied to
  `DomainAuthoritySummary`/`REPORT_SCHEMA`, not to the receipt — cited here only as
  the sibling precedent for "additive, not a schema bump," not as a second source
  that scoped the receipt.
- **No ADR status change.** See "Sequencing: promotion, not yet" above.

## Amendment (AAASM-6307): revocation is transitive, and the gate reads the live ledger

### Why

Three statements in this ADR and the code it describes were false, found by the
AAASM-6290 independent QA pass. (1) §11 and D2 say a revocation recorded after a child's
derivation is caught through `DelegationProvenance::parent_generation`. It was not:
`authority_gate`/`check_attenuation` never read the `DelegationLedger`; the generation
was compared with the generation of the lease value captured in the `ParentAuthority`
snapshot, so gating a child against a *held* root ancestry after `ledger.revoke(root)`
passed — one hop, not only the transitive case. (2) The ledger tracked state per lease id
with no link between a child and its parent, so `derive_child` read only the immediate
parent and a fresh grandchild could be minted under a revoked root. (3) The
"Documented, pinned gap" comment in `check_attenuation` described a ledger comparison
that did not exist. Severity High; production does not yet build an `Ancestry::Parent`
(`resolve_ancestry` returns only `Root` or `UnresolvedParent`), so the exposure was
latent and becomes live with AAASM-6273 (cross-process parent-authority handoff), which
this change must precede.

### §8 (amended): `ParentAuthority` carries the live ledger

`ParentAuthority::from_gated_spec(spec, witness, ledger: Arc<DelegationLedger>)`. The
witness still proves the spec was gated; the ledger is the live source of revocation
state the snapshot cannot be. A `ParentAuthority` whose lease the ledger does not know
makes every child gated against it fail closed rather than pass. No serialized format
changes, and no production caller changes (production passes only `Ancestry::Root`).

### §11 (amended): parent edges, a transitive check, and the new refusals

- **Edges.** Each ledger entry is `{state, link, content}` (content added by AAASM-6312) with `link` one of `Root`,
  `Parent(LeaseId)` or `Unlinked`. `derive_child` inserts the child with a `Parent`
  edge under the ledger lock. `revoke` changes state only and keeps the edge; revoking
  an id the ledger does not know inserts it as `Unlinked`.
- **No resurrection, no severing.** `derive_child` refuses a child id the ledger already
  knows (`DuplicateLeaseId`). `register_parent` (now `Result`) accepts only a lease with
  no delegation provenance; a mid-chain lease is refused (`AncestryUnverifiable`),
  because registering it as a root would cut its link to the ancestors above it.
  Registering a known id is `DuplicateLeaseId`. Since AAASM-6312 `derive_child` no
  longer auto-registers an unknown parent (that let any caller seed its own chain with a
  forged lease); an unknown parent is `AncestryUnverifiable`, and roots enter only
  through `register_parent`. A ledger built with `with_trusted_issuer` accepts a root
  only when the lease's own claimed issuer matches (`UntrustedIssuer`); `new()` is
  unrestricted and is for in-process/test use.
- **Derive time.** `derive_child` walks the parent's whole chain and returns
  `ParentRevoked` ("the parent or any ancestor") if any hop is revoked and
  `AncestryUnverifiable` if a hop is unknown or unlinked. The walk is bounded by the
  size of the map.
- **Gate time.** In `check_attenuation`, after the snapshot `validate_at` and before the
  violation/escalation branch (so an independently-approved escalation cannot launder a
  revoked chain), when the parent holds a lease for the domain that lease and every hop
  above it must be known, linked and active in the ledger: `RevokedInLedger { domain,
  lease, reason }` for a revoked hop, `LedgerUnverifiable { domain, lease }` for an
  unknown or unlinked one. A child lease the ledger knows to be revoked is refused with
  `RevokedInLedger`; a child lease the ledger has never seen is not refused for that
  reason alone.
- `DelegationDenied` and `AuthorityRefusal` stay `#[non_exhaustive]`; the new variants
  are additive.

### D2 and `StaleParentGeneration`, corrected

D2's `validate_at` check is a snapshot check and sees only a revocation already present
in the lease value. A revocation recorded in the ledger after the snapshot is caught by
the chain check above. `StaleParentGeneration` remains a comparison against the
*snapshot's* generation and is reachable only for a reaffirmed-but-still-`Active` parent.

### What this amendment claims, and does not

- The chain is observed under the ledger lock at gate time. A revocation recorded a
  moment later is not seen by a gate call already past that point, and this ADR still
  makes no revocation-latency claim.
- Since AAASM-6312 the ledger records each lease's content (every field except the
  mutable revocation state) and the gate refuses a parent or tracked child whose content
  differs from the record (`LedgerContentMismatch`, `DelegationDenied::ContentMismatch`),
  so a wider snapshot reusing a tracked id no longer passes. This binds content to the
  ledger's record; it does not authenticate the issuer, which is asserted-only
  (AAASM-5533), and the ledger is still chosen by the caller of `from_gated_spec`.
- The ledger is chosen by the caller of `from_gated_spec`. Nothing ties a lease to the
  ledger that issued it: a provenance-free lease can be registered as a root in any
  ledger, which would not see a revocation recorded in another. `LedgerUnverifiable`
  therefore means "this ledger has no record", not "this is the issuing ledger".
  Across processes the supervisor registry is the authoritative ledger (§27–§29.4);
  AAASM-6273 owns its design.
- Cross-process handoff (AAASM-6273) is unchanged and still open.

## Amendment (AAASM-6347/6348/6349): `credentials: posture` — authoring the credential-brokerage requirement

The AAASM-6164 amendment built `credential_gate` but left no way to ask for it:
`aasm run` constructed `CredentialContract::not_required()` for every launch. J84
(golden journey, AAASM-6262) therefore had a brokerage mechanism no operator could
require. This amendment adds the authoring surface and the one enforcement point
that reads it.

### 22. A two-value `credentials:` policy node

`credentials: { posture: not_required | broker_required }` (`aa-policy`, AAASM-6347)
lowers to `CredentialContract::not_required()` or `CredentialContract::broker_required()`
(`credential_contract_for` in `aa-cli/src/commands/run.rs`). Only the posture is
authorable. The required mode, raw-fallback policy and ceilings stay at the weakest
contract `broker_required()` builds (`AnySecretlessMode`, raw fallback refused, no
ceilings); a stronger contract needs a schema change, not a reinterpretation. The node
counts as an enforcement section, so a `credentials:`-only document loads, while a
document with nothing but `posture: not_required` is still "no enforcement section".

### 23. `--isolation none` runs the credential gates, and says it is not a boundary

Credential brokerage is a statement about which secrets reach the child, not about
confinement, so `--isolation none` no longer drops it. When the policy states
`broker_required`, the none arm runs `authority_gate` and then `credential_gate`
(`unconfined_credential_refusal`) and refuses the launch if either refuses. The
refusal text names `credentials: posture: broker_required` and the gate's reason.
The backend arm runs the same two gates before it consults a backend. The none arm
establishes no boundary and claims none.

`credential_gate` admits only when all four facts hold:

1. the broker is available and does not fail open;
2. at least one upstream service is brokered (`no upstream service is covered by any
   credential brokerage` otherwise);
3. an explicit `authority.leases` entry for domain `credential` covers the launch
   (`no explicit grant authorizes credential brokerage for this run` otherwise), and
   that lease is valid at launch time and was issued to this launch's identity;
4. every brokered env name is withheld from the child's environment.

### 24. Egress authority is never credential authority

A brokered-egress posture (`egress: broker_required`) or an egress lease does not
supply fact 3. `credential_contract_for` reads only the credentials node, and the
none-arm spec carries no `Credential` requirement, so the no-lease state is `Denied`
rather than `CompatibilityResidual`. That second property is an invariant of the
none-arm spec, documented on `unconfined_credential_refusal`; a spec that gained a
`Credential` requirement without a lease would read as the compatibility residual and
`check_credential_grant` would admit it.

### What this amendment claims, and does not

- **Verified live** (AAASM-6349, macOS, real `aasm run`, default `--isolation none`):
  with `broker_required` and no credential lease, or a lease but no brokered service,
  the launch is refused and the child never starts; with a lease and a brokered
  service the launch is admitted and a synthetic sentinel in the ambient provider-key
  variable is absent from the child's env, argv and open descriptors and from every
  state, receipt and log file the run wrote. A `not_required` control shows the same
  sentinel does reach the child, so the absence is not an artifact of the detector.
- **Not verified live**: an isolated backend. None is usable on the macOS host used
  for that evidence; the backend-arm gates are covered by unit tests only.
- **Residual, not solved**: the withholding is by env *name* the broker covers. An
  ambient credential under any other name still reaches an unconfined child, and the
  gate does not look at values. The `aasm` supervisor's own exec-time environment
  still holds the operator's real key, and a same-uid descendant can read it (`ps
  -Eww -p <supervisor pid>` on macOS, `/proc/<pid>/environ` on Linux). Nothing here
  makes the secret unreadable by a same-uid process, and no plaintext-secret
  isolation is claimed.
- **Timing**: the none-arm refusal happens at bind time, after registration and the
  launch audit record. A refused run leaves a registered identity and a launch record;
  only the child is never started.
- J84 stays `partial`: the live evidence is macOS-only, the isolated-backend arm has
  none, and the `ps -E` channel is open.

## Amendment (AAASM-6273): cross-process parent-authority handoff — direction decided, implementation gated

AAASM-6273 was recorded above as the one place a real multi-process sub-agent tree's
attenuation guarantee stays partial. This amendment records the owner decision on its
direction and the acceptance contract any implementation must meet. It changes no code
and enables nothing: the cross-process handoff is **not implemented, and must be
neither built nor enabled in any environment until the B3 evidence gate below
passes.** What may land before the gate is limited to: this documentation; and the
gate's own evidence harness (§30), which runs against a stand-in fixture directory
(never the production registry), is never shipped as handoff code and is not reachable
behind a flag. Everything else waits for the implementation Story, which starts only
after the gate passes: the supervisor registry, the §28 refusal on real launches (its
registry path is a configured input; enabling it can refuse launches whose write scope
is an ancestor of that path, for example a home or working directory, and that
compatibility effect is assessed in the Story), and the §29.2–§29.4 tests, which
exercise handoff code. Before the gate the harness exercises kernel-level denial (§30.3)
against the stand-in directory only; the §29.1 refusal cases, including the
remove-the-check falsification, need the admission check and run in the Story.

### 27. Supervisor-mediated authority; no serialized or caller-supplied parent authority

A parent's authority stays inside the supervisor that launched the child. A child
process presents no authority material of its own: its place in the ancestry is
established by the supervisor that launched it, never by a value the child (or its
caller) hands over. Consequently:

- `ParentAuthority` is **not serialized** across a process boundary, in any form. The
  witness-gating of §2, §8 and §15 exists to make a `ParentAuthority` unforgeable; any
  encoding a second process can construct reopens that hole.
- There is **no caller-controlled parent-authority file or flag** (the
  `--parent-authority-file` shape already rejected in the AAASM-6272 amendment).
- A receipt-derived re-derivation of the parent in the child is excluded for the same
  reason: it is an artifact a second process can construct. Revisiting this requires a
  new amendment to this ADR.

### 28. Universal requirement: a confined launch must not hold write authority over the supervisor registry

Whatever the supervisor records about the processes it launched is only as trustworthy
as the exclusivity of its writer. Therefore **every confined AASM launch must be
refused if it would give the child effective write authority over the supervisor
registry directory or over any ancestor of that directory.** The rule is universal over
confined launches: it is not conditional on whether the launch participates in a
handoff, on the policy domain, or on which isolation backend is in use.

- *Effective write authority* means any route by which the child could create, modify,
  rename, replace or unlink an entry in that directory, or rename, replace or unlink
  the directory or any ancestor itself (which lets it substitute a path component), or
  write a registry file or socket inside it, or hard-link a registry entry into a
  location it can write. It is computed from all of: the launch's filesystem-write
  scopes; inherited descriptors, including `O_PATH` and directory descriptors used with
  `*at` calls; mount, root and alias resolution (symlinks, `..`, bind mounts, a
  different mount namespace or `chroot`, `/proc/self/fd`, `/proc/<pid>/root`); and
  discretionary access (the child's uid and gid, group-write bits, ACLs, and whether the
  child owns, or can chmod or chown, the registry directory or any ancestor of it) —
  and from same-uid control of whoever writes the registry: `ptrace`,
  `process_vm_writev`, `/proc/<pid>/mem` or `pidfd_getfd` against the supervisor or
  any registry-capable process, and a descriptor obtained after launch (passed over
  `SCM_RIGHTS` or taken with `pidfd_getfd`) as well as an inherited one. Where the
  child shares a uid with the supervisor, the launch must also separate them (a
  distinct uid, or a PID namespace with the routes denied) or establish that those
  routes are denied by mechanisms the kernel actually provides: Yama
  `ptrace_scope` of at least 1 (a host-wide sysctl the launch cannot set, which
  `CAP_SYS_PTRACE` bypasses, so the admission check verifies both), or a child Landlock
  domain that is more restricted than the supervisor's, which Landlock's own ptrace rule
  uses to refuse the child's attach. Landlock's `LANDLOCK_SCOPE_*` flags (abstract unix
  sockets, signals) do not cover these routes. Otherwise the launch is refused.
  The computation is only the admission check. The control for filesystem write routes is the
  kernel-enforced Landlock domain, which is checked when a path is opened. It does not
  mediate metadata changes (`chmod`, `chown`, `setxattr`, ACL changes, `utimes`), so
  those are denied by a distinct uid, by DAC ownership, or by admission refusal, and
  are tested that way, not as Landlock denials; it does not
  revoke a writable descriptor the child already holds, so descriptors are handled by
  hygiene (every descriptor except stdio is closed or close-on-exec at launch, and no
  registry-capable process sends descriptors to the child) together with the ptrace and
  `pidfd_getfd` denial above. A confined launch on a backend with no equivalent
  kernel-enforced control is refused under the fail-closed rule below. Once a registry
  is configured that refuses every such launch (for example on macOS), handoff or not;
  with no registry configured the rule has nothing to protect and is vacuous. What
  counts as an equivalent control is defined in the Story, with the J84 isolated backend
  as its first test case, and the Story's compatibility assessment covers this effect.
  The supervisor must not call `prctl(PR_SET_PTRACER)` to widen Yama access to a child.
- The check **fails closed**: when the launch's write authority cannot be resolved or
  compared, the launch is refused and the reason is reported.
- An unconfined launch (`--isolation none`) establishes no boundary and claims none
  (§23 of the AAASM-6347 amendment). It therefore cannot carry a cross-process
  attenuation claim: the handoff stays refused for it.

### 29. Acceptance contract for the implementation Story

Tests are required, not optional, and each pairs an adversarial case with a positive
control that moves with the condition under test (a check that cannot fail proves
nothing):

1. **Registry write-protection.** Refused: a write scope equal to the registry
   directory; to an ancestor of it; a path that resolves to either through a symlink,
   `..` or a bind-mount alias; an inherited descriptor (including `O_PATH`) that
   reaches it; rename or replacement of the registry directory or of an ancestor
   component; a hard link between a registry entry and a child-writable directory; a
   writable registry file or socket; write access obtained through the child's uid,
   gid, group bits, ACL, or ownership of (or chmod/chown over) the registry directory
   or any ancestor; `ptrace`, `process_vm_writev`, `/proc/<pid>/mem` or `pidfd_getfd`
   against the supervisor; a descriptor received after launch over `SCM_RIGHTS` (exercising the hygiene and `pidfd_getfd` denial above). Admitted (positive
   control): a sibling directory outside the registry's ancestor chain, with an
   identical-shape launch. The refusal tests must fail when the check is removed.
2. **Cross-tree impersonation.** A child launched in tree A that claims a parent, or a
   sibling's identity, in tree B is refused; so is a replay of a child-asserted claim after
   its parent exited or its process identity was reused. Positive control: a child
   legitimately launched in the same tree is accepted with the same claim shape.
3. **Authority escalation.** A child lease wider than its parent's is refused at every
   hop (the §8–§11 monotonic rule, now across processes); a child-forged or
   hand-built claim of ancestry, and an entry the child planted in the registry, are not
   honoured. Positive control: a child lease equal to or narrower than its parent's is
   admitted at the same hop.
4. **Transitive revocation across the process boundary.** Revoking any ancestor's
   lease refuses the descendants, including an already-launched one (the AAASM-6307
   property, shown with real separate processes rather than an in-process ledger).
   Positive control: with no ancestor revoked, the same descendants keep running.

Properties that depend on kernel behaviour are evidenced on a real kernel only (§30).
A test that is skipped, or that exercises a mock or fake kernel, is recorded as *not
run* and never counted toward acceptance.

### 30. The B3 evidence gate (mandatory before any implementation is built or enabled)

The handoff's security rests on five kernel-level assumptions. Each must be
demonstrated, with a positive and an adversarial negative control, on a real Linux
kernel whose relevant capabilities were verified *first*:

1. **Landlock cross-process restriction** — a confined process cannot reach the
   registry or lift its own restriction, and a process in another tree is unaffected
   by this tree's ruleset. The kernel's Landlock ABI is queried at run time and must
   cover rename/link (`REFER`, ABI 2) and truncate (ABI 3) rights, so ABI 3 or newer is
   required; an older ABI is not accepted as evidence for §28 (ABI 1 denies
   cross-directory rename and link outright rather than letting a ruleset govern them,
   and ABI 1–2 cannot restrict truncation).
2. **pidfs identity** — a process identity obtained as a pidfd is stable against pid
   reuse. The evidence records the exact
   kernel version, the kernel documentation relied on, and the runtime behaviour shown:
   a pidfd the supervisor obtained at clone time (`CLONE_PIDFD`) stays bound to its own
   process; once that process is reaped, `pidfd_send_signal` on it returns `ESRCH` and
   never reaches a later holder of the same pid; and the runtime check shows that the pidfd's pidfs inode number (`fstat`
   `st_ino`) distinguishes two different processes and stays stable across pid reuse;
   `kcmp` is not used, because it compares open files, not processes. The evidence
   records the kernel version at which that inode behaviour was observed; this ADR
   asserts no minimum version. A pidfd is not a secret (`pidfd_open` needs no permission), so the claim is stability, not
   unforgeability.
3. **Registry write isolation** — a confined child's attempts to write the registry
   (§28) fail at the kernel, including through aliases. Metadata changes are outside
   Landlock's reach (§28) and are evidenced under item 5 and the DAC separation.
4. **Real multi-process ancestry** — the launched tree's parent/child relation is
   observed from real processes, not synthesized.
5. **Same-uid control denied** — a confined child sharing the supervisor's uid cannot
   `ptrace`, `process_vm_writev`, read or write `/proc/<pid>/mem`, or `pidfd_getfd` the
   supervisor or a registry-capable process, and cannot use a descriptor the supervisor
   did not give it; the evidence records `ptrace_scope`, the child's capabilities, and a
   positive control in which the same operation succeeds when the separation is
   removed.

An environment that cannot show a property (a kernel without Landlock compiled in or
not in the active LSM list, a kernel whose pidfd behaviour fails §30.2, a container whose host kernel
was not itself verified) yields *no evidence*, not a pass. The gate is not waivable by
reading source, by unit tests, or by an unsupported configuration.

### Current state, stated precisely

- **J82 (monotonic capability attenuation across sub-agent trees, AAASM-6161 /
  AAASM-6260) stays `partial` for the cross-process case (AAASM-6273)** until the gate and the §29 tests pass and are independently verified. No production path builds `Ancestry::Parent` from another process; the
  multi-process case remains refused, not accepted.
- **rc.8 release scope:** J82 is deferred from the rc.8 release-blocking set by founder
  decision (release scope only; not a PASS, not an implementation claim). AAASM-6273 still
  owns the work and the B3 gate above is unchanged. rc.8 makes no cross-process attenuation
  guarantee; a claimed parent that cannot be resolved is refused by `authority_gate`
  (`Ancestry::UnresolvedParent`).
- **Verified on the available host (2026-10-22):** the only Linux kernel reachable
  from the development host is Docker Desktop's VM, `6.10.14-linuxkit` (aarch64). Its
  `/proc/config.gz` reports `# CONFIG_SECURITY_LANDLOCK is not set` and
  `CONFIG_LSM="yama,loadpin,safesetid,integrity,bpf"`. **B3 cannot be established
  there.** The development host itself
  is macOS, which has no Landlock.
- **Missing capability, minimally stated:** a Linux kernel built with
  `CONFIG_SECURITY_LANDLOCK=y`, with `landlock` in the active LSM list
  (`/sys/kernel/security/lsm`) and an ABI of 3 or newer, whose pidfd behaviour passes
  the runtime checks in §30.2, with Yama `ptrace_scope` of at least 1 or a uid/PID
  namespace separation available for §30.5, that the operator may run isolated,
  bounded, multi-process tests on without touching the host network.

### What this amendment does not decide

- The on-disk or in-memory design of the supervisor registry. Any record of a launched
  process's place in the ancestry is supervisor-side only and unreachable by the
  child; there is no child-held attestation. The design and record format belong to the
  implementation Story, which starts only after the gate (see the order above), and
  must satisfy §27–§30.
- Any receipt-schema change (`LeaseBinding`), or cryptographic identity binding
  (AAASM-5533 still owns verification).
- That the gate passes. It records the gate; it does not claim any of it.

## Amendment (AAASM-6259): runtime gate seam in `handle_policy_query`

This amendment adds a seam, not an enforcement feature.

- `aa-runtime/src/pipeline/lease_gate.rs` defines `LeaseGate`, which answers
  `Permit` or `Deny { reason }` for `(server-side agent id, CheckActionRequest, now)`.
  `pipeline::run_with_lease_gate` takes an `Option<Arc<dyn LeaseGate>>`; `pipeline::run`
  is unchanged and passes `None`. In `handle_policy_query` the gate runs after the
  op-control halt and before the gateway forward, because a handled gateway response
  returns early.
- **An absent gate behaves exactly as before.** This is not a decision on the
  compatibility switch of section 3; it is the absence of a gate.
- **A production gate exists only in governed mode** (section 37). `PolicyLeaseGate`
  implements `LeaseGate` and the runtime passes it to `run_with_lease_gate` when, and only
  when, `AA_LEASE_POLICY` is set. With it unset the runtime passes `None`, as at the time
  this seam was added. A runtime built for crates.io has no gate and refuses to start if
  asked to govern.
- **Restrict-only.** `Permit` falls through to the gateway and local policy and cannot
  grant over an op-control halt, a gateway deny or a local `blocked_actions` rule.
- **Fail closed when a gate is installed.** A `Deny`, a gate panic and an empty subject
  all deny before any gateway forward. The SDK receives a generic "capability lease
  required" message; the gate's detail goes only to the runtime log.
- **The gate is consulted for every action type**, including `LLM_CALL`, `TOOL_RESULT`
  and unspecified or unknown codes. The seam exempts nothing: the gate owns
  classification and decides which classes need no lease.
- The subject is the runtime's server-side `agent_id`, never the SDK-asserted
  `CheckActionRequest.agent_id`, and it is runtime-wide rather than per connection.
  The clock is read once per query and passed to the gate.
- The verdict is point-in-time and `check` runs inline in the single pipeline loop with
  no timeout, so a real gate must answer from an in-memory snapshot. Panic containment
  needs `panic = "unwind"`.
- `ParentAuthority` is not serialized and no cross-process handoff is introduced
  (sections 27 to 30 are unchanged).
- **Known limitation.** `action_type` and the rest of the request are SDK-asserted, so
  this seam belongs to the advisory layer. It binds cooperative, SDK-wrapped calls and
  does not stop a process that bypasses the SDK or misreports what it is doing. This is
  why the seam exempts no action class.
- A gate that holds a `std::sync::Mutex` across a panic poisons it and then denies every
  later call: fail-closed, but persistent.

## Amendment (AAASM-6259): operator-declared tool capabilities

This amendment fixes the authored half of per-call tool admission: the policy field an
operator uses to say what authority a tool's calls need. **Only the schema, validation,
digest and resolution carry-through exist today.** No runtime consumes the declaration,
and no shipped binary denies or admits a tool call because of it; that arrives in later
changes under the same ticket. Nothing below should be read as a statement that a tool
call is currently checked against a lease.

### 31. `tools.<name>.capabilities` is a declaration of need, never a grant

```yaml
tools:
  web_search: { allow: true, capabilities: [network_egress, name_resolution] }
  write_note: { allow: true, capabilities: [filesystem_write] }
  calculator: { allow: true, capabilities: [none] }   # purely logical, needs no lease
```

The vocabulary is exactly the names `LeaseDomain::parse` accepts, mapped one to one to
capability domains, plus `none`. The field is `Option<Vec<ToolCapability>>`: **absent is
undeclared and is a different state from `[none]`**. `authority.leases` stays
independently authored and is never derived from a declaration, for the reason section 2
gives: a lease computed from the thing it is later checked against would make the check a
tautology.

The validator rejects an empty list, an unknown word, a duplicate, `none` combined with
any other word, `resource` and `workspace_transaction` (launch-boundary authority, not
something a single call exercises), and any declaration under the `"*"` tool key
(declarations are matched by exact tool name, and a wildcard would make every tool
declared). `process_creation` and `syscall` **pass** the validator: they are real domains
a tool may need. The governed decision in section 32 refuses them; authoring is not where
that refusal belongs. The canonical parser in `aa-security` applies the same rules and
never lowers the field into `ToolRule` or the eBPF rule set.

The field participates in `content_digest` only when present, so every existing policy id
is unchanged. The effective-policy resolution carries the declared map (declared tools
only) and the digest so a later decision can attribute itself to the exact document it
read.

### 32. Governed mode is triggered by `AA_LEASE_POLICY`, not by "the policy authors a lease"

Decided here, implemented later. The runtime treats itself as governed when, and only when,
`AA_LEASE_POLICY` is set. The alternative considered, "governed once the policy authors at
least one lease", fails open: deleting the leases from a policy silently returns the
runtime to ungoverned. An operator-set switch outside the policy document cannot be
removed by editing the document.

In governed mode an undeclared tool is denied, and a tool that declares `process_creation`
or `syscall` is refused. Those two are refused because this admission check cannot bound
them: a tool that may spawn a process or issue raw syscalls is not confined by a lease the
SDK-side wrapper consulted.

### 33. What this is not: admission, not confinement

The check this field enables is an **admission lease check for a cooperative SDK
`TOOL_CALL`**. `action_type` and the rest of the request are SDK-asserted (see the known
limitation under the AAASM-6259 gate-seam amendment), so a process that bypasses the SDK or
misreports what a tool does is not stopped by it. A declaration is also a claim by the
operator about the tool, not a measurement of it: a tool declared `[none]` that in fact
writes files is not caught here.

Selector-scoped leases (a lease whose scope is a path or destination list) never admit a
tool. A declaration names a domain, not a destination, and answering "may this call reach
that destination" from a domain-level declaration would widen the lease. Only a
`scope: whole` lease in the declared domain admits.

The field is trusted operator policy. It is read only from the operator-authored document
and never from anything an agent, SDK or tool supplies.

### 34. Compatibility

The key is an additive public schema change (see the protocol changelog). An rc.7 binary
does not know the key and rejects the document as an unknown key, which is fail-closed:
a policy carrying declarations cannot be silently loaded by a binary that would ignore
them.


### 35. The governed decision

`aa-runtime/src/lease/decide.rs` implements the decision section 32 describes as "decided
here, implemented later", and `lease/gate.rs` wraps it as a `LeaseGate`. Section 37
records how the runtime builds the governance, installs the gate and reloads revocations;
this section and section 36 describe the decision itself.

`decide(governance, revoked, request, now)` is pure. `LeaseGovernance` is built once from
operator-trusted input: the server-side agent id, an `Enforced` policy load (a permissive,
unconfigured or failed load is a construction error, and governed mode never falls back to
ungoverned), the tool table from `tools.<name>.capabilities` joined with `allow`, and the
leases lowered by the same `authored_lease_from` and `lower_leases` path `aasm run` uses
(the conversion now lives in `aa-runtime` and `aa-cli` calls it). A policy that authors
`max_count` or two leases for one domain cannot be governed and refuses to start.

| request | verdict |
|---|---|
| `TOOL_CALL`, tool declared `[none]`, `allow: true` | Permit |
| `TOOL_CALL`, declared domain classes, `allow: true` | Permit only if every class has a valid, un-revoked, `whole`-scope lease naming the governed subject (`admit_lease` with `RequirementScope::Whole`) |
| `TOOL_CALL`, undeclared tool; `allow: false`; missing or empty tool name; no `ToolCallContext` | Deny |
| `TOOL_CALL`, tool declaring `process_creation` or `syscall`; any unrecognised class | Deny, even with a lease for that class |
| `LLM_CALL`, `TOOL_RESULT`, with or without a context | Deny |
| `FILE_OPERATION`, `NETWORK_CALL`, `PROCESS_EXEC`, `AGENT_SPAWN`, `UNSPECIFIED`, unknown codes | Deny |

A `Permit` only falls through to the gateway and local policy; the gate can only restrict.
The typed action types deny because admitting one would need a typed filesystem or network
claim, and the request carries only an SDK-asserted `action_type`; there is nothing
trustworthy to check a lease against. `process_creation` and `syscall` deny because an
admission check cannot bound a class that subsumes every other. A lease selected by named
selectors never admits a tool (section 33) because the requirement is `Whole`, which a
selector lease does not cover. Revocation is a set of lease ids supplied by the caller;
the library does not read lease state.

`agent_id`, `caller_agent_id`, `args_json`, `tool_source`, `target_url`, the credential
token and the trace and span ids never influence a verdict. The decision reads only
`action_type`, the tool name and operator-trusted state.

### 36. Limits of the governed decision

- **Admission, not confinement.** It decides whether a cooperative SDK-wrapped call may
  proceed. A process that bypasses the SDK, or a tool that does more than its declaration
  says, is not stopped.
- **`action_type` is SDK-asserted, so only `TOOL_CALL` can be admitted.** `LLM_CALL` and
  `TOOL_RESULT` are denied in governed mode in every form (context omitted, a
  `ToolCallContext` left in, an empty matching context, or another typed context), because
  a label the client chooses cannot be allowed to waive the lease check. No shipped SDK
  sends them as a policy query (Python, Node and Go each send `TOOL_CALL` with a
  `ToolCallContext`), so no cooperative path is lost; ungoverned runtimes are unchanged. This
  closes the admission of a relabelled request, not a client that skips the query or runs
  the tool without asking, which stays the advisory-layer limit above.
- **Leases do not refresh.** Lease TTLs count from the run record's `issued_at`. After
  `issued_at + ttl` every tool that declares a leased class denies until an operator starts
  a new run; this is fail-closed by design, not a bug. Tools declared `[none]` are
  unaffected.
- **Tool names match exactly.** No case folding, trimming or wildcard expansion; a `"*"`
  entry declares nothing. A tool the operator did not declare by exact name is undeclared.
- **The subject is runtime-wide.** Every connection to one runtime shares the server-side
  agent id, so a lease admits all of them, not one caller.
- **Verdicts are point-in-time.** Expiry and revocation are read when the query is
  decided; a lease that lapses or is revoked while an approval is pending is not
  re-checked when the approval resolves.
- **A poisoned snapshot lock denies every call** until the process restarts, and a refused
  `install` does not heal it.

### 37. Wiring: what the runtime does with the gate

`aa-runtime` builds the gate at the very top of `run()`, before the metrics recorder, the
IPC socket, the health server or any task exists, so a refusal precedes every subsystem
start-up log line (asserted in the wiring test) and leaves no socket or listener.
`run()` now returns `Result<(), StartupRefusal>` and the binary exits with status 78.

**Trigger.** `AA_LEASE_POLICY` being *set* is the only trigger (section 32). A set but empty
value is still "requested" and is refused; this differs deliberately from `AA_POLICY_PATH`,
where empty means disabled, because here "disabled" would be a fail-open. `AA_LEASE_STATE`
names the record, the same variable `aasm lease` reads. A record that merely exists does not
turn governed mode on.

**Startup refuses** (exit 78, message on stderr and in the log) when: `AA_LEASE_POLICY` is
set but this build cannot enforce leases (crates.io build without the gate, or a non-unix
host); `AA_LEASE_STATE` is unset; the policy fails to load or is not an enforced policy;
the record is missing, corrupt, of an unsupported version, insecure, for a different subject
than the server `AA_AGENT_ID`, or bound to a different policy digest (the message names the
digest to pass to `aasm lease init`); or the policy authors a lease the lowering refuses
(`max_count`, two leases for one domain). A missing record is never created: `aasm lease
init` is the only thing that starts a run. `process_creation` and `syscall` leases are not
a startup refusal; the decision denies every tool that declares those classes (section 35).
The policy is loaded from the explicit path only (`aa_policy::resolve::load`), never
through the search path, so a missing file cannot fall back to another policy. The
refusal for "asked to govern, build cannot" sits outside the strip region in
`lease/wiring.rs`; only the call into the gate is stripped, so the crates.io binary refuses.

**Time.** Expiry is judged against the host's wall clock (`SystemTime::now()`) at each check, so a clock stepped forward expires leases early and one stepped back extends them; there is no monotonic-clock guard. `GovernedIssuance.issued_at` is the record's `issued_at` and the lease ids come
from the record (`LeaseGovernance::from_state`), so ids and windows agree with what
`aasm lease init` printed. Expiry is evaluated against the wall clock at each check with no
grace. A restart does not refresh a lease; only a new run does.

**Reload.** A task re-reads the record every 100 ms off the async workers. A valid update
that passes `check_monotonic` installs a new snapshot with the new revoked set. Any
anomaly (unreadable, corrupt, deleted, changed anchor, subject or digest, a shrunk
revocation set, a generation that went backwards, I/O error) installs deny-all and ends the
task: the gate stays denied until restart and never heals, even if the original record is
put back. The first I/O error latches too: there is no retry, because a transient read
failure is indistinguishable here from a record someone is racing to restore, so the
gate fails closed and an operator restarts it (accepted trade-off, not an oversight).
Each read is bounded (2 s); a read that does not return in time trips the gate. The reload
task is supervised: if it panics, is aborted, or ends without a shutdown, the supervisor
installs deny-all, so a gate that can no longer learn of revocations stops permitting. The policy file is read once; editing it takes effect only at restart, and then
only if the record is re-initialised for the new digest.

**Revocation acknowledgement.** `GET /health` gains an additive `lease_governance:
{run_id, generation, state}` object (`state` is `governed` or `denied_all`), present only in
governed mode, so ungoverned output is unchanged. The field is written only after the gate
accepted the snapshot. `aasm lease revoke --wait-health <URL>` (or `AA_LEASE_HEALTH_URL`)
returns only once `/health` shows *this run's* `run_id` at the new generation or later, and
fails on timeout (default 5 s, clamped to one hour), against a runtime that reports no
`lease_governance`, or against another run's runtime. A runtime reporting `denied_all` for
this run also acknowledges (everything is refused) but `revoke` exits 3 so a script cannot
mistake it for "revoked and applied". The client ignores environment proxies, does not
follow redirects, and never prints URL userinfo, query or fragment. Without the
flag the revocation is recorded and applied within about one reload interval, with no
acknowledgement. The runtime health address is not discoverable from the state record, so
the URL is an explicit operator input.

**Residuals, stated.**
- A same-UID agent can edit the policy file, the state record and its directory. The record
  is owner-only (0600) and rollback-checked while the runtime runs, but an agent that can
  write it can trip deny-all or, across a restart, present an older valid record (AAASM-5533).
- The subject is runtime-wide; the gate is point-in-time; it is admission, not confinement
  (sections 33 and 36).
- `aa-runtime` started by an SDK helper (for example the Python `start_runtime`) inherits
  that process's environment, so whether it is governed is decided by what that environment
  carries, not by anything the SDK asserts.
- The gate sits in `handle_policy_query`. Other paths that reach a tool without an
  SDK-wrapped policy query (the proxy, eBPF, a non-cooperative SDK) are not gated by it.
- A read that hangs (a dead network filesystem) is cut off after 2 s and trips deny-all, so
  a revocation can lag by at most that long before the gate fails closed. The blocked
  thread itself cannot be cancelled; the binary bounds its exit with a runtime shutdown
  timeout so it cannot keep the process alive.

**Evidence.** `aa-runtime/tests/aaasm_6259_lease_gate_wiring.rs` drives the real binary over
its IPC socket against a counting fake gateway; see the PR for the falsifier table. J81
remains partial until the PR6 end-to-end journey. The real Python-SDK harness for that journey is
`scripts/qa/j81-sdk-lease-e2e.sh` (see `docs/src/qa/j81-sdk-lease-e2e.md`). It is manual local evidence, not a CI gate. Its S5e rows
send the omit-context relabel and expect a deny; they have not been run since that change
(NOT_RUN until an independent run).

### 38. Plan-time / runtime parity: `aasm run --dry-run` calls the same decision

`aasm run --dry-run` prints a `--- lease plan ---` section: for every tool the policy
declares under `tools.<name>.capabilities`, one verdict line, plus a line for an
undeclared tool and one per typed action type. Each verdict is produced by the
`aa_runtime::lease::decide::decide` the runtime's `PolicyLeaseGate` calls, over a
`LeaseGovernance` built by the same `LeaseGovernance::from_resolution`, from the
policy's authored `authority.leases` only. The section describes what a *governed* runtime
(section 32: one started with `AA_LEASE_POLICY` and a record from `aasm lease init`) would
decide; a runtime started without `AA_LEASE_POLICY` runs no lease gate at all, and the
preview says so. The preview owns no rule of its own: it
builds the request a wrapped call would carry and formats the answer, so a change to
the decision changes the plan with it.

The parity is pinned by tests, not asserted by construction. A table of rows (lease
held, missing, expired, cross-capability, selector-scoped, `[none]`, capabilities
absent, unknown tool, `allow: false`, `process_creation`) is run through the plan and
through `PolicyLeaseGate` at the same clock and must agree, and each row carries a
hand-written expected verdict so mutating `decide` moves both sides off the pin. A
deliberately divergent re-implementation is compared the same way and must be caught.

What the plan is not:

- **Point-in-time.** Leases are planned as issued at the moment of the preview, with
  the `aasm run` launch default (3600s, the same value governed mode uses; a test pins the
  two together) for a grant that states none; each `lease:` line prints its `ttl` and
  whether it was `authored` or `default`. The real run record's
  `issued_at` is the `aasm lease init` time, so a plan cannot show a lease that has
  lapsed in a real run.
- **Revocation is runtime-only.** The plan evaluates against an empty revoked set and
  says so. It reads no state record and creates none.
- **Not authorization and not enforcement.** A `PERMIT` is not a grant and a `DENY` is
  not a refusal; the runtime decides per call with the clock and revocation state it
  has then, and a `PERMIT` there still falls through to the gateway and local policy.
- **Unavailable is not permissive.** For a policy that is not an enforced load, or that
  authors a lease governed mode cannot issue, the section states the reason and prints
  no verdicts.
- **Preview only, and strip-bound.** The section lives in `run.rs`, so it is removed
  from the published crate with the rest of `aasm run`.
- **Tools without `capabilities` are not listed.** The plan lists tools that declare
  capabilities, a `summary:` of how many would be denied, and one `tool <undeclared>` line
  that also covers any tool declared without `capabilities` (a governed runtime denies it).

## Amendment (AAASM-6312, 2026-10-28): the ledger is authoritative for generation, and only an issuer-bound writer can change it

**Status: design, not yet implemented.** Nothing below is in the code on `main`. No production path builds a
`DelegationLedger` today, and none may until AAASM-6273's security and kernel evidence gates (B3, §29/§30) pass.

### Decision (founder, 2026-10-28)

Cross-process delegated authority must be issuer-bound and verified against an authoritative ledger. The gate must
not trust a lease id alone, a caller-provided lease snapshot, a self-claimed issuer, or an unverified approval
reference. Unknown or unverifiable delegated authority fails closed. Legitimate attenuation and delegation are
preserved.

### What was wrong

`StaleParentGeneration` compared a child's recorded `parent_generation` with the generation inside the
`ParentAuthority` *snapshot's* lease value. `CapabilityLease::with_revocation` is public and `same_content` excludes
`revocation` on purpose (a revocation must not read as a content change), so a caller-built snapshot chose the number it
was compared against. Reaffirmation was detectable only if the caller happened to hand the gate the reaffirmed snapshot.

### Semantics

1. **The ledger holds the generation.** Each ledger entry records the lease's authoritative generation. It starts at the
   generation of the lease as registered or derived, and only two ledger operations change it: `revoke` (existing:
   the entry becomes `Revoked` at the stated generation) and a new `reaffirm`.
2. **`reaffirm(id, generation)` is a writer-only operation.** It is refused unless the lease is known, currently
   `Active` in the ledger, its whole chain verifies, and `generation` is strictly greater than the recorded one. It
   cannot resurrect a revoked lease and cannot move a generation backwards. It does not touch the lease's content,
   so a reaffirmation never makes `content_matches` fail.
3. **The gate compares against the ledger.** For a child with provenance, `check_attenuation` compares
   `provenance.parent_generation` with the ledger's current generation for the parent's id. The snapshot's own
   `revocation` field is no longer an input to that comparison. A parent id the ledger does not know is
   `LedgerUnverifiable`, as before.
4. **Reaffirmation keeps its meaning.** A child derived at generation `g` is stale once the parent is reaffirmed to
   `g' > g`: `StaleParentGeneration`, re-derive under the new generation. This is the behaviour the existing text
   describes ("a child derived at an earlier generation, then gated against a later-reaffirmed-but-still-`Active`
   parent is still stale"), now detected whenever the ledger was reaffirmed and not only when the caller supplies the
   newer snapshot.
5. **Derivation stamps from the ledger.** `derive_child` already records the generation it observes under the ledger
   lock; that remains the only source of a child's `parent_generation`.
6. **Snapshots remain inputs for what the ledger does not decide.** Scope, expiry, limits and delegation rights are
   still compared from the snapshot, because `content_matches` has already bound the snapshot to the ledger's record
   of exactly those fields.

### Issuer binding

7. **Only the ledger's writer registers roots, reaffirms, or revokes.** The ledger is created for one issuer
   identity and hands back a writer token; the `Arc` the gate holds cannot write. A root whose `basis.issuer` is not
   that identity is refused (`UntrustedIssuer`). This removes the unrestricted `DelegationLedger::new()` and the
   string-comparing `with_trusted_issuer`: the writer capability, not a claimed string, is what makes a ledger entry
   trustworthy.
8. **Escalation is admitted only for a ledger-recorded root.** A child wider than its parent passes only when the
   ledger recorded it as a `Root` through the writer with matching content, carries a `policy_rule` bound by content,
   and its recorded issuer is neither the child's nor the parent's subject. An `approval_ref` alone, or a claimed
   issuer on a lease the ledger never recorded, is refused (`EscalationNotIndependentlyApproved`). Nothing today can
   verify an `approval_ref` against a lease's scope, so refusing it is the correct default; checking approvals
   against the approval store would be a separate feature.
9. **A child the ledger never saw is refused under `Ancestry::Parent`.** Presenting a hand-built narrower child is
   not delegation. Legitimate attenuation goes through `derive_child`, which records the child and its edge.

### Fail-closed matrix

| Case | Refusal |
|---|---|
| Parent not registered | `LedgerUnverifiable` |
| Root whose issuer is not the ledger's | `UntrustedIssuer` |
| Lease registered in a different ledger | `LedgerUnverifiable` |
| Known id, different content | `LedgerContentMismatch` |
| Child the ledger never saw | `LedgerUnverifiable` on the child |
| Child whose edge names another parent | `ProvenanceMismatch` |
| Child stamped at an older generation than the ledger's | `StaleParentGeneration` |
| `reaffirm` to an equal or lower generation, or on a revoked lease | refused, ledger unchanged |
| Escalation backed only by `approval_ref`, or by an unrecorded claimed issuer | `EscalationNotIndependentlyApproved` |
| Any revoked hop | `RevokedInLedger` |

### Required tests (each refused case paired with an otherwise identical admitted case)

- A snapshot rebuilt with `with_revocation` at the child's stamped generation is refused when the ledger's generation
  differs; reverting the comparison to read the snapshot makes this test fail (mutation check).
- `reaffirm` advances the generation; a child derived before it is `StaleParentGeneration`; a child re-derived after it
  is admitted; `reaffirm` to the same or a lower generation, and on a revoked lease, is refused.
- A reaffirmation does not change `content_matches` for the lease.
- A hand-built narrower child under `Ancestry::Parent` is refused; the same shape produced by `derive_child` is
  admitted.
- A root with a foreign issuer is refused; the same lease with the ledger's issuer registers; a lease registered in
  ledger B does not verify in ledger A.
- Escalation with `approval_ref` only is refused; the same recorded root with a `policy_rule` is admitted; an issuer equal
  to the parent's subject is refused.
- The existing attenuation positive controls, the transitive revocation tests and the native Linux test stay green.

### What this still does not claim

The ledger issuer's identity string, the in-process `spec.identity`, what an `approval_ref` says and what a
`policy_rule` string means remain asserted, not authenticated; identity is owned by AAASM-5533. Cross-process
operation stays behind the §27 contract (the supervisor holds authority, the child presents nothing, nothing is
serialized) and the B3 evidence on a real Linux kernel with Landlock ABI 3 or newer. This amendment activates nothing.
