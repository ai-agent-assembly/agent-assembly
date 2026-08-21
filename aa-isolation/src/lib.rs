//! Backend-neutral execution isolation contract for Agent Assembly.
//!
//! This crate defines *what a governed launch requires* and *what a backend can
//! actually do about it*, as data. It contains no isolation mechanism, spawns
//! no process and names no operating-system facility. Implementations of
//! [`IsolationBackend`] supply the mechanism; this crate supplies the vocabulary
//! they must answer in, and the negotiation that decides whether a launch may
//! proceed at all.
//!
//! Authority: ADR 0035, *Agent Execution Isolation & Pluggable Enforcement
//! Backends*. Implementation is tracked by Epic AAASM-5702; this crate is
//! AAASM-5704.
//!
//! # The one failure this crate exists to prevent
//!
//! A control that only *watches* an action must never be reported as a control
//! that *stopped* it. Every type here is shaped around that distinction:
//!
//! * [`CapabilityReport::can_prevent`] is the only path to a prevention claim,
//!   and it requires enforcement, pre-effect decision timing and synchronous
//!   semantics together — no two of the three suffice.
//! * [`negotiate`] refuses before spawn when a [`RequirementPosture::Required`]
//!   prevention requirement meets an observe-only capability. Refusal is the
//!   `Err` arm, so a refused launch is not representable as an
//!   [`EnforcementPlan`].
//! * [`EnforcementEvidence::supports_prevention_claim`] ignores
//!   [`EvidenceKind::Configured`] and [`EvidenceKind::Installed`] records
//!   entirely. Having installed a control is not evidence that it decided
//!   anything.
//! * [`BackendAvailability`] lives on capability *discovery* and is absent from
//!   [`EnforcementEvidence`] by construction. "A backend is available" is a fact
//!   about the host, not about a run.
//!
//! # Why a separate crate rather than `aa-core`
//!
//! `aa-core` is the natural home for a pure contract, and this contract *is*
//! pure. It was still put here, for a reason that is measurable rather than
//! stylistic: `aa-core` is not platform-free under its default `std` feature.
//! It exposes [`std::process::Command`] in two public trait signatures
//! (`dev_tool.rs`, `integration/contract.rs`), and uses `dirs::home_dir()` and
//! `std::os::unix::fs::PermissionsExt`. It is `no_std`-clean only under
//! `alloc`, and the `alloc` build is precisely the one that excludes those
//! surfaces.
//!
//! Adding the isolation contract to `aa-core` would therefore either (a) land it
//! next to `std::process::Command`, in a crate whose stated contract is "no
//! runtime or I/O dependencies", or (b) require a third feature axis to keep it
//! away from them. A crate that depends on nothing but `aa-core`'s attestation
//! vocabulary states the boundary directly and costs one manifest.
//!
//! The dependency runs one way only: `aa-isolation` → `aa-core`. Nothing in
//! `aa-core` knows this crate exists.
//!
//! # Policy lowering, and why it lives here (AAASM-5707)
//!
//! [`lowering`] maps an effective policy onto [`ControlRequirement`]s. That
//! needs the canonical policy AST, so the crate now has a second dependency,
//! `aa-security` — a leaf crate that is not a platform, an async runtime or a
//! serialization format, which are the three things the paragraph above is
//! about.
//!
//! The edge direction is forced rather than preferred. `aa-policy` owns
//! effective-policy resolution and would be the natural home, but it carries no
//! `publish = false` and is therefore in `cargo workspaces publish`'s set, while
//! this crate opts out — so `aa-policy` → `aa-isolation` fails `cargo publish`
//! on a dependency that is not on crates.io. `aa-security` → `aa-isolation` is
//! a cycle, because `aa-core` already depends on `aa-security`. What remains is
//! `aa-isolation` → `aa-security`, which is acyclic and packaging-safe.
//!
//! Lowering reads policy and never writes it: no type in [`lowering`] is a
//! policy node, and nothing there anticipates a schema that does not exist.
//! Where the schema cannot express a domain, the gap is reported as
//! [`DomainCoverage::PolicyCannotExpress`] rather than as an absent
//! requirement, because those two are read very differently by anyone deciding
//! whether a boundary is complete.
//!
//! # Ambient authority and descendant inheritance (AAASM-5709)
//!
//! Three modules turn ADR 0035 §6 and §9 from prose into checkable properties,
//! and each exists to keep one pair of states from collapsing into one:
//!
//! | Module | The pair it keeps apart |
//! | --- | --- |
//! | [`ambient`] | A credential *removed* from the child, and one that **could not be** removed |
//! | [`descriptor`] | A descriptor known absent, and one nothing enumerated |
//! | [`descendant`] | A sub-agent launch that narrows authority, and one that widens it |
//!
//! The first is the load-bearing one. [`CredentialPosture`] has always had the
//! three-way split; what [`EnvironmentPlanner`] adds is that a posture built
//! from a real environment *cannot* place a kept compatibility exception in
//! `removed`, and [`CredentialPosture::contradictions`] is the predicate that
//! catches a hand-written posture which does. A non-empty
//! [`CredentialPosture::ambient_unremoved`] means the run is not
//! least-authority, and every rendering of it must say so rather than reporting
//! the delegated set as the whole story.
//!
//! None of the three enforces anything. They describe a launch before it starts,
//! so a caller can refuse, degrade or record — the same three outcomes
//! [`negotiate`] already offers, reached from a different input.
//!
//! # Reused vocabulary, and one deliberate rename
//!
//! Evidence terms are [`aa_core::attestation::ClaimTerm`] verbatim — this crate
//! does not define a competing set. Degradation reuses the planned/achieved
//! shape of `aa_core::integration::state::ProtectionState::Degraded`, so a gap
//! between what was intended and what was reached is legible in both places the
//! same way.
//!
//! ADR 0035 §2 names the backend-capability object `CapabilitySet`. That name is
//! already taken: [`aa_core::capability::CapabilitySet`] is the nine-capability
//! *policy* set (what an agent is permitted to do). This crate's object answers
//! a different question — what a *backend* can mechanically do on *this host* —
//! and the two would be confused in every call site that imports both. It is
//! [`BackendCapabilities`] here. ADR 0035 §2 admits this explicitly: "names may
//! be refined without changing their semantics".
//!
//! # No mechanism vocabulary
//!
//! No operating-system or vendor isolation mechanism is named anywhere in this
//! crate. A backend's mechanism-specific realization travels as [`Lowering`],
//! an opaque list of backend-authored strings that this crate stores, renders
//! and never parses. Backend identity, version and provenance ride in
//! [`EnforcementPlan`] and [`EnforcementEvidence`] via [`BackendIdentity`] and
//! are absent from [`ExecutionSpec`] and [`ControlRequirement`] by construction,
//! so policy cannot come to depend on which backend answered it (ADR 0035 §3).
//!
//! # Packaging
//!
//! `publish = false`, and the crate is not added to the crates.io release set.
//!
//! `cargo workspaces publish` in `release.yml`'s `publish-crates` job ships
//! every workspace member that does not carry `publish = false`, so this is an
//! opt-out, and omitting the key would have been a decision to publish rather
//! than a neutral default. Three reasons to opt out:
//!
//! 1. **Nothing published would consume it.** The only intended consumer is
//!    `aa-cli`'s `aasm run`, and `.ci/strip-for-publish.sh` deletes
//!    `aa-cli/src/commands/run.rs` from the published tarball outright. A
//!    published `aa-isolation` would sit on crates.io with no published caller.
//! 2. **`release.yml` already records the governing rule** for the dev-tool
//!    subsystem this launch path belongs to: it is held back from the alpha so
//!    that "nothing published advertises a surface nothing published can serve".
//!    Publishing an isolation contract for a command absent from the published
//!    binary is the case that rule describes.
//! 3. **The contract is not settled.** Five sibling tickets under Epic
//!    AAASM-5702 will still be reshaping these types. A crates.io release is
//!    one-way: a version can be yanked, never edited.
//!
//! The reverse direction is cheap and the forward direction is not, which is why
//! the decision falls this way at this point in the Epic. Making the crate
//! publishable later is a one-line manifest change plus an entry in the release
//! set; unpublishing is not possible.
//!
//! **Consequence for the integration ticket:** `aa-cli` publishes, so its
//! dependency on this crate must sit inside a `# strip-for-publish:begin
//! <region>` / `:end` fence in `aa-cli/Cargo.toml`, exactly as the existing
//! `devtool` and `sdkclient` regions do for `aa-sdk-client`. Without the fence,
//! `cargo publish` for `aa-cli` fails on a dependency that is not on crates.io.
//! That edit is not made here — `aa-cli/Cargo.toml` is out of scope for
//! AAASM-5704.
//!
//! # Serialization
//!
//! `serde` is an optional, non-default feature. These types are a *contract
//! between crates*, not a wire format, and deriving `Serialize` by default would
//! quietly make every field name a compatibility obligation the moment anything
//! wrote one to disk or an API. Consumers that need a wire representation should
//! enable the feature deliberately and own the resulting stability question.
//!
//! [`std::process::Command`]: https://doc.rust-lang.org/std/process/struct.Command.html

#![warn(missing_docs)]

pub mod ambient;
pub mod backend;
pub mod capability;
pub mod descendant;
pub mod descriptor;
pub mod evidence;
pub mod lowering;
pub mod plan;
pub mod report;
pub mod spec;

#[cfg(feature = "mock-backend")]
pub mod mock;

pub use ambient::{
    classify_env_name, is_supervisor_credential, AmbientAuthorityKind, ClassifiedName, CompatibilityException,
    EnvironmentPlan, EnvironmentPlanner, CLOUD_METADATA_ENDPOINTS,
};
pub use backend::{
    ExecutionHandle, ExitDisposition, IsolationBackend, PreparedExecution, SpawnError, TerminationRequest,
};
pub use capability::{
    BackendAvailability, BackendCapabilities, CapabilityDomain, CapabilityReport, DecisionTiming, DescendantCoverage,
    DuplicateDomain, FailurePosture, Mediation, PlatformBoundary, Prerequisite, PrerequisiteStatus, SupportLevel,
    Synchrony,
};
pub use descendant::{authority_widening, covers_ordinary_descendants, is_same_or_narrower, AuthorityWidening};
pub use descriptor::{
    DescriptorDisposition, DescriptorInventory, InheritedDescriptor, InventoryCompleteness, STANDARD_DESCRIPTORS,
};
pub use evidence::{EnforcementEvidence, EvidenceKind, EvidenceRecord};
pub use lowering::{
    lower_policy, permit_only_selector, permitted_selector, DomainCoverage, DomainLowering, LoweringOptions,
    NoRequirementsLowered, PolicyLowering, ScopeGranularity, PERMIT_ONLY_SELECTOR,
};
pub use plan::{
    negotiate, AchievedControl, BackendIdentity, EnforcementPlan, LaunchPosture, Lowering, PlanRefusal,
    PlannedRequirement, Provenance, RefusalReason, RequirementOutcome,
};
pub use report::{
    BackendSelection, CandidateVerdict, ConsideredBackend, ControlState, DomainProjection, EvidenceBasis,
    IsolationReport, ReportStage, ReportedPosture, RequestedControl, SelectionMode, SessionRef, TargetRef,
    UnmeasuredReason, REPORT_SCHEMA,
};
pub use spec::{
    ControlRequirement, CredentialPosture, DescendantRequirement, ExecutionSpec, IdentityRef, RequirementIntent,
    RequirementPosture, RequirementScope, ResourceLimits,
};
