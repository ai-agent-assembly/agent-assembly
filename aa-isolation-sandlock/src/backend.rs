//! The backend itself: discovery, planning, preparation, launch and evidence.
//!
//! # The single launch path
//!
//! There is exactly one place in this crate that starts the caller's program,
//! and it always starts it as an argument of the confinement executable. There
//! is no branch that constructs a [`Command`] from
//! [`ExecutionSpec::program`] directly, and no error arm that falls back to
//! one. A preparation or launch failure returns [`SpawnError`] and produces no
//! process at all.
//!
//! That is ADR 0035's "no silent unconfined fallback" held structurally rather
//! than by discipline, and
//! [`tests::a_broken_backend_executable_produces_no_process_at_all`] is the
//! negative control: it points the backend at a path that cannot execute and
//! asserts that the effect the program would have had did not happen.
//!
//! # What a run of this backend can and cannot claim
//!
//! [`EnforcementEvidence::supports_prevention_claim`] is false for every domain
//! after every ordinary run, and that is correct rather than a defect to be
//! worked around. The confinement is enforced by the kernel against the
//! confined process; the denial is delivered to *that* process as an error
//! return, and the supervisor this backend talks to has no channel that reports
//! it back. So this backend can say a control was configured, that it was
//! installed before the program started, and that the program ran — the three
//! grades that are honest — and it cannot say the control decided anything.
//!
//! Reaching [`EvidenceKind::Decision`] would need a per-decision record from the
//! mechanism. Until one exists, the absence is the finding, and manufacturing a
//! `Decision` record from "the program exited non-zero" would be exactly the
//! promotion the contract is built to prevent.

use std::collections::HashMap;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aa_core::attestation::ClaimTerm;
use aa_isolation::{
    negotiate, BackendCapabilities, BackendIdentity, CapabilityDomain, EnforcementEvidence, EnforcementPlan,
    EvidenceKind, EvidenceRecord, ExecutionHandle, ExecutionSpec, IsolationBackend, Lowering, PlanRefusal,
    PreparedExecution, Provenance, RequirementOutcome, SpawnError,
};

use crate::capability;
use crate::host::{BackendLookupError, HostFacts};
use crate::lower::{build_argv, credential_flags, lower_requirement, unremoved_ambient, Argv, FLAG_ALLOW_DEGRADED};
use crate::probe::{self, ConfinementProbe};

/// The stable machine identifier this backend answers to.
pub const BACKEND_ID: &str = "sandlock";

/// Where the mechanism comes from.
///
/// Recorded, not checked — `aa-isolation` has no opinion on licences. The
/// values are the ones measured for the release recorded in
/// `metadata/isolation-backends.json`; the *version* travels separately because
/// it comes from the executable actually present on the host, which may not be
/// the reviewed one.
pub const SOURCE_URL: &str = "https://github.com/multikernel/sandlock";
/// SPDX identifier of the mechanism, read from its `LICENSE` at the reviewed
/// tag.
pub const SPDX_LICENSE: &str = "Apache-2.0";

/// What the mechanism was doing when this backend was asked about it.
#[derive(Debug)]
struct Prepared {
    plan: EnforcementPlan,
    argv: Argv,
    residual_authority: Vec<String>,
}

/// A finished run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedRun {
    /// The confined program's exit status, as the mechanism reported it.
    pub status: ExitStatus,
    /// Everything the run wrote to standard output, when the backend was
    /// configured to capture it.
    pub stdout: String,
    /// Everything the run wrote to standard error, when the backend was
    /// configured to capture it.
    pub stderr: String,
}

/// A Linux process-isolation backend built on an external confinement
/// supervisor.
#[derive(Debug)]
pub struct SandlockBackend {
    identity: BackendIdentity,
    capabilities: BackendCapabilities,
    facts: Option<HostFacts>,
    probe: ConfinementProbe,
    /// Protections a caller waived by name, and the flags that realise the
    /// waiver. Empty unless someone asked for it.
    degraded: Vec<String>,
    degraded_flags: Vec<String>,
    capture_output: bool,
    prepared: Mutex<HashMap<String, Prepared>>,
    running: Mutex<HashMap<String, Child>>,
    completed: Mutex<HashMap<String, CompletedRun>>,
    next_token: AtomicU64,
}

impl SandlockBackend {
    /// Discover the host and measure what the boundary actually does here.
    ///
    /// Never fails. A host where the mechanism is absent, the platform is
    /// wrong, or the kernel will not confine produces a backend whose
    /// availability is `Unavailable`, so the refusal happens in
    /// [`IsolationBackend::plan`] — before any program is started — rather than
    /// as a surprise at launch. That ordering is an acceptance criterion of
    /// AAASM-5708, not an implementation detail.
    ///
    /// Costs one `--version` invocation plus the controlled pairs in
    /// [`crate::probe`], once.
    pub fn discover() -> Self {
        Self::discover_authorising_degraded(&[])
    }

    /// Discover, having authorised the mechanism to waive named protections on
    /// a host too old to provide them.
    ///
    /// # Why this is an explicit, named argument and not a fallback
    ///
    /// The mechanism enforces every protection it knows about by default, and
    /// refuses to confine at all when the host kernel cannot provide one. It
    /// also offers to waive a protection instead — and it does so **silently**:
    /// it prints nothing, records nothing, and offers no way to ask afterwards
    /// which protections were installed. A backend that reached for that waiver
    /// on its own, to make an old host work, would produce a launch that looked
    /// exactly like a fully confined one.
    ///
    /// So the waiver is never automatic. A caller names the protections, in the
    /// mechanism's own vocabulary, and this backend:
    ///
    /// * writes them into every launch, including the discovery probes, so the
    ///   posture that was measured is the posture that runs;
    /// * reports any capability domain the waiver removes as unsupported, so a
    ///   requirement that needed it is refused rather than silently unmet; and
    /// * records the waiver in evidence, on every run, as
    ///   [`ClaimTerm::Degraded`].
    ///
    /// Passing an empty slice is the strict default and is what
    /// [`discover`](Self::discover) does.
    pub fn discover_authorising_degraded(protections: &[&str]) -> Self {
        let degraded: Vec<String> = protections.iter().map(|p| (*p).to_string()).collect();
        let degraded_flags: Vec<String> = degraded
            .iter()
            .flat_map(|p| [FLAG_ALLOW_DEGRADED.to_string(), p.clone()])
            .collect();
        match HostFacts::discover() {
            Ok(facts) => {
                let probe = probe::measure(&facts, &degraded_flags);
                let capabilities = capability::discover(&facts, &probe, &degraded);
                let identity = identity_for(facts.version());
                let mut backend = Self::assemble(identity, capabilities, Some(facts), probe);
                backend.degraded = degraded;
                backend.degraded_flags = degraded_flags;
                backend
            }
            Err(error) => Self::unavailable(&error),
        }
    }

    /// Build a backend from measurements the caller already took.
    ///
    /// `pub(crate)` on purpose. Every field it accepts is something the rest of
    /// this crate *measures*; a public constructor would let a caller hand in a
    /// [`ConfinementProbe`] that says "denied" without anything having been
    /// denied, which is the one input that turns a capability report into a
    /// permission to claim prevention.
    #[cfg(test)]
    pub(crate) fn from_measured(facts: HostFacts, probe: ConfinementProbe) -> Self {
        let capabilities = capability::discover(&facts, &probe, &[]);
        let identity = identity_for(facts.version());
        Self::assemble(identity, capabilities, Some(facts), probe)
    }

    /// The protections a caller waived, if any.
    pub fn authorised_degraded_protections(&self) -> &[String] {
        &self.degraded
    }

    /// A backend that cannot be used here, carrying the reason.
    pub fn unavailable(error: &BackendLookupError) -> Self {
        let reason = error.to_string();
        Self::assemble(
            identity_for("unavailable"),
            capability::unavailable(reason.clone()),
            None,
            ConfinementProbe::unmeasured(reason),
        )
    }

    /// Capture the confined program's output instead of passing it through.
    ///
    /// Off by default: a governed launch is a launch of the operator's program,
    /// and swallowing its output by default would change what running it means.
    /// Tests and callers that need to assert on the output turn it on.
    pub fn with_captured_output(mut self, capture: bool) -> Self {
        self.capture_output = capture;
        self
    }

    fn assemble(
        identity: BackendIdentity,
        capabilities: BackendCapabilities,
        facts: Option<HostFacts>,
        probe: ConfinementProbe,
    ) -> Self {
        Self {
            identity,
            capabilities,
            facts,
            probe,
            degraded: Vec::new(),
            degraded_flags: Vec::new(),
            capture_output: false,
            prepared: Mutex::new(HashMap::new()),
            running: Mutex::new(HashMap::new()),
            completed: Mutex::new(HashMap::new()),
            next_token: AtomicU64::new(0),
        }
    }

    /// What the probe established on this host.
    pub fn probe_result(&self) -> &ConfinementProbe {
        &self.probe
    }

    /// The measured host facts, or `None` when the backend is unavailable.
    pub fn host(&self) -> Option<&HostFacts> {
        self.facts.as_ref()
    }

    /// The command line a prepared execution will run, for `--dry-run` output
    /// and for tests that assert argv is passed as argv.
    pub fn command_line(&self, prepared: &PreparedExecution) -> Option<Vec<String>> {
        let held = self.prepared.lock().expect("backend state poisoned");
        held.get(prepared.token()).map(|p| p.argv.args().to_vec())
    }

    /// Wait for a launched run to finish.
    ///
    /// Separate from [`IsolationBackend::spawn`] because the contract's five
    /// stages end at "hand the process off": a supervisor that blocked inside
    /// `spawn` could not be the thing that stays outside the boundary while the
    /// agent runs.
    ///
    /// # Errors
    ///
    /// [`SpawnError::Spawn`] when the handle names no running execution, or the
    /// wait itself fails.
    pub fn wait(&self, handle: &ExecutionHandle) -> Result<CompletedRun, SpawnError> {
        let child = self
            .running
            .lock()
            .expect("backend state poisoned")
            .remove(handle.token());
        let Some(child) = child else {
            // Already waited for: return the recorded result rather than
            // pretending the run never happened.
            return self
                .completed
                .lock()
                .expect("backend state poisoned")
                .get(handle.token())
                .cloned()
                .ok_or_else(|| SpawnError::Spawn {
                    detail: format!("no running execution for handle `{}`", handle.token()),
                });
        };
        let output = child.wait_with_output().map_err(|e| SpawnError::Spawn {
            detail: format!("waiting for the confined run failed: {e}"),
        })?;
        let completed = CompletedRun {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        self.completed
            .lock()
            .expect("backend state poisoned")
            .insert(handle.token().to_string(), completed.clone());
        Ok(completed)
    }

    fn issue_token(&self) -> String {
        format!("{BACKEND_ID}-{}", self.next_token.fetch_add(1, Ordering::Relaxed))
    }
}

/// The identity every plan and every evidence object carries.
fn identity_for(version: &str) -> BackendIdentity {
    BackendIdentity {
        id: BACKEND_ID.to_string(),
        version: version.to_string(),
        provenance: Provenance {
            source: SOURCE_URL.to_string(),
            license: SPDX_LICENSE.to_string(),
            // AASM carries no patches: the mechanism is an external executable
            // the operator installs, and nothing in this repository rebuilds or
            // modifies it. Flipping this to `true` is a statement-of-changes
            // obligation under Apache-2.0 §4(b), which is why it is a measured
            // fact and not a default.
            modified: false,
        },
    }
}

impl IsolationBackend for SandlockBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity.clone()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    fn plan(&self, spec: &ExecutionSpec) -> Result<EnforcementPlan, PlanRefusal> {
        // Narrowing describes this spec's requirements more precisely; the
        // decision about what a narrowed report permits stays in `negotiate`.
        let capabilities = capability::narrow_for(&self.capabilities, spec);
        negotiate(
            spec,
            &self.identity,
            &capabilities,
            &|requirement, outcome| match lower_requirement(requirement) {
                Ok(lowered) if emits_flags(outcome) => Lowering::new(lowered.steps),
                Ok(lowered) => {
                    let mut steps = lowered.steps;
                    steps.push(format!(
                        "{}: the requirement fell short, so no grant is emitted for it. The mechanism is \
                         default-deny, so an absent grant is stricter than the requirement asked for, \
                         never weaker",
                        requirement.domain()
                    ));
                    Lowering::new(steps)
                }
                Err(gap) => Lowering::new([format!("{}: not expressible — {}", gap.domain, gap.reason)]),
            },
        )
    }

    fn prepare(&self, plan: EnforcementPlan) -> Result<PreparedExecution, SpawnError> {
        if plan.backend().id != self.identity.id {
            return Err(SpawnError::BackendMismatch {
                expected: self.identity.id.clone(),
                found: plan.backend().id.clone(),
            });
        }
        // An unavailable host cannot reach here through `plan`, which refuses
        // first. Checking again is not redundant: `prepare` is public and takes
        // a plan, so nothing stops a caller carrying one in from elsewhere.
        if self.facts.is_none() {
            return Err(SpawnError::Prepare {
                detail: "the backend is not available on this host; no boundary can be established".to_string(),
            });
        }

        let mut confinement = Vec::new();
        for planned in plan.planned() {
            if !emits_flags(&planned.outcome) {
                continue;
            }
            let lowered = lower_requirement(&planned.requirement).map_err(|gap| SpawnError::Prepare {
                detail: format!(
                    "the plan accepted a `{}` requirement this backend cannot express ({}); refusing \
                     rather than launching without it",
                    gap.domain, gap.reason
                ),
            })?;
            confinement.extend(lowered.flags);
        }
        confinement.extend(credential_flags(plan.spec()));
        // Last, so a waiver is visible at the end of the command line rather
        // than buried among the grants, and so it is impossible for a grant to
        // be silently dropped in favour of one.
        confinement.extend(self.degraded_flags.iter().cloned());

        let residual_authority = residual_authority(plan.spec());
        let argv = build_argv(plan.spec(), confinement);
        let token = self.issue_token();
        self.prepared.lock().expect("backend state poisoned").insert(
            token.clone(),
            Prepared {
                plan: plan.clone(),
                argv,
                residual_authority,
            },
        );
        Ok(PreparedExecution::new(plan, token))
    }

    fn spawn(&self, prepared: PreparedExecution) -> Result<ExecutionHandle, SpawnError> {
        if prepared.plan().backend().id != self.identity.id {
            return Err(SpawnError::BackendMismatch {
                expected: self.identity.id.clone(),
                found: prepared.plan().backend().id.clone(),
            });
        }
        let Some(facts) = self.facts.as_ref() else {
            return Err(SpawnError::Spawn {
                detail: "the backend is not available on this host".to_string(),
            });
        };
        let argv = {
            let held = self.prepared.lock().expect("backend state poisoned");
            let Some(entry) = held.get(prepared.token()) else {
                return Err(SpawnError::Spawn {
                    detail: format!("no prepared boundary for token `{}`", prepared.token()),
                });
            };
            entry.argv.clone()
        };

        // THE ONLY LAUNCH. The program under governance is an argument here,
        // never the executable. Every element of `argv` is pushed whole, so no
        // caller-supplied value is ever parsed by anything.
        let mut command = Command::new(facts.executable());
        for arg in argv.args() {
            command.arg(arg);
        }
        command.stdin(Stdio::null());
        if self.capture_output {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let child = command.spawn().map_err(|e| SpawnError::Spawn {
            detail: format!(
                "the confinement executable `{}` could not be started: {e}. No process was started \
                 outside the boundary",
                facts.executable().display()
            ),
        })?;

        let handle = ExecutionHandle::new(self.identity.clone(), prepared.token(), prepared.plan().posture());
        self.running
            .lock()
            .expect("backend state poisoned")
            .insert(prepared.token().to_string(), child);
        Ok(handle)
    }

    fn evidence(&self, handle: &ExecutionHandle) -> EnforcementEvidence {
        let held = self.prepared.lock().expect("backend state poisoned");
        let Some(entry) = held.get(handle.token()) else {
            return EnforcementEvidence::new(self.identity.clone(), handle.posture()).with_record(
                EvidenceRecord::about_run(
                    EvidenceKind::Configured,
                    ClaimTerm::Unmeasured,
                    "no prepared boundary is recorded for this handle",
                ),
            );
        };
        let mut evidence = EnforcementEvidence::from_plan(&entry.plan);

        // Installed: the flags were on the command line the mechanism accepted,
        // and the mechanism applies them before it executes the program. Not a
        // claim that anything was decided — `EvidenceKind::Installed` is
        // ignored by every prevention predicate for exactly that reason.
        for planned in entry.plan.planned() {
            if !emits_flags(&planned.outcome) {
                continue;
            }
            evidence.record(EvidenceRecord::new(
                EvidenceKind::Installed,
                planned.requirement.domain(),
                ClaimTerm::Planned,
                format!(
                    "the confinement flags for this domain were on the command line the mechanism \
                     accepted before it executed the program ({} lowering step(s))",
                    planned.lowering.steps().len()
                ),
            ));
        }

        // The residue, always, including when it is empty — a run whose evidence
        // is silent about ambient authority reads as a run that had none.
        evidence.record(EvidenceRecord::new(
            EvidenceKind::Installed,
            CapabilityDomain::Credential,
            ClaimTerm::Planned,
            if entry.residual_authority.is_empty() {
                "residual authority reaching the confined program: none beyond the three standard \
                 descriptors, which are delegated by design"
                    .to_string()
            } else {
                format!(
                    "residual authority reaching the confined program: {}",
                    entry.residual_authority.join(", ")
                )
            },
        ));

        if !self.degraded.is_empty() {
            // Every run, not only the ones that hit the waived protection. A
            // record that appeared only when the waiver mattered would be
            // absent from exactly the runs an auditor reads to establish that
            // it did not.
            evidence.record(EvidenceRecord::about_run(
                EvidenceKind::Configured,
                ClaimTerm::Degraded,
                format!(
                    "the launch waived {} protection(s) the host kernel cannot provide, by explicit \
                     authorisation: {}. The mechanism applies a waiver silently and reports nothing \
                     about it, so this record is the only trace",
                    self.degraded.len(),
                    self.degraded.join(", ")
                ),
            ));
        }

        if let Some(completed) = self
            .completed
            .lock()
            .expect("backend state poisoned")
            .get(handle.token())
        {
            // `Exercised`, not `Decision`. That the program ran inside the
            // boundary is a fact about the run; that any control decided
            // something is not derivable from it, and this backend has no
            // channel that would tell it. See the module documentation.
            evidence.record(EvidenceRecord::about_run(
                EvidenceKind::Exercised,
                ClaimTerm::Observed,
                format!(
                    "the program ran inside the boundary and exited with {}. The mechanism reports no \
                     per-decision record to the supervisor, so no control's decision is claimed here",
                    completed.status
                ),
            ));
        }

        evidence
    }
}

/// Whether an outcome means the backend should emit this requirement's flags.
///
/// Shortfalls emit nothing. Because the mechanism is default-deny, an absent
/// grant is the *strictest* posture available, so omitting a degraded
/// requirement's grants can only narrow the boundary. The reverse convention —
/// emitting a partial grant for a requirement that fell short — would widen it
/// on exactly the launches that already failed to get what policy asked for.
fn emits_flags(outcome: &RequirementOutcome) -> bool {
    matches!(
        outcome,
        RequirementOutcome::Enforced { .. } | RequirementOutcome::Observed { .. }
    )
}

/// Authority reaching the confined program that this backend did not remove.
///
/// Always includes the standard descriptors, because they are inherited by
/// design and an operator reading evidence should see them named rather than
/// have to know they are implied.
fn residual_authority(spec: &ExecutionSpec) -> Vec<String> {
    let mut residual: Vec<String> = unremoved_ambient(spec)
        .into_iter()
        .map(|name| {
            format!(
                "environment variable `{name}` (policy asked for its removal; this launch \
                             delegates no environment, so nothing was replaced)"
            )
        })
        .collect();
    if credential_flags(spec).is_empty() {
        residual.push(
            "the whole launching environment, inherited: the spec's credential posture named nothing to \
             remove or delegate, so no environment replacement was requested"
                .to_string(),
        );
    }
    residual
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_isolation::{ControlRequirement, IdentityRef, RequirementPosture};

    fn spec() -> ExecutionSpec {
        ExecutionSpec::new("/bin/echo", IdentityRef::root("agent-under-test")).with_args(["hello"])
    }

    /// Discovery must never panic and never leave the caller without a usable
    /// object, on any host — including this one, whatever it is.
    #[test]
    fn discovery_always_yields_a_backend() {
        let backend = SandlockBackend::discover();
        assert_eq!(backend.identity().id, BACKEND_ID);
        assert_eq!(backend.identity().provenance.license, SPDX_LICENSE);
    }

    /// On a host without the mechanism, the refusal has to come from `plan` —
    /// before anything is prepared and long before anything is spawned.
    #[test]
    fn an_unavailable_host_refuses_at_plan_time() {
        let backend = SandlockBackend::unavailable(&BackendLookupError::NotOnPath);
        let spec = spec().with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        let refusal = backend.plan(&spec).expect_err("an unavailable backend must refuse");
        assert!(
            refusal.backend_unavailable().is_some(),
            "the refusal must name the host-level reason: {refusal:?}"
        );
    }

    /// A refusal is not a failure, and the evidence for one has to be
    /// constructible — E6 needs to see that a launch was stopped.
    #[test]
    fn a_refusal_becomes_evidence_with_no_prevention_claim() {
        let backend = SandlockBackend::unavailable(&BackendLookupError::NotOnPath);
        let spec = spec().with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        let refusal = backend.plan(&spec).expect_err("refused");
        let evidence = EnforcementEvidence::from_refusal(&refusal);
        assert_eq!(evidence.posture(), aa_isolation::LaunchPosture::Refused);
        assert!(!evidence.supports_prevention_claim(CapabilityDomain::FilesystemWrite));
    }

    /// A required syscall requirement must refuse on every host, because the
    /// domain is unsupported by construction rather than by measurement. This
    /// is the one refusal that does not depend on the host, so it is the one
    /// that can be asserted anywhere.
    #[test]
    fn a_required_syscall_requirement_refuses_everywhere() {
        let backend = SandlockBackend::from_measured(broken_host(), denied_everything());
        let spec = spec().with_requirement(ControlRequirement::prevent(CapabilityDomain::Syscall).with_scope(
            aa_isolation::RequirementScope::Selectors(vec![aa_isolation::permit_only_selector("read")]),
        ));
        let refusal = backend
            .plan(&spec)
            .expect_err("a permitted syscall set is not expressible");
        assert!(
            refusal
                .reasons()
                .iter()
                .any(|r| r.domain() == Some(CapabilityDomain::Syscall)),
            "{refusal:?}"
        );
    }

    /// An optional requirement for the same domain must *not* refuse — the
    /// control for the test above. Without it, the refusal could be coming from
    /// something other than the requirement's posture.
    #[test]
    fn an_optional_syscall_requirement_does_not_refuse_the_launch() {
        let backend = SandlockBackend::from_measured(broken_host(), denied_everything());
        let spec = spec().with_requirement(
            ControlRequirement::prevent(CapabilityDomain::Syscall)
                .with_posture(RequirementPosture::Optional)
                .with_scope(aa_isolation::RequirementScope::Selectors(vec![
                    aa_isolation::permit_only_selector("read"),
                ])),
        );
        let plan = backend
            .plan(&spec)
            .expect("an optional requirement never refuses the launch");
        assert_eq!(plan.posture(), aa_isolation::LaunchPosture::Degraded);
        assert_eq!(plan.shortfalls().count(), 1);
    }

    /// A plan from one backend must not be preparable by another.
    #[test]
    fn a_foreign_plan_is_rejected_rather_than_prepared() {
        let backend = SandlockBackend::from_measured(broken_host(), denied_everything());
        let other = BackendIdentity {
            id: "somebody-else".to_string(),
            version: "1".to_string(),
            provenance: Provenance {
                source: "test".to_string(),
                license: "Apache-2.0".to_string(),
                modified: false,
            },
        };
        let capabilities = capability::discover(&broken_host(), &denied_everything(), &[]);
        let foreign = negotiate(&writing_spec("/tmp/never"), &other, &capabilities, &|_, _| {
            Lowering::none()
        })
        .expect("a measured capability set accepts the plan");
        let error = backend
            .prepare(foreign)
            .expect_err("a plan from another backend must not be prepared");
        assert!(matches!(error, SpawnError::BackendMismatch { .. }), "{error:?}");
    }

    /// **The negative control for "no silent unconfined fallback".**
    ///
    /// The backend is pointed at a confinement executable that does not exist.
    /// Planning and preparation both succeed — the capabilities were measured,
    /// so there is nothing to refuse — and only the launch fails. The assertion
    /// is not that an error came back: it is that the *effect the program would
    /// have had did not happen*. A fallback that quietly ran the program
    /// outside the boundary would leave the file behind, and this test would
    /// fail.
    #[test]
    fn a_broken_backend_executable_produces_no_process_at_all() {
        let scratch = std::env::temp_dir().join(format!("aa-sandlock-fallback-{}", std::process::id()));
        let _ = std::fs::remove_file(&scratch);
        let backend = SandlockBackend::from_measured(broken_host(), denied_everything());
        let spec = writing_spec(&scratch.to_string_lossy());

        let plan = backend.plan(&spec).expect("a measured backend plans this spec");
        let prepared = backend
            .prepare(plan)
            .expect("preparation builds a command line, it does not run it");
        let error = backend
            .spawn(prepared)
            .expect_err("a confinement executable that does not exist cannot launch anything");

        assert!(matches!(error, SpawnError::Spawn { .. }), "{error:?}");
        assert!(
            !scratch.exists(),
            "the program ran even though the boundary could not be established: {} exists",
            scratch.display()
        );
    }

    /// The single most important thing an out-of-process backend must not do:
    /// turn "the program ran" into "the control decided".
    #[test]
    fn no_run_of_this_backend_supports_a_prevention_claim() {
        let backend = SandlockBackend::from_measured(broken_host(), denied_everything());
        let spec = writing_spec("/tmp/never");
        let plan = backend.plan(&spec).expect("planned");
        let prepared = backend.prepare(plan).expect("prepared");
        let handle = ExecutionHandle::new(backend.identity(), prepared.token(), prepared.plan().posture());
        let evidence = backend.evidence(&handle);

        assert!(
            evidence.records().iter().any(|r| r.kind == EvidenceKind::Installed),
            "an installed control must be recorded: {:?}",
            evidence.records()
        );
        for domain in CapabilityDomain::ALL {
            assert!(
                !evidence.supports_prevention_claim(*domain),
                "{domain} produced a prevention claim from a run with no decision record"
            );
        }
        assert!(
            !evidence.records().iter().any(|r| r.kind == EvidenceKind::Decision),
            "this backend has no per-decision channel and must emit no Decision record"
        );
    }

    /// Residual authority is recorded on every run, including when there is
    /// none — silence about ambient authority reads as an absence of it.
    #[test]
    fn residual_authority_is_always_recorded() {
        let backend = SandlockBackend::from_measured(broken_host(), denied_everything());
        let plan = backend.plan(&writing_spec("/tmp/never")).expect("planned");
        let prepared = backend.prepare(plan).expect("prepared");
        let handle = ExecutionHandle::new(backend.identity(), prepared.token(), prepared.plan().posture());
        let evidence = backend.evidence(&handle);
        assert!(
            evidence
                .records_for(CapabilityDomain::Credential)
                .any(|r| r.detail.contains("residual authority")),
            "{:?}",
            evidence.records()
        );
    }

    /// The command line must put the caller's program after the separator and
    /// the confinement executable outside the argument vector entirely.
    #[test]
    fn the_prepared_command_line_confines_rather_than_executes_the_program() {
        let backend = SandlockBackend::from_measured(broken_host(), denied_everything());
        let plan = backend.plan(&writing_spec("/tmp/never")).expect("planned");
        let prepared = backend.prepare(plan).expect("prepared");
        let argv = backend
            .command_line(&prepared)
            .expect("a prepared boundary has a command line");
        assert_eq!(argv[0], "run");
        let separator = argv
            .iter()
            .position(|a| a == "--")
            .expect("a separator is always emitted");
        assert_eq!(argv[separator + 1], "/bin/sh");
        assert!(
            !argv[..separator].contains(&"/bin/sh".to_string()),
            "the program leaked into the confinement flags: {argv:?}"
        );
    }

    /// A waiver must never appear unless someone authorised it, and must appear
    /// in evidence when they did. The pair is the control.
    #[test]
    fn a_protection_waiver_appears_only_when_authorised_and_is_always_recorded() {
        let strict = SandlockBackend::from_measured(broken_host(), denied_everything());
        let plan = strict.plan(&writing_spec("/tmp/never")).expect("planned");
        let prepared = strict.prepare(plan).expect("prepared");
        let argv = strict.command_line(&prepared).expect("command line");
        assert!(
            !argv.contains(&FLAG_ALLOW_DEGRADED.to_string()),
            "an unauthorised waiver reached the command line: {argv:?}"
        );

        let mut waived = SandlockBackend::from_measured(broken_host(), denied_everything());
        waived.degraded = vec![crate::capability::ABSTRACT_UNIX_SOCKET_SCOPE.to_string()];
        waived.degraded_flags = vec![
            FLAG_ALLOW_DEGRADED.to_string(),
            crate::capability::ABSTRACT_UNIX_SOCKET_SCOPE.to_string(),
        ];
        let plan = waived.plan(&writing_spec("/tmp/never")).expect("planned");
        let prepared = waived.prepare(plan).expect("prepared");
        let argv = waived.command_line(&prepared).expect("command line");
        assert!(argv.contains(&FLAG_ALLOW_DEGRADED.to_string()), "{argv:?}");

        let handle = ExecutionHandle::new(waived.identity(), prepared.token(), prepared.plan().posture());
        let evidence = waived.evidence(&handle);
        assert!(
            evidence
                .records()
                .iter()
                .any(|r| r.claim == ClaimTerm::Degraded && r.detail.contains("waived")),
            "an authorised waiver must be recorded: {:?}",
            evidence.records()
        );
    }

    /// A waived protection removes the domain it covered, rather than leaving
    /// it reported as partially supported.
    #[test]
    fn waiving_the_socket_scope_removes_the_ipc_domain() {
        let capabilities = capability::discover(
            &broken_host(),
            &denied_everything(),
            &[crate::capability::ABSTRACT_UNIX_SOCKET_SCOPE.to_string()],
        );
        let report = capabilities.report_for(CapabilityDomain::Ipc).expect("reported");
        assert!(matches!(
            report.support(),
            aa_isolation::SupportLevel::Unsupported { .. }
        ));
        assert!(!report.can_prevent());
    }

    // ---- fixtures ---------------------------------------------------------

    /// Host facts naming a confinement executable that is not there.
    ///
    /// Used by the launch tests: everything up to the launch is real, and the
    /// launch is the only thing that fails.
    fn broken_host() -> HostFacts {
        HostFacts::for_test(
            "/nonexistent/aa-sandlock-test-binary",
            "sandlock 0.0.0-test",
            Some(crate::host::KernelVersion { major: 6, minor: 12 }),
        )
        .with_landlock_abi(Some(6))
    }

    /// A probe that observed every measurable denial, so the capability reports
    /// permit a plan and the tests above exercise the launch path rather than
    /// the refusal path.
    fn denied_everything() -> ConfinementProbe {
        ConfinementProbe {
            filesystem_read: crate::probe::Observation::Denied,
            filesystem_write: crate::probe::Observation::Denied,
            process_ceiling: crate::probe::Observation::Denied,
            network_egress: crate::probe::Observation::Denied,
        }
    }

    /// A spec whose program creates `target`, so its effect is observable from
    /// outside the boundary.
    fn writing_spec(target: &str) -> ExecutionSpec {
        ExecutionSpec::new("/bin/sh", IdentityRef::root("agent-under-test"))
            .with_args(["-c", &format!("printf x > {target}")])
            .with_requirement(
                ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_scope(
                    aa_isolation::RequirementScope::Selectors(vec![aa_isolation::permit_only_selector("/tmp")]),
                ),
            )
    }
}
