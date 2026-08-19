//! The backend itself: discovery, planning, preparation, launch and evidence.
//!
//! # The single launch path
//!
//! There is exactly one place in this crate that starts the caller's program, and
//! it always starts it as an argument of the launcher binary. There is no branch
//! that constructs a [`Command`] from [`ExecutionSpec::program`] directly, and no
//! error arm that falls back to one. A preparation or launch failure returns
//! [`SpawnError`] and produces no process at all, and the launcher itself refuses
//! without executing anything if the boundary cannot be installed.
//!
//! That is ADR 0035's "no silent unconfined fallback" held structurally rather
//! than by discipline, and
//! [`tests::a_missing_launcher_produces_no_process_at_all`] is the negative
//! control: it points the backend at a path that cannot execute and asserts that
//! the effect the program would have had did not happen.
//!
//! # What a run of this backend can and cannot claim
//!
//! [`EnforcementEvidence::supports_prevention_claim`] is false for every domain
//! after every ordinary run, and that is correct rather than a defect to be
//! worked around. The confinement is enforced by the kernel against the confined
//! process; the denial is delivered to *that* process as an error return, and
//! this supervisor has no channel that reports it back. So this backend can say a
//! control was configured, that it was installed before the program started, and
//! that the program ran — the three grades that are honest — and it cannot say
//! the control decided anything.
//!
//! ADR 0035's AAASM-5801 amendment records this as a decision rather than a
//! shortfall: a seccomp user-notification channel "could earn a stronger claim
//! later — the supervisor would then receive a synchronous notification per
//! filtered syscall rather than only configuring a filter the kernel enforces
//! unobserved — but that is explicitly deferred". Until such a channel exists,
//! the absence is the finding, and manufacturing a `Decision` record from "the
//! program exited non-zero" would be exactly the promotion the contract is built
//! to prevent.

use std::collections::{BTreeMap, HashMap};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aa_core::attestation::ClaimTerm;
use aa_isolation::{
    negotiate, BackendCapabilities, BackendIdentity, CapabilityDomain, DescriptorInventory, EnforcementEvidence,
    EnforcementPlan, EvidenceKind, EvidenceRecord, ExecutionHandle, ExecutionSpec, ExitDisposition, IsolationBackend,
    Lowering, PlanRefusal, PreparedExecution, Provenance, RequirementOutcome, SpawnError, TerminationRequest,
};

use crate::capability;
use crate::host::{HostFacts, HostUnusable};
use crate::inherit::seal_inherited_descriptors;
use crate::launch::{self, Grants};
use crate::lower::{lower_requirement, unremoved_ambient};
use crate::probe::{self, ConfinementProbe};
use crate::rules::{self, RulePlan};

/// The stable machine identifier this backend answers to.
///
/// Names the backend, not the kernel mechanism it configures. ADR 0035 decision 3,
/// reaffirmed by the AAASM-5801 amendment, keeps "Landlock" and "seccomp" out of
/// any value a policy or a CLI invocation authors directly — including this one,
/// which `--isolation-backend` accepts.
pub const BACKEND_ID: &str = "aasm-native";

/// Where the backend implementation comes from.
///
/// Unlike the Sandlock backend, this is AASM's own source: there is no external
/// executable to record provenance for, and the launcher this crate ships is
/// built from this repository. The third-party surface is the kernel binding
/// crate, recorded in [`BINDING_CRATE`] and in every run's evidence, and covered
/// by `cargo deny check` because it is in the cargo dependency graph.
pub const SOURCE_URL: &str = "https://github.com/ai-agent-assembly/agent-assembly";

/// SPDX identifier of the backend implementation — this repository's own licence.
pub const SPDX_LICENSE: &str = "Apache-2.0";

/// The kernel-binding crate this backend configures the mechanism through, with
/// the licence verified before it was pinned (ADR 0035 decision 11).
///
/// Recorded on every run rather than only in the manifest: an operator reading an
/// evidence record needs to know which third-party code stood between AASM and
/// the kernel, and a `Cargo.toml` is not part of a run.
pub const BINDING_CRATE: &str = "landlock (crates.io), MIT OR Apache-2.0, upstream \
                                 https://github.com/landlock-lsm/rust-landlock";

/// What the boundary was going to be when this backend was asked about it.
#[derive(Debug)]
struct Prepared {
    plan: EnforcementPlan,
    argv: Vec<String>,
    rules: RulePlan,
    residual_authority: Vec<String>,
    /// Taken in `prepare`, not in `evidence`: the descriptors that matter are the
    /// ones open at the moment the boundary was built, and an inventory taken
    /// later would describe a different process.
    descriptors: DescriptorInventory,
}

/// A finished run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedRun {
    /// The confined program's exit status, as the operating system reported it.
    pub status: ExitStatus,
    /// Everything the run wrote to standard output, when the backend was
    /// configured to capture it.
    pub stdout: String,
    /// Everything the run wrote to standard error, when the backend was
    /// configured to capture it.
    pub stderr: String,
}

impl CompletedRun {
    /// Whether the launcher refused to establish the boundary and therefore
    /// executed nothing.
    ///
    /// Reads the marker line rather than the exit code: the program the launcher
    /// would have executed is free to exit with the same number, and an exit code
    /// is a channel shared with untrusted code. `false` when output was not
    /// captured, which is why every caller of this treats it as *evidence that a
    /// refusal happened* and never as evidence that one did not.
    pub fn launcher_refused(&self) -> bool {
        self.stderr.contains(launch::FAILURE_MARKER)
    }
}

/// The AASM-native Linux process-isolation backend.
#[derive(Debug)]
pub struct NativeBackend {
    identity: BackendIdentity,
    capabilities: BackendCapabilities,
    facts: Option<HostFacts>,
    probe: ConfinementProbe,
    capture_output: bool,
    /// The exact environment the confined program is to receive, when the caller
    /// computed one. `None` means the launcher — and therefore the program it
    /// becomes — inherits this process's environment.
    child_environment: Option<BTreeMap<String, String>>,
    prepared: Mutex<HashMap<String, Prepared>>,
    running: Mutex<HashMap<String, Child>>,
    /// The launcher's process id per token, kept separately from
    /// [`Self::running`] because [`Self::wait`] has to take the `Child` by value
    /// to reap it. Without this, a termination request arriving while a supervisor
    /// was already waiting would find nothing to signal — which is exactly the
    /// interleaving a `Ctrl-C` produces.
    pids: Mutex<HashMap<String, u32>>,
    completed: Mutex<HashMap<String, CompletedRun>>,
    next_token: AtomicU64,
}

impl NativeBackend {
    /// Discover the host and measure what the boundary actually does here.
    ///
    /// Never fails. A host where the launcher is absent, the platform is wrong, or
    /// the kernel is below the measured floor produces a backend whose
    /// availability is `Unavailable`, so the refusal happens in
    /// [`IsolationBackend::plan`] — before any program is started — rather than as
    /// a surprise at launch.
    ///
    /// Costs one version query plus the controlled pairs in [`crate::probe`],
    /// once.
    pub fn discover() -> Self {
        Self::from_host(HostFacts::discover())
    }

    /// Discover against a launcher the caller already has.
    ///
    /// Identical to [`discover`](Self::discover) except for where the launcher
    /// comes from — every capability verdict still comes from the live probe. See
    /// [`HostFacts::discover_with_launcher`] for why this is public.
    pub fn discover_with_launcher(launcher: impl Into<std::path::PathBuf>) -> Self {
        Self::from_host(HostFacts::discover_with_launcher(launcher))
    }

    fn from_host(host: Result<HostFacts, HostUnusable>) -> Self {
        match host {
            Ok(facts) => {
                let probe = probe::measure(&facts);
                let capabilities = capability::discover(&facts, &probe);
                Self::assemble(identity(), capabilities, Some(facts), probe)
            }
            Err(error) => Self::unavailable(&error),
        }
    }

    /// A backend that cannot be used here, carrying the reason.
    pub fn unavailable(error: &HostUnusable) -> Self {
        let reason = error.to_string();
        Self::assemble(
            identity(),
            capability::unavailable(reason.clone()),
            None,
            ConfinementProbe::unmeasured(reason),
        )
    }

    /// Build a backend from measurements the caller already took.
    ///
    /// `pub(crate)` and test-only on purpose. Every field it accepts is something
    /// the rest of this crate *measures*; a public constructor would let a caller
    /// hand in a [`ConfinementProbe`] that says "denied" without anything having
    /// been denied, which is the one input that turns a capability report into a
    /// permission to claim prevention.
    #[cfg(test)]
    pub(crate) fn from_measured(facts: HostFacts, probe: ConfinementProbe) -> Self {
        let capabilities = capability::discover(&facts, &probe);
        Self::assemble(identity(), capabilities, Some(facts), probe)
    }

    /// Capture the confined program's output instead of passing it through.
    ///
    /// Off by default: a governed launch is a launch of the operator's program,
    /// and swallowing its output by default would change what running it means.
    pub fn with_captured_output(mut self, capture: bool) -> Self {
        self.capture_output = capture;
        self
    }

    /// Install `env` as the confined program's **entire** environment.
    ///
    /// A setter rather than a `with_`-style builder because the caller that has
    /// the environment is not the caller that selected the backend: `aasm run`
    /// selects one while resolving the launch — early, so an unavailable host
    /// refuses before anything is registered — and only computes the child
    /// environment once an identity exists to put in it.
    ///
    /// # Why the values never travel on a command line
    ///
    /// The map is applied to the launcher process with `env_clear` plus these
    /// names, and `execve` carries the result into the confined program. Nothing
    /// is passed as an argument, so a credential value never appears in
    /// `/proc/<pid>/cmdline`, which every other process on the host can read.
    ///
    /// The map is applied verbatim. Precedence was already decided by whoever
    /// built it; re-deciding it here would be a second implementation of the
    /// merge.
    pub fn set_child_environment(&mut self, env: BTreeMap<String, String>) {
        self.child_environment = Some(env);
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
            capture_output: false,
            child_environment: None,
            prepared: Mutex::new(HashMap::new()),
            running: Mutex::new(HashMap::new()),
            pids: Mutex::new(HashMap::new()),
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

    /// The command line a prepared execution will run, for `--dry-run` output and
    /// for tests that assert argv is passed as argv.
    pub fn command_line(&self, prepared: &PreparedExecution) -> Option<Vec<String>> {
        let held = self.prepared.lock().expect("backend state poisoned");
        held.get(prepared.token()).map(|p| p.argv.clone())
    }

    /// The kernel rules a prepared execution will install.
    ///
    /// Exposed so a test can assert on the *boundary* rather than on the argument
    /// vector that encodes it — the two are different claims, and a rule plan that
    /// silently changed shape would still produce a plausible command line.
    pub fn rule_plan(&self, prepared: &PreparedExecution) -> Option<RulePlan> {
        let held = self.prepared.lock().expect("backend state poisoned");
        held.get(prepared.token()).map(|p| p.rules.clone())
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
    /// [`SpawnError::Supervision`] when the handle names no running execution, or
    /// the wait itself fails. Not [`SpawnError::Spawn`]: by the time this is
    /// called something was started, and reporting a lost wait as a failed launch
    /// would tell an operator no process exists at the moment one does.
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
                .ok_or_else(|| SpawnError::Supervision {
                    detail: format!("no running execution for handle `{}`", handle.token()),
                });
        };
        let output = child.wait_with_output().map_err(|e| SpawnError::Supervision {
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
fn identity() -> BackendIdentity {
    BackendIdentity {
        id: BACKEND_ID.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        provenance: Provenance {
            source: SOURCE_URL.to_string(),
            license: SPDX_LICENSE.to_string(),
            // This backend is AASM's own code and carries no vendored or patched
            // third-party implementation: the kernel primitive is the kernel's,
            // and the binding crate is consumed unmodified from crates.io.
            modified: false,
        },
    }
}

/// Collect the permitted path scope every enforced requirement contributes.
///
/// Shortfalls contribute nothing. Because the mechanism is default-deny, an
/// absent grant is the *strictest* posture available, so omitting a degraded
/// requirement's paths can only narrow the boundary. The reverse convention —
/// granting for a requirement that fell short — would widen it on exactly the
/// launches that already failed to get what policy asked for.
fn grants_for(plan: &EnforcementPlan) -> Result<Grants, SpawnError> {
    let mut grants = Grants::default();
    for planned in plan.planned() {
        if !emits_grants(&planned.outcome) {
            continue;
        }
        let lowered = lower_requirement(&planned.requirement).map_err(|gap| SpawnError::Prepare {
            detail: format!(
                "the plan accepted a `{}` requirement this backend cannot express ({}); refusing rather \
                 than launching without it",
                gap.domain, gap.reason
            ),
        })?;
        grants.read.extend(lowered.grants.read);
        grants.write.extend(lowered.grants.write);
    }
    Ok(grants)
}

/// Whether an outcome means the backend should grant this requirement's paths.
fn emits_grants(outcome: &RequirementOutcome) -> bool {
    matches!(
        outcome,
        RequirementOutcome::Enforced { .. } | RequirementOutcome::Observed { .. }
    )
}

impl IsolationBackend for NativeBackend {
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
                Ok(lowered) if emits_grants(outcome) => Lowering::new(lowered.steps),
                Ok(lowered) => {
                    let mut steps = lowered.steps;
                    steps.push(format!(
                        "{}: the requirement fell short, so no path is granted for it. The mechanism is \
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
        // first. Checking again is not redundant: `prepare` is public and takes a
        // plan, so nothing stops a caller carrying one in from elsewhere.
        if self.facts.is_none() {
            return Err(SpawnError::Prepare {
                detail: "the backend is not available on this host; no boundary can be established".to_string(),
            });
        }

        let grants = grants_for(&plan)?;
        let rules = rules::plan(&grants);
        // Before the argument vector is built and long before anything is
        // launched: a descriptor marked here cannot cross the `exec` that starts
        // the launcher, and therefore cannot reach the program the launcher
        // becomes.
        let descriptors = seal_inherited_descriptors();
        let residual_authority = residual_authority(plan.spec(), self.child_environment.is_some());
        let argv = launch::build(&grants, plan.spec().program(), plan.spec().args());
        let token = self.issue_token();
        self.prepared.lock().expect("backend state poisoned").insert(
            token.clone(),
            Prepared {
                plan: plan.clone(),
                argv,
                rules,
                residual_authority,
                descriptors,
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

        // THE ONLY LAUNCH. The program under governance is an argument here, never
        // the executable. Every element of `argv` is pushed whole, so no
        // caller-supplied value is ever parsed by anything.
        let mut command = Command::new(facts.launcher());
        for arg in &argv {
            command.arg(arg);
        }
        if let Some(env) = &self.child_environment {
            // Start empty and add back only what the caller resolved: removing
            // named variables from an inherited environment would leave
            // everything nobody thought to name, which is the opposite of least
            // authority.
            command.env_clear();
            command.envs(env);
        }
        if let Some(dir) = prepared.plan().spec().working_dir() {
            command.current_dir(dir);
        }
        command.stdin(Stdio::null());
        if self.capture_output {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let child = command.spawn().map_err(|e| SpawnError::Spawn {
            detail: format!(
                "the launcher `{}` could not be started: {e}. No process was started outside the boundary",
                facts.launcher().display()
            ),
        })?;

        let handle = ExecutionHandle::new(self.identity.clone(), prepared.token(), prepared.plan().posture());
        self.pids
            .lock()
            .expect("backend state poisoned")
            .insert(prepared.token().to_string(), child.id());
        self.running
            .lock()
            .expect("backend state poisoned")
            .insert(prepared.token().to_string(), child);
        Ok(handle)
    }

    /// Block until the launcher's process exits, and report its code.
    ///
    /// The code is the confined program's, because the launcher `execve`s it and
    /// therefore *is* it by the time it exits — with one exception, which is why
    /// [`CompletedRun::launcher_refused`] exists: a launcher that could not
    /// install the boundary never execs and exits
    /// [`launch::EXIT_LAUNCH_REFUSED`] instead. This backend does not guess
    /// between the two from the number alone.
    fn wait_for_exit(&self, handle: &ExecutionHandle) -> Result<ExitDisposition, SpawnError> {
        let completed = self.wait(handle)?;
        Ok(match completed.status.code() {
            Some(code) => ExitDisposition::Code(code),
            None => ExitDisposition::NoCode {
                detail: format!(
                    "the confined run reported `{}`, which carries no exit code; on this platform that is \
                     what a process ended by a signal produces",
                    completed.status
                ),
            },
        })
    }

    /// Deliver a termination request to the confined process.
    ///
    /// The process signalled is the one this backend spawned — the launcher,
    /// which has become the confined program by `execve` and therefore keeps the
    /// same process id. The supervisor holds no identifier *inside* the boundary
    /// beyond that, by design (ADR 0035 §5). Whether the program honours the
    /// request is a fact about untrusted code, which is why `Ok` here promises
    /// delivery and nothing more.
    ///
    /// # Errors
    ///
    /// [`SpawnError::Supervision`] when the handle names no launch of this
    /// backend, when the run has already ended, or — off Linux — when the backend
    /// has no way to deliver one at all.
    fn terminate(&self, handle: &ExecutionHandle, request: TerminationRequest) -> Result<(), SpawnError> {
        if self
            .completed
            .lock()
            .expect("backend state poisoned")
            .contains_key(handle.token())
        {
            return Err(SpawnError::Supervision {
                detail: format!(
                    "the run behind handle `{}` has already ended; a termination request now would name a \
                     process id this backend no longer owns",
                    handle.token()
                ),
            });
        }
        let pid = self
            .pids
            .lock()
            .expect("backend state poisoned")
            .get(handle.token())
            .copied()
            .ok_or_else(|| SpawnError::Supervision {
                detail: format!("no launch of this backend is recorded for handle `{}`", handle.token()),
            })?;
        deliver_termination(pid, request)
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

        // What stood between AASM and the kernel, on every run. A licence and a
        // provenance recorded only in a manifest is not part of a run, and an
        // operator auditing one should not have to find the manifest that built
        // the binary to learn which third-party code configured the boundary.
        evidence.record(EvidenceRecord::about_run(
            EvidenceKind::Configured,
            ClaimTerm::Planned,
            format!(
                "the boundary was configured through {BINDING_CRATE}; the backend itself is this \
                 repository's own code and redistributes no third-party executable"
            ),
        ));

        // What the host was measured to be, always — including the ABI, which is
        // the number every claim below is standing on.
        evidence.record(EvidenceRecord::about_run(
            EvidenceKind::Configured,
            if self.facts.is_some() {
                ClaimTerm::Observed
            } else {
                ClaimTerm::Unmeasured
            },
            match &self.facts {
                Some(facts) => format!("measured host: {}", facts.describe()),
                None => "the host could not be measured; this backend was not available on it".to_string(),
            },
        ));

        // Installed: the rules were on the command line the launcher accepted, and
        // the launcher applies them to itself before it executes the program. Not
        // a claim that anything was decided — `EvidenceKind::Installed` is ignored
        // by every prevention predicate for exactly that reason.
        for planned in entry.plan.planned() {
            if !emits_grants(&planned.outcome) {
                continue;
            }
            evidence.record(EvidenceRecord::new(
                EvidenceKind::Installed,
                planned.requirement.domain(),
                ClaimTerm::Planned,
                format!(
                    "the permitted path scope for this domain was on the command line the launcher \
                     accepted, and the launcher installs the boundary on itself before it executes the \
                     program ({} lowering step(s))",
                    planned.lowering.steps().len()
                ),
            ));
        }

        // The rules themselves, always, including when there are none — a run
        // whose evidence is silent about the boundary reads as a run that had a
        // permissive one, and an empty rule set is the strictest posture rather
        // than an absent one.
        evidence.record(EvidenceRecord::new(
            EvidenceKind::Installed,
            CapabilityDomain::FilesystemRead,
            ClaimTerm::Planned,
            if entry.rules.denies_everything() {
                "permitted path scope: none. The boundary is default-deny within every access right it \
                 handles, so this launch permits no filesystem access at all"
                    .to_string()
            } else {
                format!("permitted path scope: {}", entry.rules.describe().join("; "))
            },
        ));

        // The residue, always, including when it is empty — a run whose evidence
        // is silent about ambient authority reads as a run that had none.
        //
        // `Degraded` rather than `Planned` when anything is left: a launch that
        // could not remove authority policy asked it to remove is not the launch
        // policy described, and the claim term is where an E6 consumer reads that
        // without parsing the sentence.
        evidence.record(EvidenceRecord::new(
            EvidenceKind::Installed,
            CapabilityDomain::Credential,
            if entry.residual_authority.is_empty() {
                ClaimTerm::Planned
            } else {
                ClaimTerm::Degraded
            },
            if entry.residual_authority.is_empty() {
                "residual authority reaching the confined program: none beyond the three standard \
                 descriptors, which are delegated by design"
                    .to_string()
            } else {
                format!(
                    "residual authority reaching the confined program, which policy asked to remove and \
                     this launch could not: {}. This run is NOT least-authority",
                    entry.residual_authority.join(", ")
                )
            },
        ));

        // The descriptors, always, and with the completeness of the enumeration
        // attached. An inventory that could not be taken must not read like one
        // that came back empty.
        evidence.record(EvidenceRecord::new(
            EvidenceKind::Installed,
            CapabilityDomain::Ipc,
            if entry.descriptors.asserts_clean_boundary() {
                ClaimTerm::Planned
            } else {
                ClaimTerm::Unmeasured
            },
            format!(
                "inherited descriptors ({}): {}",
                if entry.descriptors.asserts_clean_boundary() {
                    "every one accounted for"
                } else {
                    "NOT a clean boundary — some reach the confined program unaccounted for"
                },
                entry.descriptors.describe().join("; ")
            ),
        ));

        if let Some(completed) = self
            .completed
            .lock()
            .expect("backend state poisoned")
            .get(handle.token())
        {
            // `Exercised`, not `Decision`. That the program ran inside the
            // boundary is a fact about the run; that any control decided
            // something is not derivable from it, and this backend has no channel
            // that would tell it. See the module documentation.
            //
            // A launcher refusal is the one case where the program did NOT run,
            // and it is reported as such rather than folded into the same
            // sentence: "the boundary held" and "nothing was confined because
            // nothing started" are opposite readings of the same exit code.
            evidence.record(if completed.launcher_refused() {
                EvidenceRecord::about_run(
                    EvidenceKind::Configured,
                    ClaimTerm::Unmeasured,
                    format!(
                        "the launcher refused to establish the boundary and executed NOTHING, so this run \
                         measured no control at all. It reported: {}",
                        completed.stderr.trim()
                    ),
                )
            } else {
                EvidenceRecord::about_run(
                    EvidenceKind::Exercised,
                    ClaimTerm::Observed,
                    format!(
                        "the program ran inside the boundary and exited with {}. The kernel delivers a \
                         denial to the confined process rather than to this supervisor, so no control's \
                         decision is claimed here",
                        completed.status
                    ),
                )
            });
        }

        evidence
    }
}

/// Authority reaching the confined program that this launch did not decide to
/// give it.
fn residual_authority(spec: &ExecutionSpec, replaced: bool) -> Vec<String> {
    let mut residual: Vec<String> = unremoved_ambient(spec, replaced)
        .into_iter()
        .map(|name| {
            if replaced {
                format!(
                    "environment variable `{name}` (policy asked for its removal; this launch replaced the \
                     environment and passed it through anyway, as a recorded compatibility exception)"
                )
            } else {
                format!(
                    "environment variable `{name}` (policy asked for its removal; this launch replaced no \
                     environment, so it was inherited along with everything else)"
                )
            }
        })
        .collect();
    if !replaced {
        residual.push(
            "the whole launching environment, inherited: no caller supplied an explicit child \
             environment, so the launcher — and the program it becomes — receives this process's"
                .to_string(),
        );
    }
    residual
}

/// Send a termination request to the confined process.
///
/// Linux only, and the non-Linux arm returns an error rather than doing nothing
/// quietly: a supervisor that forwarded `Ctrl-C` and got `Ok` from a build that
/// cannot deliver one would report a stop request that never left the process.
#[cfg(target_os = "linux")]
fn deliver_termination(pid: u32, request: TerminationRequest) -> Result<(), SpawnError> {
    let signal = match request {
        TerminationRequest::Graceful => libc::SIGTERM,
        TerminationRequest::Immediate => libc::SIGKILL,
        // `TerminationRequest` is `#[non_exhaustive]`; a request this backend has
        // not been taught is refused rather than approximated by the nearest one,
        // because the two arms above differ in whether the target may decline.
        other => {
            return Err(SpawnError::Supervision {
                detail: format!("this backend does not know how to deliver `{other:?}`"),
            })
        }
    };
    // Safety: `pid` is the id of a child this backend spawned. The window in which
    // it could name a different process is between that child's exit and the reap
    // in `wait`; `terminate` narrows it by refusing once a completion has been
    // recorded.
    let sent = unsafe { libc::kill(pid as libc::pid_t, signal) };
    if sent == 0 {
        return Ok(());
    }
    Err(SpawnError::Supervision {
        detail: format!(
            "the termination request could not be delivered to the confined process: {}",
            std::io::Error::last_os_error()
        ),
    })
}

/// The non-Linux arm. See the Linux one for why this is an error.
#[cfg(not(target_os = "linux"))]
fn deliver_termination(pid: u32, _request: TerminationRequest) -> Result<(), SpawnError> {
    Err(SpawnError::Supervision {
        detail: format!(
            "this backend confines Linux processes and cannot deliver a termination request on {}; \
             process {pid} was not signalled",
            std::env::consts::OS
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::AbiFloor;
    use crate::probe::Observation;
    use aa_isolation::{permit_only_selector, ControlRequirement, IdentityRef, RequirementPosture, RequirementScope};

    /// Host facts naming a launcher that is not there.
    ///
    /// Used by the launch tests: everything up to the launch is real, and the
    /// launch is the only thing that fails.
    fn missing_launcher() -> HostFacts {
        HostFacts::for_test("/nonexistent/aa-isolation-launch-test", AbiFloor::Met { measured: 5 })
    }

    /// A probe that observed every measurable denial, so the capability reports
    /// permit a plan and the tests below exercise the launch path rather than the
    /// refusal path.
    fn denied_everything() -> ConfinementProbe {
        ConfinementProbe {
            filesystem_read: Observation::Denied,
            filesystem_write: Observation::Denied,
            filesystem_truncate: Observation::Denied,
        }
    }

    fn backend() -> NativeBackend {
        NativeBackend::from_measured(missing_launcher(), denied_everything())
    }

    /// A spec whose program creates `target`, so its effect is observable from
    /// outside the boundary.
    fn writing_spec(target: &str) -> ExecutionSpec {
        ExecutionSpec::new("/bin/sh", IdentityRef::root("agent-under-test"))
            .with_args(["-c", &format!("printf x > {target}")])
            .with_requirement(
                ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
                    .with_scope(RequirementScope::Selectors(vec![permit_only_selector("/tmp")])),
            )
    }

    /// Discovery must never panic and never leave the caller without a usable
    /// object, on any host — including this one, whatever it is.
    #[test]
    fn discovery_always_yields_a_backend() {
        let backend = NativeBackend::discover();
        assert_eq!(backend.identity().id, BACKEND_ID);
        assert_eq!(backend.identity().provenance.license, SPDX_LICENSE);
    }

    /// The backend id must never name the kernel mechanism: ADR 0035 decision 3
    /// keeps mechanism vocabulary out of every value a CLI invocation authors,
    /// and `--isolation-backend` accepts this one.
    #[test]
    fn the_backend_id_names_no_kernel_mechanism() {
        for mechanism in ["landlock", "seccomp", "bpf", "namespace", "cgroup"] {
            assert!(
                !BACKEND_ID.to_ascii_lowercase().contains(mechanism),
                "the backend id `{BACKEND_ID}` names the mechanism `{mechanism}`"
            );
        }
    }

    /// On a host without the launcher, the refusal has to come from `plan` —
    /// before anything is prepared and long before anything is spawned.
    #[test]
    fn an_unavailable_host_refuses_at_plan_time() {
        let backend = NativeBackend::unavailable(&HostUnusable::LauncherNotFound { searched: Vec::new() });
        let refusal = backend
            .plan(&writing_spec("/tmp/never"))
            .expect_err("an unavailable backend must refuse");
        assert!(
            refusal.backend_unavailable().is_some(),
            "the refusal must name the host-level reason: {refusal:?}"
        );
    }

    /// A refusal is not a failure, and the evidence for one has to be
    /// constructible — E6 needs to see that a launch was stopped.
    #[test]
    fn a_refusal_becomes_evidence_with_no_prevention_claim() {
        let backend = NativeBackend::unavailable(&HostUnusable::LauncherNotFound { searched: Vec::new() });
        let refusal = backend.plan(&writing_spec("/tmp/never")).expect_err("refused");
        let evidence = EnforcementEvidence::from_refusal(&refusal);
        assert_eq!(evidence.posture(), aa_isolation::LaunchPosture::Refused);
        assert!(!evidence.supports_prevention_claim(CapabilityDomain::FilesystemWrite));
    }

    /// A required requirement in a domain this version does not implement must
    /// refuse on every host, because the domain is unsupported by construction
    /// rather than by measurement.
    #[test]
    fn a_required_syscall_requirement_refuses_everywhere() {
        let spec = writing_spec("/tmp/never").with_requirement(
            ControlRequirement::prevent(CapabilityDomain::Syscall)
                .with_scope(RequirementScope::Selectors(vec![permit_only_selector("read")])),
        );
        let refusal = backend()
            .plan(&spec)
            .expect_err("this version installs no system-call filter");
        assert!(
            refusal
                .reasons()
                .iter()
                .any(|r| r.domain() == Some(CapabilityDomain::Syscall)),
            "{refusal:?}"
        );
    }

    /// The control for the test above: an *optional* requirement for the same
    /// domain must not refuse the launch. Without it, the refusal could be coming
    /// from something other than the requirement's posture.
    #[test]
    fn an_optional_syscall_requirement_does_not_refuse_the_launch() {
        let spec = writing_spec("/tmp/never").with_requirement(
            ControlRequirement::prevent(CapabilityDomain::Syscall)
                .with_posture(RequirementPosture::Optional)
                .with_scope(RequirementScope::Selectors(vec![permit_only_selector("read")])),
        );
        let plan = backend().plan(&spec).expect("an optional requirement never refuses");
        assert_eq!(plan.posture(), aa_isolation::LaunchPosture::Degraded);
        assert_eq!(plan.shortfalls().count(), 1);
    }

    /// A plan from one backend must not be preparable by another.
    #[test]
    fn a_foreign_plan_is_rejected_rather_than_prepared() {
        let other = BackendIdentity {
            id: "somebody-else".to_string(),
            version: "1".to_string(),
            provenance: Provenance {
                source: "test".to_string(),
                license: "Apache-2.0".to_string(),
                modified: false,
            },
        };
        let capabilities = capability::discover(&missing_launcher(), &denied_everything());
        let foreign = negotiate(&writing_spec("/tmp/never"), &other, &capabilities, &|_, _| {
            Lowering::none()
        })
        .expect("a measured capability set accepts the plan");
        let error = backend()
            .prepare(foreign)
            .expect_err("a plan from another backend must not be prepared");
        assert!(matches!(error, SpawnError::BackendMismatch { .. }), "{error:?}");
    }

    /// **The negative control for "no silent unconfined fallback".**
    ///
    /// The backend is pointed at a launcher that does not exist. Planning and
    /// preparation both succeed — the capabilities were measured, so there is
    /// nothing to refuse — and only the launch fails. The assertion is not that an
    /// error came back: it is that the *effect the program would have had did not
    /// happen*. A fallback that quietly ran the program outside the boundary would
    /// leave the file behind, and this test would fail.
    #[test]
    fn a_missing_launcher_produces_no_process_at_all() {
        let scratch = std::env::temp_dir().join(format!("aa-native-fallback-{}", std::process::id()));
        let _ = std::fs::remove_file(&scratch);
        let backend = backend();
        let spec = writing_spec(&scratch.to_string_lossy());

        let plan = backend.plan(&spec).expect("a measured backend plans this spec");
        let prepared = backend
            .prepare(plan)
            .expect("preparation builds a command line, it does not run it");
        let error = backend
            .spawn(prepared)
            .expect_err("a launcher that does not exist cannot launch anything");

        assert!(matches!(error, SpawnError::Spawn { .. }), "{error:?}");
        assert!(
            !scratch.exists(),
            "the program ran even though the boundary could not be established: {} exists",
            scratch.display()
        );
    }

    /// The single most important thing this backend must not do: turn "the
    /// program ran" into "the control decided".
    #[test]
    fn no_run_of_this_backend_supports_a_prevention_claim() {
        let backend = backend();
        let plan = backend.plan(&writing_spec("/tmp/never")).expect("planned");
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

    /// The command line must put the caller's program after the separator and the
    /// launcher outside the argument vector entirely.
    #[test]
    fn the_prepared_command_line_confines_rather_than_executes_the_program() {
        let backend = backend();
        let plan = backend.plan(&writing_spec("/tmp/never")).expect("planned");
        let prepared = backend.prepare(plan).expect("prepared");
        let argv = backend
            .command_line(&prepared)
            .expect("a prepared boundary has a command line");
        let separator = argv
            .iter()
            .position(|a| a == launch::ARG_SEPARATOR)
            .expect("a separator is always emitted");
        assert_eq!(argv[separator + 1], "/bin/sh");
        assert!(
            !argv[..separator].contains(&"/bin/sh".to_string()),
            "the program leaked into the boundary flags: {argv:?}"
        );
        assert_eq!(argv[..separator], ["--fs-write=/tmp"]);
    }

    /// The boundary itself, not the command line that encodes it: a policy that
    /// permitted `/tmp` for writing must produce exactly that rule and no other.
    #[test]
    fn the_installed_rules_are_the_ones_policy_named() {
        let backend = backend();
        let plan = backend.plan(&writing_spec("/tmp/never")).expect("planned");
        let prepared = backend.prepare(plan).expect("prepared");
        let rules = backend.rule_plan(&prepared).expect("a prepared boundary has rules");
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.rules[0].path, "/tmp");
        assert!(rules.rules[0].verbs.write);
        assert!(!rules.rules[0].verbs.read, "a write grant became a read grant");
    }

    /// A degraded requirement must contribute no grant. The pair is the control:
    /// the same spec with the requirement met produces the grant.
    #[test]
    fn a_shortfall_grants_nothing_and_the_control_shows_the_grant_exists() {
        let backend = backend();
        let met = backend.plan(&writing_spec("/tmp/never")).expect("planned");
        assert_eq!(grants_for(&met).expect("expressible").write.len(), 1);

        let short = writing_spec("/tmp/never").with_requirement(
            ControlRequirement::prevent(CapabilityDomain::Resource)
                .with_posture(RequirementPosture::DegradeIfUnavailable),
        );
        let planned = backend.plan(&short).expect("a degradable requirement never refuses");
        let grants = grants_for(&planned).expect("expressible");
        assert_eq!(grants.write.len(), 1, "the met requirement lost its grant");
        assert!(grants.read.is_empty(), "a shortfall contributed a grant");
    }

    /// Residual authority is recorded on every run, including when there is none
    /// — silence about ambient authority reads as an absence of it.
    #[test]
    fn residual_authority_is_always_recorded() {
        let backend = backend();
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

    /// **The property this Epic exists for, at the evidence layer.** A name the
    /// launch could not remove must be named in evidence *and* must mark the run
    /// as not least-authority.
    ///
    /// The negative control is the identical spec with the same variable moved
    /// into `removed`: the record flips to the no-residue wording and drops the
    /// name.
    #[test]
    fn unremoved_ambient_authority_is_named_in_evidence_and_marks_the_run_degraded() {
        let mut backend = backend();
        backend.set_child_environment(BTreeMap::new());

        let kept = writing_spec("/tmp/never").with_credentials(aa_isolation::CredentialPosture {
            removed: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
            delegated: Vec::new(),
            ambient_unremoved: vec!["PATH".to_string()],
        });
        let record = credential_record(&backend, &kept);
        assert!(
            record.detail.contains("PATH") && record.detail.contains("NOT least-authority"),
            "{}",
            record.detail
        );
        assert_eq!(record.claim, ClaimTerm::Degraded);
        assert!(
            !record.detail.contains("AWS_SECRET_ACCESS_KEY"),
            "a removed name was reported as residual authority: {}",
            record.detail
        );

        let removed = writing_spec("/tmp/never").with_credentials(aa_isolation::CredentialPosture {
            removed: vec!["AWS_SECRET_ACCESS_KEY".to_string(), "PATH".to_string()],
            delegated: Vec::new(),
            ambient_unremoved: Vec::new(),
        });
        let record = credential_record(&backend, &removed);
        assert!(
            record.detail.contains("none beyond the three standard descriptors"),
            "{}",
            record.detail
        );
        assert_eq!(record.claim, ClaimTerm::Planned);
    }

    /// A launch with no explicit child environment inherits the supervisor's, and
    /// evidence must say so rather than reporting a clean one.
    #[test]
    fn an_inherited_environment_is_reported_as_residue() {
        let backend = backend();
        let record = credential_record(&backend, &writing_spec("/tmp/never"));
        assert!(
            record.detail.contains("the whole launching environment, inherited"),
            "{}",
            record.detail
        );
        assert_eq!(record.claim, ClaimTerm::Degraded);
    }

    /// The kernel-binding crate and its licence must be on every run's record,
    /// not only in a manifest — an operator auditing a run does not have the
    /// manifest that built the binary.
    #[test]
    fn the_binding_crate_and_its_licence_are_recorded_on_every_run() {
        let backend = backend();
        let plan = backend.plan(&writing_spec("/tmp/never")).expect("planned");
        let prepared = backend.prepare(plan).expect("prepared");
        let handle = ExecutionHandle::new(backend.identity(), prepared.token(), prepared.plan().posture());
        let evidence = backend.evidence(&handle);
        assert!(
            evidence
                .records()
                .iter()
                .any(|r| r.detail.contains("MIT OR Apache-2.0") && r.detail.contains("landlock")),
            "{:?}",
            evidence.records()
        );
    }

    /// The permitted scope is recorded in both directions: a launch that permits
    /// nothing must say so, because silence about the boundary reads as a
    /// permissive one.
    #[test]
    fn the_permitted_scope_is_stated_in_both_directions() {
        let backend = backend();

        let scoped = backend.plan(&writing_spec("/tmp/never")).expect("planned");
        let prepared = backend.prepare(scoped).expect("prepared");
        let handle = ExecutionHandle::new(backend.identity(), prepared.token(), prepared.plan().posture());
        let scoped_detail = scope_record(&backend.evidence(&handle));
        assert!(scoped_detail.contains("/tmp"), "{scoped_detail}");

        let whole = ExecutionSpec::new("/bin/true", IdentityRef::root("a"))
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        let plan = backend.plan(&whole).expect("planned");
        let prepared = backend.prepare(plan).expect("prepared");
        let handle = ExecutionHandle::new(backend.identity(), prepared.token(), prepared.plan().posture());
        let empty_detail = scope_record(&backend.evidence(&handle));
        assert!(
            empty_detail.contains("permits no filesystem access at all"),
            "{empty_detail}"
        );
    }

    // ---- fixtures ---------------------------------------------------------

    fn credential_record(backend: &NativeBackend, spec: &ExecutionSpec) -> EvidenceRecord {
        let plan = backend.plan(spec).expect("planned");
        let prepared = backend.prepare(plan).expect("prepared");
        let handle = ExecutionHandle::new(backend.identity(), prepared.token(), prepared.plan().posture());
        let evidence = backend.evidence(&handle);
        let found = evidence
            .records_for(CapabilityDomain::Credential)
            .find(|r| r.detail.starts_with("residual authority"))
            .cloned();
        found.unwrap_or_else(|| panic!("no residual-authority record: {:?}", evidence.records()))
    }

    fn scope_record(evidence: &EnforcementEvidence) -> String {
        evidence
            .records_for(CapabilityDomain::FilesystemRead)
            .find(|r| r.detail.starts_with("permitted path scope"))
            .map(|r| r.detail.clone())
            .unwrap_or_else(|| panic!("no permitted-scope record: {:?}", evidence.records()))
    }
}
