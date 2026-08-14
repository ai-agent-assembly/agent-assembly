//! A backend-agnostic adversarial harness (AAASM-5712).
//!
//! # What this is for
//!
//! An AI-agent workload is adaptive. It enumerates the environment, the
//! filesystem, process state, proxy configuration and metadata endpoints, and
//! then retries whatever route is left. A happy-path sandbox test does not
//! demonstrate a boundary against that; it demonstrates that one command failed
//! once. This module supplies the vocabulary the scenarios in
//! `adversarial_negotiation.rs` and `adversarial_boundary_linux.rs` are written
//! in, so every attack in both files is stated the same way and judged by the
//! same rule.
//!
//! # The rule: an attack counts only as half of a controlled pair
//!
//! [`ControlledPair`] holds two [`Effect`]s — the attack run and its control —
//! and [`ControlledPair::verdict`] has three answers, not two:
//!
//! * [`PairVerdict::Prevented`] — the control produced the effect and the attack
//!   did not. The only answer that establishes anything.
//! * [`PairVerdict::Bypassed`] — the attack produced the effect. The boundary is
//!   not there, whatever the control did.
//! * [`PairVerdict::ControlProducedNoEffect`] — the control produced nothing, so
//!   the attack's silence is unattributable. A broken fixture, an unwritable
//!   directory, a mistyped command and a boundary that never engaged all land
//!   here, and every one of them would otherwise read as a denial.
//!
//! [`assert_prevented`] turns the third into a recorded
//! [`Measurement::NotMeasured`] and a failure. **A broken probe must never read
//! as a denial** is the single property this harness exists to hold.
//!
//! # Effects, never exit codes
//!
//! An [`Effect`] is a fact about the world: a byte that arrived at a listener a
//! test owns, a file that exists, a file whose contents are unchanged. It is
//! never an exit status and never an error message. A denial before the effect
//! and a kill after it produce the same non-zero exit and completely different
//! security postures.
//!
//! # Two backends, one interface
//!
//! [`AdversarialTarget`] is the whole surface a scenario needs, and both
//! [`SandlockTarget`] and [`MockTarget`] implement it over `dyn
//! IsolationBackend`. The negotiation-level attacks — a required control that
//! cannot be enforced, an observe-only capability asked to prevent, a waived
//! protection — run against both, so nothing in those scenarios can be an
//! accident of one mechanism.
//!
//! # The ceiling this harness must never raise
//!
//! `EnforcementEvidence::supports_prevention_claim` is false for every domain on
//! the Sandlock backend, always: the kernel returns a denial to the *confined
//! process* as an errno, and the mechanism exposes no out-of-process decision
//! record. In the ADR 0033 §6 vocabulary the measured fact is **Denied before
//! execution** at the kernel — the action did not take effect, and the decision
//! preceded the effect — while at AASM's evidence layer the same action is
//! **Unmeasured**, since the mechanism hands out no decision record for the
//! pipeline to attribute. [`assert_no_prevention_claim`] is how every
//! scenario re-states that ceiling, and a scenario that measures a real denial
//! and then asserts a prevention claim would be asserting a lie about the
//! evidence pipeline rather than about the kernel.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aa_isolation::{
    permit_only_selector, CapabilityDomain, ControlRequirement, EnforcementEvidence, ExecutionHandle, ExecutionSpec,
    IdentityRef, IsolationBackend, IsolationReport, LaunchPosture, PlanRefusal, RequirementIntent, RequirementScope,
};
use aa_isolation_sandlock::{host::DEFAULT_PROTECTION_FLOOR_ABI, CompletedRun, SandlockBackend};

/// The shared evidence ledger, included by path.
///
/// Included rather than copied for the same reason `linux_confinement.rs`
/// includes it: one CI summary reads every suite's records, and two
/// implementations of "what a decline looks like" would drift until the summary
/// quietly stopped seeing one of them. Re-exported from here so the two test
/// binaries in this crate share one include rather than two.
#[path = "../../../aa-integration-tests/tests/evidence/mod.rs"]
pub mod evidence;

pub use evidence::Measurement;

/// The synthetic content every scenario looks for.
///
/// Unmistakably fabricated. No scenario in this suite reads, writes or transmits
/// a real credential — the acceptance criterion is that metadata-service and
/// secret-directory attempts are exercised *without* relying on production
/// credentials, and a fixture that used one would violate it whatever it proved.
pub const SECRET: &str = "aa-adversarial-conformance-secret-8f2c";

// ---------------------------------------------------------------------------
// Attack families.
// ---------------------------------------------------------------------------

/// The families of boundary bypass this suite covers.
///
/// Enumerated rather than left implicit in test names so that a scenario states
/// which family it belongs to in the evidence ledger, and so the CI job summary
/// answers "which attack families did this lane actually measure" without anyone
/// reading the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackFamily {
    /// Reading credential material and policy-denied paths.
    ForbiddenFilesystemRead,
    /// Writing, creating or tampering where the launch did not permit it.
    ForbiddenFilesystemWrite,
    /// `/proc` and other process-state inspection.
    ProcessInspection,
    /// Reaching a destination directly instead of through the configured proxy.
    DirectEgressBypass,
    /// Instance-metadata services, which mint credentials for anything that
    /// reaches them.
    CloudMetadata,
    /// Alternate spellings of a destination: another address on a permitted
    /// port, decimal and octal IPv4 forms, IPv6.
    AddressRepresentation,
    /// Unix sockets, inherited sockets, inherited descriptors.
    UnixSocketsAndDescriptors,
    /// Children, grandchildren, detached descendants and alternate paths to the
    /// same executable.
    ProcessTreeAndAlternateExecutables,
    /// Enumerating the environment for credentials.
    CredentialEnumeration,
    /// Disallowed system calls and resource ceilings.
    SyscallAndResource,
    /// A backend that is missing, disabled or only partially configured.
    BackendPosture,
    /// Whether an observe-only or degraded launch says so.
    ObserveAndDegradedTruthfulness,
}

impl AttackFamily {
    /// Every family, so a sweep cannot silently drop one.
    pub const ALL: &'static [Self] = &[
        Self::ForbiddenFilesystemRead,
        Self::ForbiddenFilesystemWrite,
        Self::ProcessInspection,
        Self::DirectEgressBypass,
        Self::CloudMetadata,
        Self::AddressRepresentation,
        Self::UnixSocketsAndDescriptors,
        Self::ProcessTreeAndAlternateExecutables,
        Self::CredentialEnumeration,
        Self::SyscallAndResource,
        Self::BackendPosture,
        Self::ObserveAndDegradedTruthfulness,
    ];

    /// A stable identifier for a ledger record.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForbiddenFilesystemRead => "forbidden_filesystem_read",
            Self::ForbiddenFilesystemWrite => "forbidden_filesystem_write",
            Self::ProcessInspection => "process_inspection",
            Self::DirectEgressBypass => "direct_egress_bypass",
            Self::CloudMetadata => "cloud_metadata",
            Self::AddressRepresentation => "address_representation",
            Self::UnixSocketsAndDescriptors => "unix_sockets_and_descriptors",
            Self::ProcessTreeAndAlternateExecutables => "process_tree_and_alternate_executables",
            Self::CredentialEnumeration => "credential_enumeration",
            Self::SyscallAndResource => "syscall_and_resource",
            Self::BackendPosture => "backend_posture",
            Self::ObserveAndDegradedTruthfulness => "observe_and_degraded_truthfulness",
        }
    }
}

// ---------------------------------------------------------------------------
// Effects and controlled pairs.
// ---------------------------------------------------------------------------

/// One observed fact about the world.
///
/// `observed` is whether the *effect the attack was trying to produce* actually
/// happened — bytes at a listener this process owns, a file that exists, a file
/// whose contents changed. Never an exit status: a pre-effect denial and a
/// post-effect kill are indistinguishable by exit status and are entirely
/// different security postures.
#[derive(Debug, Clone)]
pub struct Effect {
    /// What was attempted, for the failure message.
    pub label: String,
    /// Whether the effect happened.
    pub observed: bool,
    /// What was actually seen, so a failure says more than "false".
    pub detail: String,
}

impl Effect {
    /// Record an attempt and whether its effect landed.
    pub fn new(label: impl Into<String>, observed: bool, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            observed,
            detail: detail.into(),
        }
    }
}

/// What a controlled pair established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairVerdict {
    /// The control produced the effect and the attack did not.
    Prevented,
    /// The attack produced the effect. There is no boundary on this route.
    Bypassed,
    /// The control produced nothing, so the attack's silence is unattributable.
    ControlProducedNoEffect,
}

/// An attack and the one run that differs from it by a single grant.
///
/// The two runs must differ by *one* thing. A pair whose control also changed
/// the command, the directory or the fixture is not a control — it is a second
/// experiment, and the difference between the two results is attributable to
/// nothing in particular.
#[derive(Debug, Clone)]
pub struct ControlledPair {
    /// Which family this attack belongs to.
    pub family: AttackFamily,
    /// The run under the boundary the scenario is testing.
    pub attack: Effect,
    /// The run that differs by exactly one grant, or by being outside the
    /// boundary entirely.
    pub control: Effect,
}

impl ControlledPair {
    /// Build a pair.
    pub fn new(family: AttackFamily, attack: Effect, control: Effect) -> Self {
        Self {
            family,
            attack,
            control,
        }
    }

    /// What the pair establishes.
    ///
    /// Order matters: a bypass is reported even when the control also failed,
    /// because an attack that produced its effect is a bypass whatever else was
    /// broken.
    pub fn verdict(&self) -> PairVerdict {
        if self.attack.observed {
            PairVerdict::Bypassed
        } else if self.control.observed {
            PairVerdict::Prevented
        } else {
            PairVerdict::ControlProducedNoEffect
        }
    }
}

/// Require a pair to have established prevention, and return the detail for the
/// ledger.
///
/// # Panics
///
/// On [`PairVerdict::Bypassed`], naming the route that worked. On
/// [`PairVerdict::ControlProducedNoEffect`] — after recording
/// [`Measurement::NotMeasured`], because a scenario that committed to measuring
/// and produced nothing is a failed measurement rather than an opt-out, and it
/// must never be netted out of the lane's substantive count as though it were a
/// skip.
pub fn assert_prevented(scenario: &str, pair: &ControlledPair) -> String {
    match pair.verdict() {
        PairVerdict::Prevented => format!(
            "[{}] `{}` produced no effect under the boundary, while `{}` — the same attempt with one \
             grant different — did. attack: {} | control: {}",
            pair.family.as_str(),
            pair.attack.label,
            pair.control.label,
            pair.attack.detail,
            pair.control.detail,
        ),
        PairVerdict::Bypassed => panic!(
            "BYPASS [{}]: `{}` produced its effect under the boundary. {}",
            pair.family.as_str(),
            pair.attack.label,
            pair.attack.detail,
        ),
        PairVerdict::ControlProducedNoEffect => {
            let reason = format!(
                "the control `{}` produced no effect, so the absence of `{}` is attributable to nothing. \
                 control: {} | attack: {}",
                pair.control.label, pair.attack.label, pair.control.detail, pair.attack.detail,
            );
            evidence::record(scenario, Measurement::NotMeasured, &reason);
            panic!("NOT MEASURED [{}]: {reason}", pair.family.as_str());
        }
    }
}

/// Require every pair in a family sweep to have established prevention, and
/// return the joined detail.
pub fn assert_all_prevented(scenario: &str, pairs: &[ControlledPair]) -> String {
    assert!(
        !pairs.is_empty(),
        "NOT MEASURED: a sweep with no pairs in it establishes nothing"
    );
    pairs
        .iter()
        .map(|pair| assert_prevented(scenario, pair))
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// Recording.
// ---------------------------------------------------------------------------

/// Print and record a decline, and return `None`.
pub fn decline<T>(scenario: &str, measurement: Measurement, reason: &str) -> Option<T> {
    println!("SKIP [{scenario}]: {reason}");
    evidence::record(scenario, measurement, reason);
    None
}

/// Record that a scenario took its measurement, tagged with its family.
pub fn measured(scenario: &str, family: AttackFamily, detail: &str) {
    evidence::record(
        scenario,
        Measurement::Measured,
        &format!("{}: {detail}", family.as_str()),
    );
}

// ---------------------------------------------------------------------------
// Guards.
// ---------------------------------------------------------------------------

/// A backend that measured a working boundary on this host, or a recorded skip.
///
/// The same four preconditions `linux_confinement.rs` folds into its own guard,
/// for the same reason: a scenario that checked three of them and forgot the
/// fourth would report a missing measurement as a product failure.
pub fn require_confining_backend(scenario: &str) -> Option<SandlockBackend> {
    if !cfg!(target_os = "linux") {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the sandlock backend confines Linux processes; this host is {}",
                std::env::consts::OS
            ),
        );
    }
    let backend = SandlockBackend::discover().with_captured_output(true);

    let Some(host) = backend.host() else {
        return decline(
            scenario,
            Measurement::ToolAbsent,
            "no sandlock executable was found; a lane that installs it and still reports this is broken",
        );
    };

    if host.below_default_protection_floor() {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the kernel's access-control interface is {} and the mechanism enforces every protection \
                 it knows about, requiring at least version {DEFAULT_PROTECTION_FLOOR_ABI}",
                host.landlock_abi()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unreadable".to_string()),
            ),
        );
    }

    let probe = backend.probe_result();
    if !probe.filesystem_write.is_denied() || !probe.filesystem_read.is_denied() {
        return decline(
            scenario,
            Measurement::NotMeasured,
            &format!(
                "the discovery probe established no filesystem denial on a host that meets every \
                 precondition. read: {} | write: {}",
                probe.filesystem_read.describe(),
                probe.filesystem_write.describe()
            ),
        );
    }
    Some(backend)
}

/// An executable on `PATH`, or a recorded skip.
pub fn require_program(scenario: &str, program: &str) -> Option<PathBuf> {
    match which(program) {
        Some(path) => Some(path),
        None => decline(
            scenario,
            Measurement::ToolAbsent,
            &format!("`{program}` is not on PATH; a lane that provisions it and still reports this is broken"),
        ),
    }
}

/// Whether an executable is on `PATH`.
pub fn which(program: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("which").arg(program).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());
    path.exists().then_some(path)
}

// ---------------------------------------------------------------------------
// Targets: one interface, two backends.
// ---------------------------------------------------------------------------

/// What one launch produced.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// The posture the launch started in.
    pub posture: LaunchPosture,
    /// What the confined program wrote to stdout, when the backend runs one.
    pub stdout: String,
    /// What it wrote to stderr.
    pub stderr: String,
    /// What may be claimed about the run.
    pub evidence: EnforcementEvidence,
}

/// A backend the harness can drive end to end, whatever mechanism it is.
///
/// Deliberately no wider than the contract: `plan`, `prepare`, `spawn`,
/// `evidence`. A scenario written against this cannot reach a Sandlock-specific
/// affordance by accident, which is what makes "this attack was run against both
/// backends" a checkable statement rather than an aspiration.
pub trait AdversarialTarget {
    /// A name for assertion messages and ledger details.
    fn label(&self) -> &'static str;

    /// The backend, as the contract sees it.
    fn backend(&self) -> &dyn IsolationBackend;

    /// Plan, prepare, launch and collect, or report the refusal.
    ///
    /// # Errors
    ///
    /// The backend's own [`PlanRefusal`]. A refusal is an outcome, not a
    /// harness failure — several scenarios exist precisely to assert one.
    #[allow(clippy::result_large_err)]
    fn launch(&self, spec: &ExecutionSpec) -> Result<RunOutcome, PlanRefusal>;
}

/// The Sandlock backend, which starts a real confined process.
pub struct SandlockTarget(pub SandlockBackend);

impl AdversarialTarget for SandlockTarget {
    fn label(&self) -> &'static str {
        "sandlock"
    }

    fn backend(&self) -> &dyn IsolationBackend {
        &self.0
    }

    fn launch(&self, spec: &ExecutionSpec) -> Result<RunOutcome, PlanRefusal> {
        let plan = self.0.plan(spec)?;
        let posture = plan.posture();
        let prepared = self.0.prepare(plan).expect("the boundary could not be prepared");
        let handle = self
            .0
            .spawn(prepared)
            .expect("the confined program could not be launched");
        let completed = self.0.wait(&handle).expect("waiting for the confined program failed");
        Ok(RunOutcome {
            posture,
            stdout: completed.stdout,
            stderr: completed.stderr,
            evidence: self.0.evidence(&handle),
        })
    }
}

/// The in-memory reference backend, which starts nothing.
///
/// Its [`RunOutcome`] carries empty streams, and that is the honest answer
/// rather than a limitation to work around: the mock applies no mechanism and
/// runs no program, so any *effect*-based attack against it would be measuring
/// the absence of a process. The scenarios that use it are the negotiation-level
/// ones, where the question is what a backend refuses, degrades or may claim —
/// and those are exactly the questions a second backend is needed to answer.
pub struct MockTarget {
    /// The backend.
    pub backend: aa_isolation::mock::MockBackend,
    /// What this configuration of it is called.
    pub label: &'static str,
}

impl AdversarialTarget for MockTarget {
    fn label(&self) -> &'static str {
        self.label
    }

    fn backend(&self) -> &dyn IsolationBackend {
        &self.backend
    }

    fn launch(&self, spec: &ExecutionSpec) -> Result<RunOutcome, PlanRefusal> {
        let plan = self.backend.plan(spec)?;
        let posture = plan.posture();
        let prepared = self.backend.prepare(plan).expect("the mock always prepares");
        let handle: ExecutionHandle = self.backend.spawn(prepared).expect("the mock always spawns");
        Ok(RunOutcome {
            posture,
            stdout: String::new(),
            stderr: String::new(),
            evidence: self.backend.evidence(&handle),
        })
    }
}

// ---------------------------------------------------------------------------
// Backend-agnostic assertions, stated as sets.
// ---------------------------------------------------------------------------

/// A spec that asks one domain to be prevented, and nothing else.
///
/// `/bin/true` because nothing here launches: every caller of this asks the
/// backend to *plan*, and a plan that refuses never reaches a program.
pub fn required_prevention_spec(domain: CapabilityDomain) -> ExecutionSpec {
    ExecutionSpec::new("/bin/true", IdentityRef::root("adversary"))
        .with_requirement(ControlRequirement::prevent(domain))
}

/// A spec that asks one domain to be observed, and nothing else.
pub fn required_observation_spec(domain: CapabilityDomain) -> ExecutionSpec {
    ExecutionSpec::new("/bin/true", IdentityRef::root("adversary"))
        .with_requirement(ControlRequirement::observe(domain))
}

/// The domains for which a required prevention requirement is refused.
///
/// A **set**, never a count. "Seven domains refused" is equally consistent with
/// the seven that should have and with six that should plus one that should not.
pub fn domains_refusing_required_prevention(backend: &dyn IsolationBackend) -> BTreeSet<CapabilityDomain> {
    CapabilityDomain::ALL
        .iter()
        .copied()
        .filter(|domain| backend.plan(&required_prevention_spec(*domain)).is_err())
        .collect()
}

/// The domains for which a required prevention requirement plans successfully.
pub fn domains_accepting_required_prevention(backend: &dyn IsolationBackend) -> BTreeSet<CapabilityDomain> {
    CapabilityDomain::ALL
        .iter()
        .copied()
        .filter(|domain| backend.plan(&required_prevention_spec(*domain)).is_ok())
        .collect()
}

/// The domains for which a required *observation* requirement plans
/// successfully.
pub fn domains_accepting_required_observation(backend: &dyn IsolationBackend) -> BTreeSet<CapabilityDomain> {
    CapabilityDomain::ALL
        .iter()
        .copied()
        .filter(|domain| backend.plan(&required_observation_spec(*domain)).is_ok())
        .collect()
}

/// Every domain, as a set, for comparing against the two above.
pub fn all_domains() -> BTreeSet<CapabilityDomain> {
    CapabilityDomain::ALL.iter().copied().collect()
}

/// The domains this evidence would support a prevention claim for.
///
/// Expected to be empty on every backend in this repository. Returned as a set
/// so an assertion can say *which* domain overclaimed rather than that one did.
pub fn prevention_claims(evidence: &EnforcementEvidence) -> BTreeSet<CapabilityDomain> {
    CapabilityDomain::ALL
        .iter()
        .copied()
        .filter(|domain| evidence.supports_prevention_claim(*domain))
        .collect()
}

/// Assert that no domain in this evidence supports a prevention claim.
///
/// The ceiling described in the module documentation, restated at every call
/// site that measures a real denial — because that is exactly where the
/// temptation to promote a measurement into a claim lives.
pub fn assert_no_prevention_claim(context: &str, evidence: &EnforcementEvidence) {
    let claimed = prevention_claims(evidence);
    assert!(
        claimed.is_empty(),
        "{context}: {claimed:?} produced a prevention claim from a run whose mechanism reports no \
         per-decision record to the supervisor. The kernel denied the action; AASM did not witness a \
         decision, and the two are not the same statement"
    );
}

/// Every domain's control state in a report, as `(domain, token)` pairs.
///
/// Tokens rather than values so an assertion reads as the report renders, and so
/// `blocked`, `unsupported` and `unmeasured` being three different words is the
/// thing being checked.
pub fn control_states(report: &IsolationReport) -> Vec<(CapabilityDomain, &'static str)> {
    report.domains().iter().map(|d| (d.domain, d.state.as_str())).collect()
}

/// Every domain's evidence basis in a report.
pub fn evidence_bases(report: &IsolationReport) -> Vec<(CapabilityDomain, &'static str)> {
    report
        .domains()
        .iter()
        .map(|d| (d.domain, d.evidence.as_str()))
        .collect()
}

/// The intent a requirement carries, for a scenario that builds several.
pub fn intent_of(requirement: &ControlRequirement) -> RequirementIntent {
    requirement.intent()
}

// ---------------------------------------------------------------------------
// Linux fixtures. Shared by the effect-based scenarios.
// ---------------------------------------------------------------------------

/// A scratch tree that removes itself, with a permitted and a forbidden half.
pub struct Scratch {
    /// The root of the tree.
    pub root: PathBuf,
}

impl Scratch {
    /// Create a uniquely named tree under the system temporary directory.
    pub fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "aa-adversarial-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("permitted")).expect("scratch permitted directory");
        std::fs::create_dir_all(root.join("forbidden")).expect("scratch forbidden directory");
        Self { root }
    }

    /// The half a scenario grants.
    pub fn permitted(&self) -> PathBuf {
        self.root.join("permitted")
    }

    /// The half a scenario withholds.
    pub fn forbidden(&self) -> PathBuf {
        self.root.join("forbidden")
    }

    /// A selector permitting the whole tree.
    pub fn whole_tree_selector(&self) -> String {
        permit_only_selector(&self.root.to_string_lossy())
    }

    /// A selector permitting only the granted half.
    pub fn permitted_selector(&self) -> String {
        permit_only_selector(&self.permitted().to_string_lossy())
    }

    /// A selector permitting the withheld half — the one grant a control adds.
    pub fn forbidden_selector(&self) -> String {
        permit_only_selector(&self.forbidden().to_string_lossy())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The read grants every scenario needs so the loader and the shell work.
pub fn system_reads() -> Vec<String> {
    system_reads_excluding(&[])
}

/// The same, minus paths a scenario is deliberately withholding.
///
/// `/proc` is the one that matters: it is on the default list because the loader
/// and the interpreter are happier with it, and it is also the route by which a
/// confined program inspects other processes. A scenario that measures process
/// inspection has to be able to take it away.
pub fn system_reads_excluding(withheld: &[&str]) -> Vec<String> {
    ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"]
        .iter()
        .filter(|p| !withheld.contains(*p))
        .filter(|p| Path::new(p).exists())
        .map(|p| permit_only_selector(p))
        .collect()
}

/// A spec that runs `script` through a shell with the given extra grants.
pub fn shell_spec(script: &str, reads: Vec<String>, writes: Vec<String>) -> ExecutionSpec {
    shell_spec_with_system_reads(script, system_reads(), reads, writes)
}

/// The same, with the system read set supplied explicitly.
pub fn shell_spec_with_system_reads(
    script: &str,
    system: Vec<String>,
    reads: Vec<String>,
    writes: Vec<String>,
) -> ExecutionSpec {
    shell_spec_using("/bin/sh", script, system, reads, writes)
}

/// The same, with the shell named.
///
/// Exists for the alternate-executable-path attack: `/bin/sh` and `/usr/bin/sh`
/// are two names for one binary on a merged-`/usr` host, and a boundary keyed on
/// the path a program was reached by rather than on the process would confine one
/// and not the other.
pub fn shell_spec_using(
    program: &str,
    script: &str,
    system: Vec<String>,
    reads: Vec<String>,
    writes: Vec<String>,
) -> ExecutionSpec {
    let mut all_reads = system;
    all_reads.extend(reads);
    ExecutionSpec::new(program, IdentityRef::root("agent-under-test"))
        .with_args(["-c", script])
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(all_reads)),
        )
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
                .with_scope(RequirementScope::Selectors(writes)),
        )
}

/// Permit egress to exactly the listed destinations.
pub fn egress_to(destinations: &[String]) -> ControlRequirement {
    ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(RequirementScope::Selectors(
        destinations.iter().map(|d| permit_only_selector(d)).collect(),
    ))
}

/// Plan, prepare, launch and wait on the Sandlock backend.
pub fn launch_confined(backend: &SandlockBackend, spec: &ExecutionSpec) -> (CompletedRun, EnforcementEvidence) {
    let plan = backend
        .plan(spec)
        .unwrap_or_else(|refusal| panic!("the backend refused a spec this scenario needs: {refusal:?}"));
    let prepared = backend.prepare(plan).expect("the boundary could not be prepared");
    let handle: ExecutionHandle = backend
        .spawn(prepared)
        .expect("the confined program could not be launched");
    let completed = backend.wait(&handle).expect("waiting for the confined program failed");
    let evidence = backend.evidence(&handle);
    (completed, evidence)
}

/// Perform `inner` from a *grandchild* of the launched process.
///
/// No `2>/dev/null` anywhere in this module, and none may be added: the null
/// device is opened for *writing*, which a default-deny write policy denies, so
/// the redirection fails before the command under test runs and every control
/// run turns into a spurious decline. Stderr is captured by the backend and
/// surfaces in assertion messages instead.
pub fn as_grandchild(inner: &str) -> String {
    format!("/bin/sh -c {}; exit 0", quote(inner))
}

/// Single-quote a value for a shell script this harness constructs.
pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Run a command outside any boundary, for a control whose premise is that the
/// action works when nothing is stopping it.
pub fn unconfined(script: &str) -> std::process::Output {
    std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .expect("the unconfined control command runs")
}

// ---------------------------------------------------------------------------
// Listeners.
// ---------------------------------------------------------------------------

/// A non-blocking loopback listener on `address`, and the port it took.
///
/// `None` when the address cannot be bound, which a scenario turns into a
/// recorded skip rather than into a silent single-address measurement.
pub fn listener_on(address: &str) -> Option<(TcpListener, u16)> {
    let listener = TcpListener::bind(format!("{address}:0")).ok()?;
    listener.set_nonblocking(true).ok()?;
    let port = listener.local_addr().ok()?.port();
    Some((listener, port))
}

/// A non-blocking listener on `address` at a specific port.
pub fn listener_on_port(address: &str, port: u16) -> Option<TcpListener> {
    let listener = TcpListener::bind(format!("{address}:{port}")).ok()?;
    listener.set_nonblocking(true).ok()?;
    Some(listener)
}

/// Accept one pending connection and read what it sent, or `None`.
///
/// Bounded: a scenario waiting indefinitely for a connection it expects *not* to
/// arrive would hang instead of failing.
pub fn accepted_payload(listener: &TcpListener) -> Option<String> {
    accepted_payload_within(listener, Duration::from_secs(2))
}

/// The same, with the window stated.
pub fn accepted_payload_within(listener: &TcpListener, window: Duration) -> Option<String> {
    let deadline = std::time::Instant::now() + window;
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .expect("read timeout");
                let mut buffer = Vec::new();
                let _ = stream.read_to_end(&mut buffer);
                return Some(String::from_utf8_lossy(&buffer).into_owned());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
    None
}

/// Everything a listener received during `window`, in arrival order.
///
/// Several scenarios send more than one report down the same permitted channel —
/// one per attempted representation — and asserting on only the first would let
/// a later bypass go unread.
pub fn accepted_payloads(listener: &TcpListener, expected: usize, window: Duration) -> Vec<String> {
    let deadline = std::time::Instant::now() + window;
    let mut out = Vec::new();
    while out.len() < expected && std::time::Instant::now() < deadline {
        match accepted_payload_within(listener, Duration::from_millis(200)) {
            Some(payload) => out.push(payload),
            None => continue,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The adjudicator's own tests.
// ---------------------------------------------------------------------------
//
// [`ControlledPair::verdict`] and [`assert_prevented`] decide what this suite
// reports, and the scenarios were their only exercise until these tests
// existed — which reads as coverage without being it. A scenario states its
// finding *through* the adjudicator, so an adjudicator that answered
// [`PairVerdict::Prevented`] for a pair whose attack landed would turn the whole
// suite green while leaving each scenario's source untouched. Inverting the
// first branch of `verdict` used to redden nothing in this repository, which is
// the measurement that motivated this section.
//
// The per-scenario controls sit below this and cannot reach it. A control
// guards against a broken probe: a predicate stuck at `false` leaves the control
// false too, and the pair lands on [`PairVerdict::ControlProducedNoEffect`].
// That says nothing about a fault in the code that reads the two effects.
//
// Plain `#[test]` rather than a `#[cfg(test)] mod tests`: this module is
// compiled into an integration-test binary, where `cfg(test)` is false, so the
// guarded form would be dropped without a diagnostic.

/// A pair built from the two booleans the adjudicator reads, and nothing else.
///
/// The labels and details are fixtures: the decision depends on `observed`
/// alone, and pinning the rest keeps each case below a one-variable change.
fn adjudicated(attack_observed: bool, control_observed: bool) -> ControlledPair {
    ControlledPair::new(
        AttackFamily::BackendPosture,
        Effect::new("attack under the boundary", attack_observed, "self-test fixture"),
        Effect::new("control with one grant more", control_observed, "self-test fixture"),
    )
}

/// Point the evidence ledger at a scratch directory for the life of the guard.
///
/// [`assert_prevented`] records [`Measurement::NotMeasured`] before it panics,
/// which is part of what the case below is checking. In CI
/// `AA_CONFORMANCE_OUTCOME_DIR` names the lane's real ledger, where a record
/// written by a self-test would read as a scenario that committed to measuring
/// and produced nothing — a false entry in the artifact the lane's guards assert
/// over. Redirecting keeps the write path exercised and leaves the lane's ledger
/// to the scenarios.
///
/// Sound under `cargo nextest`, which is what the isolation lane runs: it gives
/// each test its own process, so the variable is not shared with a scenario
/// running at the same time. Under `cargo test` the variable is per-binary, and
/// there the ledger is switched off unless someone sets the variable by hand.
struct RedirectedLedger {
    previous: Option<std::ffi::OsString>,
    scratch: PathBuf,
}

impl RedirectedLedger {
    fn to_scratch() -> Self {
        let previous = std::env::var_os(evidence::OUTCOME_DIR_ENV);
        let scratch = std::env::temp_dir().join(format!("aa-adversarial-harness-selftest-{}", std::process::id()));
        std::env::set_var(evidence::OUTCOME_DIR_ENV, &scratch);
        Self { previous, scratch }
    }
}

impl Drop for RedirectedLedger {
    /// Runs during the unwind of the `should_panic` case, so the variable is put
    /// back whichever way the guarded call ended.
    fn drop(&mut self) {
        match self.previous.take() {
            Some(previous) => std::env::set_var(evidence::OUTCOME_DIR_ENV, previous),
            None => std::env::remove_var(evidence::OUTCOME_DIR_ENV),
        }
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

#[test]
fn a_working_control_beside_a_silent_attack_reads_as_prevented() {
    assert_eq!(adjudicated(false, true).verdict(), PairVerdict::Prevented);
}

#[test]
fn an_attack_that_produced_its_effect_reads_as_bypassed() {
    assert_eq!(adjudicated(true, true).verdict(), PairVerdict::Bypassed);
}

/// The branch order is load-bearing. An attack that landed is a bypass whatever
/// the control did, so a broken control must not downgrade it into an
/// unattributable result and take it out of the failure report.
#[test]
fn a_landed_attack_reads_as_bypassed_even_where_the_control_produced_nothing() {
    assert_eq!(adjudicated(true, false).verdict(), PairVerdict::Bypassed);
}

#[test]
fn two_silent_runs_read_as_control_produced_no_effect() {
    assert_eq!(
        adjudicated(false, false).verdict(),
        PairVerdict::ControlProducedNoEffect
    );
}

/// The detail a prevented pair returns is what the scenario hands to the ledger,
/// so the family and the two labels have to survive into it.
#[test]
fn a_prevented_pair_yields_a_detail_naming_its_family_and_both_runs() {
    let detail = assert_prevented("harness self-test: prevented", &adjudicated(false, true));
    assert!(
        detail.contains("backend_posture"),
        "family missing from detail: {detail}"
    );
    assert!(
        detail.contains("attack under the boundary") && detail.contains("control with one grant more"),
        "both runs belong in the detail: {detail}"
    );
}

#[test]
#[should_panic(expected = "BYPASS [backend_posture]")]
fn assert_prevented_refuses_a_pair_whose_attack_landed() {
    assert_prevented("harness self-test: bypass", &adjudicated(true, false));
}

#[test]
#[should_panic(expected = "NOT MEASURED [backend_posture]")]
fn assert_prevented_refuses_a_pair_whose_control_produced_nothing() {
    let _ledger = RedirectedLedger::to_scratch();
    assert_prevented(
        "harness self-test: control produced no effect",
        &adjudicated(false, false),
    );
}

/// A sweep with nothing in it would otherwise pass `assert_all_prevented`
/// vacuously, which is the family-level shape of the same fault.
#[test]
#[should_panic(expected = "NOT MEASURED")]
fn assert_all_prevented_refuses_a_sweep_with_no_pairs_in_it() {
    assert_all_prevented("harness self-test: empty sweep", &[]);
}
