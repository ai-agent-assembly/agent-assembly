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

use aa_core::attestation::ClaimTerm;
use aa_isolation::{
    permit_only_selector, CapabilityDomain, ControlRequirement, EnforcementEvidence, EnforcementPlan, EvidenceKind,
    EvidenceRecord, ExecutionHandle, ExecutionSpec, IdentityRef, IsolationBackend, IsolationReport, LaunchPosture,
    PlanRefusal, RequirementIntent, RequirementPosture, RequirementScope, SessionRef,
};

/// The shared evidence ledger, included by path.
///
/// Included rather than copied for the same reason `linux_confinement.rs`
/// includes it: one CI summary reads every suite's records, and two
/// implementations of "what a decline looks like" would drift until the summary
/// quietly stopped seeing one of them. Re-exported from here so every test
/// binary that includes this module by path shares one include rather than one
/// per backend.
#[path = "../evidence/mod.rs"]
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
// Targets: one interface, many backends.
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
/// `evidence`. A scenario written against this cannot reach a backend-specific
/// affordance by accident, which is what makes "this attack was run against
/// every backend" a checkable statement rather than an aspiration.
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
// Shared negotiation-scenario bodies (AAASM-5805).
// ---------------------------------------------------------------------------
//
// Lifted out of `adversarial_negotiation.rs` so the AASM-native lane can drive
// the same negotiation-level assertions without re-deriving them. Only these
// four generalize: the other four of the original eight negotiation scenarios
// (`every_resource_ceiling_...`, `unsupported_and_unmeasured_domains_...`,
// `a_waived_protection_...`, `missing_disabled_and_partially_configured_...`)
// drive `aa_isolation_sandlock::capability::discover`/`narrow_for` directly —
// Sandlock's own two-step capability-negotiation internals, including
// prerequisite-gated `Partial` support and protection waivers — rather than
// going through [`AdversarialTarget`]. Native's capability model has no
// `Partial` support level and no waiver vocabulary (every domain it does not
// measure is flatly `Unsupported`, see `aa-isolation-native/src/capability.rs`),
// so there is nothing for a shared body to parameterize over for those four;
// native's own negotiation tests measure what is actually true of native's
// capability set instead, in `adversarial_negotiation_native.rs`.

/// A session reference for a report. The values are correlation ids and carry
/// no authority; nothing here depends on their content.
fn session() -> SessionRef {
    SessionRef::new("adversarial-session", "adversarial-trace")
}

/// AC: a required prevention requirement is refused by every backend that
/// cannot enforce it, and the refusal is a property of the contract rather
/// than of one mechanism.
///
/// The assertion is over the **set** of refused domains, never a count. "Nine
/// domains refused" is equally consistent with the nine that should have and
/// with eight that should plus one that should not.
///
/// `can_enforce` is the control: a backend differing from every one of
/// `cannot_enforce` in exactly one respect — it can mediate — so a refusal
/// above is attributable to that and not to the requirement being malformed.
pub fn assert_required_prevention_refused_by_every_uncapable_backend(
    scenario: &str,
    cannot_enforce: &[&dyn AdversarialTarget],
    can_enforce: &dyn AdversarialTarget,
) {
    for target in cannot_enforce {
        assert_eq!(
            domains_refusing_required_prevention(target.backend()),
            all_domains(),
            "`{}` accepted a required prevention requirement for a domain it cannot enforce",
            target.label()
        );
    }

    assert_eq!(
        domains_refusing_required_prevention(can_enforce.backend()),
        BTreeSet::new(),
        "the control backend refused something too, so the refusals above prove nothing"
    );
    assert_eq!(
        domains_accepting_required_prevention(can_enforce.backend()),
        all_domains(),
        "the control backend did not accept every domain"
    );

    measured(
        scenario,
        AttackFamily::BackendPosture,
        "every backend that cannot enforce a required prevention requirement refused it for all nine \
         domains, while a backend differing only in mediation accepted all nine",
    );
}

/// AC: observation is never promoted to enforcement, on any backend.
///
/// Self-contained: both sides of the comparison are `MockBackend`
/// configurations, so this needs no backend under test and holds identically
/// wherever it runs.
pub fn assert_observation_is_never_promoted_to_prevention(scenario: &str) {
    let observing = MockTarget {
        backend: aa_isolation::mock::MockBackend::observing(CapabilityDomain::ALL),
        label: "mock/observe-only",
    };
    let preventing = MockTarget {
        backend: aa_isolation::mock::MockBackend::preventing(CapabilityDomain::ALL),
        label: "mock/preventing",
    };

    for target in [&observing, &preventing] {
        assert_eq!(
            domains_accepting_required_observation(target.backend()),
            all_domains(),
            "`{}` refused an observation requirement it can meet",
            target.label()
        );
    }

    let spec = required_observation_spec(CapabilityDomain::FilesystemWrite);
    for target in [&observing, &preventing] {
        let outcome = target
            .launch(&spec)
            .unwrap_or_else(|refusal| panic!("`{}` refused an observation it accepts: {refusal:?}", target.label()));
        assert_eq!(outcome.posture, LaunchPosture::Ready);
        assert_no_prevention_claim(target.label(), &outcome.evidence);
        assert!(
            !outcome
                .evidence
                .claim_for(CapabilityDomain::FilesystemWrite)
                .is_prevention(),
            "`{}` derived a prevention term from a run that recorded no decision",
            target.label()
        );
    }

    let observed_state = mock_control_state(&observing, CapabilityDomain::FilesystemWrite, &spec);
    let prevented_state = mock_control_state(
        &preventing,
        CapabilityDomain::FilesystemWrite,
        &required_prevention_spec(CapabilityDomain::FilesystemWrite),
    );
    assert_eq!(observed_state, "observe_only");
    assert_eq!(prevented_state, "prevention");

    measured(
        scenario,
        AttackFamily::ObserveAndDegradedTruthfulness,
        "an observe-only backend met every observation requirement and no prevention requirement; a \
         backend that reports prevention still produced no prevention claim from a run",
    );
}

/// The control state one mock target projects for one domain.
fn mock_control_state(target: &MockTarget, domain: CapabilityDomain, spec: &ExecutionSpec) -> &'static str {
    let plan = target.backend().plan(spec).expect("planned");
    let report = IsolationReport::from_plan(session(), &plan);
    report
        .domains()
        .iter()
        .find(|d| d.domain == domain)
        .expect("every domain is projected")
        .state
        .as_str()
}

/// AC: audit/evidence assertions confirm blocked, unsupported and unmeasured
/// are not conflated.
///
/// Four silences and one denial, in one sweep, all against `MockBackend` — the
/// report's vocabulary for "nothing is known" is a property of
/// `aa_isolation::IsolationReport` itself, not of any one mechanism.
pub fn assert_blocked_unsupported_and_unmeasured_stay_distinct(scenario: &str) {
    let backend = aa_isolation::mock::MockBackend::preventing(&[CapabilityDomain::FilesystemWrite]);
    let spec = ExecutionSpec::new("/bin/true", IdentityRef::root("adversary"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress)
                .with_posture(RequirementPosture::DegradeIfUnavailable),
        );
    let plan = backend.plan(&spec).expect("the degrading requirement permits a plan");
    let planned = IsolationReport::from_plan(session(), &plan);
    let states: Vec<(CapabilityDomain, &str)> = control_states(&planned);

    assert!(
        states.contains(&(CapabilityDomain::FilesystemWrite, "prevention")),
        "{states:?}"
    );
    assert!(
        states.contains(&(CapabilityDomain::NetworkEgress, "degraded")),
        "a requirement that fell short is not reported as degraded: {states:?}"
    );
    assert!(
        states.contains(&(CapabilityDomain::Ipc, "unmeasured")),
        "a domain nobody asked about is not reported as unmeasured: {states:?}"
    );

    let refused_spec = spec
        .clone()
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::Syscall));
    let refusal = backend
        .plan(&refused_spec)
        .expect_err("a required requirement for an unreported domain must refuse");
    let refused = IsolationReport::from_refusal(session(), &refused_spec, &refusal);
    let refused_states: Vec<(CapabilityDomain, &str)> = control_states(&refused);
    assert!(
        refused_states.contains(&(CapabilityDomain::Syscall, "unsupported")),
        "{refused_states:?}"
    );
    assert!(
        refused_states.contains(&(CapabilityDomain::FilesystemWrite, "unmeasured")),
        "a requirement whose outcome was never reported is not reported as unmeasured: {refused_states:?}"
    );

    let no_boundary = IsolationReport::no_boundary(
        session(),
        IdentityRef::root("adversary"),
        aa_isolation::TargetRef::of(&spec),
        aa_isolation::CredentialPosture::default(),
        "no backend was selected for this launch",
    );
    let reasons: BTreeSet<&str> = [
        unmeasured_reason(&planned, CapabilityDomain::Ipc),
        unmeasured_reason(&refused, CapabilityDomain::FilesystemWrite),
        unmeasured_reason(&no_boundary, CapabilityDomain::FilesystemWrite),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        reasons,
        ["inconclusive", "no_backend_selected", "no_control_requested"]
            .into_iter()
            .collect::<BTreeSet<&str>>(),
        "the three silences collapsed into fewer than three reasons"
    );
    assert_eq!(no_boundary.posture().as_str(), "no_boundary");

    measured(
        scenario,
        AttackFamily::ObserveAndDegradedTruthfulness,
        "one sweep produced prevention, degraded, unsupported and unmeasured states, and the three \
         unmeasured reasons stayed distinct",
    );
}

/// The unmeasured reason a report gives for one domain.
fn unmeasured_reason(report: &IsolationReport, domain: CapabilityDomain) -> &'static str {
    match &report
        .domains()
        .iter()
        .find(|d| d.domain == domain)
        .expect("every domain is projected")
        .state
    {
        aa_isolation::ControlState::Unmeasured { reason } => reason.as_str(),
        other => panic!("{domain} is `{}`, not unmeasured", other.as_str()),
    }
}

/// AC: a claim is promoted only by a decision record, and corroboration is not
/// a decision.
///
/// Three points on one axis, which is what makes this a control rather than a
/// restatement of the predicate:
///
/// 1. a real run of a backend that *reports* prevention yields `setup_only` and
///    no prevention claim;
/// 2. an `IndependentVerification` record carrying a prevention term still
///    yields no prevention claim — the claim is downgraded to `observed`;
/// 3. a `Decision` record carrying the same term does yield one.
///
/// Without (3) the predicate could be false for every input and every
/// assertion here would still pass. Runs entirely against `MockBackend` — the
/// promotion rule lives in `aa_isolation::EnforcementEvidence`, not in any one
/// mechanism.
pub fn assert_claim_is_promoted_only_by_a_decision_record(scenario: &str) {
    let target = MockTarget {
        backend: aa_isolation::mock::MockBackend::preventing(CapabilityDomain::ALL),
        label: "mock/preventing",
    };
    let spec = required_prevention_spec(CapabilityDomain::FilesystemWrite);
    let plan = target.backend().plan(&spec).expect("planned");
    let outcome = target.launch(&spec).expect("the mock always launches");

    let run_report = IsolationReport::from_plan(session(), &plan).with_evidence(&outcome.evidence);
    assert!(
        evidence_bases(&run_report).contains(&(CapabilityDomain::FilesystemWrite, "setup_only")),
        "a run with only setup-time records reported a stronger basis: {:?}",
        evidence_bases(&run_report)
    );
    assert_no_prevention_claim("mock/preventing", &outcome.evidence);

    let corroborated = evidence_with(&plan, EvidenceKind::IndependentVerification);
    assert!(
        prevention_claims(&corroborated).is_empty(),
        "an out-of-band probe was treated as the enforcing control's own decision"
    );
    let corroborated_report = IsolationReport::from_plan(session(), &plan).with_evidence(&corroborated);
    assert_eq!(
        claim_for(&corroborated_report, CapabilityDomain::FilesystemWrite),
        ClaimTerm::Observed,
        "a prevention term arrived with no decision behind it and was not downgraded"
    );

    let decided = evidence_with(&plan, EvidenceKind::Decision);
    assert_eq!(
        prevention_claims(&decided),
        [CapabilityDomain::FilesystemWrite].into_iter().collect::<BTreeSet<_>>(),
        "a decision record carrying a prevention term did not support a prevention claim, so the \
         assertions above hold vacuously"
    );
    let decided_report = IsolationReport::from_plan(session(), &plan).with_evidence(&decided);
    assert_eq!(
        claim_for(&decided_report, CapabilityDomain::FilesystemWrite),
        ClaimTerm::DeniedBeforeExecution
    );
    assert!(evidence_bases(&decided_report).contains(&(CapabilityDomain::FilesystemWrite, "decision")));

    measured(
        scenario,
        AttackFamily::ObserveAndDegradedTruthfulness,
        "a setup-only run and an independently corroborated run both yielded no prevention claim, \
         while the same evidence graded as a decision did",
    );
}

/// Evidence for `plan` carrying one extra record of the given grade with a
/// prevention term, so the grade is the only variable.
fn evidence_with(plan: &EnforcementPlan, kind: EvidenceKind) -> EnforcementEvidence {
    EnforcementEvidence::from_plan(plan).with_record(EvidenceRecord::new(
        kind,
        CapabilityDomain::FilesystemWrite,
        ClaimTerm::DeniedBeforeExecution,
        "a forbidden write did not take effect",
    ))
}

/// The claim a report states for one domain.
fn claim_for(report: &IsolationReport, domain: CapabilityDomain) -> ClaimTerm {
    report
        .domains()
        .iter()
        .find(|d| d.domain == domain)
        .expect("every domain is projected")
        .claim
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
