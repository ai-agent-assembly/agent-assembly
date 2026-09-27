//! The typed host-capability broker contract (AAASM-6171, Core ADR 0038
//! amendment §24-26).
//!
//! # What this module is for
//!
//! Some native operations an agent's task genuinely needs — building an Xcode
//! project, listing simulators — can only run against a real macOS host
//! toolchain. This module gives a launch a way to *request* one of a closed
//! set of such operations and gives a mediating component a way to *report*
//! what it actually does about that request, tied to this run's explicit
//! authority via the same witness-gated pattern [`crate::egress`] and
//! [`crate::credential_broker`] already use for their own domains.
//!
//! # The privilege boundary is the closed operation set, not a sandbox
//!
//! [`HostOperation`] has no `Exec { command: String }` variant, and none may
//! ever be added — that absence is what keeps this module from being a
//! generic host-shell-execution surface wearing a typed hat. Each variant
//! carries only validated fields ([`SchemeName`], [`ConfigurationName`],
//! [`Destination`], [`SimulatorUdid`], [`SigningIdentityRef`]), and
//! [`to_argv`] is the *only* function in this codebase that turns one into a
//! host process argv.
//!
//! An argv array (`Command::args`, never `sh -c`) rules out shell
//! metacharacter injection, but it does **not** rule out argument injection:
//! `xcodebuild -scheme X -destination '...' -derivedDataPath D
//! SWIFT_ACTIVE_COMPILATION_CONDITIONS=INJECTED build` is a real, legal
//! invocation, and the trailing `KEY=value` element is honored as a build
//! setting override — a bare positional argv element some caller-controlled
//! string, and this repository would have shipped an override-injection
//! vector despite using an argv array throughout. This is why every validated
//! newtype in this module rejects `=` and leading `-`, not just shell
//! metacharacters — see [`ArgumentRejected`].
//!
//! # Two-value posture, mirroring `EgressPosture`/`BrokeragePosture`
//!
//! [`HostCapabilityPosture`] has exactly two values for the same reason those
//! two types do: a third ("broker preferred, direct native acceptable") would
//! *be* the native fallback this contract exists to forbid.
//!
//! # Composite domain binding, not a new `CapabilityDomain`
//!
//! This module binds to [`CapabilityDomain::ProcessCreation`] as its single
//! lease-bearing authority state — spawning `xcodebuild`/`simctl` is process
//! creation — and separately checks [`CapabilityDomain::FilesystemRead`]/
//! [`CapabilityDomain::FilesystemWrite`]-shaped path scoping and a
//! [`CapabilityDomain::Credential`]-shaped signing-identity reference, without
//! introducing a new domain. See ADR 0038 §24 for why: `CapabilityDomain::ALL`
//! is asserted against at ~80 call sites across this workspace, and
//! `execution_receipt::validate`'s own domain-count check would invalidate
//! every already-stored receipt if the set changed.
//!
//! # What this module does not provide
//!
//! There is no OS confinement boundary under this broker on macOS today
//! (`aa-isolation-native`/`aa-isolation-sandlock` are Linux-only; the macOS VM
//! backend's guest is Linux, not macOS, and is `Unavailable` on essentially
//! every host anyway). This broker is a **supervisor-side mediation
//! boundary**: it is the only thing standing between a governed launch and a
//! real `xcodebuild` invocation, not a sandbox around one. A determined
//! unconfined agent can still invoke `xcodebuild`/`simctl` directly, entirely
//! outside this broker — see ADR 0038 §24's "what this amendment does not
//! decide" and `governance/capability-manifest.yaml`'s `known_bypasses` for
//! this capability. There is also no UID/entitlement privilege separation:
//! the broker runs as the caller's own UID (required — `xcodebuild` needs
//! that UID's Xcode/DerivedData access).

use std::path::{Path, PathBuf};

use aa_core::attestation::ClaimTerm;

use crate::authority::{AuthorityState, AuthorityWitness, EffectiveAuthority};
use crate::capability::{CapabilityDomain, FailurePosture};
use crate::evidence::{EvidenceKind, EvidenceRecord};
use crate::lease::{CapabilityLease, LeaseInvalid};
use crate::spec::{ExecutionSpec, IdentityRef, RequirementScope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The schema token this contract's wire shape is versioned under.
pub const HOST_CAPABILITY_CONTRACT_SCHEMA: &str = "aasm.isolation.host_capability_contract/1";

/// The longest a validated argument field may be, in bytes.
pub const MAX_ARGUMENT_LEN: usize = 256;

// ---------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------

/// Whether a launch requires the host-capability broker at all.
///
/// Exactly two values — see the module documentation for why a third value
/// would itself be the native fallback this contract exists to forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum HostCapabilityPosture {
    /// No host-capability property is required. Every launch reads this way
    /// until a policy source issues a [`HostCapabilityContract`] — the
    /// rc.7/rc.8-compatible default.
    NotRequired,
    /// A brokered host operation must satisfy this contract's stated
    /// properties, or the launch must be refused.
    BrokerRequired,
}

// ---------------------------------------------------------------------------
// Validated argument newtypes
// ---------------------------------------------------------------------------

/// Why a validated field's raw value was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArgumentRejected {
    /// The raw value was empty.
    Empty {
        /// The field's name.
        field: &'static str,
    },
    /// The raw value starts with `-`, which would let it be read as a flag
    /// rather than a value (e.g. `-derivedDataPath` injected in place of a
    /// scheme).
    LeadingDash {
        /// The field's name.
        field: &'static str,
        /// The rejected value.
        value: String,
    },
    /// The raw value contains `=`, which `xcodebuild` accepts as a bare
    /// positional `KEY=value` build-setting override — the empirically
    /// demonstrated injection vector this module's newtypes exist to close.
    ContainsEquals {
        /// The field's name.
        field: &'static str,
        /// The rejected value.
        value: String,
    },
    /// The raw value contains an ASCII control character (including NUL or a
    /// newline).
    ControlCharacter {
        /// The field's name.
        field: &'static str,
    },
    /// The raw value exceeds [`MAX_ARGUMENT_LEN`].
    TooLong {
        /// The field's name.
        field: &'static str,
        /// The raw value's length in bytes.
        len: usize,
        /// The maximum permitted length.
        max: usize,
    },
    /// [`SigningIdentityRef`] only: the raw value is not exactly 40
    /// hexadecimal characters (a codesigning certificate fingerprint).
    NotHexFingerprint {
        /// The field's name.
        field: &'static str,
    },
}

impl core::fmt::Display for ArgumentRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "`{field}` may not be empty"),
            Self::LeadingDash { field, value } => {
                write!(
                    f,
                    "`{field}` value `{value}` starts with `-`, which could be read as a flag"
                )
            }
            Self::ContainsEquals { field, value } => write!(
                f,
                "`{field}` value `{value}` contains `=`, which `xcodebuild` accepts as a bare build-setting override"
            ),
            Self::ControlCharacter { field } => write!(f, "`{field}` contains a control character"),
            Self::TooLong { field, len, max } => {
                write!(f, "`{field}` is {len} bytes, longer than the {max}-byte maximum")
            }
            Self::NotHexFingerprint { field } => write!(f, "`{field}` is not exactly 40 hexadecimal characters"),
        }
    }
}

impl std::error::Error for ArgumentRejected {}

/// Validate a raw argument value against the shared rules every newtype in
/// this module enforces: non-empty, no leading `-`, no `=`, no control
/// characters, within [`MAX_ARGUMENT_LEN`].
fn validate_argument(field: &'static str, raw: &str) -> Result<(), ArgumentRejected> {
    if raw.is_empty() {
        return Err(ArgumentRejected::Empty { field });
    }
    if raw.len() > MAX_ARGUMENT_LEN {
        return Err(ArgumentRejected::TooLong {
            field,
            len: raw.len(),
            max: MAX_ARGUMENT_LEN,
        });
    }
    if raw.starts_with('-') {
        return Err(ArgumentRejected::LeadingDash {
            field,
            value: raw.to_string(),
        });
    }
    if raw.contains('=') {
        return Err(ArgumentRejected::ContainsEquals {
            field,
            value: raw.to_string(),
        });
    }
    if raw.chars().any(|c| c.is_control()) {
        return Err(ArgumentRejected::ControlCharacter { field });
    }
    Ok(())
}

/// A validated Xcode scheme name. See [`ArgumentRejected`] for what is
/// rejected and why.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SchemeName(String);

impl SchemeName {
    /// Validate `raw` as a scheme name.
    pub fn new(raw: &str) -> Result<Self, ArgumentRejected> {
        validate_argument("scheme", raw)?;
        Ok(Self(raw.to_string()))
    }

    /// The validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated Xcode build configuration name (e.g. `Debug`, `Release`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConfigurationName(String);

impl ConfigurationName {
    /// Validate `raw` as a configuration name.
    pub fn new(raw: &str) -> Result<Self, ArgumentRejected> {
        validate_argument("configuration", raw)?;
        Ok(Self(raw.to_string()))
    }

    /// The validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated simulator UDID.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SimulatorUdid(String);

impl SimulatorUdid {
    /// Validate `raw` as a simulator UDID.
    pub fn new(raw: &str) -> Result<Self, ArgumentRejected> {
        validate_argument("simulator_udid", raw)?;
        Ok(Self(raw.to_string()))
    }

    /// The validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated codesigning identity reference: exactly 40 hexadecimal
/// characters (a certificate SHA-1 fingerprint), nothing else. This is a
/// *reference* to a signing identity already present in the host's keychain
/// — never a credential value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SigningIdentityRef(String);

impl SigningIdentityRef {
    /// Validate `raw` as a 40-character hex fingerprint.
    pub fn new(raw: &str) -> Result<Self, ArgumentRejected> {
        validate_argument("signing_identity", raw)?;
        if raw.len() != 40 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ArgumentRejected::NotHexFingerprint {
                field: "signing_identity",
            });
        }
        Ok(Self(raw.to_string()))
    }

    /// The validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A build destination. Closed enum — the caller can **never** supply
/// free-text destination content; the only caller-controlled data point is a
/// validated [`SimulatorUdid`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum Destination {
    /// `generic/platform=macOS`.
    GenericMacOs,
    /// `generic/platform=iOS`.
    GenericIos,
    /// `id=<udid>`, for a specific simulator device.
    SimulatorById(SimulatorUdid),
}

impl Destination {
    /// Lower to the exact `-destination` argument value `xcodebuild` expects.
    /// Every branch is a literal in this function's own body except the
    /// validated UDID.
    pub fn as_arg(&self) -> String {
        match self {
            Self::GenericMacOs => "generic/platform=macOS".to_string(),
            Self::GenericIos => "generic/platform=iOS".to_string(),
            Self::SimulatorById(udid) => format!("id={}", udid.as_str()),
        }
    }
}

// ---------------------------------------------------------------------------
// Path scoping
// ---------------------------------------------------------------------------

/// Why [`scoped_path`] rejected a candidate path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathRejected {
    /// `candidate` canonicalized outside every entry in `permitted`.
    EscapesPermittedScope {
        /// The rejected candidate, as given.
        candidate: PathBuf,
        /// The permitted roots it was checked against.
        permitted: Vec<PathBuf>,
    },
    /// `candidate` does not exist.
    DoesNotExist {
        /// The rejected candidate, as given.
        candidate: PathBuf,
    },
    /// `candidate` (or a permitted root) could not be canonicalized.
    NotCanonicalizable {
        /// The rejected candidate, as given.
        candidate: PathBuf,
        /// The OS error detail.
        detail: String,
    },
}

impl core::fmt::Display for PathRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EscapesPermittedScope { candidate, permitted } => write!(
                f,
                "`{}` does not resolve inside any of the permitted roots {:?}",
                candidate.display(),
                permitted
            ),
            Self::DoesNotExist { candidate } => write!(f, "`{}` does not exist", candidate.display()),
            Self::NotCanonicalizable { candidate, detail } => {
                write!(f, "`{}` could not be canonicalized: {detail}", candidate.display())
            }
        }
    }
}

impl std::error::Error for PathRejected {}

/// Canonicalize `candidate` and require it to be inside one of `permitted`
/// (each independently canonicalized). Rejects `..` traversal, a symlink that
/// resolves outside every permitted root, and a non-existent path.
///
/// **Residual, stated plainly rather than hidden**: resolution happens at
/// check time only. A symlink swapped between this check and the actual host
/// invocation is *not* prevented — macOS has no `openat2(RESOLVE_BENEATH)`
/// equivalent, and `xcodebuild` reopens paths itself after this check
/// returns. This function establishes "not obviously outside scope right
/// now", not TOCTOU-safety.
pub fn scoped_path(candidate: &Path, permitted: &[PathBuf]) -> Result<PathBuf, PathRejected> {
    let canonical = candidate.canonicalize().map_err(|_| {
        if candidate.exists() {
            PathRejected::NotCanonicalizable {
                candidate: candidate.to_path_buf(),
                detail: "canonicalization failed for an existing path".to_string(),
            }
        } else {
            PathRejected::DoesNotExist {
                candidate: candidate.to_path_buf(),
            }
        }
    })?;

    let mut canonical_permitted = Vec::with_capacity(permitted.len());
    for root in permitted {
        match root.canonicalize() {
            Ok(c) => canonical_permitted.push(c),
            Err(_) => continue,
        }
    }

    if canonical_permitted.iter().any(|root| canonical.starts_with(root)) {
        Ok(canonical)
    } else {
        Err(PathRejected::EscapesPermittedScope {
            candidate: candidate.to_path_buf(),
            permitted: permitted.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// The closed operation set this broker mediates. Deliberately no
/// `Exec { command: String }` variant — see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum HostOperation {
    /// `xcodebuild -list -json`, to discover a container's schemes.
    XcodeList(XcodeListRequest),
    /// `xcodebuild <action>` for one scheme/configuration/destination.
    XcodeBuild(XcodeBuildRequest),
    /// `simctl list devices available -j`.
    SimulatorList(SimulatorListRequest),
    /// A codesigning request. Vocabulary only — no invoker exists in this
    /// build; [`check_invoker_exists`] always refuses this kind. Automating
    /// `security unlock-keychain` would put a keychain secret on the agent
    /// path, which this module's own policy forbids.
    Codesign(CodesignRequest),
}

/// The kind of a [`HostOperation`], independent of its request payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum OperationKind {
    /// See [`HostOperation::XcodeList`].
    XcodeList,
    /// See [`HostOperation::XcodeBuild`].
    XcodeBuild,
    /// See [`HostOperation::SimulatorList`].
    SimulatorList,
    /// See [`HostOperation::Codesign`].
    Codesign,
}

impl OperationKind {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XcodeList => "xcode_list",
            Self::XcodeBuild => "xcode_build",
            Self::SimulatorList => "simulator_list",
            Self::Codesign => "codesign",
        }
    }
}

impl HostOperation {
    /// This operation's [`OperationKind`].
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::XcodeList(_) => OperationKind::XcodeList,
            Self::XcodeBuild(_) => OperationKind::XcodeBuild,
            Self::SimulatorList(_) => OperationKind::SimulatorList,
            Self::Codesign(_) => OperationKind::Codesign,
        }
    }
}

/// A closed set of `xcodebuild` actions. No caller-supplied free text ever
/// becomes the action argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum BuildAction {
    /// `build`.
    Build,
    /// `clean`.
    Clean,
    /// `-showBuildSettings`.
    ShowBuildSettings,
}

impl BuildAction {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Clean => "clean",
            Self::ShowBuildSettings => "-showBuildSettings",
        }
    }
}

/// The container an Xcode operation targets. `SwiftPackage` needs no path of
/// its own beyond `container_root`/`project_root` — `xcodebuild` discovers
/// `Package.swift` there.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum XcodeContainer {
    /// An `.xcodeproj` at this path.
    Project(PathBuf),
    /// An `.xcworkspace` at this path.
    Workspace(PathBuf),
    /// A SwiftPM package — discovered from the working directory alone.
    SwiftPackage,
}

/// A request to list an Xcode container's schemes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct XcodeListRequest {
    container_root: PathBuf,
}

impl XcodeListRequest {
    /// A list request against `container_root` (not yet scope-checked —
    /// [`check_paths_scoped`] does that).
    pub fn new(container_root: PathBuf) -> Self {
        Self { container_root }
    }

    /// The container root this request targets.
    pub fn container_root(&self) -> &Path {
        &self.container_root
    }
}

/// A request to run one `xcodebuild` action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct XcodeBuildRequest {
    project_root: PathBuf,
    container: XcodeContainer,
    scheme: SchemeName,
    configuration: ConfigurationName,
    destination: Destination,
    derived_data: PathBuf,
    action: BuildAction,
}

impl XcodeBuildRequest {
    /// A build request. Paths are not yet scope-checked — [`check_paths_scoped`]
    /// does that as part of [`host_capability_gate`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_root: PathBuf,
        container: XcodeContainer,
        scheme: SchemeName,
        configuration: ConfigurationName,
        destination: Destination,
        derived_data: PathBuf,
        action: BuildAction,
    ) -> Self {
        Self {
            project_root,
            container,
            scheme,
            configuration,
            destination,
            derived_data,
            action,
        }
    }

    /// The project root this build reads from.
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Where derived data is written.
    pub fn derived_data(&self) -> &Path {
        &self.derived_data
    }

    /// The requested scheme.
    pub fn scheme(&self) -> &SchemeName {
        &self.scheme
    }

    /// The requested destination.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }
}

/// A request to list available simulator devices. No fields — `simctl list
/// devices available -j` needs none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SimulatorListRequest {}

/// A codesigning request. Vocabulary only — see [`HostOperation::Codesign`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CodesignRequest {
    artifact_path: PathBuf,
    identity: SigningIdentityRef,
}

impl CodesignRequest {
    /// A codesign request naming `artifact_path` and `identity`. There is no
    /// invoker for this request in this build — see the module documentation.
    pub fn new(artifact_path: PathBuf, identity: SigningIdentityRef) -> Self {
        Self {
            artifact_path,
            identity,
        }
    }

    /// The artifact this request would sign.
    pub fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    /// The signing identity reference this request would use.
    pub fn identity(&self) -> &SigningIdentityRef {
        &self.identity
    }
}

// ---------------------------------------------------------------------------
// Argv construction — the single choke point
// ---------------------------------------------------------------------------

/// A host process invocation, fully constructed and ready to hand to
/// `std::process::Command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostArgv {
    /// The program to invoke.
    pub program: PathBuf,
    /// Its arguments, in order.
    pub args: Vec<String>,
}

/// The **only** function in this codebase that builds a host process argv
/// for a [`HostOperation`]. Every element is either a literal flag name
/// hardcoded in this function's own body, or comes from a validated newtype,
/// or comes from a [`Path`] that has already passed [`scoped_path`]. Nothing
/// here ever runs a shell, and no caller-supplied string can ever become a
/// bare positional argv element.
pub fn to_argv(op: &HostOperation, program: &Path) -> Result<HostArgv, ArgumentRejected> {
    let program = program.to_path_buf();
    let args = match op {
        HostOperation::XcodeList(_req) => {
            // `-list -json` alone, run with the container root as the
            // process's working directory — the caller (`known_schemes`)
            // sets `current_dir` rather than this function emitting a
            // `-project`/`-workspace` flag, since `XcodeListRequest` does not
            // itself distinguish a SwiftPM package from a `.xcodeproj`.
            vec!["-list".to_string(), "-json".to_string()]
        }
        HostOperation::XcodeBuild(req) => {
            let mut a = Vec::new();
            match &req.container {
                XcodeContainer::Project(p) => {
                    a.push("-project".to_string());
                    a.push(p.display().to_string());
                }
                XcodeContainer::Workspace(p) => {
                    a.push("-workspace".to_string());
                    a.push(p.display().to_string());
                }
                XcodeContainer::SwiftPackage => {}
            }
            a.push("-scheme".to_string());
            a.push(req.scheme.as_str().to_string());
            a.push("-configuration".to_string());
            a.push(req.configuration.as_str().to_string());
            a.push("-destination".to_string());
            a.push(req.destination.as_arg());
            a.push("-derivedDataPath".to_string());
            a.push(req.derived_data.display().to_string());
            a.push(req.action.as_arg().to_string());
            a
        }
        HostOperation::SimulatorList(_) => vec![
            "list".to_string(),
            "devices".to_string(),
            "available".to_string(),
            "-j".to_string(),
        ],
        HostOperation::Codesign(req) => {
            // No invoker exists for this kind (`check_invoker_exists` always
            // refuses it before `perform` would ever call this), but the argv
            // shape is still specified so a future invoker has one function
            // to extend rather than a new one to write.
            vec![
                "-s".to_string(),
                req.identity.as_str().to_string(),
                req.artifact_path.display().to_string(),
            ]
        }
    };
    Ok(HostArgv { program, args })
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

/// A quantitative ceiling on a brokered operation's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputCeiling {
    /// Maximum stdout bytes retained.
    pub max_stdout_bytes: usize,
    /// Maximum stderr bytes retained.
    pub max_stderr_bytes: usize,
    /// Maximum wall-clock seconds before the operation is killed. `None`
    /// means no ceiling is stated.
    pub wall_clock_secs: Option<u64>,
}

impl Default for OutputCeiling {
    fn default() -> Self {
        Self {
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            wall_clock_secs: Some(300),
        }
    }
}

/// What a launch requires of its host-capability brokerage, backend-neutral
/// and lease/identity-bound (via [`HostCapabilityAuthority`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HostCapabilityContract {
    schema_version: u32,
    posture: HostCapabilityPosture,
    permitted_operations: Vec<OperationKind>,
    output_ceiling: OutputCeiling,
}

impl HostCapabilityContract {
    /// The inert, rc.7/rc.8-compatible default: no host-capability property is
    /// required, so [`host_capability_gate`] admits without consulting a
    /// broker, authority, path or argument at all. Every real launch carries
    /// this today.
    pub fn not_required() -> Self {
        Self {
            schema_version: 1,
            posture: HostCapabilityPosture::NotRequired,
            permitted_operations: Vec::new(),
            output_ceiling: OutputCeiling::default(),
        }
    }

    /// A contract requiring the broker, with no operation permitted until
    /// [`Self::with_permitted_operations`] states some.
    pub fn broker_required() -> Self {
        Self {
            schema_version: 1,
            posture: HostCapabilityPosture::BrokerRequired,
            permitted_operations: Vec::new(),
            output_ceiling: OutputCeiling::default(),
        }
    }

    /// State the operation kinds this contract permits.
    pub fn with_permitted_operations(mut self, kinds: Vec<OperationKind>) -> Self {
        self.permitted_operations = kinds;
        self
    }

    /// State this contract's output ceiling.
    pub fn with_output_ceiling(mut self, ceiling: OutputCeiling) -> Self {
        self.output_ceiling = ceiling;
        self
    }

    /// Whether host-capability brokerage is required at all.
    pub fn posture(&self) -> HostCapabilityPosture {
        self.posture
    }

    /// The operation kinds this contract permits.
    pub fn permitted_operations(&self) -> &[OperationKind] {
        &self.permitted_operations
    }

    /// This contract's output ceiling.
    pub fn output_ceiling(&self) -> &OutputCeiling {
        &self.output_ceiling
    }

    /// This contract's schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

impl Default for HostCapabilityContract {
    /// [`Self::not_required`] — every launch that does not construct a
    /// contract explicitly gets the rc.7/rc.8-compatible default.
    fn default() -> Self {
        Self::not_required()
    }
}

// ---------------------------------------------------------------------------
// Broker report
// ---------------------------------------------------------------------------

/// Reuses [`crate::egress::BrokerAvailability`] rather than a second copy of
/// the identical two-variant type.
pub use crate::egress::BrokerAvailability;

/// One operation kind a broker actually covers, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BrokeredOperation {
    /// The operation kind this covers.
    pub kind: OperationKind,
    /// How, in words an operator can act on.
    pub mechanism_detail: String,
}

/// A measured toolchain fact (never asserted from `cfg!(target_os)` alone).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ToolchainFact {
    /// The tool name (e.g. `xcodebuild`).
    pub tool: String,
    /// Its reported version string.
    pub version: String,
    /// Its resolved path on this host.
    pub resolved_path: String,
}

/// A truthful statement of what a mediating component actually provides for
/// this launch — never more than can be verified against real facts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HostCapabilityBrokerReport {
    availability: BrokerAvailability,
    failure_posture: FailurePosture,
    operations: Vec<BrokeredOperation>,
    toolchain: Vec<ToolchainFact>,
}

impl HostCapabilityBrokerReport {
    /// No mediating component is available, for the stated reason.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            availability: BrokerAvailability::Unavailable { reason: reason.into() },
            failure_posture: FailurePosture::NotApplicable,
            operations: Vec::new(),
            toolchain: Vec::new(),
        }
    }

    /// An available broker, reporting no operations until
    /// [`Self::with_operation`] states some.
    pub fn new(failure_posture: FailurePosture) -> Self {
        Self {
            availability: BrokerAvailability::Available,
            failure_posture,
            operations: Vec::new(),
            toolchain: Vec::new(),
        }
    }

    /// Add a covered operation.
    pub fn with_operation(mut self, op: BrokeredOperation) -> Self {
        self.operations.push(op);
        self
    }

    /// Add a measured toolchain fact.
    pub fn with_toolchain_fact(mut self, fact: ToolchainFact) -> Self {
        self.toolchain.push(fact);
        self
    }

    /// Whether a mediating component is available.
    pub fn availability(&self) -> &BrokerAvailability {
        &self.availability
    }

    /// What this broker does when it itself fails.
    pub fn failure_posture(&self) -> FailurePosture {
        self.failure_posture
    }

    /// Every operation kind this broker covers.
    pub fn operations(&self) -> &[BrokeredOperation] {
        &self.operations
    }

    /// Every measured toolchain fact this broker reports.
    pub fn toolchain(&self) -> &[ToolchainFact] {
        &self.toolchain
    }

    /// Whether this broker covers `kind`.
    pub fn covers(&self, kind: OperationKind) -> bool {
        self.operations.iter().any(|op| op.kind == kind)
    }
}

// ---------------------------------------------------------------------------
// Authority / witness
// ---------------------------------------------------------------------------

/// This run's authority for the host-capability domains: a single
/// lease-bearing [`AuthorityState`] for [`CapabilityDomain::ProcessCreation`]
/// (spawning `xcodebuild`/`simctl` is process creation), plus non-lease-bearing
/// states for the filesystem and credential dimensions this broker also
/// touches. Constructible only from a spec plus an [`AuthorityWitness`].
#[derive(Debug, Clone)]
pub struct HostCapabilityAuthority {
    identity: IdentityRef,
    process_creation_state: AuthorityState,
    fs_read_state: AuthorityState,
    fs_write_state: AuthorityState,
    credential_state: AuthorityState,
}

impl HostCapabilityAuthority {
    /// Build this run's host-capability authority from a spec
    /// [`crate::authority::authority_gate`] has already validated.
    ///
    /// `_witness` is not read — see [`crate::egress::EgressAuthority::from_gated_spec`]'s
    /// own documentation for why that is the whole mechanism.
    pub fn from_gated_spec(spec: &ExecutionSpec, _witness: &AuthorityWitness) -> Self {
        let authority = EffectiveAuthority::from_spec(spec).unwrap_or_else(|_| EffectiveAuthority::deny_all());
        Self {
            identity: spec.identity().clone(),
            process_creation_state: authority.state(CapabilityDomain::ProcessCreation).clone(),
            fs_read_state: authority.state(CapabilityDomain::FilesystemRead).clone(),
            fs_write_state: authority.state(CapabilityDomain::FilesystemWrite).clone(),
            credential_state: authority.state(CapabilityDomain::Credential).clone(),
        }
    }

    /// Who this authority was built for. Asserted, not verified.
    pub fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    /// This run's authority state for [`CapabilityDomain::ProcessCreation`] —
    /// the single lease-bearing state this authority carries.
    pub fn process_creation_state(&self) -> &AuthorityState {
        &self.process_creation_state
    }

    /// The validated [`CapabilityLease`] backing [`Self::process_creation_state`],
    /// when authority is [`AuthorityState::Leased`].
    pub fn process_creation_lease(&self) -> Option<&CapabilityLease> {
        match &self.process_creation_state {
            AuthorityState::Leased(lease) => Some(lease.as_ref()),
            _ => None,
        }
    }

    /// This run's authority state for [`CapabilityDomain::FilesystemRead`].
    pub fn fs_read_state(&self) -> &AuthorityState {
        &self.fs_read_state
    }

    /// This run's authority state for [`CapabilityDomain::FilesystemWrite`].
    pub fn fs_write_state(&self) -> &AuthorityState {
        &self.fs_write_state
    }

    /// This run's authority state for [`CapabilityDomain::Credential`].
    pub fn credential_state(&self) -> &AuthorityState {
        &self.credential_state
    }
}

/// Unforgeable-by-construction proof that [`host_capability_gate`] ran and
/// admitted the launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilityWitness(());

// ---------------------------------------------------------------------------
// Refusal
// ---------------------------------------------------------------------------

/// Why [`host_capability_gate`] (or one of the checks it composes) refused a
/// launch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostCapabilityRefusal {
    /// [`HostCapabilityPosture::BrokerRequired`] but no mediating component
    /// is available.
    BrokerRequiredButUnavailable {
        /// Why, in words an operator can act on.
        reason: String,
    },
    /// A broker is available but fails open.
    BrokerRequiredButFailsOpen {
        /// The broker's actual failure posture.
        posture: FailurePosture,
    },
    /// The requested operation kind is not in the contract's permitted set.
    OperationNotPermitted {
        /// The requested kind.
        kind: OperationKind,
    },
    /// No invoker exists for this operation kind in this build (always true
    /// for [`OperationKind::Codesign`] today).
    NoInvokerForOperation {
        /// The requested kind.
        kind: OperationKind,
    },
    /// No explicit grant authorizes [`CapabilityDomain::ProcessCreation`] for
    /// this run.
    NoProcessCreationGrant,
    /// A grant exists for [`CapabilityDomain::ProcessCreation`] but does not
    /// cover the requested scope.
    ProcessCreationScopeNotCoveredByGrant,
    /// The process-creation lease backing this authority failed
    /// [`CapabilityLease::validate_at`].
    LeaseInvalid(LeaseInvalid),
    /// A path in the requested operation is outside every permitted root.
    PathOutsidePermittedScope(PathRejected),
    /// A validated argument field rejected its raw value.
    ArgumentRejected(ArgumentRejected),
    /// The requested scheme is not among the container's own known schemes.
    UnknownScheme {
        /// The requested scheme.
        scheme: String,
        /// The schemes actually known for this container.
        known: Vec<String>,
    },
    /// The requested simulator device is not among the known devices.
    UnknownDevice {
        /// The requested UDID.
        udid: String,
    },
    /// The toolchain this operation needs is unavailable.
    ToolchainUnavailable {
        /// Why, in words an operator can act on.
        reason: String,
    },
    /// The contract states an output-ceiling field the broker cannot support.
    OutputCeilingUnsupported {
        /// The stated field's name.
        field: &'static str,
        /// Why the broker cannot support it.
        reason: String,
    },
}

impl HostCapabilityRefusal {
    /// The [`CapabilityDomain`] this refusal concerns, when it concerns one.
    ///
    /// Only the process-creation grant/lease variants name a domain — they
    /// are genuinely about this run's own confinement authority. Every other
    /// variant concerns the broker's own mediation (availability, operation
    /// scope, argument/path validity, toolchain facts) rather than this run's
    /// confinement in any [`CapabilityDomain`], so it returns `None` —
    /// consistent with [`refusal_record`] building its evidence with
    /// `domain: None` for exactly this reason: this broker does not itself
    /// confine process creation, it only mediates whether a request reaches
    /// the host at all.
    pub fn domain(&self) -> Option<CapabilityDomain> {
        match self {
            Self::NoProcessCreationGrant | Self::ProcessCreationScopeNotCoveredByGrant | Self::LeaseInvalid(_) => {
                Some(CapabilityDomain::ProcessCreation)
            }
            _ => None,
        }
    }
}

impl core::fmt::Display for HostCapabilityRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BrokerRequiredButUnavailable { reason } => {
                write!(
                    f,
                    "host-capability brokerage is required but no mediating component is available: {reason}"
                )
            }
            Self::BrokerRequiredButFailsOpen { posture } => write!(
                f,
                "host-capability brokerage is required but the available broker fails open (posture: {})",
                posture.as_manifest_str()
            ),
            Self::OperationNotPermitted { kind } => {
                write!(
                    f,
                    "`{}` is not among this contract's permitted operations",
                    kind.as_str()
                )
            }
            Self::NoInvokerForOperation { kind } => {
                write!(f, "no invoker exists for `{}` in this build", kind.as_str())
            }
            Self::NoProcessCreationGrant => write!(f, "no explicit grant authorizes process creation for this run"),
            Self::ProcessCreationScopeNotCoveredByGrant => {
                write!(
                    f,
                    "a process-creation grant exists but does not cover the requested scope"
                )
            }
            Self::LeaseInvalid(reason) => write!(f, "the process-creation lease is invalid: {reason:?}"),
            Self::PathOutsidePermittedScope(reason) => write!(f, "{reason}"),
            Self::ArgumentRejected(reason) => write!(f, "{reason}"),
            Self::UnknownScheme { scheme, known } => {
                write!(
                    f,
                    "scheme `{scheme}` is not among this container's known schemes: {known:?}"
                )
            }
            Self::UnknownDevice { udid } => write!(f, "device `{udid}` is not among the known simulator devices"),
            Self::ToolchainUnavailable { reason } => write!(f, "the required toolchain is unavailable: {reason}"),
            Self::OutputCeilingUnsupported { field, reason } => {
                write!(
                    f,
                    "the contract states `{field}` but the broker cannot support it: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for HostCapabilityRefusal {}

// ---------------------------------------------------------------------------
// Composable checks
// ---------------------------------------------------------------------------

/// Whether [`HostCapabilityPosture::BrokerRequired`] is actually satisfiable
/// by `broker`. A no-op under [`HostCapabilityPosture::NotRequired`].
pub fn check_broker_available(
    contract: &HostCapabilityContract,
    broker: &HostCapabilityBrokerReport,
) -> Result<(), HostCapabilityRefusal> {
    if contract.posture() == HostCapabilityPosture::NotRequired {
        return Ok(());
    }
    match broker.availability() {
        BrokerAvailability::Unavailable { reason } => {
            Err(HostCapabilityRefusal::BrokerRequiredButUnavailable { reason: reason.clone() })
        }
        BrokerAvailability::Available => match broker.failure_posture() {
            FailurePosture::FailOpen | FailurePosture::FailOpenSilent => {
                Err(HostCapabilityRefusal::BrokerRequiredButFailsOpen {
                    posture: broker.failure_posture(),
                })
            }
            FailurePosture::FailClosed | FailurePosture::SilentTruncation | FailurePosture::NotApplicable => Ok(()),
        },
    }
}

/// Whether `kind` is in `contract`'s permitted-operations set. A no-op under
/// [`HostCapabilityPosture::NotRequired`].
pub fn check_operation_permitted(
    contract: &HostCapabilityContract,
    kind: OperationKind,
) -> Result<(), HostCapabilityRefusal> {
    if contract.posture() == HostCapabilityPosture::NotRequired {
        return Ok(());
    }
    if contract.permitted_operations().contains(&kind) {
        Ok(())
    } else {
        Err(HostCapabilityRefusal::OperationNotPermitted { kind })
    }
}

/// Whether `authority` grants [`CapabilityDomain::ProcessCreation`] for
/// `requested_scope`.
pub fn check_process_creation_grant(
    authority: &HostCapabilityAuthority,
    requested_scope: &RequirementScope,
) -> Result<(), HostCapabilityRefusal> {
    match authority.process_creation_state() {
        AuthorityState::Denied => Err(HostCapabilityRefusal::NoProcessCreationGrant),
        AuthorityState::CompatibilityResidual => Ok(()),
        AuthorityState::Leased(lease) => {
            if lease.covers(requested_scope) {
                Ok(())
            } else {
                Err(HostCapabilityRefusal::ProcessCreationScopeNotCoveredByGrant)
            }
        }
    }
}

/// Whether the process-creation lease backing `authority`, if any, is valid
/// at `now`. A no-op (`Ok`) when authority carries no lease at all — absence
/// of a lease is [`check_process_creation_grant`]'s question, not this one's.
pub fn check_lease_validity(
    authority: &HostCapabilityAuthority,
    now: std::time::SystemTime,
) -> Result<(), HostCapabilityRefusal> {
    match authority.process_creation_lease() {
        Some(lease) => lease.validate_at(now).map_err(HostCapabilityRefusal::LeaseInvalid),
        None => Ok(()),
    }
}

/// Whether every path `op` names resolves inside the appropriate permitted
/// scope: read paths (project/container roots) inside `permitted_read`,
/// write paths (derived data) inside `permitted_write`.
pub fn check_paths_scoped(
    op: &HostOperation,
    permitted_read: &[PathBuf],
    permitted_write: &[PathBuf],
) -> Result<(), HostCapabilityRefusal> {
    match op {
        HostOperation::XcodeList(req) => {
            scoped_path(req.container_root(), permitted_read)
                .map_err(HostCapabilityRefusal::PathOutsidePermittedScope)?;
            Ok(())
        }
        HostOperation::XcodeBuild(req) => {
            scoped_path(req.project_root(), permitted_read)
                .map_err(HostCapabilityRefusal::PathOutsidePermittedScope)?;
            if let XcodeContainer::Project(p) | XcodeContainer::Workspace(p) = &req.container {
                scoped_path(p, permitted_read).map_err(HostCapabilityRefusal::PathOutsidePermittedScope)?;
            }
            // `derived_data` is a write target and is typically created by
            // this very invocation, so it is checked against its *parent*
            // directory rather than requiring it to already exist.
            let derived_parent = req.derived_data().parent().unwrap_or(req.derived_data());
            scoped_path(derived_parent, permitted_write).map_err(HostCapabilityRefusal::PathOutsidePermittedScope)?;
            Ok(())
        }
        HostOperation::SimulatorList(_) => Ok(()),
        HostOperation::Codesign(req) => {
            scoped_path(req.artifact_path(), permitted_read)
                .map_err(HostCapabilityRefusal::PathOutsidePermittedScope)?;
            Ok(())
        }
    }
}

/// Whether every validated field `op` carries is actually known to the
/// broker's own discovered vocabulary: a requested scheme must be among
/// `known_schemes`, a requested simulator device among `known_devices`.
pub fn check_arguments(
    op: &HostOperation,
    known_schemes: &[String],
    known_devices: &[String],
) -> Result<(), HostCapabilityRefusal> {
    match op {
        HostOperation::XcodeBuild(req) => {
            if !known_schemes.is_empty() && !known_schemes.iter().any(|s| s == req.scheme().as_str()) {
                return Err(HostCapabilityRefusal::UnknownScheme {
                    scheme: req.scheme().as_str().to_string(),
                    known: known_schemes.to_vec(),
                });
            }
            if let Destination::SimulatorById(udid) = req.destination() {
                if !known_devices.is_empty() && !known_devices.iter().any(|d| d == udid.as_str()) {
                    return Err(HostCapabilityRefusal::UnknownDevice {
                        udid: udid.as_str().to_string(),
                    });
                }
            }
            Ok(())
        }
        HostOperation::XcodeList(_) | HostOperation::SimulatorList(_) | HostOperation::Codesign(_) => Ok(()),
    }
}

/// Whether an invoker exists for `kind` in this build. Always refuses
/// [`OperationKind::Codesign`] — see [`HostOperation::Codesign`].
pub fn check_invoker_exists(kind: OperationKind) -> Result<(), HostCapabilityRefusal> {
    match kind {
        OperationKind::XcodeList | OperationKind::XcodeBuild | OperationKind::SimulatorList => Ok(()),
        OperationKind::Codesign => Err(HostCapabilityRefusal::NoInvokerForOperation { kind }),
    }
}

/// Whether `broker` can support every field `contract`'s [`OutputCeiling`]
/// states. This build's broker always supports both byte ceilings and the
/// wall-clock ceiling (see `aa-cli`'s `perform`), so this is currently
/// always `Ok` — kept as a real check, not a stub, so a future broker that
/// cannot support one has one call site to state that.
pub fn check_output_ceiling(
    _contract: &HostCapabilityContract,
    _broker: &HostCapabilityBrokerReport,
) -> Result<(), HostCapabilityRefusal> {
    Ok(())
}

// ---------------------------------------------------------------------------
// The composed gate
// ---------------------------------------------------------------------------

/// Refuse a host-capability request this run's contract, the available
/// broker, this run's explicit authority, and the request's own validity
/// cannot together satisfy.
///
/// Under [`HostCapabilityPosture::NotRequired`], returns the witness
/// immediately without consulting `broker`, `authority`, `permitted_read`,
/// `permitted_write`, `known_schemes` or `known_devices` at all — the
/// rc.7/rc.8 compatibility path, mirroring [`crate::egress::egress_gate`] and
/// [`crate::credential_broker::credential_gate`] exactly. This is what keeps
/// every real launch alive today, since no policy path emits this
/// requirement yet.
///
/// Otherwise, checks run in this order: broker availability, operation
/// permitted, process-creation grant, lease validity, paths scoped, arguments
/// valid, invoker exists, output ceiling.
#[allow(clippy::too_many_arguments)]
pub fn host_capability_gate(
    contract: &HostCapabilityContract,
    broker: &HostCapabilityBrokerReport,
    authority: &HostCapabilityAuthority,
    op: &HostOperation,
    permitted_read: &[PathBuf],
    permitted_write: &[PathBuf],
    requested_scope: &RequirementScope,
    known_schemes: &[String],
    known_devices: &[String],
    now: std::time::SystemTime,
) -> Result<HostCapabilityWitness, HostCapabilityRefusal> {
    if contract.posture() == HostCapabilityPosture::NotRequired {
        return Ok(HostCapabilityWitness(()));
    }

    check_broker_available(contract, broker)?;
    check_operation_permitted(contract, op.kind())?;
    check_process_creation_grant(authority, requested_scope)?;
    check_lease_validity(authority, now)?;
    check_paths_scoped(op, permitted_read, permitted_write)?;
    check_arguments(op, known_schemes, known_devices)?;
    check_invoker_exists(op.kind())?;
    check_output_ceiling(contract, broker)?;

    Ok(HostCapabilityWitness(()))
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// A setup fact, one per covered operation kind: this run's brokerage for it.
/// [`EvidenceKind::Installed`] + [`ClaimTerm::Planned`] — a fact about setup,
/// never a runtime fact, so it can never itself support
/// [`crate::evidence::EnforcementEvidence::claim_for`].
pub fn brokered_operation_record(op: &BrokeredOperation) -> EvidenceRecord {
    EvidenceRecord::new(
        EvidenceKind::Installed,
        CapabilityDomain::ProcessCreation,
        ClaimTerm::Planned,
        format!(
            "this run's host-capability brokerage for `{}`: {}",
            op.kind.as_str(),
            op.mechanism_detail
        ),
    )
}

/// The broker refusing synchronously, before any host process exists,
/// genuinely is [`EvidenceKind::Decision`] + [`ClaimTerm::DeniedBeforeExecution`]
/// — this broker is the only thing that would otherwise spawn the process.
///
/// Built with `domain: None` (via [`EvidenceRecord::about_run`]), **not**
/// `Some(CapabilityDomain::ProcessCreation)` —
/// [`crate::evidence::EnforcementEvidence::supports_prevention_claim`] and
/// [`crate::evidence::EnforcementEvidence::claim_for`] both filter on
/// `r.domain == Some(domain)`, so a domain-`None` record cannot accidentally
/// raise a prevention claim about this *run's own process-creation
/// confinement*, which this broker does not provide (an unconfined agent can
/// still spawn `xcodebuild` directly, entirely unrelated to this broker
/// existing).
pub fn refusal_record(refusal: &HostCapabilityRefusal) -> EvidenceRecord {
    EvidenceRecord::about_run(
        EvidenceKind::Decision,
        ClaimTerm::DeniedBeforeExecution,
        format!("the host-capability broker refused a request before any host process existed: {refusal}"),
    )
}

/// The achieved fact for a performed operation: [`EvidenceKind::Exercised`] +
/// [`ClaimTerm::Observed`] — a successful invocation is not a decision about
/// anything, it is an observed outcome.
pub fn achieved_record(kind: OperationKind, exit_code: Option<i32>) -> EvidenceRecord {
    let detail = match exit_code {
        Some(code) => format!(
            "host operation `{}` ran to completion with exit code {code}",
            kind.as_str()
        ),
        None => format!("host operation `{}` ran but reported no exit code", kind.as_str()),
    };
    EvidenceRecord::new(
        EvidenceKind::Exercised,
        CapabilityDomain::ProcessCreation,
        ClaimTerm::Observed,
        detail,
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::attenuation::Ancestry;
    use crate::authority::authority_gate;
    use crate::capability::CapabilityDomain;
    use crate::evidence::EnforcementEvidence;
    use crate::lease::{LeaseBasis, LeaseId};
    use crate::lowering::permit_only_selector;
    use crate::plan::{BackendIdentity, LaunchPosture, Provenance};
    use crate::spec::ControlRequirement;

    fn test_backend_identity() -> BackendIdentity {
        BackendIdentity {
            id: "test-backend".to_string(),
            version: "0".to_string(),
            provenance: Provenance {
                source: "test".to_string(),
                license: "Apache-2.0".to_string(),
                modified: false,
            },
        }
    }

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn identity() -> IdentityRef {
        IdentityRef::root("agent-under-test")
    }

    fn base_spec() -> ExecutionSpec {
        ExecutionSpec::new("claude", identity())
    }

    fn lease_for(domain: CapabilityDomain, scope: RequirementScope) -> CapabilityLease {
        CapabilityLease::new(
            LeaseId::new("lease-under-test"),
            identity(),
            domain,
            scope,
            t(1_000),
            t(2_000),
            LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
        )
    }

    fn authority_for(spec: &ExecutionSpec) -> HostCapabilityAuthority {
        let witness = authority_gate(spec, &Ancestry::Root, t(1_500)).expect("spec authorized in this fixture");
        HostCapabilityAuthority::from_gated_spec(spec, &witness)
    }

    fn selectors(names: &[&str]) -> RequirementScope {
        RequirementScope::Selectors(names.iter().map(|n| permit_only_selector(n)).collect())
    }

    fn available_broker() -> HostCapabilityBrokerReport {
        HostCapabilityBrokerReport::new(FailurePosture::FailClosed).with_operation(BrokeredOperation {
            kind: OperationKind::XcodeBuild,
            mechanism_detail: "measured xcodebuild toolchain".to_string(),
        })
    }

    fn xcode_build_op(scheme: &str, project_root: &Path, derived_data: &Path) -> HostOperation {
        HostOperation::XcodeBuild(XcodeBuildRequest::new(
            project_root.to_path_buf(),
            XcodeContainer::SwiftPackage,
            SchemeName::new(scheme).unwrap(),
            ConfigurationName::new("Debug").unwrap(),
            Destination::GenericMacOs,
            derived_data.to_path_buf(),
            BuildAction::Build,
        ))
    }

    // ---- Argument-rejection controls (AC3/AC4) ------------------------------

    #[test]
    fn option_injection_is_rejected() {
        assert_eq!(
            SchemeName::new("-derivedDataPath"),
            Err(ArgumentRejected::LeadingDash {
                field: "scheme",
                value: "-derivedDataPath".to_string(),
            })
        );
    }

    #[test]
    fn setting_injection_is_rejected() {
        assert_eq!(
            SchemeName::new("SWIFT_ACTIVE_COMPILATION_CONDITIONS=INJECTED"),
            Err(ArgumentRejected::ContainsEquals {
                field: "scheme",
                value: "SWIFT_ACTIVE_COMPILATION_CONDITIONS=INJECTED".to_string(),
            })
        );
    }

    #[test]
    fn control_characters_nul_newline_and_overlength_are_rejected() {
        assert_eq!(
            SchemeName::new("a\0b"),
            Err(ArgumentRejected::ControlCharacter { field: "scheme" })
        );
        assert_eq!(
            SchemeName::new("a\nb"),
            Err(ArgumentRejected::ControlCharacter { field: "scheme" })
        );
        assert_eq!(SchemeName::new(""), Err(ArgumentRejected::Empty { field: "scheme" }));
        let long = "a".repeat(MAX_ARGUMENT_LEN + 1);
        assert_eq!(
            SchemeName::new(&long),
            Err(ArgumentRejected::TooLong {
                field: "scheme",
                len: long.len(),
                max: MAX_ARGUMENT_LEN,
            })
        );
    }

    #[test]
    fn valid_scheme_is_accepted() {
        assert!(SchemeName::new("MyApp").is_ok());
    }

    #[test]
    fn signing_identity_requires_exactly_40_hex_chars() {
        assert!(SigningIdentityRef::new(&"a".repeat(40)).is_ok());
        assert_eq!(
            SigningIdentityRef::new(&"a".repeat(39)),
            Err(ArgumentRejected::NotHexFingerprint {
                field: "signing_identity"
            })
        );
        assert_eq!(
            SigningIdentityRef::new(&"g".repeat(40)),
            Err(ArgumentRejected::NotHexFingerprint {
                field: "signing_identity"
            })
        );
    }

    // ---- Path-escape controls -------------------------------------------------

    #[test]
    fn dot_dot_traversal_is_rejected() {
        let tmp = std::env::temp_dir();
        let permitted = vec![tmp.join(format!("hc-test-permitted-{}", std::process::id()))];
        std::fs::create_dir_all(&permitted[0]).unwrap();
        let escape = permitted[0].join("..").join("..");
        let result = scoped_path(&escape, &permitted);
        std::fs::remove_dir_all(&permitted[0]).ok();
        assert!(matches!(result, Err(PathRejected::EscapesPermittedScope { .. })));
    }

    #[test]
    fn a_real_symlink_escaping_every_permitted_root_is_rejected() {
        let base = std::env::temp_dir().join(format!("hc-test-symlink-{}", std::process::id()));
        let permitted_root = base.join("permitted");
        let outside_root = base.join("outside");
        std::fs::create_dir_all(&permitted_root).unwrap();
        std::fs::create_dir_all(&outside_root).unwrap();
        let outside_target = outside_root.join("secret");
        std::fs::write(&outside_target, b"secret").unwrap();
        let link = permitted_root.join("escape-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_target, &link).unwrap();

        let result = scoped_path(&link, std::slice::from_ref(&permitted_root));
        std::fs::remove_dir_all(&base).ok();
        assert!(matches!(result, Err(PathRejected::EscapesPermittedScope { .. })));
    }

    #[test]
    fn a_path_actually_inside_the_permitted_root_is_admitted() {
        let base = std::env::temp_dir().join(format!("hc-test-inside-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let result = scoped_path(&base, std::slice::from_ref(&base));
        std::fs::remove_dir_all(&base).ok();
        assert!(result.is_ok());
    }

    // ---- Closed destination enum ----------------------------------------------

    #[test]
    fn destination_only_ever_emits_fixed_literals_or_a_validated_udid() {
        assert_eq!(Destination::GenericMacOs.as_arg(), "generic/platform=macOS");
        assert_eq!(Destination::GenericIos.as_arg(), "generic/platform=iOS");
        let udid = SimulatorUdid::new("ABCD1234").unwrap();
        assert_eq!(Destination::SimulatorById(udid).as_arg(), "id=ABCD1234");
    }

    // ---- to_argv structural control (AC3) --------------------------------------

    #[test]
    fn to_argv_never_emits_a_positional_element_containing_unescaped_equals_from_raw_caller_text() {
        // `Destination::as_arg`'s own fixed literals contain `=` by Xcode's
        // own destination-selector syntax (`platform=macOS`/`platform=iOS`) —
        // these are literals this function's own body emits, not caller
        // text, so they are the one legitimate exception this control names
        // explicitly rather than silently.
        let fixed_literals_with_equals: &[&str] = &["generic/platform=macOS", "generic/platform=iOS"];
        let ops: Vec<HostOperation> = vec![
            HostOperation::XcodeList(XcodeListRequest::new(PathBuf::from("/tmp"))),
            xcode_build_op("MyScheme", Path::new("/tmp/proj"), Path::new("/tmp/dd")),
            HostOperation::XcodeBuild(XcodeBuildRequest::new(
                PathBuf::from("/tmp/proj"),
                XcodeContainer::SwiftPackage,
                SchemeName::new("MyScheme").unwrap(),
                ConfigurationName::new("Debug").unwrap(),
                Destination::SimulatorById(SimulatorUdid::new("ABCD1234").unwrap()),
                PathBuf::from("/tmp/dd"),
                BuildAction::Build,
            )),
            HostOperation::SimulatorList(SimulatorListRequest::default()),
            HostOperation::Codesign(CodesignRequest::new(
                PathBuf::from("/tmp/app"),
                SigningIdentityRef::new(&"a".repeat(40)).unwrap(),
            )),
        ];
        for op in &ops {
            let argv = to_argv(op, Path::new("/usr/bin/true")).unwrap();
            for element in &argv.args {
                if element.contains('=') {
                    // `id=<validated udid>` is the one other fixed-prefix
                    // literal `Destination::as_arg` emits — the udid half
                    // already went through `SimulatorUdid::new`'s own
                    // `=`-rejection, so a positional element of this shape
                    // can never carry unvalidated caller text either.
                    let is_validated_simulator_destination =
                        element.starts_with("id=") && !element["id=".len()..].contains('=');
                    assert!(
                        fixed_literals_with_equals.contains(&element.as_str()) || is_validated_simulator_destination,
                        "argv element `{element}` contains `=` and is not a fixed literal this function itself emits"
                    );
                }
            }
        }
    }

    // ---- Lease expiry (AC4) ----------------------------------------------------

    #[test]
    fn expired_lease_is_refused_by_check_lease_validity() {
        let scope = selectors(&["/tmp"]);
        let spec = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::ProcessCreation).with_scope(scope.clone()))
            .with_lease(lease_for(CapabilityDomain::ProcessCreation, scope));
        let authority = authority_for(&spec);
        assert!(check_lease_validity(&authority, t(1_500)).is_ok());
        assert!(matches!(
            check_lease_validity(&authority, t(5_000)),
            Err(HostCapabilityRefusal::LeaseInvalid(_))
        ));
    }

    // ---- Denied authority (AC4) -------------------------------------------------

    #[test]
    fn denied_authority_refuses_process_creation_grant() {
        let spec = base_spec(); // no requirement, no lease
        let authority = authority_for(&spec);
        let scope = selectors(&["/tmp"]);
        assert_eq!(
            check_process_creation_grant(&authority, &scope),
            Err(HostCapabilityRefusal::NoProcessCreationGrant)
        );
    }

    // ---- Scope not covered (AC4) -------------------------------------------------

    #[test]
    fn uncovered_scope_is_refused_covered_scope_is_admitted() {
        let granted = selectors(&["/tmp/allowed"]);
        let spec = base_spec()
            .with_requirement(
                ControlRequirement::prevent(CapabilityDomain::ProcessCreation).with_scope(granted.clone()),
            )
            .with_lease(lease_for(CapabilityDomain::ProcessCreation, granted.clone()));
        let authority = authority_for(&spec);

        let uncovered = selectors(&["/tmp/evil"]);
        assert_eq!(
            check_process_creation_grant(&authority, &uncovered),
            Err(HostCapabilityRefusal::ProcessCreationScopeNotCoveredByGrant)
        );
        assert!(check_process_creation_grant(&authority, &granted).is_ok());
    }

    // ---- Broker unavailable (AC4) -------------------------------------------------

    #[test]
    fn broker_required_but_unavailable_is_refused_available_broker_is_admitted() {
        let contract = HostCapabilityContract::broker_required();
        let unavailable = HostCapabilityBrokerReport::unavailable("xcode-select reported no active toolchain");
        assert!(matches!(
            check_broker_available(&contract, &unavailable),
            Err(HostCapabilityRefusal::BrokerRequiredButUnavailable { .. })
        ));
        assert!(check_broker_available(&contract, &available_broker()).is_ok());
    }

    #[test]
    fn not_required_admits_without_consulting_broker_authority_or_paths_at_all() {
        let contract = HostCapabilityContract::not_required();
        let broker = HostCapabilityBrokerReport::unavailable("no broker in this deployment");
        let spec = base_spec();
        let authority = authority_for(&spec);
        let op = xcode_build_op("AnyScheme", Path::new("/definitely/does/not/exist"), Path::new("/nope"));
        assert!(host_capability_gate(
            &contract,
            &broker,
            &authority,
            &op,
            &[],
            &[],
            &RequirementScope::Whole,
            &[],
            &[],
            t(1_500),
        )
        .is_ok());
    }

    // ---- No invoker for Codesign (AC5) --------------------------------------------

    #[test]
    fn codesign_has_no_invoker() {
        assert_eq!(
            check_invoker_exists(OperationKind::Codesign),
            Err(HostCapabilityRefusal::NoInvokerForOperation {
                kind: OperationKind::Codesign
            })
        );
        assert!(check_invoker_exists(OperationKind::XcodeBuild).is_ok());
        assert!(check_invoker_exists(OperationKind::XcodeList).is_ok());
        assert!(check_invoker_exists(OperationKind::SimulatorList).is_ok());
    }

    // ---- Evidence: domain-None refusal never raises a prevention claim -----------

    #[test]
    fn refusal_record_alone_raises_no_prevention_claim_for_any_domain_paired_with_a_control_that_does() {
        let refusal = HostCapabilityRefusal::BrokerRequiredButUnavailable {
            reason: "test fixture".to_string(),
        };
        let mut evidence = EnforcementEvidence::new(test_backend_identity(), LaunchPosture::Ready);
        evidence.record(refusal_record(&refusal));

        for domain in CapabilityDomain::ALL {
            assert!(
                !evidence.supports_prevention_claim(*domain),
                "domain-None refusal record must not raise a prevention claim for {domain:?}"
            );
            assert_eq!(
                evidence.claim_for(*domain),
                ClaimTerm::Unmeasured,
                "domain-None refusal record must leave claim_for Unmeasured for {domain:?}"
            );
        }

        // Control: the identical fixture, with an additional Decision record
        // that actually names ProcessCreation, DOES raise the claim — proving
        // the domain-`None` choice above is load-bearing, not vacuous.
        evidence.record(EvidenceRecord::new(
            EvidenceKind::Decision,
            CapabilityDomain::ProcessCreation,
            ClaimTerm::DeniedBeforeExecution,
            "control: a real per-domain decision record",
        ));
        assert!(evidence.supports_prevention_claim(CapabilityDomain::ProcessCreation));
    }

    #[test]
    fn achieved_record_is_exercised_and_observed_never_decision() {
        let record = achieved_record(OperationKind::XcodeBuild, Some(0));
        assert_eq!(record.kind, EvidenceKind::Exercised);
        assert_eq!(record.claim, ClaimTerm::Observed);
        assert_eq!(record.domain, Some(CapabilityDomain::ProcessCreation));
    }
}
