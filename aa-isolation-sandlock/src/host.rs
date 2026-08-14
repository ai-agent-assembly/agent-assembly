//! What this host actually is, measured rather than assumed.
//!
//! Every field here is the result of an observation taken on the machine the
//! process is running on: a file that was read, a binary that was located, a
//! command that was executed. Nothing is derived from upstream documentation,
//! and nothing is a constant compiled in from a table of kernel versions.
//!
//! The distinction matters because [`crate::capability`] turns these facts into
//! a [`BackendCapabilities`](aa_isolation::BackendCapabilities), and a
//! capability report that was populated from a vendor's feature matrix is a
//! claim about the vendor, not about this host.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The environment variable that overrides the `PATH` lookup for the backend
/// executable.
///
/// Exists so a CI lane can point at an installation it provisioned itself, and
/// so a test can point at a deliberately broken path to exercise the
/// unavailable branch. Read once, during discovery.
pub const BACKEND_PATH_ENV: &str = "AA_SANDLOCK_BIN";

/// The executable name looked up on `PATH` when [`BACKEND_PATH_ENV`] is unset.
pub const BACKEND_PROGRAM: &str = "sandlock";

/// A kernel release, reduced to the two components that gate features.
///
/// Patch level and distribution suffix are deliberately dropped: nothing this
/// crate reports turns on them, and keeping them would invite a comparison that
/// looks precise while being wrong (`6.8.0-1015-azure` is not less than
/// `6.8.0-40-generic`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    /// Major release number.
    pub major: u32,
    /// Minor release number.
    pub minor: u32,
}

impl KernelVersion {
    /// Parse the leading `major.minor` of a `uname -r` style string.
    ///
    /// Returns `None` rather than a default: a kernel release that could not be
    /// parsed is unknown, and an unknown version must not compare as new enough
    /// for anything.
    pub fn parse(release: &str) -> Option<Self> {
        let mut parts = release.trim().split(['.', '-', '+']);
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some(Self { major, minor })
    }

    /// Whether this release is at least `major.minor`.
    pub fn at_least(self, major: u32, minor: u32) -> bool {
        (self.major, self.minor) >= (major, minor)
    }
}

impl core::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Why the backend executable could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendLookupError {
    /// The host operating system is not the one this backend confines on.
    WrongPlatform {
        /// What this host is.
        os: String,
    },
    /// [`BACKEND_PATH_ENV`] named a path that is not there.
    OverrideMissing {
        /// The path that was named.
        path: PathBuf,
    },
    /// Nothing named [`BACKEND_PROGRAM`] was found on `PATH`.
    NotOnPath,
    /// The executable was found but would not report its version.
    VersionUnreadable {
        /// Where it was found.
        path: PathBuf,
        /// What went wrong.
        detail: String,
    },
}

impl core::fmt::Display for BackendLookupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongPlatform { os } => write!(
                f,
                "the sandlock backend confines Linux processes; this host is {os}. No configuration \
                 on this host can change that answer"
            ),
            Self::OverrideMissing { path } => {
                write!(f, "{BACKEND_PATH_ENV} names `{}`, which does not exist", path.display())
            }
            Self::NotOnPath => write!(
                f,
                "no `{BACKEND_PROGRAM}` executable on PATH; install it or set {BACKEND_PATH_ENV}"
            ),
            Self::VersionUnreadable { path, detail } => {
                write!(f, "`{}` did not report a version: {detail}", path.display())
            }
        }
    }
}

impl std::error::Error for BackendLookupError {}

/// The measured state of one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    executable: PathBuf,
    version: String,
    kernel: Option<KernelVersion>,
    kernel_release: Option<String>,
    security_modules: Vec<String>,
    landlock_abi: Option<u32>,
    self_check: Option<String>,
}

impl HostFacts {
    /// Locate the backend executable and read everything cheap about the host.
    ///
    /// "Cheap" means: no sandbox is established and no confined process is
    /// started. Whether confinement *works* is a separate, more expensive
    /// question answered by [`crate::probe`], and keeping the two apart is what
    /// lets the expensive one be the thing that justifies a prevention claim.
    ///
    /// # Errors
    ///
    /// [`BackendLookupError`] when the host is not Linux, the executable cannot
    /// be found, or it will not state its version.
    pub fn discover() -> Result<Self, BackendLookupError> {
        if !cfg!(target_os = "linux") {
            return Err(BackendLookupError::WrongPlatform {
                os: std::env::consts::OS.to_string(),
            });
        }
        let executable = locate_executable()?;
        let version = read_version(&executable)?;
        let kernel_release = read_trimmed("/proc/sys/kernel/osrelease");
        let kernel = kernel_release.as_deref().and_then(KernelVersion::parse);
        let security_modules = read_trimmed("/sys/kernel/security/lsm")
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let self_check = run_self_check(&executable);
        let landlock_abi = self_check.as_deref().and_then(parse_landlock_abi);
        Ok(Self {
            executable,
            version,
            kernel,
            kernel_release,
            security_modules,
            landlock_abi,
            self_check,
        })
    }

    /// Build facts directly, for tests that need a host they do not have.
    ///
    /// Not a way to fake a measurement into production: nothing constructed
    /// here reaches [`crate::capability`]'s prevention path, which requires the
    /// live probe in [`crate::probe`] regardless of what these fields say.
    pub fn for_test(executable: impl Into<PathBuf>, version: impl Into<String>, kernel: Option<KernelVersion>) -> Self {
        Self {
            executable: executable.into(),
            version: version.into(),
            kernel,
            kernel_release: kernel.map(|k| k.to_string()),
            security_modules: Vec::new(),
            landlock_abi: None,
            self_check: None,
        }
    }

    /// Set the access-control interface version, for tests that need a host
    /// whose kernel they do not have.
    pub fn with_landlock_abi(mut self, abi: Option<u32>) -> Self {
        self.landlock_abi = abi;
        self
    }

    /// Where the backend executable is.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// The version string the executable reported, verbatim.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The parsed kernel release, or `None` if it could not be read or parsed.
    pub fn kernel(&self) -> Option<KernelVersion> {
        self.kernel
    }

    /// The raw kernel release string, for messages an operator reads.
    pub fn kernel_release(&self) -> Option<&str> {
        self.kernel_release.as_deref()
    }

    /// The security modules the kernel says are active.
    ///
    /// Diagnostic only. It is *not* the basis on which any capability here
    /// claims to prevent anything — a module being listed says it is compiled
    /// in and enabled, not that it stopped a specific action. The measurement
    /// that does support that claim is [`crate::probe`].
    pub fn security_modules(&self) -> &[String] {
        &self.security_modules
    }

    /// The kernel's per-process access-control interface version, as the
    /// mechanism's own host check reported it.
    ///
    /// Diagnostic, and the input to one decision only: whether the two newest
    /// protections the mechanism enforces by default are available here. It is
    /// never the basis for a prevention claim — [`crate::probe`] is.
    pub fn landlock_abi(&self) -> Option<u32> {
        self.landlock_abi
    }

    /// The mechanism's own host-capability report, verbatim.
    ///
    /// Carried into evidence rather than parsed into a verdict. Note that this
    /// command exits zero even when it reports the host as unsupported, so its
    /// exit status is not a usable gate and is deliberately ignored.
    pub fn self_check(&self) -> Option<&str> {
        self.self_check.as_deref()
    }

    /// Whether the host is below the floor the mechanism enforces by default.
    ///
    /// An unreadable version answers `true`: a floor that cannot be shown to be
    /// met has not been met.
    pub fn below_default_protection_floor(&self) -> bool {
        !matches!(self.landlock_abi, Some(abi) if abi >= DEFAULT_PROTECTION_FLOOR_ABI)
    }
}

/// The access-control interface version the mechanism requires for every
/// protection it enforces by default.
///
/// Two of its protections — signal scoping and abstract-socket scoping — were
/// added at this version, and the mechanism treats every protection as strict
/// unless told otherwise, so a host below this floor makes it refuse rather
/// than confine. Recorded here as the number the backend explains a refusal
/// with; the refusal itself is the mechanism's.
pub const DEFAULT_PROTECTION_FLOOR_ABI: u32 = 6;

/// Resolve the executable, honouring the override.
fn locate_executable() -> Result<PathBuf, BackendLookupError> {
    if let Some(explicit) = std::env::var_os(BACKEND_PATH_ENV) {
        let path = PathBuf::from(explicit);
        return if path.exists() {
            Ok(path)
        } else {
            Err(BackendLookupError::OverrideMissing { path })
        };
    }
    let output = Command::new("which")
        .arg(BACKEND_PROGRAM)
        .output()
        .map_err(|_| BackendLookupError::NotOnPath)?;
    if !output.status.success() {
        return Err(BackendLookupError::NotOnPath);
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());
    if path.as_os_str().is_empty() || !path.exists() {
        return Err(BackendLookupError::NotOnPath);
    }
    Ok(path)
}

/// Ask the executable what it is.
///
/// The whole trimmed line is kept rather than a parsed semver: the version is
/// carried into [`aa_isolation::BackendIdentity`] and from there into evidence,
/// where an operator comparing a run against an advisory needs the string the
/// binary actually printed, not this crate's reading of it.
fn read_version(executable: &Path) -> Result<String, BackendLookupError> {
    let output =
        Command::new(executable)
            .arg("--version")
            .output()
            .map_err(|e| BackendLookupError::VersionUnreadable {
                path: executable.to_path_buf(),
                detail: e.to_string(),
            })?;
    if !output.status.success() {
        return Err(BackendLookupError::VersionUnreadable {
            path: executable.to_path_buf(),
            detail: format!("exited with {}", output.status),
        });
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return Err(BackendLookupError::VersionUnreadable {
            path: executable.to_path_buf(),
            detail: "printed nothing on stdout".to_string(),
        });
    }
    Ok(line.to_string())
}

/// Ask the mechanism what it can do on this host.
///
/// The output is unstructured text and the command exits zero even when it
/// reports the host as unsupported, so this is captured for an operator to read
/// and mined for exactly one number. Nothing here gates anything.
fn run_self_check(executable: &Path) -> Option<String> {
    let output = Command::new(executable).arg("check").output().ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Pull the access-control interface version out of the self-check text.
///
/// Deliberately narrow: it matches the one line that states the host's own
/// version and ignores every line that states a requirement, because those
/// carry version numbers too and picking the wrong one would report a host as
/// newer than it is.
fn parse_landlock_abi(report: &str) -> Option<u32> {
    report
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("Landlock:"))
        .and_then(|line| line.split("ABI v").nth(1))
        .and_then(|rest| {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
}

/// Read a file and trim it, or `None` if it is not readable.
///
/// Unreadable is deliberately not an error. A host with `securityfs` unmounted
/// is a host this crate knows less about, which shows up as an unsatisfied
/// prerequisite rather than as a failure to start.
fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_parses_release_strings() {
        assert_eq!(
            KernelVersion::parse("6.11.0-1015-azure"),
            Some(KernelVersion { major: 6, minor: 11 })
        );
        assert_eq!(
            KernelVersion::parse("5.15.0"),
            Some(KernelVersion { major: 5, minor: 15 })
        );
        assert_eq!(
            KernelVersion::parse("6.12"),
            Some(KernelVersion { major: 6, minor: 12 })
        );
    }

    /// An unparseable release must be `None`, never a zero that would compare
    /// as "older than everything" and quietly disable features, nor a default
    /// that would compare as new enough.
    #[test]
    fn unparseable_kernel_release_is_unknown() {
        assert_eq!(KernelVersion::parse(""), None);
        assert_eq!(KernelVersion::parse("linux"), None);
        assert_eq!(KernelVersion::parse("6"), None);
    }

    /// The self-check text states the host's version on one line and a
    /// requirement on the next. Reading the requirement instead would report
    /// every host as meeting the floor it does not meet.
    #[test]
    fn the_abi_parser_reads_the_host_line_and_not_the_requirement_line() {
        let report = "Landlock: ABI v5\nMinimum required: ABI v6\nStatus: UNSUPPORTED (upgrade kernel)";
        assert_eq!(parse_landlock_abi(report), Some(5));
    }

    #[test]
    fn an_unreadable_abi_is_treated_as_below_the_floor() {
        let facts = HostFacts::for_test("/usr/bin/sandlock", "sandlock 0.8.6", None);
        assert!(facts.below_default_protection_floor());
        assert!(facts
            .clone()
            .with_landlock_abi(Some(5))
            .below_default_protection_floor());
        assert!(!facts.with_landlock_abi(Some(6)).below_default_protection_floor());
    }

    #[test]
    fn at_least_compares_major_before_minor() {
        let k = KernelVersion { major: 6, minor: 7 };
        assert!(k.at_least(6, 7));
        assert!(k.at_least(5, 19));
        assert!(!k.at_least(6, 12));
        assert!(!k.at_least(7, 0));
    }

    /// The platform gate is the first thing discovery checks, so a non-Linux
    /// host can never reach the executable lookup and report something about a
    /// binary it has no way to use.
    #[test]
    fn discovery_refuses_non_linux_hosts_before_looking_for_a_binary() {
        if cfg!(target_os = "linux") {
            return;
        }
        let err = HostFacts::discover().expect_err("a non-Linux host must not produce host facts");
        assert!(matches!(err, BackendLookupError::WrongPlatform { .. }), "got {err:?}");
    }
}
