//! What this host actually is, measured rather than assumed.
//!
//! Every field here is the result of an observation taken on the machine the
//! process is running on: a file that was read, a binary that was located, a
//! syscall that answered. Nothing is derived from a table of kernel versions,
//! and in particular the Landlock ABI is asked of the kernel rather than
//! inferred from `uname -r` — a distribution kernel's release string and its
//! Landlock ABI are independent facts, and backporting makes the inference
//! wrong in the unsafe direction.
//!
//! # The floor is a measurement, not a constant
//!
//! [`crate::rules::REQUIRED_ABI_VERSION`] is a constant, and it is a statement
//! about *this backend's claim*: the access rights its filesystem claim needs.
//! Whether a host meets it is [`HostFacts::abi_floor`], and that is measured
//! here, per host, every time the backend is constructed. ADR 0035's AAASM-5801
//! amendment asks for exactly that split — "a measured floor per host, not a
//! guessed one recorded now and corrected later".

use std::path::{Path, PathBuf};

/// The environment variable that overrides the search for the launcher binary.
///
/// Exists so a CI lane can point at the launcher `cargo` just built, so an
/// installed `aasm` can find the launcher shipped beside it, and so a test can
/// point at a deliberately broken path to exercise the refusal branch. Read
/// once, during discovery.
pub const LAUNCHER_PATH_ENV: &str = "AA_ISOLATION_LAUNCHER";

/// The launcher's file name, as built by this crate's `[[bin]]` target.
pub const LAUNCHER_PROGRAM: &str = "aa-isolation-launch";

/// Why the backend cannot be used on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostUnusable {
    /// The host operating system is not the one this backend confines on.
    WrongPlatform {
        /// What this host is.
        os: String,
    },
    /// [`LAUNCHER_PATH_ENV`] named a path that is not there.
    OverrideMissing {
        /// The path that was named.
        path: PathBuf,
    },
    /// The launcher binary could not be found.
    LauncherNotFound {
        /// Every place that was looked, so an operator can fix it without
        /// guessing which one this build uses.
        searched: Vec<String>,
    },
    /// The kernel provides no Landlock at all.
    LandlockAbsent {
        /// What the version query returned, verbatim.
        detail: String,
    },
    /// The kernel's Landlock ABI is below what this backend's claim requires.
    ///
    /// Its own variant rather than a reuse of
    /// [`LandlockAbsent`](Self::LandlockAbsent): the two need different fixes
    /// and, more importantly, the second is a host that could confine *something*
    /// while being unable to support the claim this backend makes. Collapsing
    /// them would invite a future reader to "just use best-effort here".
    AbiBelowFloor {
        /// What the kernel reported.
        measured: u32,
        /// What this backend's claim requires.
        required: u32,
    },
}

impl core::fmt::Display for HostUnusable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongPlatform { os } => write!(
                f,
                "this backend confines Linux processes; this host is {os}. No configuration on this host \
                 can change that answer"
            ),
            Self::OverrideMissing { path } => write!(
                f,
                "{LAUNCHER_PATH_ENV} names `{}`, which does not exist",
                path.display()
            ),
            Self::LauncherNotFound { searched } => write!(
                f,
                "no `{LAUNCHER_PROGRAM}` binary was found. Looked in: {}. Build it with `cargo build -p \
                 aa-isolation-native --bin {LAUNCHER_PROGRAM}`, install it beside the `aasm` binary, or \
                 set {LAUNCHER_PATH_ENV}",
                searched.join(", ")
            ),
            Self::LandlockAbsent { detail } => write!(
                f,
                "this kernel provides no Landlock ({detail}). It can be enabled by building the kernel \
                 with CONFIG_SECURITY_LANDLOCK=y and prepending \"landlock,\" to CONFIG_LSM or to the \
                 `lsm=` boot parameter"
            ),
            Self::AbiBelowFloor { measured, required } => write!(
                f,
                "this kernel's Landlock ABI is v{measured} and this backend's filesystem claim requires \
                 at least v{required} (Linux {} or newer). Below v{required} the kernel does not handle \
                 the truncate right, so a path-scoped write restriction does not stop `truncate(2)` on a \
                 file outside the permitted set — the claim would be false rather than merely weaker",
                crate::rules::REQUIRED_KERNEL_RELEASE
            ),
        }
    }
}

impl std::error::Error for HostUnusable {}

/// Whether this host meets the ABI floor this backend's claim requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiFloor {
    /// The kernel reported an ABI at or above the floor.
    Met {
        /// What the kernel reported.
        measured: u32,
    },
    /// The kernel reported an ABI below the floor.
    Below {
        /// What the kernel reported.
        measured: u32,
    },
    /// Landlock is absent from this kernel, so there is no ABI to compare.
    ///
    /// Distinct from [`Below`](Self::Below) for the same reason
    /// [`HostUnusable::LandlockAbsent`] is distinct from
    /// [`HostUnusable::AbiBelowFloor`].
    NoLandlock,
}

impl AbiFloor {
    /// The measured ABI, when there was one.
    pub fn measured(self) -> Option<u32> {
        match self {
            Self::Met { measured } | Self::Below { measured } => Some(measured),
            Self::NoLandlock => None,
        }
    }

    /// Whether the floor is met.
    pub fn is_met(self) -> bool {
        matches!(self, Self::Met { .. })
    }
}

/// Whether this host's kernel can install the syscall filter [`crate::seccomp`]
/// builds.
///
/// A measured fact, not folded into [`HostUnusable`]: seccomp absence must not
/// take the filesystem domains down with it. A host below Linux 3.17 (no
/// seccomp at all) or missing `CONFIG_SECCOMP_FILTER` still confines
/// filesystem access perfectly well, and reporting the whole backend
/// unavailable for that would be a false statement about a control this host
/// genuinely offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallFilterSupport {
    /// The kernel answered the availability query for `SECCOMP_RET_KILL_PROCESS`
    /// affirmatively.
    Available,
    /// The kernel understands `SECCOMP_GET_ACTION_AVAIL` but reported this
    /// action as unavailable.
    ActionUnavailable {
        /// What the kernel reported.
        detail: String,
    },
    /// The kernel does not implement seccomp's action-availability query at
    /// all (below Linux 4.14, or seccomp itself absent below Linux 3.17).
    Absent {
        /// What was found instead.
        detail: String,
    },
    /// This host is not Linux on x86_64, so the filter this crate builds
    /// (Finding 3) cannot be installed regardless of what the kernel supports.
    WrongArchitecture {
        /// The measured `(os, arch)` pair, as an operator-legible string.
        arch: String,
    },
}

impl SyscallFilterSupport {
    /// Whether a filter built by [`crate::seccomp::program`] can be installed
    /// here.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// The measured state of one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    launcher: PathBuf,
    kernel_release: Option<String>,
    security_modules: Vec<String>,
    abi: AbiFloor,
    syscall_filter: SyscallFilterSupport,
}

impl HostFacts {
    /// Locate the launcher and read everything cheap about the host.
    ///
    /// "Cheap" means no boundary is established and no confined process is
    /// started. Whether confinement *works* is a separate, more expensive
    /// question answered by [`crate::probe`], and keeping the two apart is what
    /// lets the expensive one be the thing that justifies a prevention claim.
    ///
    /// # Errors
    ///
    /// [`HostUnusable`] when the host is not Linux, the launcher cannot be
    /// found, or the kernel is below the measured floor.
    pub fn discover() -> Result<Self, HostUnusable> {
        Self::discover_inner(None)
    }

    /// Measure this host against a launcher the caller already has.
    ///
    /// Everything except the search is identical to [`discover`](Self::discover):
    /// the kernel is still asked for its ABI, the floor is still checked, and the
    /// probe that follows still has to observe a real denial before any claim is
    /// made. Only *which* launcher is used differs.
    ///
    /// # Why this is public rather than a test hook
    ///
    /// Two callers need it and neither is a test fixture. The confinement suite
    /// must measure the launcher `cargo` just built rather than whichever one the
    /// search happens to find, or a green lane would prove nothing about the code
    /// under review. And a packaged `aasm` that ships the launcher in a known
    /// location can name it directly instead of relying on the executable's
    /// directory layout surviving installation.
    ///
    /// It is not a way to fake a measurement: the path is only *where the boundary
    /// comes from*, and every verdict still comes from [`crate::probe`].
    ///
    /// # Errors
    ///
    /// [`HostUnusable`] when the host is not Linux, `launcher` does not exist, or
    /// the kernel is below the measured floor.
    pub fn discover_with_launcher(launcher: impl Into<PathBuf>) -> Result<Self, HostUnusable> {
        Self::discover_inner(Some(launcher.into()))
    }

    fn discover_inner(explicit: Option<PathBuf>) -> Result<Self, HostUnusable> {
        if !cfg!(target_os = "linux") {
            return Err(HostUnusable::WrongPlatform {
                os: std::env::consts::OS.to_string(),
            });
        }
        let launcher = match explicit {
            Some(path) if path.is_file() => path,
            Some(path) => return Err(HostUnusable::OverrideMissing { path }),
            None => locate_launcher()?,
        };
        let abi = measure_abi();
        match abi {
            AbiFloor::NoLandlock => {
                return Err(HostUnusable::LandlockAbsent {
                    detail: "the kernel does not implement the Landlock version query".to_string(),
                })
            }
            AbiFloor::Below { measured } => {
                return Err(HostUnusable::AbiBelowFloor {
                    measured,
                    required: crate::rules::REQUIRED_ABI_VERSION,
                })
            }
            AbiFloor::Met { .. } => {}
        }
        Ok(Self {
            launcher,
            kernel_release: read_trimmed("/proc/sys/kernel/osrelease"),
            security_modules: read_trimmed("/sys/kernel/security/lsm")
                .map(|raw| {
                    raw.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            abi,
            syscall_filter: measure_syscall_filter(),
        })
    }

    /// Build facts directly, for tests that need a host they do not have.
    ///
    /// Not a way to fake a measurement into production: nothing constructed here
    /// reaches [`crate::capability`]'s prevention path, which requires the live
    /// probe in [`crate::probe`] regardless of what these fields say.
    pub fn for_test(launcher: impl Into<PathBuf>, abi: AbiFloor) -> Self {
        Self::for_test_with_syscall_support(launcher, abi, SyscallFilterSupport::Available)
    }

    /// [`Self::for_test`] with an explicit [`SyscallFilterSupport`], for tests
    /// that need to exercise the unsupported-host arm of the syscall report.
    pub fn for_test_with_syscall_support(
        launcher: impl Into<PathBuf>,
        abi: AbiFloor,
        syscall_filter: SyscallFilterSupport,
    ) -> Self {
        Self {
            launcher: launcher.into(),
            kernel_release: None,
            security_modules: Vec::new(),
            abi,
            syscall_filter,
        }
    }

    /// Where the launcher binary is.
    pub fn launcher(&self) -> &Path {
        &self.launcher
    }

    /// The raw kernel release string, for messages an operator reads.
    ///
    /// Diagnostic only, and deliberately never compared against a number: the
    /// verdict comes from [`Self::abi_floor`], which asked the kernel.
    pub fn kernel_release(&self) -> Option<&str> {
        self.kernel_release.as_deref()
    }

    /// The security modules the kernel says are active.
    ///
    /// Diagnostic only. A module being listed says it is compiled in and
    /// enabled, not that it stopped a specific action. The measurement that
    /// supports that claim is [`crate::probe`].
    pub fn security_modules(&self) -> &[String] {
        &self.security_modules
    }

    /// The measured Landlock ABI, against this backend's floor.
    pub fn abi_floor(&self) -> AbiFloor {
        self.abi
    }

    /// Whether this host's kernel can install [`crate::seccomp`]'s filter.
    pub fn syscall_filter(&self) -> &SyscallFilterSupport {
        &self.syscall_filter
    }

    /// One sentence describing what was measured here, for evidence.
    pub fn describe(&self) -> String {
        format!(
            "kernel {} | Landlock ABI {} (this backend's filesystem claim requires v{}) | active LSMs: {} \
             | syscall filter: {}",
            self.kernel_release.as_deref().unwrap_or("<unreadable>"),
            self.abi
                .measured()
                .map(|v| format!("v{v}"))
                .unwrap_or_else(|| "absent".to_string()),
            crate::rules::REQUIRED_ABI_VERSION,
            if self.security_modules.is_empty() {
                "<unreadable>".to_string()
            } else {
                self.security_modules.join(", ")
            },
            match &self.syscall_filter {
                SyscallFilterSupport::Available => "available".to_string(),
                SyscallFilterSupport::ActionUnavailable { detail } => format!("action unavailable ({detail})"),
                SyscallFilterSupport::Absent { detail } => format!("absent ({detail})"),
                SyscallFilterSupport::WrongArchitecture { arch } => format!("wrong architecture ({arch})"),
            }
        )
    }
}

/// Ask the kernel whether it can honour `SECCOMP_RET_KILL_PROCESS`, the action
/// [`crate::seccomp::install`] asks for on every mismatch.
///
/// Mirrors [`measure_abi`]'s own "ask the kernel" pattern: `SECCOMP_GET_ACTION_AVAIL`
/// is itself the query form of the `seccomp` syscall, side-effect-free, and
/// answers the same question `crate::seccomp::install` will actually depend on
/// rather than a version-string proxy for it.
#[cfg(target_os = "linux")]
fn measure_syscall_filter() -> SyscallFilterSupport {
    if !cfg!(target_arch = "x86_64") {
        return SyscallFilterSupport::WrongArchitecture {
            arch: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        };
    }
    const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
    // `SECCOMP_RET_KILL_PROCESS`, from `linux/seccomp.h`. Duplicated from
    // `crate::seccomp` rather than imported: this module must not depend on
    // that one compiling on a non-Linux host, and the value is fixed kernel
    // ABI either way.
    let kill_process: u32 = 0x8000_0000;
    // Safety: `SECCOMP_GET_ACTION_AVAIL` reads `available_action` (a valid
    // `&u32` alive for the duration of this call) and writes nothing through
    // it; it either returns 0 (the action is available) or a negative error
    // and creates no kernel object. Sound on a kernel that does not implement
    // it (`-EINVAL`) as well as one that does.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_ACTION_AVAIL,
            0u32,
            &kill_process as *const u32,
        )
    };
    if rc == 0 {
        SyscallFilterSupport::Available
    } else {
        let error = std::io::Error::last_os_error();
        // `ENOSYS` — the query itself is not implemented — is `Absent`, not
        // `ActionUnavailable`: the two need different fixes (a kernel too old
        // for the query at all, versus one that understands the query and
        // says no), the same distinction `HostUnusable::LandlockAbsent` and
        // `HostUnusable::AbiBelowFloor` keep apart for Landlock.
        match error.raw_os_error() {
            Some(libc::ENOSYS) => SyscallFilterSupport::Absent {
                detail: format!("the kernel does not implement SECCOMP_GET_ACTION_AVAIL: {error}"),
            },
            _ => SyscallFilterSupport::ActionUnavailable {
                detail: format!("the kernel reported SECCOMP_RET_KILL_PROCESS as unavailable: {error}"),
            },
        }
    }
}

/// The non-Linux arm. Never reached through [`HostFacts::discover`], which
/// checks the platform first; present so the module compiles everywhere.
#[cfg(not(target_os = "linux"))]
fn measure_syscall_filter() -> SyscallFilterSupport {
    SyscallFilterSupport::WrongArchitecture {
        arch: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
    }
}

/// Ask the kernel which Landlock ABI it implements.
///
/// # Why the syscall rather than a kernel release comparison
///
/// A distribution kernel's release string and its Landlock ABI are independent:
/// a vendor can backport the feature to an older release, and a newer release
/// can ship with Landlock disabled at boot. Comparing `uname -r` against a table
/// would be wrong in both directions, and wrong in the *unsafe* direction for
/// the backport case only if the answer were used to permit something — which is
/// why this asks instead.
///
/// The binding crate performs the same query internally and deliberately keeps
/// it private, to stop callers building an ABI-dependent access set at run time
/// (`AccessFs::from_all(current_abi())` would make the same policy mean
/// different things on two hosts). This crate does not do that: the access set
/// is fixed at [`crate::rules::REQUIRED_ABI`], and this number is used only to
/// decide *whether* to run and to say so in evidence.
#[cfg(target_os = "linux")]
fn measure_abi() -> AbiFloor {
    // `LANDLOCK_CREATE_RULESET_VERSION`, from `linux/landlock.h`. Passing it
    // with a null attribute pointer and a zero size asks for the supported ABI
    // version and creates nothing — it is the query form of the syscall, not a
    // side-effecting call.
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
    // Safety: the version form of `landlock_create_ruleset` takes a null
    // attribute pointer and a zero size by definition, creates no kernel object
    // and returns the ABI version or a negative error. Nothing is dereferenced
    // and nothing is leaked, so this call is sound on a kernel that does not
    // implement it (it returns `-ENOSYS`) as well as on one that does.
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if version <= 0 {
        return AbiFloor::NoLandlock;
    }
    let measured = version as u32;
    if measured >= crate::rules::REQUIRED_ABI_VERSION {
        AbiFloor::Met { measured }
    } else {
        AbiFloor::Below { measured }
    }
}

/// The non-Linux arm. Never reached through [`HostFacts::discover`], which
/// checks the platform first; present so the module compiles everywhere and so
/// the answer off Linux is "no Landlock" rather than a value.
#[cfg(not(target_os = "linux"))]
fn measure_abi() -> AbiFloor {
    AbiFloor::NoLandlock
}

/// Find the launcher: the override, then beside this executable, then `PATH`.
///
/// Ordered from most specific to least. The middle case is the one an installed
/// `aasm` uses — the launcher ships beside it — and it is preferred over `PATH`
/// so that a binary of the same name earlier on `PATH` cannot displace the one
/// this build was released with.
fn locate_launcher() -> Result<PathBuf, HostUnusable> {
    locate_launcher_from(
        std::env::var_os(LAUNCHER_PATH_ENV),
        std::env::current_exe().ok(),
        std::env::var_os("PATH"),
    )
}

/// The search itself, over the three facts [`locate_launcher`] reads from the
/// environment.
///
/// Split out so the search order — and, crucially, the `$PATH` filtering below —
/// can be exercised without racing every other test in the binary over process
/// environment variables: a test names the override, the exe path and the
/// `$PATH` string it wants, and this function has no other input besides the
/// process's current directory (still read implicitly via `is_file()`, since
/// that is the exact thing under test — see the AAASM-5979 tests).
///
/// # Why `$PATH` entries are filtered to absolute paths
///
/// A zero-length or relative `$PATH` entry is not a directory to search —
/// `std::env::split_paths` does not drop empty entries, and joining the
/// launcher name onto one yields a bare relative path that `is_file()`
/// resolves against the process cwd (POSIX treats a zero-length `$PATH`
/// prefix as "."). That reinstates the attacker-substitution primitive
/// AAASM-4020 and AAASM-5937 removed elsewhere: an attacker who controls the
/// directory `aasm` is invoked from, on a host whose `$PATH` carries a stray
/// colon, gets their binary executed as the isolation launcher — the program
/// that establishes the execution-isolation boundary. Non-absolute entries
/// are skipped, not rejected, so the rest of `$PATH` still resolves. See
/// AAASM-5979.
fn locate_launcher_from(
    override_path: Option<std::ffi::OsString>,
    current_exe: Option<PathBuf>,
    path_var: Option<std::ffi::OsString>,
) -> Result<PathBuf, HostUnusable> {
    let mut searched = Vec::new();

    if let Some(explicit) = override_path {
        let path = PathBuf::from(explicit);
        return if path.is_file() {
            Ok(path)
        } else {
            Err(HostUnusable::OverrideMissing { path })
        };
    }
    searched.push(format!("${LAUNCHER_PATH_ENV} (unset)"));

    if let Some(current) = current_exe {
        if let Some(sibling) = current.parent().map(|dir| dir.join(LAUNCHER_PROGRAM)) {
            if sibling.is_file() {
                return Ok(sibling);
            }
            searched.push(sibling.display().to_string());
        }
    }

    if let Some(path_var) = path_var {
        for dir in std::env::split_paths(&path_var).filter(|d| d.is_absolute()) {
            let candidate = dir.join(LAUNCHER_PROGRAM);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        searched.push(format!("each absolute directory on $PATH ({LAUNCHER_PROGRAM})"));
    }

    Err(HostUnusable::LauncherNotFound { searched })
}

/// Read a file and trim it, or `None` if it is not readable.
///
/// Unreadable is deliberately not an error. A host with `securityfs` unmounted
/// is a host this crate knows less about, which shows up as a less informative
/// evidence sentence rather than as a failure to start.
fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The platform gate is the first thing discovery checks, so a non-Linux
    /// host can never reach the launcher lookup and report something about a
    /// binary it has no way to use.
    #[test]
    fn discovery_refuses_non_linux_hosts_before_looking_for_a_launcher() {
        if cfg!(target_os = "linux") {
            return;
        }
        let error = HostFacts::discover().expect_err("a non-Linux host must not produce host facts");
        assert!(matches!(error, HostUnusable::WrongPlatform { .. }), "{error:?}");
    }

    /// A host below the floor and a host with no Landlock at all need different
    /// fixes, and the two must never render as one another.
    #[test]
    fn the_floor_keeps_absent_and_too_old_apart() {
        assert_eq!(AbiFloor::NoLandlock.measured(), None);
        assert!(!AbiFloor::NoLandlock.is_met());
        assert!(!AbiFloor::Below { measured: 2 }.is_met());
        assert!(AbiFloor::Met { measured: 3 }.is_met());

        let absent = HostUnusable::LandlockAbsent {
            detail: "test".to_string(),
        }
        .to_string();
        let old = HostUnusable::AbiBelowFloor {
            measured: 2,
            required: crate::rules::REQUIRED_ABI_VERSION,
        }
        .to_string();
        assert!(absent.contains("no Landlock"), "{absent}");
        assert!(old.contains("truncate(2)"), "{old}");
        assert_ne!(absent, old);
    }

    /// The floor number this backend states must be the one its rule
    /// construction actually asks the kernel for. Two constants that could drift
    /// apart would let the refusal message and the syscall disagree.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_stated_floor_is_the_abi_the_rules_are_built_against() {
        assert_eq!(crate::rules::REQUIRED_ABI as u32, crate::rules::REQUIRED_ABI_VERSION);
    }

    /// The override wins over everything, and a broken override is an error
    /// rather than a fall-through to `PATH` — a lane that pointed at a launcher
    /// it meant to test must not silently measure a different one.
    #[test]
    fn a_broken_override_is_an_error_rather_than_a_fallback() {
        // Not run under a mutated process environment: setting a variable from a
        // test races every other test in the binary. The behaviour is asserted
        // through the error type the code constructs for that path.
        let error = HostUnusable::OverrideMissing {
            path: PathBuf::from("/nonexistent/aa-isolation-launch"),
        };
        assert!(error.to_string().contains(LAUNCHER_PATH_ENV));
    }

    /// Serializes every test below that calls `std::env::set_current_dir` — the
    /// process cwd is global state, and `cargo nextest` runs each test in its
    /// own process but this crate's `cargo test`-driven coverage lane (and any
    /// future `--no-fail-fast` retry inside one binary) does not.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn cwd_guard() -> std::sync::MutexGuard<'static, ()> {
        CWD_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn touch(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
    }

    /// AAASM-5979 AC 3 (regression) and AC 5 (falsified against the pre-fix
    /// shape): with cwd set to a directory holding a planted
    /// `aa-isolation-launch`, every one of `""`, `":"`, `"rel/bin"` and
    /// `"./rel/bin"` on `$PATH` must resolve nothing — a relative or empty
    /// `$PATH` entry is a cwd-relative lookup by another name, and the plant is
    /// at the bare binary name because that is exactly the candidate those
    /// entries produce (`PathBuf::from("").join(LAUNCHER_PROGRAM)` is the bare
    /// relative path). A plant anywhere else cannot detect this defect — see
    /// the ticket's "Provenance" section for how that blind spot let AAASM-5937
    /// ship past review with exactly this gap.
    ///
    /// Falsified: reverting the `.filter(|d| d.is_absolute())` in
    /// `locate_launcher_from` turns every case below into `Ok(..)`, reddening
    /// this test (verified for AAASM-5979's PR evidence, not merely asserted
    /// here).
    #[test]
    fn a_relative_or_empty_path_entry_contributes_no_candidate() {
        let _cwd_lock = cwd_guard();

        let cwd = tempfile::tempdir().unwrap();
        // What an empty entry resolves to, and what a relative entry resolves to.
        touch(&cwd.path().join(LAUNCHER_PROGRAM));
        let rel_dir = cwd.path().join("rel").join("bin");
        std::fs::create_dir_all(&rel_dir).unwrap();
        touch(&rel_dir.join(LAUNCHER_PROGRAM));

        let prior_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd.path()).unwrap();
        let results: Vec<_> = ["", ":", "rel/bin", "./rel/bin"]
            .into_iter()
            .map(|path_var| {
                let got = locate_launcher_from(None, None, Some(std::ffi::OsString::from(path_var)));
                (path_var, got)
            })
            .collect();
        // Restored before asserting, so a failure does not leave every later
        // test in this binary running from a deleted temporary directory.
        std::env::set_current_dir(&prior_cwd).unwrap();

        for (path_var, got) in results {
            assert!(
                got.is_err(),
                "PATH={path_var:?} resolved {got:?} — a non-absolute $PATH entry let a \
                 cwd-planted binary stand in for the isolation launcher (AAASM-5979)"
            );
        }
    }

    /// AAASM-5979 AC 4 (no-behaviour-change control) and AC 5 (falsified
    /// against an over-broad fix): the same unsafe entries from the test above,
    /// each paired with a real absolute directory on the same `$PATH` string —
    /// including with the unsafe entry listed first — must still resolve that
    /// directory's launcher. Without this half, a filter that dropped every
    /// `$PATH` entry would pass the negative-control test above while breaking
    /// `$PATH` lookup outright.
    ///
    /// Falsified: replacing the `.filter(|d| d.is_absolute())` with a filter
    /// that drops every entry (`|_| false`) turns every case below into
    /// `Err(..)`, reddening this test.
    #[test]
    fn a_real_absolute_path_entry_still_resolves_beside_an_unsafe_one() {
        let _cwd_lock = cwd_guard();

        let cwd = tempfile::tempdir().unwrap();
        touch(&cwd.path().join(LAUNCHER_PROGRAM));
        let rel_dir = cwd.path().join("rel").join("bin");
        std::fs::create_dir_all(&rel_dir).unwrap();
        touch(&rel_dir.join(LAUNCHER_PROGRAM));

        let real = tempfile::tempdir().unwrap();
        let real_launcher = real.path().join(LAUNCHER_PROGRAM);
        touch(&real_launcher);
        let real_dir = real.path().to_str().unwrap();

        let prior_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd.path()).unwrap();
        let results: Vec<_> = [
            format!(":{real_dir}"),
            format!("{real_dir}:"),
            format!("rel/bin:{real_dir}"),
            format!("{real_dir}:rel/bin"),
        ]
        .into_iter()
        .map(|path_var| {
            let got = locate_launcher_from(None, None, Some(std::ffi::OsString::from(path_var.clone())));
            (path_var, got)
        })
        .collect();
        std::env::set_current_dir(&prior_cwd).unwrap();

        for (path_var, got) in results {
            assert_eq!(
                got.ok(),
                Some(real_launcher.clone()),
                "PATH={path_var:?} failed to resolve the real launcher directory \
                 alongside an unsafe entry"
            );
        }
    }

    /// The refactor that split `locate_launcher` into `locate_launcher_from`
    /// must not have disturbed the *other* half of the search order: the exe
    /// sibling still wins over an absolute `$PATH` directory. This is the
    /// ordering ADR 0030 §6.4 makes a security property (`aasm` and its
    /// children ship as one versioned unit, so a `$PATH` hit must never
    /// shadow the sibling shipped with the running executable) — the same
    /// property `aa-cli`'s `resolve_from_prefers_the_exe_sibling_over_path_and_cargo_bin`
    /// pins for the gateway resolver. The `$PATH`-filtering tests above only
    /// ever pass `current_exe: None`, so on their own they cannot show this
    /// ordering survived the refactor.
    #[test]
    fn the_exe_sibling_still_wins_over_an_absolute_path_directory() {
        let exe_dir = tempfile::tempdir().unwrap();
        let exe = exe_dir.path().join("aasm");
        touch(&exe);
        let sibling = exe_dir.path().join(LAUNCHER_PROGRAM);
        touch(&sibling);

        let path_dir = tempfile::tempdir().unwrap();
        touch(&path_dir.path().join(LAUNCHER_PROGRAM));

        let got = locate_launcher_from(
            None,
            Some(exe.clone()),
            Some(std::ffi::OsString::from(path_dir.path().to_str().unwrap())),
        );
        assert_eq!(
            got.ok(),
            Some(sibling),
            "the $PATH directory's launcher won over the exe sibling"
        );
    }
}
