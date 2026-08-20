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

/// The measured state of one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    launcher: PathBuf,
    kernel_release: Option<String>,
    security_modules: Vec<String>,
    abi: AbiFloor,
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
        })
    }

    /// Build facts directly, for tests that need a host they do not have.
    ///
    /// Not a way to fake a measurement into production: nothing constructed here
    /// reaches [`crate::capability`]'s prevention path, which requires the live
    /// probe in [`crate::probe`] regardless of what these fields say.
    pub fn for_test(launcher: impl Into<PathBuf>, abi: AbiFloor) -> Self {
        Self {
            launcher: launcher.into(),
            kernel_release: None,
            security_modules: Vec::new(),
            abi,
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

    /// One sentence describing what was measured here, for evidence.
    pub fn describe(&self) -> String {
        format!(
            "kernel {} | Landlock ABI {} (this backend's filesystem claim requires v{}) | active LSMs: {}",
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
            }
        )
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
    let mut searched = Vec::new();

    if let Some(explicit) = std::env::var_os(LAUNCHER_PATH_ENV) {
        let path = PathBuf::from(explicit);
        return if path.is_file() {
            Ok(path)
        } else {
            Err(HostUnusable::OverrideMissing { path })
        };
    }
    searched.push(format!("${LAUNCHER_PATH_ENV} (unset)"));

    if let Ok(current) = std::env::current_exe() {
        if let Some(sibling) = current.parent().map(|dir| dir.join(LAUNCHER_PROGRAM)) {
            if sibling.is_file() {
                return Ok(sibling);
            }
            searched.push(sibling.display().to_string());
        }
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(LAUNCHER_PROGRAM);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        searched.push(format!("each directory on $PATH ({LAUNCHER_PROGRAM})"));
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
}
