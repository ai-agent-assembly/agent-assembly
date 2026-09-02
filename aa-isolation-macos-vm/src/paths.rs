//! Host→guest path mapping for the macOS VM backend (AAASM-5837).
//!
//! # Why this exists, and why it refuses more than it maps
//!
//! The guest's *only* window onto the host filesystem is one virtiofs share
//! of the launch's working directory — that is a structural security
//! property this Epic is built around (AAASM-5811 AC2: host credentials
//! outside the project directory must be verified absent from the guest's
//! reachable filesystem), not a limitation to work around. So a host path
//! either falls under the shared directory (and is rewritten to where the
//! guest mounted it), or it names one of the handful of binaries actually
//! baked into the guest image (and passes through unmapped), or it names
//! something the guest cannot reach at all — and this module refuses the
//! third case rather than silently building a `LaunchRequest` naming a path
//! the guest will fail to find.
//!
//! **The guest image carries a real, minimal dev toolchain** — `git`,
//! `python3`, and `/bin/sh` (AAASM-5849; see
//! `aa-isolation-macos-vm-poc/README.md`'s "Guest dev toolchain (AAASM-5849)"
//! for what was actually verified and what wasn't). Every real
//! `aasm run <command>` invocation whose program is not one of
//! [`GUEST_RESIDENT_PROGRAMS`] and not under the shared directory still
//! refuses here, honestly, rather than reaching the guest and failing there
//! in a way this backend cannot distinguish from every other kind of
//! guest-side failure.

use std::path::{Path, PathBuf};

/// Where the project directory is mounted inside the guest — see
/// `aa-isolation-macos-vm-poc/scripts/build-guest-rootfs.sh` and every prior
/// pass's `--share-tag aa-share` convention.
pub const GUEST_SHARE_MOUNTPOINT: &str = "/mnt/share";

/// Absolute guest paths that exist in the guest image independent of any
/// virtiofs share — see `aa-isolation-macos-vm-poc/scripts/build-guest-rootfs.sh`.
/// A request naming one of these passes through unmapped; naming anything
/// else absolute and outside the share is refused (see [`to_guest_path`]).
///
/// `/usr/bin/git`, `/usr/bin/python3`, and `/bin/sh` (AAASM-5849) are the
/// real paths `scripts/fetch-guest-toolchain.sh`'s pinned Alpine extraction
/// installs them at — confirmed by the same extraction the rootfs build
/// uses, not assumed.
pub const GUEST_RESIDENT_PROGRAMS: &[&str] = &[
    "/usr/local/bin/aa-isolation-launch",
    "/usr/local/bin/busybox",
    "/usr/bin/git",
    "/usr/bin/python3",
    "/bin/sh",
];

/// Why a host path could not be mapped into the guest's reachable
/// filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMappingError {
    /// No share directory was configured for this launch — nothing is
    /// mounted in the guest at all beyond the fixed guest-resident binaries.
    NoShareConfigured,
    /// The path is outside the shared directory and is not one of
    /// [`GUEST_RESIDENT_PROGRAMS`] — the guest's fixed toolchain (AAASM-5849)
    /// does not include this program either.
    Unreachable {
        /// The host path that could not be mapped.
        host_path: String,
    },
}

impl core::fmt::Display for PathMappingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoShareConfigured => write!(
                f,
                "no project directory is shared with the guest for this launch, and the path is not one of \
                 this guest image's fixed resident binaries"
            ),
            Self::Unreachable { host_path } => write!(
                f,
                "`{host_path}` is outside the shared project directory and is not one of this guest image's \
                 fixed resident binaries ({}) — see AAASM-5849 for what the guest's toolchain does carry",
                GUEST_RESIDENT_PROGRAMS.join(", ")
            ),
        }
    }
}

/// Map one host-absolute path to where the guest can reach it.
///
/// `share_host_dir` is the host directory virtiofs-shared at
/// [`GUEST_SHARE_MOUNTPOINT`] for this launch, when one was configured — see
/// [`share_dir_for`].
pub fn to_guest_path(host_path: &str, share_host_dir: Option<&Path>) -> Result<String, PathMappingError> {
    if GUEST_RESIDENT_PROGRAMS.contains(&host_path) {
        return Ok(host_path.to_string());
    }
    let Some(share_host_dir) = share_host_dir else {
        return Err(PathMappingError::NoShareConfigured);
    };
    let host = Path::new(host_path);
    let Ok(relative) = host.strip_prefix(share_host_dir) else {
        return Err(PathMappingError::Unreachable {
            host_path: host_path.to_string(),
        });
    };
    let mut guest = PathBuf::from(GUEST_SHARE_MOUNTPOINT);
    guest.push(relative);
    Ok(guest.to_string_lossy().into_owned())
}

/// The host directory to virtiofs-share for this launch — the spec's working
/// directory, when the caller supplied one.
///
/// `None` here means [`to_guest_path`] can only resolve
/// [`GUEST_RESIDENT_PROGRAMS`]; a launch whose program or any grant falls
/// outside that fixed set refuses rather than boots a guest with nothing
/// shared into it.
pub fn share_dir_for(working_dir: Option<&Path>) -> Option<PathBuf> {
    working_dir.map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guest_resident_program_passes_through_unmapped_even_with_no_share() {
        assert_eq!(
            to_guest_path("/usr/local/bin/busybox", None),
            Ok("/usr/local/bin/busybox".to_string())
        );
    }

    #[test]
    fn the_aaasm_5849_toolchain_programs_pass_through_unmapped_even_with_no_share() {
        for program in ["/usr/bin/git", "/usr/bin/python3", "/bin/sh"] {
            assert_eq!(to_guest_path(program, None), Ok(program.to_string()));
        }
    }

    #[test]
    fn a_path_under_the_share_is_rewritten_to_the_guest_mountpoint() {
        let share = Path::new("/Users/dev/myproject");
        assert_eq!(
            to_guest_path("/Users/dev/myproject/src/main.py", Some(share)),
            Ok("/mnt/share/src/main.py".to_string())
        );
    }

    #[test]
    fn a_path_outside_the_share_is_refused_by_name() {
        let share = Path::new("/Users/dev/myproject");
        let result = to_guest_path("/usr/bin/ruby", Some(share));
        assert_eq!(
            result,
            Err(PathMappingError::Unreachable {
                host_path: "/usr/bin/ruby".to_string()
            })
        );
    }

    #[test]
    fn a_path_outside_the_share_with_no_share_configured_names_the_right_error() {
        assert_eq!(
            to_guest_path("/usr/bin/ruby", None),
            Err(PathMappingError::NoShareConfigured)
        );
    }
}
