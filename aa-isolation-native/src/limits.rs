//! `RLIMIT_NOFILE`/`RLIMIT_FSIZE` enforcement, installed on the confined
//! process by the launcher before it `execve`s the program (AAASM-6165).
//!
//! # Why rlimits, and why only these two
//!
//! See the ADR (`docs/src/adr/0041-resource-ceiling-enforcement.md`) for the
//! full rlimits-first rationale. In short: rlimits need no delegated
//! filesystem subtree, are inherited across `fork`/`execve` unchanged, and
//! `libc` is already a dependency of this crate. `max_memory_bytes` and
//! `max_pids` are **not** handled here — see `crate::lower`'s `resource()`
//! function for why (no cgroup subtree for memory; `RLIMIT_NPROC` is
//! host-wide per-UID, not tree-scoped, for PIDs).
//!
//! # Soft equals hard, always
//!
//! `prlimit64` is already in [`crate::seccomp::STARTUP_BASELINE`], so a
//! confined child that is only given a lowered *soft* limit could raise it
//! back toward the hard ceiling itself. Setting soft == hard here closes
//! that — a limitation of this version stated on the capability report
//! rather than left for someone to discover empirically.

use std::fmt;

/// The numeric ceilings this backend can lower to an rlimit, resolved from
/// zero or more [`aa_isolation::ControlRequirement`]s against
/// [`CapabilityDomain::Resource`].
///
/// `None` means "not requested for this launch" — not "no ceiling". An
/// absent field installs nothing, leaving the kernel's own default (which is
/// usually `RLIM_INFINITY`) in force for that resource.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeLimits {
    /// Maximum simultaneously open file descriptors (`RLIMIT_NOFILE`).
    pub max_open_files: Option<u32>,
    /// Maximum size of any single file the process creates, in bytes
    /// (`RLIMIT_FSIZE`).
    pub max_file_size_bytes: Option<u64>,
}

impl NativeLimits {
    /// Whether no ceiling was requested at all.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl fmt::Display for NativeLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(n) = self.max_open_files {
            parts.push(format!("max_open_files={n}"));
        }
        if let Some(n) = self.max_file_size_bytes {
            parts.push(format!("max_file_size_bytes={n}"));
        }
        if parts.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

/// Install `limits` on the calling process, soft == hard for each ceiling
/// stated.
///
/// Must run after [`crate::rules::install`] (Landlock opens paths, and a
/// tight `RLIMIT_NOFILE` set beforehand could make installing the boundary
/// itself fail) and before [`crate::seccomp::install`] (the filter's
/// permitted syscall set is not consulted here, so `prlimit64` must still be
/// reachable when this runs) — see `src/bin/aa-isolation-launch.rs`'s
/// `confine_and_exec` for the enforced ordering.
///
/// # Errors
///
/// A description of which `setrlimit` call failed and why, on any failure.
/// Nothing here falls back to a softer limit on failure — a limit that could
/// not be installed must refuse the launch, not launch unconfined.
#[cfg(target_os = "linux")]
pub fn install(limits: &NativeLimits) -> Result<Vec<String>, String> {
    let mut steps = Vec::new();
    if let Some(max) = limits.max_open_files {
        set_rlimit(libc::RLIMIT_NOFILE, u64::from(max), "RLIMIT_NOFILE")?;
        steps.push(format!("RLIMIT_NOFILE installed: soft == hard == {max}"));
    }
    if let Some(max) = limits.max_file_size_bytes {
        set_rlimit(libc::RLIMIT_FSIZE, max, "RLIMIT_FSIZE")?;
        steps.push(format!("RLIMIT_FSIZE installed: soft == hard == {max} byte(s)"));
    }
    Ok(steps)
}

#[cfg(target_os = "linux")]
fn set_rlimit(resource: libc::__rlimit_resource_t, value: u64, name: &str) -> Result<(), String> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `limit` is a valid, fully-initialized `rlimit` whose pointer does
    // not outlive this call. `setrlimit` affects only the calling process.
    let rc = unsafe { libc::setrlimit(resource, &limit) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "setrlimit({name}, {value}) failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

/// The non-Linux stub. Keeps every caller — including this crate's own
/// tests, written in the runtime-decline shape so they type-check on every
/// host — compiling on a host with no rlimit mechanism reachable from here.
///
/// An empty set installs nothing on any platform, so it succeeds here too
/// (mirroring the real Linux path's own no-op case) rather than refusing a
/// launch that asked for no ceiling at all just because this host can't
/// enforce one.
#[cfg(not(target_os = "linux"))]
pub fn install(limits: &NativeLimits) -> Result<Vec<String>, String> {
    if limits.is_empty() {
        Ok(Vec::new())
    } else {
        Err("this platform has no rlimit mechanism reachable from this crate".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_limits_report_as_empty() {
        assert!(NativeLimits::default().is_empty());
        assert!(!NativeLimits {
            max_open_files: Some(32),
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn display_names_every_stated_ceiling() {
        let limits = NativeLimits {
            max_open_files: Some(32),
            max_file_size_bytes: Some(4096),
        };
        let rendered = limits.to_string();
        assert!(rendered.contains("max_open_files=32"));
        assert!(rendered.contains("max_file_size_bytes=4096"));
    }

    #[test]
    fn installing_an_empty_set_is_a_harmless_noop() {
        assert_eq!(
            install(&NativeLimits::default()).expect("no ceiling to install"),
            Vec::<String>::new()
        );
    }
}
