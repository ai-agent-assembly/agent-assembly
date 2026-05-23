//! Kprobe management for file I/O interception (AAASM-38).
//!
//! Attaches `openat_kprobe`, `write_kprobe`, and `unlink_kprobe` from
//! `aa-ebpf-programs` to the corresponding kernel functions, filtered by
//! the target PID stored in a BPF map.

#[cfg(target_os = "linux")]
use aya::Ebpf;

use crate::error::EbpfError;

/// Attaches and manages file I/O kprobe programs.
///
/// Create via [`KprobeManager::attach`]. The probes stay active until
/// [`KprobeManager::detach`] is called or the `KprobeManager` is dropped.
pub struct KprobeManager {
    /// Target PID to filter inside the eBPF program.
    target_pid: Option<i32>,
    /// Live kprobe link handles. Dropping them detaches the probes from the
    /// kernel. Stored as type-erased `Box<dyn Any>` to avoid coupling to
    /// aya's internal link-id type (matches `UprobeManager` convention).
    #[cfg(target_os = "linux")]
    links: Vec<Box<dyn std::any::Any>>,
}

impl std::fmt::Debug for KprobeManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KprobeManager")
            .field("target_pid", &self.target_pid)
            .finish()
    }
}

impl KprobeManager {
    /// Attach file I/O kprobes (`openat`, `write`, `unlink`) for the target PID.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Attach`] if a kernel symbol cannot be found
    /// (e.g., the running kernel uses a different internal function name).
    ///
    /// # Arguments
    ///
    /// * `bpf` — live [`Ebpf`] handle from [`crate::loader::EbpfLoader::load`].
    /// * `target_pid` — PID to filter, or `None` for system-wide monitoring.
    #[cfg(target_os = "linux")]
    pub fn attach(bpf: &mut Ebpf, target_pid: Option<i32>) -> Result<Self, EbpfError> {
        // Write target PID into the BPF-side filter map so the kernel-space
        // probes only emit events for the monitored process.
        if let Some(pid) = target_pid {
            let mut pid_filter: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(
                bpf.map_mut("PID_FILTER")
                    .ok_or_else(|| EbpfError::ProbeAttach("PID_FILTER map not found".into()))?,
            )
            .map_err(|e| EbpfError::ProbeAttach(e.to_string()))?;

            pid_filter
                .insert(pid as u32, 1, 0)
                .map_err(|e| EbpfError::ProbeAttach(e.to_string()))?;
        }

        // Attach all file I/O kprobe programs to their kernel functions.
        // `aa_sys_unlink_legacy` covers the legacy `__x64_sys_unlink` entry
        // point that glibc's `unlink()` invokes on x86_64 — bypassing the
        // at-variant probe above. See AAASM-1574.
        let probes: &[(&str, &str)] = &[
            ("aa_sys_openat", "__x64_sys_openat"),
            ("aa_sys_openat_ret", "__x64_sys_openat"),
            ("aa_sys_read", "__x64_sys_read"),
            ("aa_sys_write", "__x64_sys_write"),
            ("aa_sys_unlink", "__x64_sys_unlinkat"),
            ("aa_sys_unlink_legacy", "__x64_sys_unlink"),
            ("aa_sys_rename", "__x64_sys_renameat2"),
        ];

        let mut links: Vec<Box<dyn std::any::Any>> = Vec::with_capacity(probes.len());

        for (prog_name, fn_name) in probes {
            let program: &mut aya::programs::KProbe = bpf
                .program_mut(prog_name)
                .ok_or_else(|| EbpfError::ProbeAttach(format!("{prog_name} program not found")))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| EbpfError::ProbeAttach(e.to_string()))?;

            program
                .load()
                .map_err(|e| EbpfError::ProbeAttach(format!("{prog_name} load failed: {e}")))?;

            let link = program
                .attach(fn_name, 0)
                .map_err(|e| EbpfError::ProbeAttach(format!("{prog_name} attach to {fn_name} failed: {e}")))?;

            links.push(Box::new(link));
            tracing::info!(program = prog_name, function = fn_name, "kprobe attached");
        }

        Ok(Self { target_pid, links })
    }

    /// Attach kprobes — non-Linux stub.
    ///
    /// Returns an error immediately since eBPF is not supported on this platform.
    #[cfg(not(target_os = "linux"))]
    pub fn attach(_bpf: &mut (), _target_pid: Option<i32>) -> Result<Self, EbpfError> {
        Err(EbpfError::ProbeAttach("kprobe attachment requires Linux".into()))
    }

    /// Explicitly detach all kprobes from the kernel.
    ///
    /// After this call, [`is_attached`](Self::is_attached) returns `false`.
    /// Calling `detach` on an already-detached manager is a no-op.
    /// This is also called automatically when the `KprobeManager` is dropped.
    #[cfg(target_os = "linux")]
    pub fn detach(&mut self) {
        let count = self.links.len();
        self.links.clear();
        if count > 0 {
            tracing::info!(probes = count, "kprobes detached");
        }
    }

    /// Explicitly detach — non-Linux stub (no-op).
    #[cfg(not(target_os = "linux"))]
    pub fn detach(&mut self) {}

    /// Returns `true` if the kprobes are currently attached.
    #[cfg(target_os = "linux")]
    pub fn is_attached(&self) -> bool {
        !self.links.is_empty()
    }

    /// Returns `false` — non-Linux stub (probes are never attached).
    #[cfg(not(target_os = "linux"))]
    pub fn is_attached(&self) -> bool {
        false
    }

    /// The complete list of (BPF program name, kernel function) pairs that
    /// `attach()` will load. Exposed for testing and introspection.
    pub const KPROBE_TARGETS: &[(&str, &str)] = &[
        ("aa_sys_openat", "__x64_sys_openat"),
        ("aa_sys_openat_ret", "__x64_sys_openat"),
        ("aa_sys_read", "__x64_sys_read"),
        ("aa_sys_write", "__x64_sys_write"),
        ("aa_sys_unlink", "__x64_sys_unlinkat"),
        ("aa_sys_unlink_legacy", "__x64_sys_unlink"),
        ("aa_sys_rename", "__x64_sys_renameat2"),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn attach_returns_error_on_non_linux() {
        let err = KprobeManager::attach(&mut (), Some(1234)).unwrap_err();
        assert!(matches!(err, EbpfError::ProbeAttach(_)));
        assert!(err.to_string().contains("requires Linux"));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn attach_returns_error_on_non_linux_system_wide() {
        let err = KprobeManager::attach(&mut (), None).unwrap_err();
        assert!(matches!(err, EbpfError::ProbeAttach(_)));
    }

    #[test]
    fn kprobe_targets_covers_all_file_io_syscalls() {
        let targets = KprobeManager::KPROBE_TARGETS;
        assert_eq!(targets.len(), 7);

        let prog_names: Vec<&str> = targets.iter().map(|(p, _)| *p).collect();
        assert!(prog_names.contains(&"aa_sys_openat"));
        assert!(prog_names.contains(&"aa_sys_openat_ret"));
        assert!(prog_names.contains(&"aa_sys_read"));
        assert!(prog_names.contains(&"aa_sys_write"));
        assert!(prog_names.contains(&"aa_sys_unlink"));
        assert!(prog_names.contains(&"aa_sys_unlink_legacy"));
        assert!(prog_names.contains(&"aa_sys_rename"));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn detach_is_noop_on_non_linux() {
        // Construct directly — no links field on non-Linux.
        let mut mgr = KprobeManager { target_pid: None };
        assert!(!mgr.is_attached());
        mgr.detach(); // should not panic
        assert!(!mgr.is_attached());
    }

    #[test]
    fn kprobe_targets_kernel_functions_are_prefixed() {
        for (_, fn_name) in KprobeManager::KPROBE_TARGETS {
            assert!(
                fn_name.starts_with("__x64_sys_"),
                "kernel function {fn_name} should use __x64_sys_ prefix"
            );
        }
    }
}
