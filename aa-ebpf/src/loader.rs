//! Userspace eBPF program loaders and lifecycle managers.

#[cfg(target_os = "linux")]
use aya::Ebpf;

use crate::error::EbpfError;

// ── TLS uprobe loader (AAASM-37) ────────────────────────────────────────

/// Loads the compiled `aa-ebpf-probes` TLS uprobe ELF object into the Linux kernel.
///
/// The object is embedded at build time by `build.rs`.  `EbpfLoader` is the
/// entry point for all probe attachment in this crate: obtain an [`Ebpf`]
/// handle from [`EbpfLoader::load`] and pass it to the individual managers
/// ([`crate::uprobe::UprobeManager`], [`crate::ringbuf::RingBufReader`], etc.).
pub struct EbpfLoader;

impl EbpfLoader {
    /// Load the embedded TLS uprobe ELF bytecode and return a live [`Ebpf`] handle.
    ///
    /// Parses the `aa-tls-probes` BPF ELF embedded via
    /// [`crate::AA_TLS_BPF`] and submits it to the kernel.  The returned
    /// handle owns the loaded programs; dropping it detaches all probes.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Load`] if the kernel rejects the object (e.g.
    /// missing BTF, kernel too old, or BPF verifier failure).
    ///
    /// # Linux requirements
    ///
    /// Requires Linux 5.8+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`) and
    /// `CAP_BPF` + `CAP_PERFMON` capabilities.
    #[cfg(target_os = "linux")]
    pub fn load() -> Result<Ebpf, EbpfError> {
        // AAASM-3602: fail-closed integrity check before handing bytes to the
        // kernel — a tampered or stub TLS probe is refused, not loaded blind.
        crate::integrity::verify_bytecode("aa-tls-probes", crate::AA_TLS_BPF, crate::integrity::AA_TLS_BPF_SHA256)?;
        Ok(Ebpf::load(crate::AA_TLS_BPF)?)
    }
}

// ── File I/O kprobe loader (AAASM-38) ───────────────────────────────────

#[cfg(target_os = "linux")]
use crate::alert::SensitivePathDetector;
#[cfg(target_os = "linux")]
use crate::events::FileIoEvent;
use crate::maps::PathPattern;

/// Manages the lifecycle of file I/O eBPF programs: loading bytecode,
/// attaching kprobes, and updating BPF maps at runtime.
///
/// The file I/O loader is the primary entry point for userspace interaction
/// with the file I/O kprobe subsystem. It is only functional on Linux; on
/// other platforms it returns [`EbpfError::ProgramLoad`] immediately.
pub struct FileIoLoader {
    /// Target PID to monitor (and its descendants).
    #[allow(dead_code)]
    target_pid: u32,
    /// Loaded BPF object handle (Linux only).
    #[cfg(target_os = "linux")]
    bpf: Option<aya::Ebpf>,
}

impl FileIoLoader {
    /// Create a new loader targeting the given PID and its descendants.
    pub fn new(target_pid: u32) -> Self {
        Self {
            target_pid,
            #[cfg(target_os = "linux")]
            bpf: None,
        }
    }

    /// Load the compiled eBPF bytecode into the kernel.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramLoad`] if the bytecode cannot be loaded
    /// (e.g., missing privileges, unsupported kernel, or non-Linux platform).
    pub fn load(&mut self) -> Result<(), EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(EbpfError::ProgramLoad("eBPF is only supported on Linux".into()))
        }

        #[cfg(target_os = "linux")]
        {
            tracing::info!(pid = self.target_pid, "loading eBPF programs");
            // AAASM-3602: fail-closed integrity check before kernel load.
            crate::integrity::verify_bytecode(
                "aa-file-io",
                crate::AA_FILE_IO_BPF,
                crate::integrity::AA_FILE_IO_BPF_SHA256,
            )?;
            let mut bpf = aya::Ebpf::load(crate::AA_FILE_IO_BPF).map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;

            // Insert the target PID into the PID filter map.
            let mut pid_filter: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(
                bpf.map_mut("PID_FILTER")
                    .ok_or_else(|| EbpfError::ProgramLoad("PID_FILTER map not found".into()))?,
            )
            .map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;

            pid_filter
                .insert(self.target_pid, 1, 0)
                .map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;

            self.bpf = Some(bpf);
            Ok(())
        }
    }

    /// Attach all file I/O kprobes to the running kernel.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProbeAttach`] if any kprobe fails to attach.
    pub fn attach_kprobes(&mut self) -> Result<(), EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(EbpfError::ProbeAttach("eBPF is only supported on Linux".into()))
        }

        #[cfg(target_os = "linux")]
        {
            use aya::programs::KProbe;

            let bpf = self
                .bpf
                .as_mut()
                .ok_or_else(|| EbpfError::ProbeAttach("BPF not loaded — call load() first".into()))?;

            let probes: &[(&str, &str)] = &[
                ("aa_sys_openat", "__x64_sys_openat"),
                ("aa_sys_openat_ret", "__x64_sys_openat"),
                ("aa_sys_read", "__x64_sys_read"),
                ("aa_sys_write", "__x64_sys_write"),
                ("aa_sys_unlink", "__x64_sys_unlinkat"),
                ("aa_sys_rename", "__x64_sys_renameat2"),
            ];

            for (prog_name, fn_name) in probes {
                let program: &mut KProbe = bpf
                    .program_mut(prog_name)
                    .ok_or_else(|| EbpfError::ProbeAttach(format!("{prog_name} program not found")))?
                    .try_into()
                    .map_err(|e: aya::programs::ProgramError| EbpfError::ProbeAttach(e.to_string()))?;

                program.load().map_err(|e| EbpfError::ProbeAttach(e.to_string()))?;
                program
                    .attach(fn_name, 0)
                    .map_err(|e| EbpfError::ProbeAttach(e.to_string()))?;

                tracing::info!(program = prog_name, function = fn_name, "kprobe attached");
            }

            Ok(())
        }
    }

    /// Start reading events from the BPF perf event array.
    ///
    /// Spawns a tokio task per online CPU that reads from the `EVENTS`
    /// perf array and sends parsed [`FileIoEvent`]s through the returned
    /// channel.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::EventParse`] if the perf array cannot be opened.
    #[cfg(target_os = "linux")]
    pub fn start_event_reader(&mut self) -> Result<tokio::sync::mpsc::Receiver<FileIoEvent>, EbpfError> {
        use aa_ebpf_common::file::FileIoEventRaw;
        use aya::maps::perf::AsyncPerfEventArray;
        use aya::util::online_cpus;
        use bytes::BytesMut;

        let bpf = self
            .bpf
            .as_mut()
            .ok_or_else(|| EbpfError::EventParse("BPF not loaded — call load() first".into()))?;

        // take_map returns an owned Map so the perf array (and its
        // buffers) are not tied to the `&mut self` lifetime — required
        // because buffers are moved into tokio::spawn('static).
        let mut perf_array = AsyncPerfEventArray::try_from(
            bpf.take_map("EVENTS")
                .ok_or_else(|| EbpfError::EventParse("EVENTS map not found".into()))?,
        )
        .map_err(|e| EbpfError::EventParse(e.to_string()))?;

        let (tx, rx) = tokio::sync::mpsc::channel::<FileIoEvent>(256);

        let cpus = online_cpus().map_err(|(_, e)| EbpfError::EventParse(e.to_string()))?;
        for cpu_id in cpus {
            let mut buf = perf_array
                .open(cpu_id, None)
                .map_err(|e| EbpfError::EventParse(e.to_string()))?;
            let tx = tx.clone();

            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(core::mem::size_of::<FileIoEventRaw>()))
                    .collect::<Vec<_>>();

                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(events) => events,
                        Err(e) => {
                            tracing::warn!(cpu = cpu_id, error = %e, "perf read error");
                            continue;
                        }
                    };

                    for buf in buffers.iter().take(events.read) {
                        if buf.len() < core::mem::size_of::<FileIoEventRaw>() {
                            continue;
                        }
                        let raw = unsafe { &*(buf.as_ptr() as *const FileIoEventRaw) };
                        match FileIoEvent::from_raw(raw) {
                            Ok(event) => {
                                let _ = tx.send(event).await;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to parse BPF event");
                            }
                        }
                    }
                }
            });
        }

        Ok(rx)
    }

    /// Start reading events with userspace-side sensitive path detection.
    ///
    /// Wraps [`start_event_reader`](Self::start_event_reader) and applies
    /// the [`SensitivePathDetector`] to each event, setting
    /// `is_sensitive = true` if either the BPF-side blocklist flagged it or
    /// the userspace detector matches.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::EventParse`] if the perf array cannot be opened.
    #[cfg(target_os = "linux")]
    pub fn start_event_reader_with_alerts(
        &mut self,
        detector: SensitivePathDetector,
    ) -> Result<tokio::sync::mpsc::Receiver<FileIoEvent>, EbpfError> {
        let mut inner_rx = self.start_event_reader()?;
        let (tx, rx) = tokio::sync::mpsc::channel::<FileIoEvent>(256);

        tokio::spawn(async move {
            while let Some(mut event) = inner_rx.recv().await {
                if !event.is_sensitive && detector.is_sensitive(&event) {
                    event.is_sensitive = true;
                }
                if event.is_sensitive {
                    tracing::warn!(
                        pid = event.pid,
                        path = %event.path,
                        syscall = %event.syscall,
                        "sensitive path access detected"
                    );
                }
                let _ = tx.send(event).await;
            }
        });

        Ok(rx)
    }

    /// Update the path filter BPF map with new patterns.
    ///
    /// This can be called at runtime without reloading the eBPF programs.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::MapUpdate`] if the map update fails.
    pub fn update_path_filter(&mut self, patterns: &[PathPattern]) -> Result<(), EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = patterns;
            Err(EbpfError::MapUpdate("eBPF is only supported on Linux".into()))
        }

        #[cfg(target_os = "linux")]
        {
            use crate::maps::PathVerdict;

            let bpf = self
                .bpf
                .as_mut()
                .ok_or_else(|| EbpfError::MapUpdate("BPF not loaded — call load() first".into()))?;

            // Collect deny and allow patterns separately before borrowing maps.
            let mut deny_keys = Vec::new();
            let mut allow_keys = Vec::new();
            for pat in patterns {
                let mut key = [0u8; aa_ebpf_common::file::MAX_PATH_LEN];
                let bytes = pat.pattern.as_bytes();
                let len = bytes.len().min(aa_ebpf_common::file::MAX_PATH_LEN);
                key[..len].copy_from_slice(&bytes[..len]);

                match pat.verdict {
                    PathVerdict::Deny => deny_keys.push(key),
                    PathVerdict::Allow => allow_keys.push(key),
                }
            }

            // Update blocklist map (scoped to drop borrow before allowlist).
            {
                let mut blocklist: aya::maps::HashMap<_, [u8; aa_ebpf_common::file::MAX_PATH_LEN], u8> =
                    aya::maps::HashMap::try_from(
                        bpf.map_mut("PATH_BLOCKLIST")
                            .ok_or_else(|| EbpfError::MapUpdate("PATH_BLOCKLIST map not found".into()))?,
                    )
                    .map_err(|e| EbpfError::MapUpdate(e.to_string()))?;

                let existing_keys: Vec<[u8; aa_ebpf_common::file::MAX_PATH_LEN]> =
                    blocklist.keys().filter_map(|k| k.ok()).collect();
                for key in &existing_keys {
                    let _ = blocklist.remove(key);
                }
                for key in &deny_keys {
                    blocklist
                        .insert(*key, 1, 0)
                        .map_err(|e| EbpfError::MapUpdate(e.to_string()))?;
                }
            }

            // Update allowlist map.
            {
                let mut allowlist: aya::maps::HashMap<_, [u8; aa_ebpf_common::file::MAX_PATH_LEN], u8> =
                    aya::maps::HashMap::try_from(
                        bpf.map_mut("PATH_ALLOWLIST")
                            .ok_or_else(|| EbpfError::MapUpdate("PATH_ALLOWLIST map not found".into()))?,
                    )
                    .map_err(|e| EbpfError::MapUpdate(e.to_string()))?;

                let existing_keys: Vec<[u8; aa_ebpf_common::file::MAX_PATH_LEN]> =
                    allowlist.keys().filter_map(|k| k.ok()).collect();
                for key in &existing_keys {
                    let _ = allowlist.remove(key);
                }
                for key in &allow_keys {
                    allowlist
                        .insert(*key, 1, 0)
                        .map_err(|e| EbpfError::MapUpdate(e.to_string()))?;
                }
            }

            let deny_count = deny_keys.len();
            let allow_count = allow_keys.len();

            tracing::info!(deny = deny_count, allow = allow_count, "updated path filters");
            Ok(())
        }
    }
}

// ── Exec tracepoint loader (AAASM-39) ──────────────────────────────────

use crate::lineage::ProcessLineageTracker;
use crate::shell_detect::ShellDetector;

/// Manages the lifecycle of exec tracepoint eBPF programs: loading bytecode,
/// attaching tracepoints, reading events, and feeding the lineage tracker.
///
/// The exec loader is the primary entry point for userspace interaction
/// with the process exec monitoring subsystem.
pub struct ExecLoader {
    /// Target PID to monitor (and its descendants).
    target_pid: u32,
    /// Process lineage tracker, populated by exec events.
    lineage: ProcessLineageTracker,
    /// Shell injection pattern detector.
    detector: ShellDetector,
    /// Loaded BPF object handle (Linux only).
    #[cfg(target_os = "linux")]
    bpf: Option<aya::Ebpf>,
}

impl ExecLoader {
    /// Create a new exec loader targeting the given PID and its descendants.
    pub fn new(target_pid: u32) -> Self {
        Self {
            target_pid,
            lineage: ProcessLineageTracker::new(),
            detector: ShellDetector::new(),
            #[cfg(target_os = "linux")]
            bpf: None,
        }
    }

    /// Load the compiled eBPF bytecode into the kernel.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramLoad`] if the bytecode cannot be loaded.
    pub fn load(&mut self) -> Result<(), EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(EbpfError::ProgramLoad("eBPF is only supported on Linux".into()))
        }

        #[cfg(target_os = "linux")]
        {
            tracing::info!(pid = self.target_pid, "loading exec tracepoint BPF programs");
            // AAASM-3602: fail-closed integrity check before kernel load.
            crate::integrity::verify_bytecode(
                "aa-exec-probes",
                crate::AA_EXEC_BPF,
                crate::integrity::AA_EXEC_BPF_SHA256,
            )?;
            let mut bpf = aya::Ebpf::load(crate::AA_EXEC_BPF).map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;

            // Insert the target PID into the exec PID filter map.
            let mut pid_filter: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(
                bpf.map_mut("EXEC_PID_FILTER")
                    .ok_or_else(|| EbpfError::ProgramLoad("EXEC_PID_FILTER map not found".into()))?,
            )
            .map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;

            pid_filter
                .insert(self.target_pid, 1, 0)
                .map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;

            self.bpf = Some(bpf);
            Ok(())
        }
    }

    /// Attach the `sched_process_exec` and `sched_process_exit` tracepoints.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProbeAttach`] if any tracepoint fails to attach.
    pub fn attach_tracepoints(&mut self) -> Result<(), EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(EbpfError::ProbeAttach("eBPF is only supported on Linux".into()))
        }

        #[cfg(target_os = "linux")]
        {
            let bpf = self
                .bpf
                .as_mut()
                .ok_or_else(|| EbpfError::ProbeAttach("BPF not loaded — call load() first".into()))?;

            crate::tracepoint::TracepointManager::attach(bpf)?;
            Ok(())
        }
    }

    /// Return a reference to the process lineage tracker.
    pub fn lineage(&self) -> &ProcessLineageTracker {
        &self.lineage
    }

    /// Return a mutable reference to the process lineage tracker.
    pub fn lineage_mut(&mut self) -> &mut ProcessLineageTracker {
        &mut self.lineage
    }

    /// Return a reference to the shell injection detector.
    pub fn detector(&self) -> &ShellDetector {
        &self.detector
    }

    /// Return the target PID.
    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }
}

// ── Syscall-allowlist enforcement loader (AAASM-3631) ───────────────────

/// Loads + attaches the seccomp-style syscall-allowlist enforcement probe
/// (`aa-syscall-guard`) and populates its `SYSCALL_ALLOWLIST` map.
///
/// Unlike the observe-only loaders, the attached program ENFORCES: a monitored
/// PID issuing a syscall not in the allowlist is killed in-kernel. This loader
/// is driven exclusively by the privileged daemon (AAASM-3603/3604); the map
/// is populated from the policy AST lowering
/// (`aa_security::policy::lower_to_ebpf().syscall_allowlist`, AAASM-3635).
pub struct SyscallGuardLoader {
    /// Target PID to confine (added to the probe's PID filter).
    #[allow(dead_code)]
    target_pid: u32,
    /// Loaded BPF object handle (Linux only).
    #[cfg(target_os = "linux")]
    bpf: Option<aya::Ebpf>,
}

impl SyscallGuardLoader {
    /// Create a loader confining the given PID.
    pub fn new(target_pid: u32) -> Self {
        Self {
            target_pid,
            #[cfg(target_os = "linux")]
            bpf: None,
        }
    }

    /// Integrity-verify, load the syscall-guard bytecode, and add the target
    /// PID to the probe's PID filter.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramLoad`] on non-Linux or if the kernel
    /// rejects the object / the PID filter map is missing.
    pub fn load(&mut self) -> Result<(), EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(EbpfError::ProgramLoad("eBPF is only supported on Linux".into()))
        }

        #[cfg(target_os = "linux")]
        {
            tracing::info!(pid = self.target_pid, "loading syscall-guard enforcement BPF program");
            // AAASM-3602: fail-closed integrity check before kernel load.
            crate::integrity::verify_bytecode(
                "aa-syscall-guard",
                crate::AA_SYSCALL_GUARD_BPF,
                crate::integrity::AA_SYSCALL_GUARD_BPF_SHA256,
            )?;
            let mut bpf =
                aya::Ebpf::load(crate::AA_SYSCALL_GUARD_BPF).map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;

            let mut pid_filter: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(
                bpf.map_mut("PID_FILTER")
                    .ok_or_else(|| EbpfError::ProgramLoad("PID_FILTER map not found".into()))?,
            )
            .map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;
            pid_filter
                .insert(self.target_pid, 1, 0)
                .map_err(|e| EbpfError::ProgramLoad(e.to_string()))?;

            self.bpf = Some(bpf);
            Ok(())
        }
    }

    /// Attach the enforcement tracepoint (`aa_syscall_guard` at
    /// `raw_syscalls/sys_enter`) and the descendant-confinement tracepoint
    /// (`aa_syscall_guard_fork` at `sched/sched_process_fork`, AAASM-3916).
    ///
    /// The fork tracepoint must be attached so that children of a confined
    /// process inherit `PID_FILTER` membership and cannot run unconfined.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProbeAttach`] on non-Linux or if either tracepoint
    /// fails to attach.
    pub fn attach(&mut self) -> Result<(), EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(EbpfError::ProbeAttach("eBPF is only supported on Linux".into()))
        }

        #[cfg(target_os = "linux")]
        {
            use aya::programs::TracePoint;

            let bpf = self
                .bpf
                .as_mut()
                .ok_or_else(|| EbpfError::ProbeAttach("BPF not loaded — call load() first".into()))?;

            // (program name, tracepoint category, tracepoint name)
            let tracepoints: &[(&str, &str, &str)] = &[
                ("aa_syscall_guard", "raw_syscalls", "sys_enter"),
                ("aa_syscall_guard_fork", "sched", "sched_process_fork"),
            ];

            for (prog_name, category, tp_name) in tracepoints {
                let program: &mut TracePoint = bpf
                    .program_mut(prog_name)
                    .ok_or_else(|| EbpfError::ProbeAttach(format!("{prog_name} program not found")))?
                    .try_into()
                    .map_err(|e: aya::programs::ProgramError| EbpfError::ProbeAttach(e.to_string()))?;

                program.load().map_err(|e| EbpfError::ProbeAttach(e.to_string()))?;
                program
                    .attach(category, tp_name)
                    .map_err(|e| EbpfError::ProbeAttach(e.to_string()))?;

                tracing::info!(program = prog_name, tracepoint = %format!("{category}/{tp_name}"), "syscall-guard tracepoint attached");
            }

            Ok(())
        }
    }

    /// Replace the `SYSCALL_ALLOWLIST` map contents with `syscall_numbers`
    /// (the lowered policy AST output). Clears then reapplies so the map
    /// reflects exactly the current policy.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::MapUpdate`] on non-Linux or if the map is missing
    /// / cannot be updated.
    pub fn update_syscall_allowlist(&mut self, syscall_numbers: &[u32]) -> Result<(), EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = syscall_numbers;
            Err(EbpfError::MapUpdate("eBPF is only supported on Linux".into()))
        }

        #[cfg(target_os = "linux")]
        {
            use aa_ebpf_common::syscall::SYSCALL_ALLOWED;

            let bpf = self
                .bpf
                .as_mut()
                .ok_or_else(|| EbpfError::MapUpdate("BPF not loaded — call load() first".into()))?;

            let mut allowlist: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(
                bpf.map_mut("SYSCALL_ALLOWLIST")
                    .ok_or_else(|| EbpfError::MapUpdate("SYSCALL_ALLOWLIST map not found".into()))?,
            )
            .map_err(|e| EbpfError::MapUpdate(e.to_string()))?;

            // Clear stale entries, then reapply the desired set.
            let existing: Vec<u32> = allowlist.keys().filter_map(|k| k.ok()).collect();
            for key in &existing {
                let _ = allowlist.remove(key);
            }
            for nr in syscall_numbers {
                allowlist
                    .insert(*nr, SYSCALL_ALLOWED, 0)
                    .map_err(|e| EbpfError::MapUpdate(e.to_string()))?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_target_pid() {
        let loader = FileIoLoader::new(1234);
        assert_eq!(loader.target_pid, 1234);
    }

    #[test]
    fn syscall_guard_loader_stores_target_pid() {
        let loader = SyscallGuardLoader::new(4321);
        assert_eq!(loader.target_pid, 4321);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn syscall_guard_load_returns_error_on_non_linux() {
        let mut loader = SyscallGuardLoader::new(1);
        assert!(matches!(loader.load().unwrap_err(), EbpfError::ProgramLoad(_)));
        assert!(matches!(loader.attach().unwrap_err(), EbpfError::ProbeAttach(_)));
        assert!(matches!(
            loader.update_syscall_allowlist(&[0, 1]).unwrap_err(),
            EbpfError::MapUpdate(_)
        ));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn load_returns_error_on_non_linux() {
        let mut loader = FileIoLoader::new(1);
        let err = loader.load().unwrap_err();
        assert!(matches!(err, EbpfError::ProgramLoad(_)));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn attach_kprobes_returns_error_on_non_linux() {
        let mut loader = FileIoLoader::new(1);
        let err = loader.attach_kprobes().unwrap_err();
        assert!(matches!(err, EbpfError::ProbeAttach(_)));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn update_path_filter_returns_error_on_non_linux() {
        use crate::maps::PathVerdict;

        let mut loader = FileIoLoader::new(1);
        let patterns = vec![PathPattern {
            pattern: "/etc/shadow".into(),
            verdict: PathVerdict::Deny,
        }];
        let err = loader.update_path_filter(&patterns).unwrap_err();
        assert!(matches!(err, EbpfError::MapUpdate(_)));
    }

    #[test]
    fn exec_loader_new_stores_target_pid() {
        let loader = ExecLoader::new(5678);
        assert_eq!(loader.target_pid(), 5678);
    }

    #[test]
    fn exec_loader_lineage_starts_empty() {
        let loader = ExecLoader::new(1);
        assert!(loader.lineage().is_empty());
    }

    #[test]
    fn exec_loader_lineage_mut_allows_insert() {
        let mut loader = ExecLoader::new(1);
        loader.lineage_mut().insert(100, 1, "/bin/agent".into(), 1000);
        assert_eq!(loader.lineage().len(), 1);
    }

    #[test]
    fn exec_loader_detector_works() {
        let loader = ExecLoader::new(1);
        assert!(loader.detector().check("/bin/bash").is_some());
        assert!(loader.detector().check("/usr/bin/ls").is_none());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn exec_loader_load_returns_error_on_non_linux() {
        let mut loader = ExecLoader::new(1);
        let err = loader.load().unwrap_err();
        assert!(matches!(err, EbpfError::ProgramLoad(_)));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn exec_loader_attach_returns_error_on_non_linux() {
        let mut loader = ExecLoader::new(1);
        let err = loader.attach_tracepoints().unwrap_err();
        assert!(matches!(err, EbpfError::ProbeAttach(_)));
    }
}
