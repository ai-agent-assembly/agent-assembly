//! Tracepoint management for process exec monitoring (AAASM-39).
//!
//! Attaches the `sched/sched_process_fork`, `sched/sched_process_exec`, and
//! `sched/sched_process_exit` tracepoints from the `aa-exec-probes` BPF binary.
//! The fork tracepoint supplies the real parent pid and descendant coverage
//! (AAASM-3921c).

#[cfg(target_os = "linux")]
use aya::Ebpf;

use crate::error::EbpfError;

/// Attaches and manages the `sched_process_exec` and `sched_process_exit`
/// tracepoint programs.
///
/// Create via [`TracepointManager::attach`]. The tracepoints stay active
/// until the `TracepointManager` is dropped.
pub struct TracepointManager {
    /// Live tracepoint link handles. Stored as type-erased `Box<dyn Any>`
    /// to avoid depending on aya's internal link-id type name. Dropping
    /// them detaches the tracepoints from the kernel.
    #[cfg(target_os = "linux")]
    _links: Vec<Box<dyn std::any::Any>>,
    #[cfg(not(target_os = "linux"))]
    _private: (),
}

impl TracepointManager {
    /// Attach the `sched/sched_process_fork`, `sched/sched_process_exec`, and
    /// `sched/sched_process_exit` tracepoint programs.
    ///
    /// These tracepoints fire for every `fork`/`clone`, `execve`/`execveat`,
    /// and process exit on the system. The BPF-side PID filter
    /// (`EXEC_PID_FILTER`) limits which events are emitted to the ring buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProbeAttach`] if the tracepoint category or name
    /// is not available on the running kernel.
    ///
    /// # Arguments
    ///
    /// * `bpf` — live [`Ebpf`] handle from loading [`crate::AA_EXEC_BPF`].
    #[cfg(target_os = "linux")]
    pub fn attach(bpf: &mut Ebpf) -> Result<Self, EbpfError> {
        use aya::programs::TracePoint;

        // Publish the kernel's `task_struct` field offsets so the exec probe can
        // read `current->real_parent->tgid` directly (AAASM-3921c). Best-effort:
        // if BTF is unavailable or the map is missing the probe falls back to
        // its fork-populated map path, so a failure here is not fatal.
        Self::populate_task_offsets(bpf);

        let tracepoints: &[(&str, &str, &str)] = &[
            // Attach fork first so the child→parent map is populated before any
            // exec it enables can be observed (AAASM-3921c).
            ("handle_sched_process_fork", "sched", "sched_process_fork"),
            ("handle_sched_process_exec", "sched", "sched_process_exec"),
            ("handle_sched_process_exit", "sched", "sched_process_exit"),
        ];

        let mut links: Vec<Box<dyn std::any::Any>> = Vec::with_capacity(tracepoints.len());

        for (prog_name, category, tp_name) in tracepoints {
            let program: &mut TracePoint = bpf
                .program_mut(prog_name)
                .ok_or_else(|| EbpfError::ProbeAttach(format!("{prog_name} program not found in BPF object")))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| EbpfError::ProbeAttach(e.to_string()))?;

            program
                .load()
                .map_err(|e| EbpfError::ProbeAttach(format!("{prog_name} load failed: {e}")))?;
            let link = program.attach(category, tp_name).map_err(|e| {
                EbpfError::ProbeAttach(format!("{prog_name} attach to {category}/{tp_name} failed: {e}"))
            })?;
            links.push(Box::new(link));

            tracing::info!(program = prog_name, tracepoint = %format!("{category}/{tp_name}"), "tracepoint attached");
        }

        Ok(Self { _links: links })
    }

    /// Resolve `task_struct.real_parent` / `task_struct.tgid` byte-offsets from
    /// the running kernel's BTF and write them into the exec probe's
    /// `TASK_OFFSETS` array map (index 0 = `real_parent`, 1 = `tgid`).
    ///
    /// Best-effort and non-fatal: on any failure the map is left zeroed and the
    /// probe falls back to its fork-populated `PARENT_TGID` map (AAASM-3921c).
    #[cfg(target_os = "linux")]
    fn populate_task_offsets(bpf: &mut Ebpf) {
        let Some(offsets) = crate::btf_offsets::task_offsets_from_sys() else {
            tracing::warn!("task_struct BTF offsets unavailable; exec ppid falls back to fork map");
            return;
        };

        let Some(map) = bpf.map_mut("TASK_OFFSETS") else {
            tracing::warn!("TASK_OFFSETS map not found; exec ppid falls back to fork map");
            return;
        };

        let mut arr: aya::maps::Array<_, u32> = match aya::maps::Array::try_from(map) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::warn!(error = %e, "TASK_OFFSETS not an Array map; skipping offset publish");
                return;
            }
        };

        if let Err(e) = arr
            .set(0, offsets.real_parent, 0)
            .and_then(|()| arr.set(1, offsets.tgid, 0))
        {
            tracing::warn!(error = %e, "failed to write TASK_OFFSETS; exec ppid falls back to fork map");
            return;
        }

        tracing::info!(
            real_parent = offsets.real_parent,
            tgid = offsets.tgid,
            "published task_struct offsets for CO-RE exec ppid"
        );
    }

    /// Explicitly detach all tracepoints.
    ///
    /// Dropping the link handles causes aya to detach the probes from the
    /// kernel. After this call the `TracepointManager` is inert — calling
    /// `detach` again is a no-op.
    #[cfg(target_os = "linux")]
    pub fn detach(&mut self) {
        let count = self._links.len();
        self._links.clear();
        if count > 0 {
            tracing::info!(count, "tracepoints explicitly detached");
        }
    }

    /// Explicit detach — non-Linux stub (no-op).
    #[cfg(not(target_os = "linux"))]
    pub fn detach(&mut self) {}

    /// Attach tracepoints — non-Linux stub.
    ///
    /// Returns an error immediately since eBPF is not supported on this platform.
    #[cfg(not(target_os = "linux"))]
    pub fn attach(_bpf: &mut ()) -> Result<Self, EbpfError> {
        Err(EbpfError::ProgramLoad(
            "eBPF tracepoints are only supported on Linux".into(),
        ))
    }
}

impl Drop for TracepointManager {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if !self._links.is_empty() {
            tracing::debug!(
                count = self._links.len(),
                "TracepointManager dropping, detaching tracepoints"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn attach_returns_error_on_non_linux() {
        let result = TracepointManager::attach(&mut ());
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string().contains("only supported on Linux"),
            "expected 'only supported on Linux', got: {err}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn detach_is_idempotent_no_op_on_non_linux() {
        // On non-Linux, we cannot construct a TracepointManager via attach(),
        // but we can verify detach() exists and is callable on the type.
        // This test documents the API contract: detach is a no-op stub.
        // Full lifecycle testing happens in the integration test on Linux.
        let _: fn(&mut TracepointManager) = TracepointManager::detach;
    }
}
