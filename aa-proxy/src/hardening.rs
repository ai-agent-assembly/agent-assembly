//! Process-level hardening applied once at proxy startup (AAASM-3584).
//!
//! The proxy holds every tenant's real provider keys in memory, so it must be
//! as hostile as possible to memory-disclosure. [`harden_process`] marks the
//! process non-dumpable on Linux (`prctl(PR_SET_DUMPABLE, 0)`), which:
//!
//! * suppresses core dumps — a forced crash cannot leave a file on disk
//!   containing plaintext keys, and
//! * blocks `PTRACE_ATTACH` from same-uid processes, hardening against in-host
//!   memory scraping.
//!
//! On non-Linux targets this is a no-op (the syscall does not exist), so the
//! macOS development path stays buildable.

/// Apply startup process hardening. Call once, early, before the credential
/// store is populated and before the accept loop starts.
///
/// Returns `true` when the hardening was applied (Linux, `prctl` succeeded),
/// `false` otherwise. A failure is logged but never fatal — the proxy still
/// runs, just without this particular defence-in-depth layer.
pub fn harden_process() -> bool {
    set_non_dumpable()
}

/// Linux: `prctl(PR_SET_DUMPABLE, 0)`.
#[cfg(target_os = "linux")]
fn set_non_dumpable() -> bool {
    // SAFETY: `prctl` with PR_SET_DUMPABLE takes a single integer argument and
    // has no memory-safety preconditions; the trailing prctl args are ignored
    // for this option and passed as zero.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        tracing::info!("PR_SET_DUMPABLE=0 applied: core dumps and ptrace disabled for this process");
        true
    } else {
        tracing::warn!("PR_SET_DUMPABLE=0 failed; core dumps may still be possible");
        false
    }
}

/// Non-Linux: the syscall does not exist; nothing to do.
#[cfg(not(target_os = "linux"))]
fn set_non_dumpable() -> bool {
    tracing::debug!("PR_SET_DUMPABLE not available on this platform; skipping non-dumpable hardening");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_does_not_panic_and_reports_outcome() {
        // The call must be safe to invoke on any platform and return the
        // applied/not-applied outcome. On Linux it should succeed; elsewhere it
        // is a no-op returning false. We assert only that it runs cleanly and,
        // on Linux, that /proc reflects the non-dumpable state.
        let applied = harden_process();

        #[cfg(target_os = "linux")]
        {
            assert!(applied, "PR_SET_DUMPABLE should succeed on Linux");
            // Confirm the kernel actually flipped the bit.
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let dumpable_line = status.lines().find(|l| l.starts_with("Dumpable:"));
            if let Some(line) = dumpable_line {
                assert!(
                    line.contains('0'),
                    "/proc/self/status should report non-dumpable, got: {line}"
                );
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(!applied, "hardening is a no-op off Linux");
        }
    }
}
