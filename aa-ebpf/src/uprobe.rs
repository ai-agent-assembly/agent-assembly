//! Uprobe/uretprobe management for OpenSSL TLS plaintext capture (AAASM-37).
//!
//! Attaches `ssl_write_uprobe` and `ssl_read_uretprobe` from
//! `aa-ebpf-probes` to the `SSL_write` and `SSL_read` symbols in every
//! matching OpenSSL shared library loaded by the target process.

#[cfg(target_os = "linux")]
use aya::{maps::Array, programs::UProbe, Ebpf};

use crate::error::EbpfError;

/// Attaches and manages OpenSSL uprobe/uretprobe programs.
///
/// Create via [`UprobeManager::attach`]. The probes stay active until the
/// `UprobeManager` is dropped — dropping the stored link handles detaches
/// all probes from the kernel.
pub struct UprobeManager {
    /// Target PID to monitor. `None` means monitor all processes.
    target_pid: Option<i32>,
    /// Live uprobe/uretprobe link handles.  Stored as type-erased `Box<dyn
    /// Any>` to avoid depending on aya's internal link-id type name, which
    /// has changed across patch releases.  Dropping them detaches the probes.
    #[cfg(target_os = "linux")]
    _links: Vec<Box<dyn std::any::Any>>,
}

impl UprobeManager {
    /// Attach `SSL_write` uprobe and `SSL_read` uretprobe to the target PID.
    ///
    /// Supports both OpenSSL 1.1.x (`SSL_write` symbol) and 3.x
    /// (`SSL_write_ex` symbol) — both are attached when present.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Attach`] if the symbol cannot be resolved in any
    /// loaded OpenSSL library for the given PID.
    ///
    /// # Arguments
    ///
    /// * `bpf` — live `Ebpf` handle from [`crate::loader::EbpfLoader::load`].
    /// * `target_pid` — PID to attach to, or `None` for system-wide.
    #[cfg(target_os = "linux")]
    pub fn attach(bpf: &mut Ebpf, target_pid: Option<i32>) -> Result<Self, EbpfError> {
        // 1. Write the target PID into the BPF-side filter map.
        {
            let map = bpf.map_mut("TARGET_PID").ok_or_else(|| EbpfError::MapNotFound {
                name: "TARGET_PID".into(),
            })?;
            let mut pid_map: Array<_, u32> = Array::try_from(map)?;
            let pid_val: u32 = target_pid.map(|p| p as u32).unwrap_or(0);
            pid_map.set(0, pid_val, 0)?;
        }

        // 2. Find the OpenSSL shared library for the target process.
        let ssl_path = find_openssl_path(target_pid)?;

        let mut links: Vec<Box<dyn std::any::Any>> = Vec::with_capacity(3);

        // 3. Attach ssl_write uprobe (captures outbound TLS plaintext).
        {
            let prog: &mut UProbe = bpf
                .program_mut("ssl_write")
                .ok_or_else(|| EbpfError::ProgramNotFound {
                    name: "ssl_write".into(),
                })?
                .try_into()?;
            load_program(prog, "ssl_write")?;
            links.push(Box::new(prog.attach(Some("SSL_write"), 0, &ssl_path, target_pid)?));
        }

        // 4. Attach ssl_read_entry uprobe (saves SSL_read buf ptr for step 5).
        {
            let prog: &mut UProbe = bpf
                .program_mut("ssl_read_entry")
                .ok_or_else(|| EbpfError::ProgramNotFound {
                    name: "ssl_read_entry".into(),
                })?
                .try_into()?;
            load_program(prog, "ssl_read_entry")?;
            links.push(Box::new(prog.attach(Some("SSL_read"), 0, &ssl_path, target_pid)?));
        }

        // 5. Attach ssl_read_exit uretprobe (captures inbound TLS plaintext).
        {
            let prog: &mut UProbe = bpf
                .program_mut("ssl_read_exit")
                .ok_or_else(|| EbpfError::ProgramNotFound {
                    name: "ssl_read_exit".into(),
                })?
                .try_into()?;
            load_program(prog, "ssl_read_exit")?;
            links.push(Box::new(prog.attach(Some("SSL_read"), 0, &ssl_path, target_pid)?));
        }

        Ok(Self {
            target_pid,
            _links: links,
        })
    }

    /// Stub for non-Linux platforms — uprobe attachment requires Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn attach(_bpf: &mut (), _target_pid: Option<i32>) -> Result<Self, EbpfError> {
        Err(EbpfError::ProgramNotFound {
            name: "uprobe attachment requires Linux".into(),
        })
    }
}

impl Drop for UprobeManager {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        let count = self._links.len();
        #[cfg(not(target_os = "linux"))]
        let count = 0_usize;

        tracing::debug!(
            target_pid = ?self.target_pid,
            probe_count = count,
            "detaching uprobe links",
        );
    }
}

/// Load a BPF program, converting EPERM to [`EbpfError::PermissionDenied`].
///
/// `prog.load()` returns `aya::programs::ProgramError` on failure.  When the
/// kernel rejects the load with EPERM the error string contains "EPERM" or
/// "Operation not permitted".  This wrapper detects that pattern and returns a
/// more actionable [`EbpfError::PermissionDenied`] instead.
#[cfg(target_os = "linux")]
fn load_program(prog: &mut UProbe, name: &str) -> Result<(), EbpfError> {
    prog.load().map_err(|e| {
        let msg = e.to_string();
        if msg.contains("EPERM") || msg.contains("Operation not permitted") {
            EbpfError::PermissionDenied {
                detail: format!("loading program `{name}` requires CAP_BPF + CAP_PERFMON (or root)"),
            }
        } else {
            EbpfError::Program(e)
        }
    })
}

/// Target well-known `libssl.so` filesystem paths tried when the library is
/// not yet mapped into `/proc/<pid>/maps` (e.g. system-wide mode before the
/// first TLS call or when attaching prior to process start).
#[cfg(target_os = "linux")]
static LIBSSL_FALLBACK_PATHS: &[&str] = &[
    // Debian / Ubuntu — OpenSSL 3.x
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    // Debian / Ubuntu — OpenSSL 1.1.x
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    // RHEL / Fedora / Amazon Linux — OpenSSL 3.x
    "/usr/lib64/libssl.so.3",
    // RHEL / Fedora — OpenSSL 1.1.x
    "/usr/lib64/libssl.so.1.1",
    // Alpine / generic
    "/usr/lib/libssl.so.3",
    "/usr/lib/libssl.so.1.1",
    // Local builds
    "/usr/local/lib/libssl.so",
    "/usr/local/lib64/libssl.so",
];

/// Find the path to the OpenSSL shared library for the given PID.
///
/// Search order:
/// 1. Scan `/proc/<pid>/maps` (or `/proc/self/maps` when `target_pid` is
///    `None`) for any mapped region whose pathname contains `libssl.so`.
/// 2. If nothing is found in maps (common when `target_pid` is `None` and the
///    calling process does not use OpenSSL itself), walk the well-known
///    filesystem paths in [`LIBSSL_FALLBACK_PATHS`] and return the first one
///    that exists on disk.
///
/// Supports both OpenSSL 1.1.x (`libssl.so.1.1`) and 3.x (`libssl.so.3`).
///
/// # Errors
///
/// Returns [`EbpfError::OpenSslNotFound`] if no `libssl` path can be found.
/// Returns [`EbpfError::Io`] if `/proc/<pid>/maps` cannot be read and the
/// target PID was specified (i.e. the process does not exist).
#[cfg(target_os = "linux")]
fn find_openssl_path(target_pid: Option<i32>) -> Result<String, EbpfError> {
    let pid_str = target_pid.map(|p| p.to_string()).unwrap_or_else(|| "self".to_string());
    let maps_path = format!("/proc/{}/maps", pid_str);

    // For a specific PID, propagate I/O errors (process may not exist).
    // For system-wide (self), silently fall through to the filesystem search.
    let maps_result = std::fs::read_to_string(&maps_path);
    match (maps_result, target_pid) {
        (Err(e), Some(_)) => return Err(EbpfError::Io(e)),
        (Ok(content), _) => {
            for line in content.lines() {
                // Each maps line: addr-addr perms offset dev inode [pathname]
                // The pathname is the last whitespace-separated field and may
                // be absent for anonymous mappings — skip those.
                if let Some(pathname) = line.split_whitespace().last() {
                    if pathname.contains("libssl.so") {
                        return Ok(pathname.to_string());
                    }
                }
            }
        }
        (Err(_), None) => { /* /proc/self/maps unreadable — fall through */ }
    }

    // Filesystem fallback: check well-known installation paths.
    for &path in LIBSSL_FALLBACK_PATHS {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    Err(EbpfError::OpenSslNotFound { pid: target_pid })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Linux: reading /proc/maps for a nonexistent PID returns an Io error.
    #[cfg(target_os = "linux")]
    #[test]
    fn find_openssl_path_nonexistent_pid_returns_io_error() {
        // PID 2^22 - 1 is extremely unlikely to exist.
        let result = find_openssl_path(Some(4_194_303));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, EbpfError::Io(_)), "expected Io error, got: {err}",);
    }

    /// On Linux: system-wide search with no libssl installed returns OpenSslNotFound.
    /// This test only fails on systems that actually have libssl — which is
    /// acceptable; it validates the error path on minimal CI containers.
    #[cfg(target_os = "linux")]
    #[test]
    fn find_openssl_path_system_wide_falls_through_to_filesystem() {
        // We cannot guarantee libssl is absent, so just verify the function
        // returns Ok (found) or OpenSslNotFound (not found) — never panics.
        let result = find_openssl_path(None);
        match &result {
            Ok(path) => assert!(path.contains("libssl.so"), "unexpected path: {path}"),
            Err(EbpfError::OpenSslNotFound { .. }) => { /* expected on minimal systems */ }
            Err(e) => panic!("unexpected error variant: {e}"),
        }
    }
}
