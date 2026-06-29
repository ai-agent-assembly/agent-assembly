//! Privileged control server hosted by `aa-ebpf-loaderd` (Linux only,
//! AAASM-3603/3604).
//!
//! This is the ONLY component that touches `aya`. It binds a root-owned `0600`
//! Unix socket, accepts requests from the unprivileged `aa-runtime`, and drives
//! the probe loaders. Each request is validated before any BPF operation; a
//! malformed or unauthorized request is rejected with
//! [`ControlResponse::Error`] and never reaches the kernel.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use super::codec::{read_frame, write_frame};
use super::protocol::{ControlRequest, ControlResponse, PathRuleWire, ProbeSet};
use crate::error::EbpfError;
use crate::loader::{ExecLoader, FileIoLoader, SyscallGuardLoader};
use crate::maps::{PathPattern, PathVerdict};

/// Owns the live probe loaders behind the control boundary. Only the daemon
/// (which holds CAP_BPF) ever constructs and mutates this.
#[derive(Default)]
pub struct ProbeManager {
    file_io: Option<FileIoLoader>,
    exec: Option<ExecLoader>,
    tls_loaded: bool,
    syscall_guard: Option<SyscallGuardLoader>,
}

impl ProbeManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load + attach the requested probe set.
    pub fn load(&mut self, set: ProbeSet, target_pid: u32) -> Result<(), EbpfError> {
        match set {
            ProbeSet::FileIo => {
                let mut loader = FileIoLoader::new(target_pid);
                loader.load()?;
                loader.attach_kprobes()?;
                self.file_io = Some(loader);
            }
            ProbeSet::Exec => {
                let mut loader = ExecLoader::new(target_pid);
                loader.load()?;
                loader.attach_tracepoints()?;
                self.exec = Some(loader);
            }
            ProbeSet::Tls => {
                // EbpfLoader::load runs the integrity check + kernel load.
                let _ = crate::loader::EbpfLoader::load()?;
                self.tls_loaded = true;
            }
            ProbeSet::SyscallGuard => {
                let mut loader = SyscallGuardLoader::new(target_pid);
                loader.load()?;
                loader.attach()?;
                self.syscall_guard = Some(loader);
            }
        }
        Ok(())
    }

    /// Replace the syscall allowlist map. Requires the syscall-guard probe
    /// loaded. The full desired set is applied (clear + reapply).
    pub fn update_syscall_allowlist(&mut self, syscalls: &[u32]) -> Result<(), EbpfError> {
        let loader = self.syscall_guard.as_mut().ok_or_else(|| {
            EbpfError::MapUpdate("syscall-guard probe not loaded; load it before updating the syscall allowlist".into())
        })?;
        loader.update_syscall_allowlist(syscalls)
    }

    /// Replace the path deny/allow map. Requires the file-I/O probe loaded.
    pub fn update_path_map(&mut self, rules: &[PathRuleWire]) -> Result<(), EbpfError> {
        let loader = self.file_io.as_mut().ok_or_else(|| {
            EbpfError::MapUpdate("file-io probe not loaded; load it before updating the path map".into())
        })?;
        let patterns: Vec<PathPattern> = rules
            .iter()
            .map(|r| PathPattern {
                pattern: r.pattern.clone(),
                verdict: if r.deny { PathVerdict::Deny } else { PathVerdict::Allow },
            })
            .collect();
        loader.update_path_filter(&patterns)
    }

    /// Detach + unload a probe set (dropping the loader detaches its probes).
    pub fn detach(&mut self, set: ProbeSet) {
        match set {
            ProbeSet::FileIo => self.file_io = None,
            ProbeSet::Exec => self.exec = None,
            ProbeSet::Tls => self.tls_loaded = false,
            ProbeSet::SyscallGuard => self.syscall_guard = None,
        }
    }
}

/// Bind the control socket at `path` with `root:root`-style `0600` perms.
///
/// Removes any stale socket first, then tightens the mode so only the owner
/// (the privileged daemon user, normally root) can connect. An adversarial
/// agent process under `aa-runtime` therefore cannot reach the daemon.
pub fn bind_hardened(path: &Path) -> Result<UnixListener, EbpfError> {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }

    // AAASM-3918: tighten the umask so the socket inode is created 0600 from the
    // very first instant — closing the TOCTOU window where, under a permissive
    // daemon umask (e.g. systemd `UMask=0000`), the highest-privilege control
    // socket would be group/other-writable in world-traversable /run between
    // bind and the explicit chmod below. Restore the prior umask immediately
    // after bind, regardless of outcome, so we never leak it into the rest of
    // the process. Mirrors `aa-runtime/src/ipc/server.rs` (AAASM-3581).
    let listener = {
        let prev_umask = unsafe { libc::umask(0o077) };
        let result = UnixListener::bind(path);
        unsafe { libc::umask(prev_umask) };
        result?
    };

    // Belt-and-suspenders: assert the final owner-only mode explicitly.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Run the control server loop: accept connections and dispatch requests until
/// the listener is closed. Each connection is handled on its own task.
pub async fn serve(listener: UnixListener, manager: Arc<Mutex<ProbeManager>>) -> Result<(), EbpfError> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let manager = Arc::clone(&manager);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, manager).await {
                tracing::warn!(error = %e, "control connection ended with error");
            }
        });
    }
}

/// Handle one client connection: read framed requests, apply, reply.
async fn handle_connection(mut stream: UnixStream, manager: Arc<Mutex<ProbeManager>>) -> Result<(), EbpfError> {
    while let Some(req) = read_frame::<_, ControlRequest>(&mut stream).await? {
        let resp = dispatch(&manager, req).await;
        write_frame(&mut stream, &resp).await?;
    }
    Ok(())
}

/// Validate + apply a single request, producing the response. Privileged BPF
/// operations only happen here, behind the socket boundary.
pub async fn dispatch(manager: &Arc<Mutex<ProbeManager>>, req: ControlRequest) -> ControlResponse {
    let result = match req {
        ControlRequest::Ping => return ControlResponse::Pong,
        ControlRequest::LoadProbeSet { set, target_pid } => manager.lock().await.load(set, target_pid),
        ControlRequest::UpdatePathMap { rules } => manager.lock().await.update_path_map(&rules),
        ControlRequest::UpdateSyscallAllowlist { syscalls } => manager.lock().await.update_syscall_allowlist(&syscalls),
        ControlRequest::Detach { set } => {
            manager.lock().await.detach(set);
            Ok(())
        }
    };
    match result {
        Ok(()) => ControlResponse::Ok,
        Err(e) => ControlResponse::Error { message: e.to_string() },
    }
}

/// Resolve the socket path: `$AA_EBPF_LOADERD_SOCK` or the default.
pub fn resolve_socket_path() -> PathBuf {
    std::env::var_os("AA_EBPF_LOADERD_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(super::protocol::DEFAULT_SOCKET_PATH))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ping_is_answered_without_touching_bpf() {
        let manager = Arc::new(Mutex::new(ProbeManager::new()));
        let resp = dispatch(&manager, ControlRequest::Ping).await;
        assert_eq!(resp, ControlResponse::Pong);
    }

    #[tokio::test]
    async fn detach_of_unloaded_set_is_ok() {
        let manager = Arc::new(Mutex::new(ProbeManager::new()));
        let resp = dispatch(&manager, ControlRequest::Detach { set: ProbeSet::Tls }).await;
        assert_eq!(resp, ControlResponse::Ok);
    }

    #[tokio::test]
    async fn update_path_map_without_loaded_probe_is_rejected() {
        let manager = Arc::new(Mutex::new(ProbeManager::new()));
        let resp = dispatch(
            &manager,
            ControlRequest::UpdatePathMap {
                rules: vec![PathRuleWire {
                    pattern: "/etc".into(),
                    deny: true,
                }],
            },
        )
        .await;
        assert!(matches!(resp, ControlResponse::Error { .. }));
    }

    #[test]
    fn resolve_socket_path_prefers_env() {
        // SAFETY: single-threaded test; no other thread reads the env here.
        unsafe {
            std::env::set_var("AA_EBPF_LOADERD_SOCK", "/tmp/aa-test.sock");
        }
        assert_eq!(resolve_socket_path(), PathBuf::from("/tmp/aa-test.sock"));
        unsafe {
            std::env::remove_var("AA_EBPF_LOADERD_SOCK");
        }
    }

    #[tokio::test]
    async fn bind_hardened_sets_owner_only_perms() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("aa-ebpf-loaderd-test-{}.sock", std::process::id()));
        let _listener = bind_hardened(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "control socket must be owner-only");
        let _ = std::fs::remove_file(&path);
    }
}
