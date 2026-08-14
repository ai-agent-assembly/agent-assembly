//! `aa-ebpf-loaderd` — the privileged eBPF loader daemon (AAASM-3603).
//!
//! This is the ONLY component permitted to load / attach / detach eBPF programs
//! and update BPF maps. It is a tiny, single-purpose, auditable binary that
//! holds `CAP_BPF` / `CAP_PERFMON`; nothing else in the system does. Removing
//! BPF privilege from `aa-runtime` (AAASM-3605) depends on this concentration
//! of privilege here.
//!
//! It contains NO agent / SDK / IPC-client logic. Its entire job is:
//! load → integrity-verify (AAASM-3602) → attach → serve the control channel
//! (AAASM-3604) so the unprivileged runtime can request lifecycle operations.
//!
//! # Deployment (systemd)
//!
//! Run under a unit that grants only the BPF capabilities, e.g.:
//!
//! ```ini
//! [Unit]
//! Description=Agent Assembly privileged eBPF loader daemon
//! After=network.target
//!
//! [Service]
//! Type=simple
//! ExecStart=/usr/local/bin/aa-ebpf-loaderd
//! # Grant ONLY the BPF capabilities — nothing else.
//! AmbientCapabilities=CAP_BPF CAP_PERFMON
//! CapabilityBoundingSet=CAP_BPF CAP_PERFMON
//! NoNewPrivileges=yes
//! ProtectSystem=strict
//! ProtectHome=yes
//! RuntimeDirectory=aa-ebpf-loaderd
//! # Socket at /run/aa-ebpf-loaderd.sock, created 0600 root:root by the daemon.
//!
//! [Install]
//! WantedBy=multi-user.target
//! ```

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use aa_ebpf::control::server::{bind_hardened, resolve_socket_path, serve, ProbeManager};
    use tokio::sync::Mutex;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let socket_path = resolve_socket_path();
    let listener = bind_hardened(&socket_path)?;
    tracing::info!(socket = %socket_path.display(), "aa-ebpf-loaderd listening (privileged, owner-only 0600)");

    let manager = Arc::new(Mutex::new(ProbeManager::new()));
    serve(listener, manager).await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "aa-ebpf-loaderd is Linux-only: eBPF program loading requires the Linux kernel BPF subsystem. \
         This binary is a no-op on the current platform."
    );
    std::process::exit(1);
}
