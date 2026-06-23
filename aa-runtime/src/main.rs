//! `aa-runtime` sidecar binary entry point.

fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().json())
        .init();
}

fn main() {
    init_tracing();

    // AAASM-3605: the runtime must hold NO BPF-class capabilities — probe
    // loading is delegated to the privileged aa-ebpf-loaderd daemon. Drop and
    // assert before doing anything else, so a misconfigured deployment that
    // granted CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON fails fast instead of running
    // as an over-privileged target for an adversarial agent.
    aa_runtime::privilege::enforce_least_privilege().expect("least-privilege self-check failed");

    let config = aa_runtime::config::RuntimeConfig::from_env().expect("failed to load runtime configuration");

    tracing::info!(
        agent_id = %config.agent_id,
        worker_threads = config.worker_threads,
        shutdown_timeout_secs = config.shutdown_timeout_secs,
        ipc_max_connections = config.ipc_max_connections,
        "configuration loaded"
    );

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    if config.worker_threads > 0 {
        builder.worker_threads(config.worker_threads);
    }

    builder
        .build()
        .expect("failed to build Tokio runtime")
        .block_on(aa_runtime::run(config));
}
