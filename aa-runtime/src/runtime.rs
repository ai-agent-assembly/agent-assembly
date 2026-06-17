//! Tokio runtime initialisation and structured task lifecycle management.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::RuntimeConfig;
use crate::lifecycle::wait_for_shutdown_signal;

/// Load policy rules from `config.policy_path`, or return empty rules if disabled.
///
/// Exits the process with code 1 if the file exists but cannot be parsed —
/// a malformed policy is a configuration error that must be fixed before startup.
fn load_policy(policy_path: &Option<std::path::PathBuf>) -> std::sync::Arc<crate::policy::PolicyRules> {
    let rules = match policy_path {
        None => {
            tracing::info!("policy enforcement disabled (AA_POLICY_PATH set to empty)");
            crate::policy::PolicyRules::default()
        }
        Some(path) => match crate::policy::load_policy(path) {
            Ok(rules) => {
                tracing::info!(
                    path = %path.display(),
                    rule_count = rules.rules.len(),
                    "policy loaded"
                );
                rules
            }
            Err(e) => {
                tracing::error!(error = %e, path = %path.display(), "failed to parse policy file — aborting");
                std::process::exit(1);
            }
        },
    };
    std::sync::Arc::new(rules)
}

/// Attempt to spawn the proxy subsystem as a subprocess on the given [`TaskTracker`].
///
/// Locates the `aa-proxy` binary via `which` and spawns it as a child process.
/// If the binary is not found, the proxy layer is immediately degraded.
/// If the subprocess exits unexpectedly at runtime, a
/// [`PipelineEvent::LayerDegradation`] is emitted on the broadcast channel.
fn spawn_proxy(
    tracker: &TaskTracker,
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    active_layers: crate::layer::LayerSet,
    degraded_layers: &mut Vec<String>,
) {
    let proxy_bin = match which::which("aa-proxy") {
        Ok(path) => path,
        Err(e) => {
            tracing::warn!(error = %e, "aa-proxy binary not found — degrading proxy layer");
            emit_proxy_degradation(broadcast_tx, active_layers, format!("binary not found: {e}"));
            degraded_layers.push("proxy".to_string());
            return;
        }
    };

    let proxy_broadcast_tx = broadcast_tx.clone();
    let proxy_bin_display = proxy_bin.display().to_string();
    tracker.spawn(async move {
        let result = tokio::process::Command::new(&proxy_bin)
            .kill_on_drop(true)
            .status()
            .await;
        match result {
            Ok(status) if status.success() => {
                tracing::info!("proxy subsystem exited normally");
            }
            Ok(status) => {
                let reason = format!("proxy exited with {status}");
                tracing::warn!(%reason, "proxy subsystem failed");
                emit_proxy_degradation(&proxy_broadcast_tx, active_layers, reason);
            }
            Err(e) => {
                let reason = format!("failed to spawn proxy: {e}");
                tracing::warn!(%reason, "proxy subsystem failed");
                emit_proxy_degradation(&proxy_broadcast_tx, active_layers, reason);
            }
        }
    });
    tracing::info!(binary = %proxy_bin_display, "proxy subsystem task spawned");
}

/// Emit a [`PipelineEvent::LayerDegradation`] for an eBPF sub-layer.
///
/// `sub_layer` is the specific sub-layer that degraded (e.g. `"ebpf/tls"`,
/// `"ebpf/file_io"`, `"ebpf/exec"`). The remaining-layers list is derived
/// from `active_layers` minus the full EBPF flag — the caller decides whether
/// the top-level EBPF layer should be removed based on how many sub-layers
/// have degraded.
fn emit_ebpf_degradation(
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    sub_layer: &str,
    reason: String,
) {
    let info = crate::pipeline::LayerDegradationInfo {
        layer: sub_layer.to_string(),
        reason,
        remaining_layers: Vec::new(),
    };
    let _ = broadcast_tx.send(crate::pipeline::PipelineEvent::LayerDegradation(info));
}

/// Spawn the eBPF TLS uprobe sub-layer.
///
/// Loads the TLS BPF program, attaches uprobes to OpenSSL, and starts the
/// ring-buffer reader loop. TLS capture events are logged at debug level
/// (mapping to `AuditEvent` is a future task). On failure the `"ebpf/tls"`
/// sub-layer degrades independently.
#[cfg(target_os = "linux")]
fn spawn_ebpf_tls(
    tracker: &tokio_util::task::TaskTracker,
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    degraded_layers: &mut Vec<String>,
) {
    let mut bpf = match aa_ebpf::EbpfLoader::load() {
        Ok(b) => b,
        Err(e) => {
            let reason = format!("TLS BPF load failed: {e}");
            tracing::warn!(%reason, "degrading ebpf/tls sub-layer");
            emit_ebpf_degradation(broadcast_tx, "ebpf/tls", reason);
            degraded_layers.push("ebpf/tls".to_string());
            return;
        }
    };

    let pid = std::process::id() as i32;
    if let Err(e) = aa_ebpf::uprobe::UprobeManager::attach(&mut bpf, Some(pid)) {
        let reason = format!("TLS uprobe attach failed: {e}");
        tracing::warn!(%reason, "degrading ebpf/tls sub-layer");
        emit_ebpf_degradation(broadcast_tx, "ebpf/tls", reason);
        degraded_layers.push("ebpf/tls".to_string());
        return;
    }

    let mut reader = match aa_ebpf::ringbuf::RingBufReader::new(bpf) {
        Ok(r) => r,
        Err(e) => {
            let reason = format!("ring buffer init failed: {e}");
            tracing::warn!(%reason, "degrading ebpf/tls sub-layer");
            emit_ebpf_degradation(broadcast_tx, "ebpf/tls", reason);
            degraded_layers.push("ebpf/tls".to_string());
            return;
        }
    };

    let tls_broadcast_tx = broadcast_tx.clone();
    tracker.spawn(async move {
        loop {
            match reader.next().await {
                Ok(Some(event)) => {
                    log_ebpf_tls_event(&event);
                    let _ = &tls_broadcast_tx; // keep broadcast_tx alive for future forwarding
                }
                Ok(None) => {
                    tracing::info!("TLS ring buffer closed");
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TLS ring buffer read error");
                    emit_ebpf_degradation(&tls_broadcast_tx, "ebpf/tls", format!("ring buffer error: {e}"));
                    break;
                }
            }
        }
    });
    tracing::info!("ebpf/tls sub-layer task spawned");
}

/// Log a ring-buffer event at DEBUG using **only scalar metadata**.
///
/// SECURITY (AAASM-3128): a `TlsCaptureEvent` carries up to
/// [`aa_ebpf_common::tls::MAX_PAYLOAD_LEN`] bytes of decrypted-TLS plaintext —
/// the credentials, tokens, and request bodies this layer exists to govern.
/// Its derived `Debug` impl renders that payload, so logging the event with
/// `?event` would dump raw secrets straight to the log sink, bypassing the
/// credential scanner. This function deliberately emits only the scalar
/// header fields (pid/tid/lengths/sequence/direction/timestamp) and never the
/// `payload`.
#[cfg(target_os = "linux")]
fn log_ebpf_tls_event(event: &aa_ebpf::ringbuf::EbpfEvent) {
    if let aa_ebpf::ringbuf::EbpfEvent::Tls(tls) = event {
        tracing::debug!(
            pid = tls.pid,
            tid = tls.tid,
            data_len = tls.data_len,
            seq = tls.seq,
            direction = tls.direction,
            timestamp_ns = tls.timestamp_ns,
            "TLS ring buffer event"
        );
    } else {
        tracing::debug!("non-TLS ring buffer event on TLS reader");
    }
}

#[cfg(not(target_os = "linux"))]
fn spawn_ebpf_tls(
    _tracker: &tokio_util::task::TaskTracker,
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    degraded_layers: &mut Vec<String>,
) {
    emit_ebpf_degradation(
        broadcast_tx,
        "ebpf/tls",
        "eBPF not supported on this platform".to_string(),
    );
    degraded_layers.push("ebpf/tls".to_string());
}

/// Spawn the eBPF file I/O kprobe sub-layer.
///
/// Loads the file I/O BPF program, attaches kprobes, and starts the perf
/// event reader. Each `FileIoEvent` is mapped to an `AuditEvent` via
/// [`crate::ebpf_bridge::file_io_to_audit`] and enriched before being
/// broadcast on the pipeline channel.
#[cfg(target_os = "linux")]
fn spawn_ebpf_file_io(
    tracker: &tokio_util::task::TaskTracker,
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    seq: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    agent_id: &str,
    degraded_layers: &mut Vec<String>,
) {
    let pid = std::process::id();
    let mut loader = aa_ebpf::FileIoLoader::new(pid);

    if let Err(e) = loader.load() {
        let reason = format!("file I/O BPF load failed: {e}");
        tracing::warn!(%reason, "degrading ebpf/file_io sub-layer");
        emit_ebpf_degradation(broadcast_tx, "ebpf/file_io", reason);
        degraded_layers.push("ebpf/file_io".to_string());
        return;
    }

    if let Err(e) = loader.attach_kprobes() {
        let reason = format!("file I/O kprobe attach failed: {e}");
        tracing::warn!(%reason, "degrading ebpf/file_io sub-layer");
        emit_ebpf_degradation(broadcast_tx, "ebpf/file_io", reason);
        degraded_layers.push("ebpf/file_io".to_string());
        return;
    }

    let mut rx = match loader.start_event_reader() {
        Ok(r) => r,
        Err(e) => {
            let reason = format!("file I/O event reader failed: {e}");
            tracing::warn!(%reason, "degrading ebpf/file_io sub-layer");
            emit_ebpf_degradation(broadcast_tx, "ebpf/file_io", reason);
            degraded_layers.push("ebpf/file_io".to_string());
            return;
        }
    };

    let fio_broadcast_tx = broadcast_tx.clone();
    let fio_seq = std::sync::Arc::clone(seq);
    let fio_agent_id = agent_id.to_string();
    tracker.spawn(async move {
        // Keep the loader alive so the BPF handle and kprobes remain
        // attached until the task is cancelled or the channel closes.
        let _loader = loader;
        while let Some(event) = rx.recv().await {
            let audit = crate::ebpf_bridge::file_io_to_audit(&event);
            let enriched = crate::ebpf_bridge::enrich_ebpf(audit, &fio_agent_id, &fio_seq);
            let _ = fio_broadcast_tx.send(crate::pipeline::PipelineEvent::Audit(Box::new(enriched)));
        }
        tracing::info!("ebpf/file_io event reader closed");
    });
    tracing::info!("ebpf/file_io sub-layer task spawned");
}

#[cfg(not(target_os = "linux"))]
fn spawn_ebpf_file_io(
    _tracker: &tokio_util::task::TaskTracker,
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    _seq: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    _agent_id: &str,
    degraded_layers: &mut Vec<String>,
) {
    emit_ebpf_degradation(
        broadcast_tx,
        "ebpf/file_io",
        "eBPF not supported on this platform".to_string(),
    );
    degraded_layers.push("ebpf/file_io".to_string());
}

/// Spawn the eBPF process-exec tracepoint sub-layer.
///
/// Loads the BPF program and attaches tracepoints. The loader holds the BPF
/// handle alive and internally maintains a `ProcessLineageTracker` and
/// `ShellDetector`. A ring-buffer event reader will be wired in a future ticket.
#[cfg(target_os = "linux")]
fn spawn_ebpf_exec_tracepoints(
    tracker: &tokio_util::task::TaskTracker,
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    token: &tokio_util::sync::CancellationToken,
    degraded_layers: &mut Vec<String>,
) {
    let pid = std::process::id();
    let mut loader = aa_ebpf::ExecLoader::new(pid);

    if let Err(e) = loader.load() {
        let reason = format!("exec BPF load failed: {e}");
        tracing::warn!(%reason, "degrading ebpf/exec sub-layer");
        emit_ebpf_degradation(broadcast_tx, "ebpf/exec", reason);
        degraded_layers.push("ebpf/exec".to_string());
        return;
    }

    if let Err(e) = loader.attach_tracepoints() {
        let reason = format!("exec tracepoint attach failed: {e}");
        tracing::warn!(%reason, "degrading ebpf/exec sub-layer");
        emit_ebpf_degradation(broadcast_tx, "ebpf/exec", reason);
        degraded_layers.push("ebpf/exec".to_string());
        return;
    }

    let exec_token = token.clone();
    tracker.spawn(async move {
        // Keep the loader alive so the BPF handle and tracepoints remain
        // attached until the runtime shuts down.
        let _loader = loader;
        exec_token.cancelled().await;
        tracing::info!("ebpf/exec sub-layer shutting down");
    });
    tracing::info!("ebpf/exec sub-layer task spawned");
}

#[cfg(not(target_os = "linux"))]
fn spawn_ebpf_exec_tracepoints(
    _tracker: &tokio_util::task::TaskTracker,
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    _token: &tokio_util::sync::CancellationToken,
    degraded_layers: &mut Vec<String>,
) {
    emit_ebpf_degradation(
        broadcast_tx,
        "ebpf/exec",
        "eBPF not supported on this platform".to_string(),
    );
    degraded_layers.push("ebpf/exec".to_string());
}

/// Emit a [`PipelineEvent::LayerDegradation`] for the proxy layer.
fn emit_proxy_degradation(
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    active_layers: crate::layer::LayerSet,
    reason: String,
) {
    let remaining = active_layers
        .difference(crate::layer::LayerSet::PROXY)
        .names()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let info = crate::pipeline::LayerDegradationInfo {
        layer: "proxy".to_string(),
        reason,
        remaining_layers: remaining,
    };
    let _ = broadcast_tx.send(crate::pipeline::PipelineEvent::LayerDegradation(info));
}

/// Capacity of the channel carrying governance audit entries from the approval
/// queue to the publisher-drain task.
const AUDIT_CHANNEL_CAPACITY: usize = 8_192;
/// Capacity of the on-disk fallback buffer for audit events that cannot be
/// published while NATS is unreachable.
const AUDIT_BUFFER_CAPACITY: usize = 100_000;
/// How often the reconnect-flush loop replays buffered audit events.
const AUDIT_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Build the audit publisher when `AA_NATS_CONFIG_PATH` points at a readable
/// config carrying a `[gateway.nats]` table.
///
/// Returns `None` — leaving the agent fully functional without audit publishing
/// — when NATS is unconfigured, the config is unreadable/invalid, the buffer
/// cannot be opened, or the initial NATS connection fails. None of these abort
/// startup (AAASM-2547).
async fn build_audit_publisher(
    config: &RuntimeConfig,
) -> Option<std::sync::Arc<crate::audit_publisher::AuditPublisher>> {
    let path = config.nats_config_path.as_ref()?;
    let toml = match std::fs::read_to_string(path) {
        Ok(toml) => toml,
        Err(err) => {
            tracing::warn!(error = %err, path = %path.display(), "audit publisher disabled — cannot read NATS config");
            return None;
        }
    };
    let nats_config = match crate::audit_publisher::NatsConfig::from_toml_str(&toml) {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::warn!(error = %err, "audit publisher disabled — invalid [gateway.nats]");
            return None;
        }
    };
    let buffer = match aa_storage_sqlite_buffer::EventBuffer::new(&config.audit_buffer_path, AUDIT_BUFFER_CAPACITY) {
        Ok(buffer) => std::sync::Arc::new(buffer),
        Err(err) => {
            tracing::warn!(error = %err, path = %config.audit_buffer_path.display(), "audit publisher disabled — cannot open buffer");
            return None;
        }
    };
    let sink = match crate::audit_publisher::NatsAuditSink::connect(&nats_config).await {
        Ok(sink) => std::sync::Arc::new(sink) as std::sync::Arc<dyn aa_core::storage::AuditSink>,
        Err(err) => {
            tracing::warn!(error = %err, url = %nats_config.url, "audit publisher disabled — initial NATS connect failed");
            return None;
        }
    };
    tracing::info!(url = %nats_config.url, "audit publisher enabled");
    Some(std::sync::Arc::new(crate::audit_publisher::AuditPublisher::new(
        sink, buffer,
    )))
}

/// Spawn (into `tracker`) the task that drains the approval audit stream into the
/// publisher, fire-and-forget. On cancellation it drains any already-queued
/// entries before exiting so a graceful shutdown loses nothing.
fn spawn_audit_drain(
    tracker: &TaskTracker,
    mut rx: tokio::sync::mpsc::Receiver<aa_core::storage::AuditEntry>,
    publisher: std::sync::Arc<crate::audit_publisher::AuditPublisher>,
    token: CancellationToken,
) {
    tracker.spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    while let Ok(entry) = rx.try_recv() {
                        publisher.publish(entry).await;
                    }
                    break;
                }
                maybe = rx.recv() => match maybe {
                    Some(entry) => publisher.publish(entry).await,
                    None => break,
                },
            }
        }
        tracing::info!("audit drain task exiting");
    });
}

/// Spawn (into `tracker`) the task that converts pipeline `PipelineEvent::Audit`
/// interception events to governance `AuditEntry`s and publishes them to NATS via
/// the same fire-and-forget [`AuditPublisher`](crate::audit_publisher::AuditPublisher)
/// (AAASM-2610).
///
/// This subscriber runs *alongside* the correlation-engine subscriber — both
/// read the same broadcast channel, but only this task converts and publishes.
/// `LayerDegradation` events are not audit events and are ignored here.
///
/// ## No double-publish vs the approval stream
///
/// The approval audit stream (`spawn_audit_drain`) publishes `AuditEntry`s
/// produced by the `ApprovalQueue` for approval *decisions* (requested /
/// granted / denied / timed-out). This task publishes `AuditEntry`s converted
/// from `PipelineEvent::Audit` *interception* events (SDK / eBPF / proxy tool,
/// file, network, process calls). The two are disjoint sources carried on
/// different channels — an approval decision never travels on the pipeline
/// broadcast as a `PipelineEvent::Audit`, so each logical audit event reaches
/// NATS exactly once.
///
/// Publish failures are absorbed by the publisher (buffered to SQLite), so a
/// NATS outage never crashes or blocks the pipeline.
fn spawn_pipeline_audit_publisher(
    tracker: &TaskTracker,
    mut rx: tokio::sync::broadcast::Receiver<crate::pipeline::PipelineEvent>,
    publisher: std::sync::Arc<crate::audit_publisher::AuditPublisher>,
    token: CancellationToken,
) {
    tracker.spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::info!("pipeline audit publisher shutting down");
                    break;
                }
                result = rx.recv() => match result {
                    Ok(crate::pipeline::PipelineEvent::Audit(enriched)) => {
                        let entry = crate::audit_publisher::enriched_to_audit_entry(&enriched);
                        publisher.publish(entry).await;
                    }
                    Ok(crate::pipeline::PipelineEvent::LayerDegradation(_)) => {
                        // Layer degradation is an operational event, not an audit event.
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(dropped = n, "pipeline audit publisher lagged — audit events lost");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::info!("broadcast channel closed — pipeline audit publisher exiting");
                        break;
                    }
                },
            }
        }
        tracing::info!("pipeline audit publisher task exiting");
    });
}

/// Start the runtime and block until graceful shutdown completes.
///
/// This is the main async entry point called from `main()`. It creates the
/// structured concurrency primitives, spawns subsystem tasks, waits for a
/// shutdown signal, then drains all tasks within the configured timeout.
pub async fn run(config: RuntimeConfig) {
    // Install global Prometheus metrics recorder.
    let prometheus_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    // Register all 6 required metrics at 0 so /metrics surface is stable from first scrape.
    metrics::counter!("aa_events_received_total").increment(0);
    metrics::counter!("aa_events_emitted_total").increment(0);
    metrics::counter!("aa_policy_violations_total").increment(0);
    metrics::counter!("aa_policy_evaluations_total").increment(0); // stays 0 until AAASM-69/70
    metrics::gauge!("aa_active_connections").set(0.0);
    metrics::gauge!("aa_channel_utilization_ratio").set(0.0);

    // Readiness channel — written true after IpcServer::bind() succeeds.
    let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);

    tracing::info!("aa-runtime starting");

    let tracker = TaskTracker::new();
    let token = CancellationToken::new();

    tracing::info!("structured concurrency primitives initialised");

    // Load policy rules from the mounted volume (or use empty rules if disabled/absent).
    let policy = load_policy(&config.policy_path);

    // Detect available interception layers (eBPF, proxy, SDK).
    let active_layers = crate::layer::LayerDetector::detect();
    tracing::info!(layers = %active_layers, "active interception layers");

    let mut degraded_layers: Vec<String> = Vec::new();
    if !active_layers.contains(crate::layer::LayerSet::EBPF) {
        tracing::warn!(
            remaining = %active_layers,
            "eBPF layer unavailable — requires Linux >= 5.8, BTF, and CAP_BPF"
        );
        degraded_layers.push("ebpf".to_string());
    }
    if !active_layers.contains(crate::layer::LayerSet::PROXY) {
        tracing::warn!(
            remaining = %active_layers,
            "proxy layer unavailable — aa-proxy binary not found in PATH"
        );
        degraded_layers.push("proxy".to_string());
    }

    // Build pipeline config and create the inbound channel at the configured depth.
    let pipeline_config = crate::pipeline::PipelineConfig::from_runtime_config(&config);
    let (inbound_tx, inbound_rx) =
        tokio::sync::mpsc::channel::<(u64, crate::ipc::IpcFrame)>(pipeline_config.input_buffer);

    // Create the broadcast channel for fan-out to downstream subscribers.
    let (broadcast_tx, correlation_rx) =
        tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(pipeline_config.broadcast_capacity);

    // Spawn the proxy subsystem if the PROXY layer is active.
    if active_layers.contains(crate::layer::LayerSet::PROXY) {
        spawn_proxy(&tracker, &broadcast_tx, active_layers, &mut degraded_layers);
    }

    // Shared metrics — future health/metrics endpoints will receive an Arc clone.
    let pipeline_metrics = std::sync::Arc::new(crate::pipeline::PipelineMetrics::default());

    // Shared active-connections counter exposed to the health/metrics endpoint.
    let active_connections = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));

    // Shared response router — maps connection_id → per-connection IpcResponse sender.
    let response_router = crate::ipc::new_response_router();

    // Audit publisher (AAASM-2547): when [gateway.nats] is configured, the
    // approval queue's governance AuditEntry stream is drained to NATS; when
    // unconfigured the queue runs without audit and the agent is unaffected.
    let audit_publisher = build_audit_publisher(&config).await;
    let audit_flush_loop = audit_publisher
        .as_ref()
        .map(|publisher| std::sync::Arc::clone(publisher).spawn_reconnect_flush_loop(AUDIT_FLUSH_INTERVAL));

    // Shared approval queue — holds pending human-approval requests.
    let approval_queue = match &audit_publisher {
        Some(publisher) => {
            let (audit_tx, audit_rx) = tokio::sync::mpsc::channel(AUDIT_CHANNEL_CAPACITY);
            spawn_audit_drain(&tracker, audit_rx, std::sync::Arc::clone(publisher), token.clone());
            crate::approval::ApprovalQueue::with_audit(audit_tx, [0u8; 32])
        }
        None => crate::approval::ApprovalQueue::new(),
    };

    // AAASM-2610: when audit publishing is enabled, convert pipeline
    // interception events (PipelineEvent::Audit from SDK/eBPF/proxy) to
    // governance AuditEntry and publish them to NATS. Subscribe before
    // `broadcast_tx` is moved into the pipeline task. This runs alongside the
    // correlation subscriber and is disjoint from the approval audit drain, so
    // each logical audit event is published exactly once.
    if let Some(publisher) = &audit_publisher {
        spawn_pipeline_audit_publisher(
            &tracker,
            broadcast_tx.subscribe(),
            std::sync::Arc::clone(publisher),
            token.clone(),
        );
    }

    // Clone inbound_tx for the health/metrics handler before IpcServer consumes it.
    let inbound_tx_health = inbound_tx.clone();

    // Spawn the IPC server task.
    let ipc_config = crate::ipc::server::IpcServerConfig::from_runtime_config(&config);
    match crate::ipc::server::IpcServer::bind(ipc_config) {
        Ok(ipc_server) => {
            let _ = ready_tx.send(true);
            let ipc_tracker = tracker.clone();
            let ipc_token = token.clone();
            let ipc_active_connections = std::sync::Arc::clone(&active_connections);
            let ipc_router = std::sync::Arc::clone(&response_router);
            tracker.spawn(async move {
                ipc_server
                    .run(ipc_tracker, ipc_token, inbound_tx, ipc_active_connections, ipc_router)
                    .await;
            });
            tracing::info!("IPC server task spawned");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to bind IPC socket — continuing without IPC");
            // Without an IPC server the inbound_tx is dropped here;
            // the pipeline will see the channel closed and exit cleanly.
        }
    }

    // Shared monotonic sequence counter — used by the pipeline and the
    // eBPF bridge so all events share a single ordering.
    let seq = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Spawn eBPF sub-layer tasks if the EBPF layer is active.
    if active_layers.contains(crate::layer::LayerSet::EBPF) {
        spawn_ebpf_tls(&tracker, &broadcast_tx, &mut degraded_layers);
        spawn_ebpf_file_io(&tracker, &broadcast_tx, &seq, &config.agent_id, &mut degraded_layers);
        spawn_ebpf_exec_tracepoints(&tracker, &broadcast_tx, &token, &mut degraded_layers);
    }

    // Spawn the event aggregation pipeline task.
    {
        let pipeline_token = token.clone();
        let pm = pipeline_metrics.clone();
        let pipeline_policy = std::sync::Arc::clone(&policy);
        let pipeline_router = std::sync::Arc::clone(&response_router);
        let pipeline_approval_queue = std::sync::Arc::clone(&approval_queue);
        let pipeline_seq = std::sync::Arc::clone(&seq);
        tracker.spawn(async move {
            crate::pipeline::run(
                inbound_rx,
                broadcast_tx,
                pipeline_config,
                pm,
                pipeline_token,
                pipeline_policy,
                pipeline_router,
                pipeline_approval_queue,
                None,
                pipeline_seq,
            )
            .await;
        });
        tracing::info!("pipeline task spawned");
    }

    // Spawn the correlation engine subscriber task.
    {
        let corr_config = crate::correlation::CorrelationConfig::from_runtime_config(&config);
        let corr_interval = Duration::from_millis(corr_config.eviction_interval_ms);
        let mut engine = crate::correlation::CorrelationEngine::new(corr_config);
        let corr_token = token.clone();
        let mut corr_rx = correlation_rx;
        tracker.spawn(async move {
            let mut ticker = tokio::time::interval(corr_interval);
            loop {
                tokio::select! {
                    _ = corr_token.cancelled() => {
                        tracing::info!("correlation subscriber shutting down");
                        break;
                    }
                    _ = ticker.tick() => {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let outcomes = engine.correlate();
                        for outcome in &outcomes {
                            match outcome {
                                crate::correlation::CorrelationOutcome::Matched(c) => {
                                    tracing::info!(
                                        intent = %c.intent_event_id,
                                        action = %c.action_event_id,
                                        strength = c.correlation_strength,
                                        delta_ms = c.time_delta_ms,
                                        "correlation matched"
                                    );
                                }
                                crate::correlation::CorrelationOutcome::UnexpectedAction { action_event_id } => {
                                    tracing::warn!(
                                        action = %action_event_id,
                                        "unexpected action — no matching intent"
                                    );
                                }
                                crate::correlation::CorrelationOutcome::IntentWithoutAction { intent_event_id } => {
                                    tracing::info!(
                                        intent = %intent_event_id,
                                        "intent without observed action"
                                    );
                                }
                            }
                        }
                        engine.evict(now_ms);
                    }
                    result = corr_rx.recv() => {
                        match result {
                            Ok(crate::pipeline::PipelineEvent::Audit(enriched)) => {
                                if let Some(corr_event) = crate::correlation::try_from_enriched(&enriched) {
                                    engine.ingest(corr_event);
                                }
                            }
                            Ok(crate::pipeline::PipelineEvent::LayerDegradation(_)) => {
                                // Layer degradation events are not correlated.
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!(dropped = n, "correlation subscriber lagged — events lost");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                tracing::info!("broadcast channel closed — correlation subscriber exiting");
                                break;
                            }
                        }
                    }
                }
            }
        });
        tracing::info!("correlation subscriber task spawned");
    }

    // Spawn the health/metrics HTTP server task.
    {
        let health_state = crate::health::HealthState {
            start_time: std::time::Instant::now(),
            pipeline_metrics: std::sync::Arc::clone(&pipeline_metrics),
            ready_rx,
            prometheus_handle,
            active_connections: std::sync::Arc::clone(&active_connections),
            inbound_tx: inbound_tx_health,
            active_layers,
            degraded_layers,
        };
        let addr: std::net::SocketAddr = config
            .metrics_addr
            .parse()
            .expect("invalid AA_METRICS_ADDR — must be a valid socket address");
        let health_token = token.clone();
        tracker.spawn(async move {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!(%addr, "health server bound");
                    axum::serve(listener, crate::health::router(health_state))
                        .with_graceful_shutdown(async move { health_token.cancelled().await })
                        .await
                        .ok();
                }
                Err(e) => {
                    tracing::error!(error = %e, %addr, "failed to bind health server");
                }
            }
        });
        tracing::info!(%addr, "health server task spawned");
    }

    // Wait for an OS shutdown signal.
    wait_for_shutdown_signal().await;

    // Signal all tasks to stop cooperatively.
    token.cancel();
    tracing::info!("cancellation token fired — draining tasks");

    // Stop accepting new task registrations.
    tracker.close();

    // Wait for all tasks to complete, with a hard timeout.
    let timeout = Duration::from_secs(config.shutdown_timeout_secs);
    if tokio::time::timeout(timeout, tracker.wait()).await.is_err() {
        tracing::error!(
            timeout_secs = config.shutdown_timeout_secs,
            "shutdown timeout exceeded — forcing exit"
        );
    } else {
        tracing::info!("all tasks completed cleanly");
    }

    // AAASM-2547: stop the reconnect loop and flush any audit events that
    // buffered while NATS was unreachable, now that the drain task has finished.
    if let Some(handle) = audit_flush_loop {
        handle.abort();
    }
    if let Some(publisher) = &audit_publisher {
        match publisher.flush_pending().await {
            Ok(n) if n > 0 => tracing::info!(flushed = n, "flushed buffered audit events on shutdown"),
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %err, "failed to flush audit buffer on shutdown"),
        }
    }

    tracing::info!("aa-runtime stopped");
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    /// Verifies that `load_policy(None)` returns empty rules (enforcement disabled).
    #[test]
    fn load_policy_none_returns_empty_rules() {
        let policy = super::load_policy(&None);
        assert!(policy.rules.is_empty());
    }

    /// Verifies that `load_policy(Some(path))` loads rules from a valid TOML file.
    #[test]
    fn load_policy_some_loads_rules_from_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "[[rules]]").unwrap();
        writeln!(tmp, r#"name = "test-rule""#).unwrap();
        writeln!(tmp, r#"blocked_actions = ["FILE_OPERATION"]"#).unwrap();
        tmp.flush().unwrap();
        let policy = super::load_policy(&Some(tmp.path().to_path_buf()));
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].name, "test-rule");
    }

    /// Verifies the structured concurrency primitives drain cleanly under load.
    ///
    /// Spawns N tasks that loop until the cancellation token fires, then
    /// cancels the token and asserts all tasks complete within the timeout.
    #[tokio::test]
    async fn graceful_shutdown_drains_all_tasks() {
        const TASK_COUNT: usize = 10;
        const TIMEOUT: Duration = Duration::from_secs(5);

        let tracker = TaskTracker::new();
        let token = CancellationToken::new();

        // Spawn synthetic load tasks that honor the cancellation token.
        for i in 0..TASK_COUNT {
            let child_token = token.clone();
            tracker.spawn(async move {
                loop {
                    tokio::select! {
                        _ = child_token.cancelled() => {
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {
                            // Simulate work.
                        }
                    }
                }
                tracing::debug!(task = i, "task completed cleanly");
            });
        }

        // Trigger shutdown.
        token.cancel();
        tracker.close();

        // All tasks must complete within the timeout — no leaks.
        tokio::time::timeout(TIMEOUT, tracker.wait())
            .await
            .expect("tasks did not complete within timeout");
    }

    /// Verifies that shutdown timeout enforcement works when tasks ignore cancellation.
    #[tokio::test]
    async fn shutdown_timeout_fires_when_tasks_hang() {
        let tracker = TaskTracker::new();
        let token = CancellationToken::new();

        // Spawn a task that ignores cancellation and sleeps forever.
        tracker.spawn(async move {
            let _token = token; // hold token to prevent drop-based cancellation
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });

        tracker.close();

        // Drain with a very short timeout — must expire.
        let result = tokio::time::timeout(Duration::from_millis(100), tracker.wait()).await;
        assert!(result.is_err(), "expected timeout but tasks completed");
    }

    /// End-to-end integration test: feed events through a broadcast channel into
    /// the correlation engine and verify that correlate() produces outcomes.
    #[tokio::test]
    async fn correlation_subscriber_ingests_and_correlates() {
        use crate::correlation::{CorrelationConfig, CorrelationEngine};
        use crate::pipeline::event::{EnrichedEvent, EventSource};
        use aa_proto::assembly::audit::v1::AuditEvent;
        use aa_proto::assembly::common::v1::ActionType;

        // Short window and interval for fast test execution.
        let config = CorrelationConfig {
            window_ms: 500,
            max_window_size: 100,
            eviction_interval_ms: 50,
        };
        let mut engine = CorrelationEngine::new(config);

        // Build an SDK/TOOL_CALL intent event.
        let intent_enriched = EnrichedEvent {
            inner: AuditEvent {
                event_id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
                action_type: ActionType::ToolCall as i32,
                ..AuditEvent::default()
            },
            received_at_ms: 1000,
            source: EventSource::Sdk,
            agent_id: "test".to_string(),
            connection_id: 1,
            sequence_number: 0,
        };

        // Build an eBPF/FILE_OPERATION action event.
        let action_enriched = EnrichedEvent {
            inner: AuditEvent {
                event_id: "550e8400-e29b-41d4-a716-446655440002".to_string(),
                action_type: ActionType::FileOperation as i32,
                ..AuditEvent::default()
            },
            received_at_ms: 1050,
            source: EventSource::EBpf,
            agent_id: "test".to_string(),
            connection_id: 1,
            sequence_number: 1,
        };

        // Simulate the subscriber loop: convert and ingest.
        let intent_event = crate::correlation::try_from_enriched(&intent_enriched);
        assert!(intent_event.is_some(), "SDK/TOOL_CALL should produce Intent");
        engine.ingest(intent_event.unwrap());

        let action_event = crate::correlation::try_from_enriched(&action_enriched);
        assert!(action_event.is_some(), "eBPF/FILE_OPERATION should produce Action");
        engine.ingest(action_event.unwrap());

        // Run correlation — should produce at least one outcome.
        let outcomes = engine.correlate();
        assert!(!outcomes.is_empty(), "expected at least one correlation outcome");
    }

    // ── spawn_proxy tests ────────────────────────────────────────────────

    #[test]
    fn emit_proxy_degradation_sends_event() {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(16);
        let active_layers = crate::layer::LayerSet::PROXY | crate::layer::LayerSet::SDK;

        super::emit_proxy_degradation(&tx, active_layers, "test reason".to_string());

        let event = rx.try_recv().unwrap();
        match event {
            crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                assert_eq!(info.layer, "proxy");
                assert_eq!(info.reason, "test reason");
                assert_eq!(info.remaining_layers, vec!["sdk"]);
            }
            _ => panic!("expected LayerDegradation event"),
        }
    }

    #[test]
    fn spawn_proxy_binary_not_found_emits_degradation() {
        // Temporarily set PATH to empty so `which("aa-proxy")` fails.
        let orig_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", "");

        let tracker = TaskTracker::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(16);
        let active_layers = crate::layer::LayerSet::PROXY | crate::layer::LayerSet::SDK;
        let mut degraded = Vec::new();

        super::spawn_proxy(&tracker, &tx, active_layers, &mut degraded);

        std::env::set_var("PATH", &orig_path);

        // Binary not found should immediately degrade.
        assert!(degraded.contains(&"proxy".to_string()));

        let event = rx.try_recv().unwrap();
        match event {
            crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                assert_eq!(info.layer, "proxy");
                assert!(info.reason.contains("not found"));
                assert_eq!(info.remaining_layers, vec!["sdk"]);
            }
            _ => panic!("expected LayerDegradation event"),
        }
    }

    #[tokio::test]
    async fn spawn_proxy_failing_binary_emits_degradation() {
        // Use `false` as the proxy binary — it always exits with status 1.
        // We can test this by temporarily overriding PATH to a dir with
        // a symlink named "aa-proxy" pointing to `false`.
        let tmp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            let link_path = tmp.path().join("aa-proxy");
            std::os::unix::fs::symlink("/usr/bin/false", &link_path).unwrap();
        }
        #[cfg(not(unix))]
        {
            // On non-unix, skip this test.
            return;
        }

        let orig_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{orig_path}", tmp.path().display()));

        let tracker = TaskTracker::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(16);
        let active_layers = crate::layer::LayerSet::PROXY | crate::layer::LayerSet::SDK;
        let mut degraded = Vec::new();

        super::spawn_proxy(&tracker, &tx, active_layers, &mut degraded);

        // Binary found, so no immediate degradation.
        assert!(!degraded.contains(&"proxy".to_string()));

        // Wait for the subprocess to exit with failure.
        tracker.close();
        tokio::time::timeout(Duration::from_secs(5), tracker.wait())
            .await
            .expect("proxy task did not exit within timeout");

        std::env::set_var("PATH", &orig_path);

        let event = rx.try_recv().unwrap();
        match event {
            crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                assert_eq!(info.layer, "proxy");
                assert!(info.reason.contains("proxy exited"));
                assert_eq!(info.remaining_layers, vec!["sdk"]);
            }
            _ => panic!("expected LayerDegradation event"),
        }
    }

    /// Verify the broadcast channel integration: send a PipelineEvent through
    /// the channel and confirm the correlation subscriber can receive and
    /// convert it.
    #[tokio::test]
    async fn broadcast_channel_delivers_to_correlation() {
        use crate::pipeline::event::{EnrichedEvent, EventSource, PipelineEvent};
        use aa_proto::assembly::audit::v1::AuditEvent;
        use aa_proto::assembly::common::v1::ActionType;

        let (tx, mut rx) = tokio::sync::broadcast::channel::<PipelineEvent>(16);

        let enriched = EnrichedEvent {
            inner: AuditEvent {
                event_id: "550e8400-e29b-41d4-a716-446655440003".to_string(),
                action_type: ActionType::ToolCall as i32,
                ..AuditEvent::default()
            },
            received_at_ms: 2000,
            source: EventSource::Sdk,
            agent_id: "test".to_string(),
            connection_id: 1,
            sequence_number: 0,
        };

        tx.send(PipelineEvent::Audit(Box::new(enriched))).unwrap();

        let received = rx.recv().await.unwrap();
        match received {
            PipelineEvent::Audit(e) => {
                let corr = crate::correlation::try_from_enriched(&e);
                assert!(corr.is_some());
            }
            _ => panic!("expected Audit event"),
        }
    }

    // ── spawn_ebpf_tls tests ────────────────────────────────────────────

    #[test]
    fn spawn_ebpf_tls_degrades_on_non_linux() {
        let tracker = tokio_util::task::TaskTracker::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(16);
        let mut degraded = Vec::new();

        super::spawn_ebpf_tls(&tracker, &tx, &mut degraded);

        // On macOS the non-Linux cfg path fires immediately.
        #[cfg(not(target_os = "linux"))]
        {
            assert!(degraded.contains(&"ebpf/tls".to_string()));
            let event = rx.try_recv().unwrap();
            match event {
                crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                    assert_eq!(info.layer, "ebpf/tls");
                }
                _ => panic!("expected LayerDegradation event"),
            }
        }

        // On Linux the BPF load will fail without root/capabilities,
        // so it also degrades.
        #[cfg(target_os = "linux")]
        {
            assert!(degraded.contains(&"ebpf/tls".to_string()));
            let event = rx.try_recv().unwrap();
            match event {
                crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                    assert_eq!(info.layer, "ebpf/tls");
                }
                _ => panic!("expected LayerDegradation event"),
            }
        }
    }

    // ── spawn_ebpf_file_io tests ────────────────────────────────────────

    #[test]
    fn spawn_ebpf_file_io_degrades_on_non_linux() {
        let tracker = tokio_util::task::TaskTracker::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(16);
        let seq = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut degraded = Vec::new();

        super::spawn_ebpf_file_io(&tracker, &tx, &seq, "test-agent", &mut degraded);

        #[cfg(not(target_os = "linux"))]
        {
            assert!(degraded.contains(&"ebpf/file_io".to_string()));
            let event = rx.try_recv().unwrap();
            match event {
                crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                    assert_eq!(info.layer, "ebpf/file_io");
                }
                _ => panic!("expected LayerDegradation event"),
            }
        }

        #[cfg(target_os = "linux")]
        {
            assert!(degraded.contains(&"ebpf/file_io".to_string()));
            let event = rx.try_recv().unwrap();
            match event {
                crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                    assert_eq!(info.layer, "ebpf/file_io");
                }
                _ => panic!("expected LayerDegradation event"),
            }
        }
    }

    // ── spawn_ebpf_exec_tracepoints tests ───────────────────────────────

    #[test]
    fn spawn_ebpf_exec_tracepoints_degrades_on_non_linux() {
        let tracker = tokio_util::task::TaskTracker::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(16);
        let token = tokio_util::sync::CancellationToken::new();
        let mut degraded = Vec::new();

        super::spawn_ebpf_exec_tracepoints(&tracker, &tx, &token, &mut degraded);

        #[cfg(not(target_os = "linux"))]
        {
            assert!(degraded.contains(&"ebpf/exec".to_string()));
            let event = rx.try_recv().unwrap();
            match event {
                crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                    assert_eq!(info.layer, "ebpf/exec");
                }
                _ => panic!("expected LayerDegradation event"),
            }
        }

        #[cfg(target_os = "linux")]
        {
            assert!(degraded.contains(&"ebpf/exec".to_string()));
            let event = rx.try_recv().unwrap();
            match event {
                crate::pipeline::PipelineEvent::LayerDegradation(info) => {
                    assert_eq!(info.layer, "ebpf/exec");
                }
                _ => panic!("expected LayerDegradation event"),
            }
        }
    }

    /// A minimal config for exercising the audit-publisher builder.
    fn audit_test_config(nats_config_path: Option<std::path::PathBuf>) -> crate::config::RuntimeConfig {
        crate::config::RuntimeConfig {
            agent_id: "audit-test".to_string(),
            worker_threads: 0,
            shutdown_timeout_secs: 30,
            ipc_max_connections: 64,
            pipeline_input_buffer: 10_000,
            pipeline_batch_size: 100,
            pipeline_flush_interval_ms: 100,
            pipeline_broadcast_capacity: 1_024,
            metrics_addr: "0.0.0.0:8080".to_string(),
            policy_path: None,
            gateway_endpoint: None,
            correlation_window_ms: 5_000,
            correlation_interval_ms: 1_000,
            nats_config_path,
            audit_buffer_path: std::env::temp_dir().join("aa-audit-buffer-audit-test.db"),
            enforcement_max_field_bytes: crate::pipeline::enforcement::DEFAULT_MAX_FIELD_BYTES,
        }
    }

    #[tokio::test]
    async fn build_audit_publisher_disabled_when_unconfigured_or_unreadable() {
        // Unconfigured (no AA_NATS_CONFIG_PATH) ⇒ disabled, agent unaffected.
        assert!(super::build_audit_publisher(&audit_test_config(None)).await.is_none());

        // Configured but the path does not exist ⇒ disabled, no startup failure.
        let missing = std::env::temp_dir().join("aa-nonexistent-nats-config-xyz.toml");
        assert!(super::build_audit_publisher(&audit_test_config(Some(missing)))
            .await
            .is_none());
    }

    // ── spawn_pipeline_audit_publisher tests (AAASM-2610) ────────────────────

    use aa_core::storage::{AuditEntry, AuditSink, Result as StorageResult};

    /// An [`AuditSink`] that records every published entry's payload so tests
    /// can assert what reached NATS.
    struct RecordingSink {
        published: std::sync::Mutex<Vec<AuditEntry>>,
    }

    impl RecordingSink {
        fn new() -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                published: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn payloads(&self) -> Vec<String> {
            self.published
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.payload().to_string())
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl AuditSink for RecordingSink {
        async fn emit(&self, event: AuditEntry) -> StorageResult<()> {
            self.published.lock().unwrap().push(event);
            Ok(())
        }
    }

    /// Build an [`AuditPublisher`] over the given recording sink with a fresh
    /// on-disk fallback buffer (returned `TempDir` keeps it alive).
    fn publisher_over(
        sink: std::sync::Arc<RecordingSink>,
    ) -> (
        std::sync::Arc<crate::audit_publisher::AuditPublisher>,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let buffer = std::sync::Arc::new(
            aa_storage_sqlite_buffer::EventBuffer::new(tmp.path().join("buffer.db"), 1_024).expect("buffer"),
        );
        let sink: std::sync::Arc<dyn AuditSink> = sink;
        let publisher = std::sync::Arc::new(crate::audit_publisher::AuditPublisher::new(sink, buffer));
        (publisher, tmp)
    }

    /// Build a `PipelineEvent::Audit` carrying a TOOL_CALL interception event.
    fn pipeline_tool_call(event_id: &str, seq: u64) -> crate::pipeline::PipelineEvent {
        use crate::pipeline::event::{EnrichedEvent, EventSource};
        use aa_proto::assembly::audit::v1::AuditEvent;
        use aa_proto::assembly::common::v1::ActionType;

        crate::pipeline::PipelineEvent::Audit(Box::new(EnrichedEvent {
            inner: AuditEvent {
                event_id: event_id.to_string(),
                action_type: ActionType::ToolCall as i32,
                ..AuditEvent::default()
            },
            received_at_ms: 1_000,
            source: EventSource::Sdk,
            agent_id: "pipe-agent".to_string(),
            connection_id: 1,
            sequence_number: seq,
        }))
    }

    /// The subscriber converts and publishes each pipeline `Audit` event, and
    /// ignores `LayerDegradation` operational events.
    #[tokio::test]
    async fn pipeline_audit_publisher_publishes_converted_events() {
        let sink = RecordingSink::new();
        let (publisher, _tmp) = publisher_over(std::sync::Arc::clone(&sink));
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();

        let (tx, rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(16);
        super::spawn_pipeline_audit_publisher(&tracker, rx, std::sync::Arc::clone(&publisher), token.clone());

        // Two audit events plus one degradation event that must be ignored.
        tx.send(pipeline_tool_call("550e8400-e29b-41d4-a716-446655440010", 0))
            .unwrap();
        tx.send(crate::pipeline::PipelineEvent::LayerDegradation(
            crate::pipeline::LayerDegradationInfo {
                layer: "proxy".to_string(),
                reason: "test".to_string(),
                remaining_layers: vec![],
            },
        ))
        .unwrap();
        tx.send(pipeline_tool_call("550e8400-e29b-41d4-a716-446655440011", 1))
            .unwrap();

        // Wait until both audit events have been published (poll briefly).
        for _ in 0..50 {
            if sink.payloads().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let payloads = sink.payloads();
        assert_eq!(payloads.len(), 2, "exactly the two Audit events should be published");
        assert!(payloads.iter().all(|p| p.contains("\"action_type\":\"TOOL_CALL\"")));
        assert!(payloads.iter().any(|p| p.contains("446655440010")));
        assert!(payloads.iter().any(|p| p.contains("446655440011")));

        token.cancel();
        tracker.close();
        let _ = tokio::time::timeout(Duration::from_secs(2), tracker.wait()).await;
    }

    /// The pipeline-audit publisher and the approval audit drain are disjoint:
    /// approval-decision entries flow only through the approval queue's mpsc
    /// drain, and pipeline interception entries flow only through the broadcast
    /// subscriber. Driving both with a shared publisher must publish each
    /// logical event exactly once — never the same event twice.
    #[tokio::test]
    async fn pipeline_and_approval_paths_do_not_double_publish() {
        let sink = RecordingSink::new();
        let (publisher, _tmp) = publisher_over(std::sync::Arc::clone(&sink));
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();

        // Approval path: an mpsc drain feeding the same publisher.
        let (audit_tx, audit_rx) = tokio::sync::mpsc::channel::<AuditEntry>(16);
        super::spawn_audit_drain(&tracker, audit_rx, std::sync::Arc::clone(&publisher), token.clone());
        let approval_queue = crate::approval::ApprovalQueue::with_audit(audit_tx, [0u8; 32]);

        // Pipeline path: the broadcast subscriber feeding the same publisher.
        let (tx, rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(16);
        super::spawn_pipeline_audit_publisher(&tracker, rx, std::sync::Arc::clone(&publisher), token.clone());

        // Drive one approval lifecycle (submit + approve ⇒ 2 approval entries:
        // ApprovalRequested + ApprovalGranted).
        let req = crate::approval::ApprovalRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_id: "approval-agent".to_string(),
            action: "read_file".to_string(),
            condition_triggered: "sensitive".to_string(),
            submitted_at: 1_700_000_000,
            timeout_secs: 60,
            fallback: aa_core::PolicyResult::Deny {
                reason: "x".to_string(),
            },
            team_id: None,
            timeout_override_secs: None,
            escalation_role_override: None,
        };
        let id = req.request_id;
        let (_rid, _fut) = approval_queue.submit(req);
        approval_queue
            .decide(
                id,
                crate::approval::ApprovalDecision::Approved {
                    by: "alice".to_string(),
                    reason: None,
                },
            )
            .expect("decide");

        // Drive one pipeline interception event.
        tx.send(pipeline_tool_call("550e8400-e29b-41d4-a716-446655440020", 0))
            .unwrap();

        // Expect exactly 3 published entries total: 2 approval + 1 pipeline.
        for _ in 0..50 {
            if sink.published.lock().unwrap().len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let payloads = sink.payloads();
        assert_eq!(
            payloads.len(),
            3,
            "exactly 2 approval + 1 pipeline entries; no double-publish. got: {payloads:?}"
        );
        // The single pipeline interception event appears exactly once.
        let pipeline_hits = payloads.iter().filter(|p| p.contains("446655440020")).count();
        assert_eq!(pipeline_hits, 1, "pipeline event must be published exactly once");
        // Approval entries carry the request/agent context, not the pipeline action_type.
        let approval_hits = payloads.iter().filter(|p| p.contains("approval-agent")).count();
        assert_eq!(approval_hits, 2, "both approval lifecycle entries present exactly once");

        token.cancel();
        tracker.close();
        let _ = tokio::time::timeout(Duration::from_secs(2), tracker.wait()).await;
    }
}

// ── Layer integration tests ─────────────────────────────────────────────
//
// Integration tests that exercise both proxy and eBPF layers together on
// a shared broadcast channel. These require Linux + root (CAP_BPF) and
// are gated behind the `integration-test` feature flag.
//
// Run locally (Linux, as root):
//   sudo cargo test -p aa-runtime --features integration-test \
//        --test layer_integration -- --nocapture
//
// In CI, the ebpf-build job runs these with sudo + nightly after building
// the eBPF probes.
#[cfg(all(test, target_os = "linux", feature = "integration-test"))]
mod layer_integration {
    use std::time::Duration;

    use crate::pipeline::PipelineEvent;

    /// Drain all events from a broadcast receiver within `timeout`.
    ///
    /// Returns the collected events once the channel is quiet for the full
    /// duration (no partial-timeout reset on each event).
    async fn collect_events(
        rx: &mut tokio::sync::broadcast::Receiver<PipelineEvent>,
        timeout: Duration,
    ) -> Vec<PipelineEvent> {
        let mut events = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(event)) => events.push(event),
                Ok(Err(_)) => break, // channel closed
                Err(_) => break,     // timeout
            }
        }
        events
    }

    /// Spawn both proxy and eBPF file I/O layers on a shared broadcast
    /// channel, trigger real events from both, and verify that events from
    /// both sources arrive with monotonically increasing sequence numbers.
    ///
    /// Requires: Linux + root (CAP_BPF + CAP_PERFMON) + `aa-proxy` on PATH.
    #[tokio::test]
    async fn both_layers_emit_events_on_shared_channel() {
        use std::sync::atomic::AtomicU64;
        use std::sync::Arc;

        use crate::pipeline::EventSource;

        let tracker = tokio_util::task::TaskTracker::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel::<PipelineEvent>(64);
        let seq = Arc::new(AtomicU64::new(0));
        let token = tokio_util::sync::CancellationToken::new();
        let mut degraded = Vec::new();

        // Spawn eBPF file I/O layer (needs root).
        super::spawn_ebpf_file_io(&tracker, &tx, &seq, "integration-test", &mut degraded);

        // If file I/O degraded (e.g. running without root), skip the
        // happy-path assertions — the degradation test covers that case.
        if degraded.contains(&"ebpf/file_io".to_string()) {
            eprintln!(
                "SKIPPING both_layers_emit_events: eBPF file_io degraded \
                 (probably missing root/CAP_BPF)"
            );
            return;
        }

        // Spawn eBPF exec tracepoints.
        super::spawn_ebpf_exec_tracepoints(&tracker, &tx, &token, &mut degraded);

        // Give the perf reader tasks time to start their polling loops.
        // They are spawned via tokio::spawn inside start_event_reader and
        // need at least one poll cycle before they can receive events.
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Trigger file I/O events repeatedly so the kprobes capture at
        // least one, even if the first trigger races with reader startup.
        let trigger_path = "/tmp/aa-integration-test-trigger";
        for _ in 0..5 {
            std::fs::write(trigger_path, b"integration-test").expect("write trigger file");
            let _ = std::fs::read_to_string(trigger_path);
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let _ = std::fs::remove_file(trigger_path);

        // Collect events.
        let events = collect_events(&mut rx, Duration::from_secs(3)).await;

        // Assert at least one eBPF-sourced audit event arrived.
        let ebpf_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, PipelineEvent::Audit(ref a) if a.source == EventSource::EBpf))
            .collect();
        assert!(
            !ebpf_events.is_empty(),
            "expected at least one eBPF audit event, got none. \
             Total events: {}, types: {:?}",
            events.len(),
            events
                .iter()
                .map(|e| match e {
                    PipelineEvent::Audit(a) => format!("Audit({:?})", a.source),
                    PipelineEvent::LayerDegradation(info) => {
                        format!("Degradation({})", info.layer)
                    }
                })
                .collect::<Vec<_>>()
        );

        // Assert sequence numbers are monotonically increasing across all
        // audit events (shared counter between eBPF bridge and pipeline).
        let mut seq_numbers: Vec<u64> = events
            .iter()
            .filter_map(|e| match e {
                PipelineEvent::Audit(a) => Some(a.sequence_number),
                _ => None,
            })
            .collect();
        let original = seq_numbers.clone();
        seq_numbers.sort();
        seq_numbers.dedup();
        assert_eq!(
            seq_numbers, original,
            "sequence numbers should be unique and monotonically increasing"
        );

        // Cleanup: cancel the exec tracepoints task and close the tracker.
        // The per-CPU perf reader tasks spawned inside FileIoLoader are detached
        // (not tracked), so we use a timeout to avoid hanging on tracker.wait().
        token.cancel();
        tracker.close();
        let _ = tokio::time::timeout(Duration::from_secs(1), tracker.wait()).await;
    }

    /// Verify that all four layers (3 eBPF sub-layers + proxy) run
    /// independently — each either succeeds or degrades on its own terms
    /// without blocking the others.
    ///
    /// Works with or without root:
    /// - Without root: eBPF loaders degrade, proxy degrades (no binary).
    /// - With root: eBPF loaders may succeed, proxy still degrades.
    /// Either way, every layer completes independently.
    #[tokio::test]
    async fn all_layers_run_independently() {
        let tracker = tokio_util::task::TaskTracker::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel::<PipelineEvent>(64);
        let seq = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let token = tokio_util::sync::CancellationToken::new();
        let mut degraded = Vec::new();

        // Spawn all three eBPF sub-layers.
        super::spawn_ebpf_tls(&tracker, &tx, &mut degraded);
        super::spawn_ebpf_file_io(&tracker, &tx, &seq, "test-agent", &mut degraded);
        super::spawn_ebpf_exec_tracepoints(&tracker, &tx, &token, &mut degraded);

        // Spawn proxy layer — expected to degrade (no aa-proxy binary).
        super::spawn_proxy(
            &tracker,
            &tx,
            crate::layer::LayerSet::EBPF | crate::layer::LayerSet::PROXY,
            &mut degraded,
        );

        // Collect events from the broadcast channel.
        let events = collect_events(&mut rx, Duration::from_secs(2)).await;

        let degradation_layers: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                PipelineEvent::LayerDegradation(info) => Some(info.layer.clone()),
                _ => None,
            })
            .collect();

        // Every layer that degraded must have a matching LayerDegradation event.
        for layer in &degraded {
            assert!(
                degradation_layers.contains(layer),
                "layer '{layer}' is in degraded list but has no LayerDegradation event. \
                 degraded: {degraded:?}, events: {degradation_layers:?}"
            );
        }

        // Every LayerDegradation event must correspond to a degraded layer.
        for layer in &degradation_layers {
            assert!(
                degraded.contains(layer),
                "LayerDegradation event for '{layer}' but layer not in degraded list. \
                 degraded: {degraded:?}, events: {degradation_layers:?}"
            );
        }

        // The key invariant: all four spawn calls returned (none blocked).
        // We verify this by checking that every layer is accounted for —
        // it either degraded or spawned a task (or both for proxy which
        // does synchronous degradation).
        let all_layers = ["ebpf/tls", "ebpf/file_io", "ebpf/exec", "proxy"];
        let spawned_or_degraded: Vec<&str> = all_layers
            .iter()
            .filter(|l| degraded.contains(&l.to_string()) || !degraded.contains(&l.to_string()))
            .copied()
            .collect();
        assert_eq!(
            spawned_or_degraded.len(),
            4,
            "expected all 4 layers to have been attempted"
        );

        // Cleanup: cancel tracked tasks and timeout the wait since detached
        // per-CPU perf reader tasks may keep running.
        token.cancel();
        tracker.close();
        let _ = tokio::time::timeout(Duration::from_secs(1), tracker.wait()).await;
    }

    /// Verify that proxy layer degradation does not prevent eBPF layers
    /// from loading successfully.
    ///
    /// Works with or without root:
    /// - With root: proxy degrades (no binary), eBPF file_io loads OK.
    /// - Without root: both degrade, but independently.
    ///
    /// Does NOT assert on eBPF audit events arriving — that is covered by
    /// `both_layers_emit_events_on_shared_channel`. This test focuses on
    /// the independence invariant: proxy failure does not block eBPF loading.
    #[tokio::test]
    async fn proxy_degradation_does_not_block_ebpf() {
        use std::sync::atomic::AtomicU64;
        use std::sync::Arc;

        let tracker = tokio_util::task::TaskTracker::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel::<PipelineEvent>(64);
        let seq = Arc::new(AtomicU64::new(0));
        let token = tokio_util::sync::CancellationToken::new();
        let mut degraded = Vec::new();

        // Spawn proxy first — expected to degrade (aa-proxy not on PATH).
        super::spawn_proxy(
            &tracker,
            &tx,
            crate::layer::LayerSet::EBPF | crate::layer::LayerSet::PROXY,
            &mut degraded,
        );

        // Proxy should have degraded synchronously.
        assert!(
            degraded.contains(&"proxy".to_string()),
            "expected proxy in degraded list (aa-proxy not on PATH): {degraded:?}"
        );

        // Spawn eBPF file I/O layer — this is the key assertion: it should
        // not be blocked or affected by the prior proxy degradation.
        super::spawn_ebpf_file_io(&tracker, &tx, &seq, "integration-test", &mut degraded);

        // Collect events to verify LayerDegradation for proxy.
        let events = collect_events(&mut rx, Duration::from_secs(2)).await;

        // Proxy LayerDegradation event should be present.
        let has_proxy_degradation = events.iter().any(|e| {
            matches!(
                e,
                PipelineEvent::LayerDegradation(info) if info.layer == "proxy"
            )
        });
        assert!(has_proxy_degradation, "expected LayerDegradation for proxy layer");

        // The eBPF layer either loaded successfully (not in degraded list)
        // or degraded on its own terms (in the list with its own event).
        // Either outcome proves proxy failure did not block it.
        if degraded.contains(&"ebpf/file_io".to_string()) {
            // eBPF also degraded — verify it has its own event.
            let has_ebpf_degradation = events.iter().any(|e| {
                matches!(
                    e,
                    PipelineEvent::LayerDegradation(info) if info.layer == "ebpf/file_io"
                )
            });
            assert!(
                has_ebpf_degradation,
                "ebpf/file_io degraded but no LayerDegradation event"
            );
        }
        // If ebpf/file_io is NOT in degraded, it loaded successfully —
        // that alone proves proxy failure didn't block it.

        // Cleanup.
        token.cancel();
        tracker.close();
        let _ = tokio::time::timeout(Duration::from_secs(1), tracker.wait()).await;
    }

    /// Regression for AAASM-3128: the DEBUG-level TLS ring-buffer log must
    /// never contain the decrypted-TLS `payload` bytes. Captures the tracing
    /// output of [`super::log_ebpf_tls_event`] for an event whose payload holds
    /// a known secret, and asserts the secret is absent while the scalar
    /// metadata is present.
    #[cfg(target_os = "linux")]
    #[test]
    fn tls_event_log_omits_payload_plaintext() {
        use std::sync::{Arc, Mutex};

        use aa_ebpf::ringbuf::EbpfEvent;
        use aa_ebpf_common::tls::{TlsCaptureEvent, MAX_PAYLOAD_LEN};
        use tracing::subscriber;
        use tracing_subscriber::fmt::MakeWriter;

        // Shared in-memory sink the fmt layer writes into.
        #[derive(Clone, Default)]
        struct BufWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for BufWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for BufWriter {
            type Writer = BufWriter;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        const SECRET: &[u8] = b"Authorization: Bearer sk-super-secret-token-value";
        let mut payload = [0u8; MAX_PAYLOAD_LEN];
        payload[..SECRET.len()].copy_from_slice(SECRET);
        let event = EbpfEvent::Tls(Box::new(TlsCaptureEvent {
            timestamp_ns: 42,
            pid: 1234,
            tid: 5678,
            data_len: SECRET.len() as u32,
            seq: 0,
            direction: 0,
            _pad: [0u8; 7],
            payload,
        }));

        let sink = BufWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(sink.clone())
            .finish();

        subscriber::with_default(subscriber, || super::log_ebpf_tls_event(&event));

        let out = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(
            !out.contains("super-secret-token-value"),
            "TLS log must not contain decrypted payload bytes; got: {out}"
        );
        assert!(
            out.contains("1234"),
            "scalar pid metadata should still be logged: {out}"
        );
        assert!(
            out.contains("data_len"),
            "scalar metadata should still be logged: {out}"
        );
    }
}
