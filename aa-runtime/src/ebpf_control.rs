//! AAASM-4011: drive the privileged `aa-ebpf-loaderd` daemon from the
//! unprivileged runtime.
//!
//! # Why this exists
//!
//! AAASM-3603/3605 moved all BPF privilege into the standalone
//! `aa-ebpf-loaderd` daemon: the runtime drops `CAP_BPF`/`CAP_PERFMON`
//! ([`crate::privilege`]) and holds none. Before this module, the runtime's
//! eBPF layer still tried to load probes **in-process** via `aya::Ebpf::load`
//! — which requires the very capability the runtime just dropped — so on the
//! production (unprivileged) runtime every sub-layer could only ever
//! EPERM-degrade, masking "Layer 3 never came up" as a soft degradation. The
//! privileged daemon, meanwhile, sat idle: nothing ever drove its control
//! channel, and the only enforcing (SIGKILL) probe — the syscall guard — was
//! never loaded at all.
//!
//! This module closes that gap: when the eBPF layer is active the runtime
//! connects to the loaderd control socket as an unprivileged client
//! (`aa_ebpf::control::client::LoaderControlClient`) and asks the daemon to
//! load the probe sets, push the sensitive-path map, and (opt-in) load the
//! syscall guard with its policy-derived allowlist. No BPF handle or fd ever
//! crosses the boundary — only typed control messages.
//!
//! # Observe-only vs enforce
//!
//! The TLS / file-I/O / exec probe sets are **observe-only**. The syscall guard
//! is the sole enforcing probe: for any PID in its `PID_FILTER` it default-denies
//! (SIGKILLs) every syscall not present in `SYSCALL_ALLOWLIST`. That makes its
//! lifecycle safety-critical — see [`plan_control_ops`].

// The planner + control helpers are consumed by the Linux `drive_ebpf_layer`
// (and the unit tests). On non-Linux only the degrade-everything stub compiles,
// so these are legitimately unused there — suppress dead_code just for that host.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use aa_security::policy::{lower_to_ebpf, EbpfRuleSet, PathVerdict, PolicyDocument};

/// Default control socket the daemon binds (mirrors
/// `aa_ebpf::control::DEFAULT_SOCKET_PATH` without taking a Linux-only dep on
/// non-Linux hosts).
const DEFAULT_LOADERD_SOCKET: &str = "/run/aa-ebpf-loaderd.sock";

/// Environment variable overriding the loaderd control socket path.
const LOADERD_SOCKET_ENV: &str = "AA_EBPF_LOADERD_SOCK";

/// Environment variable pointing at the YAML policy document lowered into eBPF
/// map rules. Unset/empty → an empty rule set.
const POLICY_PATH_ENV: &str = "AA_EBPF_POLICY_PATH";

/// Environment variable naming the PID confined by the SIGKILL-capable syscall
/// guard. Unset / empty / `0` / unparseable → guard stays off (opt-in).
const CONFINE_PID_ENV: &str = "AA_EBPF_CONFINE_PID";

/// Environment variable opting into the legacy in-process `aya::Ebpf::load`
/// path instead of driving the loader daemon. Off unless truthy.
const INPROCESS_LOAD_ENV: &str = "AA_EBPF_INPROCESS_LOAD";

/// The probe sets the runtime asks the daemon to bring up. Kept independent of
/// `aa-ebpf` (a Linux-only dependency) so the planner is unit-testable on any
/// host; mapped onto `aa_ebpf::control::ProbeSet` inside the Linux driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeKind {
    /// TLS uprobes (`aa-tls-probes`), observe-only.
    Tls,
    /// File-I/O kprobes (`aa-file-io`), observe-only.
    FileIo,
    /// Exec tracepoints (`aa-exec-probes`), observe-only.
    Exec,
    /// Syscall-allowlist enforcement probe (`aa-syscall-guard`) — SIGKILLs.
    SyscallGuard,
}

impl ProbeKind {
    /// The pipeline sub-layer name used in degradation events.
    fn sub_layer(self) -> &'static str {
        match self {
            ProbeKind::Tls => "ebpf/tls",
            ProbeKind::FileIo => "ebpf/file_io",
            ProbeKind::Exec => "ebpf/exec",
            ProbeKind::SyscallGuard => "ebpf/syscall_guard",
        }
    }
}

/// One ordered control operation. Independent of `aa-ebpf` so it can be planned
/// and asserted without the Linux-only client types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlannedOp {
    /// Load + attach a probe set.
    Load(ProbeKind),
    /// Replace the file-I/O path deny/allow map: `(pattern, deny)` pairs.
    UpdatePathMap(Vec<(String, bool)>),
    /// Replace the syscall-guard allowlist with these syscall numbers.
    UpdateSyscallAllowlist(Vec<u32>),
}

/// Build the ordered control plan the runtime sends to the daemon.
///
/// The observe-only sets (TLS, file-I/O, exec) are always loaded, and the
/// file-I/O path map is pushed from the lowered policy path rules (an empty map
/// simply clears any stale rules).
///
/// # Syscall-guard safety
///
/// The syscall guard is **default-deny**: the instant a PID is in its
/// `PID_FILTER`, any syscall absent from `SYSCALL_ALLOWLIST` SIGKILLs the
/// process (see `aa-ebpf-probes/src/syscall_guard.rs`). Loading it with an
/// empty allowlist therefore kills the confined process on its next syscall.
/// To make that impossible by construction, the guard is planned **only** when:
///
/// 1. a confine-target PID is explicitly configured (`AA_EBPF_CONFINE_PID`), and
/// 2. the policy lowers to a **non-empty** syscall allowlist.
///
/// When planned, `UpdateSyscallAllowlist` is ordered immediately after the
/// guard load. NOTE (load→allowlist window): the current control protocol
/// couples load+attach+PID-filter insertion in a single `LoadProbeSet`, so
/// there is a brief window between the guard load and the allowlist update
/// during which the confined PID runs with an empty allowlist. The confined
/// process must be quiescent (not yet issuing syscalls) across that window; a
/// fully race-free fix requires a protocol change (load-without-filter → set
/// allowlist → add PID) and is called out in the Linux e2e note.
pub(crate) fn plan_control_ops(ruleset: &EbpfRuleSet, confine_pid: Option<u32>) -> Vec<PlannedOp> {
    let mut plan = vec![
        PlannedOp::Load(ProbeKind::Tls),
        PlannedOp::Load(ProbeKind::FileIo),
        PlannedOp::Load(ProbeKind::Exec),
    ];

    plan.push(PlannedOp::UpdatePathMap(
        ruleset
            .path_rules
            .iter()
            .map(|r| (r.pattern.clone(), r.verdict == PathVerdict::Deny))
            .collect(),
    ));

    if confine_pid.is_some() && !ruleset.syscall_allowlist.is_empty() {
        plan.push(PlannedOp::Load(ProbeKind::SyscallGuard));
        plan.push(PlannedOp::UpdateSyscallAllowlist(ruleset.syscall_allowlist.clone()));
    }

    plan
}

/// Resolve the loaderd control socket path from `AA_EBPF_LOADERD_SOCK` or the
/// default. Matches [`crate::layer`]'s availability probe so the runtime drives
/// exactly the socket it detected.
pub(crate) fn resolve_loaderd_socket() -> std::path::PathBuf {
    std::env::var_os(LOADERD_SOCKET_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_LOADERD_SOCKET))
}

/// The confine-target PID from `AA_EBPF_CONFINE_PID`, or `None` when the
/// syscall guard is not opted in. A `0` (or unparseable) value is treated as
/// unset so the SIGKILL-capable guard stays off by default.
pub(crate) fn confine_pid() -> Option<u32> {
    std::env::var(CONFINE_PID_ENV)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&n| n > 0)
}

/// Whether the legacy in-process `aya::Ebpf::load` path is opted in via
/// `AA_EBPF_INPROCESS_LOAD` (`true`/`1`/`yes`/`on`). Off by default.
pub(crate) fn use_inprocess_load() -> bool {
    std::env::var(INPROCESS_LOAD_ENV)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"))
        .unwrap_or(false)
}

/// Load + lower the eBPF policy document referenced by `AA_EBPF_POLICY_PATH`,
/// or an empty rule set when unset/unreadable.
///
/// An empty rule set is safe: an empty path map imposes no in-kernel blocklist
/// and an empty syscall allowlist keeps the guard unplanned (see
/// [`plan_control_ops`]). Lowering reuses the single canonical
/// [`lower_to_ebpf`] pipeline the gateway uses, so the kernel layer is generated
/// from the same policy source — never hand-maintained.
pub(crate) fn load_ebpf_ruleset() -> EbpfRuleSet {
    let Some(path) = std::env::var_os(POLICY_PATH_ENV)
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
    else {
        return EbpfRuleSet::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(yaml) => match PolicyDocument::from_yaml(&yaml) {
            Ok(doc) => lower_to_ebpf(&doc),
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "eBPF policy parse failed — using empty rule set");
                EbpfRuleSet::default()
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "eBPF policy unreadable — using empty rule set");
            EbpfRuleSet::default()
        }
    }
}

/// Emit a degradation event for `sub_layer` and record it in `degraded_layers`.
fn degrade(
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    degraded_layers: &mut Vec<String>,
    sub_layer: &str,
    reason: String,
) {
    tracing::warn!(sub_layer, %reason, "degrading eBPF sub-layer");
    crate::runtime::emit_ebpf_degradation(broadcast_tx, sub_layer, reason);
    degraded_layers.push(sub_layer.to_string());
}

/// Bound (ms) on every individual loaderd control round-trip.
///
/// The former in-process `aya::Ebpf::load` path failed *fast* (local EPERM);
/// driving an external daemon substitutes network-style I/O into the boot
/// critical path, and the control client's `read_frame` has no timeout of its
/// own — a daemon that accepts the connection but never replies would otherwise
/// wedge runtime boot forever. Each request is therefore wrapped in this
/// deadline; on elapse the sub-layer degrades exactly as a connect failure does.
/// Overridable via `AA_EBPF_LOADERD_TIMEOUT_MS`.
#[cfg(target_os = "linux")]
fn loaderd_deadline() -> std::time::Duration {
    let ms = std::env::var("AA_EBPF_LOADERD_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5_000);
    std::time::Duration::from_millis(ms)
}

/// Await a loaderd control future under [`loaderd_deadline`]; a timeout maps to
/// an error string so the caller degrades the sub-layer rather than hanging.
#[cfg(target_os = "linux")]
async fn await_loaderd<F, T, E>(fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    match tokio::time::timeout(loaderd_deadline(), fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_elapsed) => Err("timed out waiting for loaderd".to_string()),
    }
}

/// Degrade all probe layers when the daemon is unreachable (Linux).
#[cfg(target_os = "linux")]
fn degrade_all_probes(
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    degraded_layers: &mut Vec<String>,
    reason: String,
    has_confine_pid: bool,
) {
    for kind in [ProbeKind::Tls, ProbeKind::FileIo, ProbeKind::Exec] {
        degrade(broadcast_tx, degraded_layers, kind.sub_layer(), reason.clone());
    }
    if has_confine_pid {
        degrade(
            broadcast_tx,
            degraded_layers,
            ProbeKind::SyscallGuard.sub_layer(),
            reason,
        );
    }
}

/// Resolve probe set and PID for a load operation (Linux).
///
/// Returns `Some((set, pid))` for valid combinations, or `None` if the syscall
/// guard was planned without a confine PID (a bug — logs an error).
#[cfg(target_os = "linux")]
fn resolve_probe_set_and_pid(
    kind: ProbeKind,
    observe_pid: u32,
    confine_pid: Option<u32>,
) -> Option<(aa_ebpf::control::protocol::ProbeSet, u32)> {
    use aa_ebpf::control::protocol::ProbeSet;

    match kind {
        ProbeKind::Tls => Some((ProbeSet::Tls, observe_pid)),
        ProbeKind::FileIo => Some((ProbeSet::FileIo, observe_pid)),
        ProbeKind::Exec => Some((ProbeSet::Exec, observe_pid)),
        // The planner only emits SyscallGuard when confine_pid is Some. Never
        // fall back to the runtime's own PID: the guard is a default-deny
        // SIGKILL probe, so scoping it to `observe_pid` would make the runtime
        // kill itself. If the invariant is ever broken, skip the load loudly.
        ProbeKind::SyscallGuard => match confine_pid {
            Some(pid) => Some((ProbeSet::SyscallGuard, pid)),
            None => {
                tracing::error!(
                    "BUG: SyscallGuard planned without a confine PID; refusing to scope \
                     the SIGKILL guard to the runtime's own PID"
                );
                None
            }
        },
    }
}

/// Execute a single planned operation against the loaderd client (Linux).
#[cfg(target_os = "linux")]
async fn execute_planned_op(
    client: &mut aa_ebpf::control::client::LoaderControlClient,
    op: PlannedOp,
    observe_pid: u32,
    confine_pid: Option<u32>,
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    degraded_layers: &mut Vec<String>,
) {
    use aa_ebpf::control::protocol::PathRuleWire;

    match op {
        PlannedOp::Load(kind) => {
            let Some((set, pid)) = resolve_probe_set_and_pid(kind, observe_pid, confine_pid) else {
                return;
            };
            if let Err(e) = await_loaderd(client.load_probe_set(set, pid)).await {
                degrade(
                    broadcast_tx,
                    degraded_layers,
                    kind.sub_layer(),
                    format!("loaderd load failed: {e}"),
                );
            }
        }
        PlannedOp::UpdatePathMap(rules) => {
            let wire: Vec<PathRuleWire> = rules
                .into_iter()
                .map(|(pattern, deny)| PathRuleWire { pattern, deny })
                .collect();
            if let Err(e) = await_loaderd(client.update_path_map(wire)).await {
                degrade(
                    broadcast_tx,
                    degraded_layers,
                    ProbeKind::FileIo.sub_layer(),
                    format!("loaderd path map update failed: {e}"),
                );
            }
        }
        PlannedOp::UpdateSyscallAllowlist(syscalls) => {
            if let Err(e) = await_loaderd(client.update_syscall_allowlist(syscalls)).await {
                degrade(
                    broadcast_tx,
                    degraded_layers,
                    ProbeKind::SyscallGuard.sub_layer(),
                    format!("loaderd syscall allowlist update failed: {e}"),
                );
            }
        }
    }
}

/// Drive the privileged loaderd daemon to bring up the eBPF layer (Linux).
///
/// Connects to the control socket as an unprivileged client and executes the
/// control plan from [`plan_control_ops`]. Each failed (or timed-out) operation
/// degrades only its own sub-layer; a failure to reach the daemon degrades all
/// of them. This replaces the former in-process `aya::Ebpf::load` path, which
/// could only EPERM-degrade on the (deliberately unprivileged) runtime.
#[cfg(target_os = "linux")]
pub(crate) async fn drive_ebpf_layer(
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    degraded_layers: &mut Vec<String>,
) {
    use aa_ebpf::control::client::LoaderControlClient;

    let socket = resolve_loaderd_socket();
    let ruleset = load_ebpf_ruleset();
    let confine_pid = confine_pid();
    // Observe-only probe sets are scoped to the runtime process (and, for exec,
    // its descendants) exactly as the former in-process path was.
    let observe_pid = std::process::id();
    let plan = plan_control_ops(&ruleset, confine_pid);

    let mut client = match await_loaderd(LoaderControlClient::connect(&socket)).await {
        Ok(c) => c,
        Err(e) => {
            let reason = format!("loaderd control socket unreachable at {}: {e}", socket.display());
            degrade_all_probes(broadcast_tx, degraded_layers, reason, confine_pid.is_some());
            return;
        }
    };

    for op in plan {
        execute_planned_op(&mut client, op, observe_pid, confine_pid, broadcast_tx, degraded_layers).await;
    }

    tracing::info!(socket = %socket.display(), confine_pid = ?confine_pid, "eBPF layer delegated to loaderd");
}

/// Non-Linux stub: eBPF is Linux-only, so every sub-layer degrades.
#[cfg(not(target_os = "linux"))]
pub(crate) async fn drive_ebpf_layer(
    broadcast_tx: &tokio::sync::broadcast::Sender<crate::pipeline::PipelineEvent>,
    degraded_layers: &mut Vec<String>,
) {
    for sub_layer in ["ebpf/tls", "ebpf/file_io", "ebpf/exec"] {
        degrade(
            broadcast_tx,
            degraded_layers,
            sub_layer,
            "eBPF not supported on this platform".to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_security::policy::{EbpfRuleSet, PathRule, PathVerdict};

    fn ruleset(path_rules: Vec<PathRule>, syscalls: Vec<u32>) -> EbpfRuleSet {
        EbpfRuleSet {
            path_rules,
            egress_allowlist: Vec::new(),
            syscall_allowlist: syscalls,
        }
    }

    #[test]
    fn plan_always_loads_the_three_observe_only_sets() {
        let plan = plan_control_ops(&ruleset(vec![], vec![]), None);
        assert!(plan.contains(&PlannedOp::Load(ProbeKind::Tls)));
        assert!(plan.contains(&PlannedOp::Load(ProbeKind::FileIo)));
        assert!(plan.contains(&PlannedOp::Load(ProbeKind::Exec)));
    }

    #[test]
    fn plan_always_pushes_a_path_map_op() {
        let plan = plan_control_ops(&ruleset(vec![], vec![]), None);
        assert!(plan.iter().any(|op| matches!(op, PlannedOp::UpdatePathMap(_))));
    }

    #[test]
    fn path_rules_lower_to_deny_flags() {
        let rules = vec![
            PathRule {
                pattern: "/etc/shadow".into(),
                verdict: PathVerdict::Deny,
            },
            PathRule {
                pattern: "/tmp/ok".into(),
                verdict: PathVerdict::Allow,
            },
        ];
        let plan = plan_control_ops(&ruleset(rules, vec![]), None);
        let map = plan
            .iter()
            .find_map(|op| match op {
                PlannedOp::UpdatePathMap(m) => Some(m.clone()),
                _ => None,
            })
            .expect("path map op present");
        assert_eq!(
            map,
            vec![("/etc/shadow".to_string(), true), ("/tmp/ok".to_string(), false)]
        );
    }

    #[test]
    fn syscall_guard_never_planned_without_a_confine_pid() {
        // Non-empty allowlist but no confine target → guard must not load,
        // otherwise it would confine an unintended (or no) PID.
        let plan = plan_control_ops(&ruleset(vec![], vec![0, 1, 60]), None);
        assert!(!plan.contains(&PlannedOp::Load(ProbeKind::SyscallGuard)));
        assert!(!plan.iter().any(|op| matches!(op, PlannedOp::UpdateSyscallAllowlist(_))));
    }

    #[test]
    fn syscall_guard_never_planned_with_empty_allowlist() {
        // A confine PID but an empty allowlist would default-deny every syscall
        // and SIGKILL the confined process — must never be planned.
        let plan = plan_control_ops(&ruleset(vec![], vec![]), Some(4321));
        assert!(!plan.contains(&PlannedOp::Load(ProbeKind::SyscallGuard)));
    }

    #[test]
    fn syscall_guard_planned_only_with_confine_pid_and_allowlist() {
        let plan = plan_control_ops(&ruleset(vec![], vec![0, 1, 60]), Some(4321));
        // Load must precede the allowlist update.
        let load_idx = plan
            .iter()
            .position(|op| *op == PlannedOp::Load(ProbeKind::SyscallGuard))
            .expect("guard load present");
        let update_idx = plan
            .iter()
            .position(|op| matches!(op, PlannedOp::UpdateSyscallAllowlist(_)))
            .expect("allowlist update present");
        assert!(load_idx < update_idx, "guard must load before its allowlist is set");
        assert_eq!(plan[update_idx], PlannedOp::UpdateSyscallAllowlist(vec![0, 1, 60]));
    }

    #[test]
    fn resolve_socket_honours_env_then_falls_back_to_default() {
        // Both cases live in one test so the shared env var cannot race a
        // sibling test running in parallel.
        // SAFETY: single test owns this var for its duration.
        unsafe {
            std::env::set_var(LOADERD_SOCKET_ENV, "/tmp/aa-loaderd-test.sock");
        }
        assert_eq!(
            resolve_loaderd_socket(),
            std::path::PathBuf::from("/tmp/aa-loaderd-test.sock")
        );
        unsafe {
            std::env::remove_var(LOADERD_SOCKET_ENV);
        }
        assert_eq!(
            resolve_loaderd_socket(),
            std::path::PathBuf::from(DEFAULT_LOADERD_SOCKET)
        );
    }
}
