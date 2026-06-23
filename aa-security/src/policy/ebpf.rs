//! Deterministic lowering of the canonical [`PolicyDocument`] into the flat
//! rule set the eBPF maps consume (AAASM-3608).
//!
//! The kernel layer is *generated from* the same policy the gateway enforces,
//! never hand-maintained — this is the mechanism behind "one policy source →
//! gateway + eBPF rules with no detectable enforcement gap". The privileged
//! loader daemon (AAASM-3603/3604) pushes the produced [`EbpfRuleSet`] into the
//! `PATH_BLOCKLIST` / `PATH_ALLOWLIST` BPF maps over the control channel.
//!
//! # What is enforceable in-kernel vs L7-only
//!
//! The eBPF probes match on **filesystem paths** and (where wired) **egress
//! hosts**. The lowering therefore covers exactly:
//!
//! - **Filesystem path rules** derived from `tools.*.requires_approval_if`
//!   predicates of the form `path starts_with "<prefix>"` (each becomes a
//!   [`PathVerdict::Deny`] [`PathRule`]) and from a capability `file_write`
//!   deny (which seeds the well-known sensitive-path deny defaults).
//! - **Egress allowlist** copied verbatim from `network.allowlist`.
//!
//! Everything else is explicitly **L7-only** and documented in
//! [`L7_ONLY_DIMENSIONS`] so the cross-layer consistency test (AAASM-3609) can
//! assert the gap is intentional and reviewed, never silent:
//!
//! - Budget / spend limits (`budget`)
//! - Schedule / active-hours (`schedule`)
//! - Credential / PII scanning + redaction (`data`)
//! - Per-tool rate limits (`tools.*.limit_per_hour`)
//! - Non-path CEL predicates (`url contains`, `args.*`, `tool_result.*`)
//! - Capability categories with no path/host projection (`agent_spawn`,
//!   `model:*`, `mcp_tool:*`, `network_inbound`, `terminal_exec`)

use super::capability::Capability;
use super::document::PolicyDocument;

/// Policy dimensions that are structurally **not** enforceable by the eBPF
/// path/egress probes and are therefore enforced only at L7 by the gateway.
///
/// The cross-layer consistency test asserts every divergence between the two
/// layers falls under one of these documented carve-outs.
pub const L7_ONLY_DIMENSIONS: &[&str] = &[
    "budget",
    "schedule",
    "data.credential_scan",
    "tools.limit_per_hour",
    "tools.non_path_predicates",
    "capability.agent_spawn",
    "capability.model",
    "capability.mcp_tool",
    "capability.network_inbound",
    "capability.terminal_exec",
];

/// Whether matching a path rule allows or denies the operation in-kernel.
///
/// Mirrors `aa_ebpf::maps::PathVerdict`; kept here so the leaf crate has no
/// dependency on `aa-ebpf` (the dependency points the other way — the loader
/// daemon consumes this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PathVerdict {
    /// The path is allowed — no policy violation.
    Allow,
    /// The path is blocked — triggers a policy violation event.
    Deny,
}

/// A single lowered filesystem path rule destined for a BPF path map.
///
/// `pattern` is a path prefix (e.g. `/etc`); the kernel probe flags any access
/// whose path starts with it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathRule {
    /// Path prefix to match.
    pub pattern: String,
    /// Verdict applied on match.
    pub verdict: PathVerdict,
}

/// The flat rule set produced by [`lower_to_ebpf`], consumed by the loader
/// daemon's map-update path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EbpfRuleSet {
    /// Filesystem path rules for `PATH_BLOCKLIST` / `PATH_ALLOWLIST`.
    pub path_rules: Vec<PathRule>,
    /// Egress host allowlist (empty means "no egress restriction").
    pub egress_allowlist: Vec<String>,
}
