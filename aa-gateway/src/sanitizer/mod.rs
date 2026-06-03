//! Write-boundary sanitizer (AAASM-2390 / AAASM-2397).
//!
//! Every audit event the Gateway consumer is about to persist passes through
//! [`sanitize`] first. The sanitizer is the *boundary* line of defense:
//! regardless of what an upstream SDK or proxy emits, the four classes of
//! "never store" data — raw LLM prompts/completions, full tool-call payloads,
//! eBPF packet bodies, and per-heartbeat sequence records — are dropped before
//! anything reaches `audit_logs`.
//!
//! The sender is the first line of defense; this module is the last. It never
//! trusts the inbound shape: it operates on the untyped JSON tree as received,
//! strips banned keys recursively, drops unknown top-level fields (counting
//! them so a newly-emitting sender is noticed), and collapses heartbeats into a
//! single "last seen" update instead of a per-beat row.

mod rules;
