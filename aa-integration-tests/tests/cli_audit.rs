//! CLI integration tests for `aasm audit` (AAASM-1461 / F121 ST-5).
//!
//! Exercises every `aasm audit <leaf>` subcommand against a live in-process
//! gateway booted via `CliFixture`. Two leaves (`list`, `export`) hit the
//! gateway via `GET /api/v1/logs`; the third (`verify-chain`) is
//! filesystem-only and reads a JSONL file via [`aa_gateway::audit::AuditWriter::verify_chain`].
//!
//! ## Leaf surface (from `aa-cli/src/commands/audit/`)
//!
//! | Leaf         | Args                                                   | Backend                                              | Notes |
//! | ------------ | ------------------------------------------------------ | ---------------------------------------------------- | ----- |
//! | list         | `--agent --action --result --since --until --limit`     | `GET /api/v1/logs`                                   | Honors global `--output {table,json,yaml}` |
//! | export       | `--format {csv,json} --output <file> --compliance ...` | `GET /api/v1/logs`                                   | Writes to stdout when `--output` is absent |
//! | verify-chain | positional `<path>`                                    | local JSONL file via `AuditWriter::verify_chain`     | Stdout `OK — N entries verified` on success; stderr `FAIL — hash chain broken at entry N` on tampered |
//!
//! Audit events surface through `/api/v1/logs` by reading JSONL files from
//! the harness's `audit_dir`. The `seed_audit_events` helper (added in this
//! file's companion `common/cli.rs` commit) writes `aa_core::AuditEntry`
//! lines into that dir so the real `AuditReader` picks them up.

mod common;

// =============================================================================
// aasm audit list
// =============================================================================

// =============================================================================
// aasm audit export
// =============================================================================

// =============================================================================
// aasm audit verify-chain
// =============================================================================
