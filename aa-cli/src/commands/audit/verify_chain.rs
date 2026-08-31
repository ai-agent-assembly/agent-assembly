//! `aasm audit verify-chain` — verify the hash chain of a JSONL audit log file.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

use aa_gateway::audit::{AuditWriter, VerifyOutcome};

/// Arguments for `aasm audit verify-chain`.
#[derive(Debug, Args)]
pub struct VerifyChainArgs {
    /// Path to the JSONL audit log file to verify.
    pub path: PathBuf,
}

/// Execute `aasm audit verify-chain`.
///
/// AAASM-5626 — three outcomes, three exit codes, so a caller (human or
/// script) never has to parse stderr wording to tell a capacity event
/// (`Incomplete`, exit 3) from tamper evidence (`Tampered`, exit 1). Exit 2
/// is reserved for clap's own usage errors, per this repo's CLI exit-code
/// convention (docs/src/cli/integrations.md).
pub fn run(args: VerifyChainArgs) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    match rt.block_on(AuditWriter::verify_chain(&args.path)) {
        Ok(result) => match result.outcome {
            VerifyOutcome::Verified => {
                println!("OK — {} entries verified", result.entries_checked);
                ExitCode::SUCCESS
            }
            VerifyOutcome::Incomplete => {
                eprintln!(
                    "INCOMPLETE — {} entries verified, chain intact; {} entries never reached \
                     the file at seq {}. Every entry present is unaltered: this is emission loss \
                     (audit backpressure, or a crash before flush), not alteration. Check the \
                     gateway log for \"audit sequence gap\".",
                    result.entries_checked,
                    result.missing_entries,
                    format_ranges(&result.missing_seq_ranges),
                );
                ExitCode::from(3)
            }
            VerifyOutcome::Tampered => {
                eprintln!(
                    "FAIL — hash chain broken at entry {} ({} entries checked)",
                    result.first_invalid.unwrap_or(0),
                    result.entries_checked,
                );
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Render inclusive `(start, end)` ranges as `"a-b, c-c"` for the CLI's
/// human-readable INCOMPLETE message.
fn format_ranges(ranges: &[(u64, u64)]) -> String {
    ranges
        .iter()
        .map(|(start, end)| format!("{start}-{end}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use aa_core::identity::{AgentId, SessionId};
    use aa_core::{AuditEntry, AuditEventType};

    use super::*;

    fn make_chain(n: u64) -> Vec<AuditEntry> {
        let agent = AgentId::from_bytes([1u8; 16]);
        let session = SessionId::from_bytes([2u8; 16]);
        let mut entries = Vec::new();
        let mut prev_hash = [0u8; 32];
        for seq in 0..n {
            let e = AuditEntry::new(
                seq,
                1_000_000 + seq,
                AuditEventType::ToolCallIntercepted,
                agent,
                session,
                format!("{{\"seq\":{seq}}}"),
                prev_hash,
            );
            prev_hash = *e.entry_hash();
            entries.push(e);
        }
        entries
    }

    fn write_chain_to_file(path: &std::path::Path, entries: &[AuditEntry]) {
        let mut f = std::fs::File::create(path).unwrap();
        for e in entries {
            writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
        }
    }

    #[test]
    fn run_returns_success_for_valid_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let entries = make_chain(5);
        write_chain_to_file(&path, &entries);
        let args = VerifyChainArgs { path };
        assert_eq!(run(args), ExitCode::SUCCESS);
    }

    #[test]
    fn run_returns_failure_for_tampered_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let entries = make_chain(3);

        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "{}", serde_json::to_string(&entries[0]).unwrap()).unwrap();
        // Entry with tampered payload — seq and previous_hash from original entry[1],
        // but event_type is different so entry_hash won't match chain linkage.
        let bad = AuditEntry::new(
            1,
            entries[1].timestamp_ns(),
            AuditEventType::PolicyViolation,
            entries[1].agent_id(),
            entries[1].session_id(),
            "TAMPERED".into(),
            *entries[1].previous_hash(),
        );
        writeln!(f, "{}", serde_json::to_string(&bad).unwrap()).unwrap();
        writeln!(f, "{}", serde_json::to_string(&entries[2]).unwrap()).unwrap();
        drop(f);

        let args = VerifyChainArgs { path };
        assert_eq!(run(args), ExitCode::FAILURE);
    }
}
