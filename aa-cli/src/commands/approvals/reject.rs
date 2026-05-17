//! `aasm approvals reject` — reject a pending action.

use std::process::ExitCode;

use clap::Args;

use crate::config::ResolvedContext;

use super::client;

/// Arguments for the `aasm approvals reject` subcommand.
#[derive(Debug, Args)]
pub struct RejectArgs {
    /// Approval request ID to reject.
    pub id: String,

    /// Reason for rejection (required in non-interactive mode).
    #[arg(long)]
    pub reason: Option<String>,
}

/// Validate that a rejection reason was provided.
///
/// Returns the reason string if present, or an error message explaining
/// that `--reason` is required for non-interactive rejection.
pub fn validate_reject_reason(reason: &Option<String>) -> Result<&str, &'static str> {
    match reason.as_deref() {
        Some(r) if !r.trim().is_empty() => Ok(r),
        _ => Err("error: --reason is required for aasm approvals reject"),
    }
}

/// Execute the `aasm approvals reject` subcommand.
pub fn run_reject(args: RejectArgs, ctx: &ResolvedContext) -> ExitCode {
    // AAASM-1477: if --reason is omitted and stdin is a pipe, read it.
    // Convert the resolved reason back to Option<String> for the
    // existing validator, which still rejects empty / whitespace input
    // (now meaning neither flag nor stdin supplied non-empty content).
    let resolved = super::reason_io::resolve_reason_from_process_stdin(args.reason);
    let reason = match validate_reject_reason(&resolved) {
        Ok(r) => r.to_string(),
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
    };

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let result = rt.block_on(client::reject_action(ctx, &args.id, &reason));

    match result {
        Ok(resp) => {
            println!("Rejected: {} (status: {})", resp.id, resp.status);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_reject_reason_none_returns_error() {
        let result = validate_reject_reason(&None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_reject_reason_empty_returns_error() {
        let empty = Some("   ".to_string());
        let result = validate_reject_reason(&empty);
        assert!(result.is_err());
    }

    #[test]
    fn validate_reject_reason_valid_returns_ok() {
        let reason = Some("policy violation".to_string());
        let result = validate_reject_reason(&reason);
        assert_eq!(result.unwrap(), "policy violation");
    }
}
