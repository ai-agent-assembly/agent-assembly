//! `aasm receipt verify` — the local verification command/API (AAASM-6166).
//!
//! Two independent checks, always both, both reported: the seal answers
//! "has this receipt been tampered with since it was written", and
//! [`validate::defects`] answers "even taking the content at face value, does
//! it claim more than its own recorded evidence supports". Collapsing the two
//! into one pass/fail would hide exactly the case AC 4 (missing evidence
//! cannot validate as a stronger state) is about: a hand-built receipt with a
//! freshly, correctly recomputed seal and an overclaiming body.
use std::process::ExitCode;

use super::schema::ReceiptEnvelope;
use super::store::{ReceiptStore, StoreError};
use super::validate::{self, ReceiptDefect};

/// Whether the seal still covers the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealVerdict {
    /// The seal matches the body exactly.
    Holds,
    /// The seal does not match the body — tampering, or a corrupt write.
    Mismatch,
    /// The seal could not even be recomputed.
    Uncomputable {
        /// Why.
        detail: String,
    },
}

/// The result of verifying one receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// Whether the seal holds.
    pub seal: SealVerdict,
    /// Every truth-downgrade defect found, independent of the seal.
    pub defects: Vec<ReceiptDefect>,
}

impl Verification {
    /// Whether this receipt may be trusted: the seal holds and there are no
    /// defects. Both conditions, always — see this module's doc comment.
    pub fn is_trustworthy(&self) -> bool {
        matches!(self.seal, SealVerdict::Holds) && self.defects.is_empty()
    }
}

/// Verify `envelope`: recompute its seal and run every truth-downgrade rule.
pub fn verify(envelope: &ReceiptEnvelope) -> Verification {
    let seal = match envelope.seal_holds() {
        Ok(true) => SealVerdict::Holds,
        Ok(false) => SealVerdict::Mismatch,
        Err(e) => SealVerdict::Uncomputable { detail: e.to_string() },
    };
    let defects = validate::defects(envelope);
    Verification { seal, defects }
}

/// Load and verify the receipt at `path`.
pub fn verify_path(path: &std::path::Path) -> Result<Verification, StoreError> {
    let envelope = ReceiptStore::load(path)?;
    Ok(verify(&envelope))
}

/// `aasm receipt` subcommands.
#[derive(clap::Subcommand)]
pub enum ReceiptCommand {
    /// Verify a stored execution receipt.
    Verify(VerifyArgs),
}

/// Arguments for `aasm receipt`.
#[derive(clap::Args)]
pub struct ReceiptArgs {
    /// The subcommand.
    #[command(subcommand)]
    pub command: ReceiptCommand,
}

/// Arguments for `aasm receipt verify`.
#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Path to the receipt file.
    pub path: std::path::PathBuf,
    /// Emit machine-readable JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

/// Dispatch `aasm receipt verify`.
///
/// Exit codes match this crate's existing binary success/failure convention
/// (`aa_cli::error`/every other subcommand's `ExitCode::SUCCESS` /
/// `ExitCode::FAILURE` — there is no established third status in this crate,
/// so this command does not invent one): `SUCCESS` when the receipt is
/// trustworthy, `FAILURE` for a seal mismatch, a defect, or a file that could
/// not be read or parsed. The distinction between those three failure causes
/// is reported on stdout/stderr, not through a third exit status.
pub fn dispatch(args: ReceiptArgs) -> ExitCode {
    match args.command {
        ReceiptCommand::Verify(args) => verify_command(args),
    }
}

fn verify_command(args: VerifyArgs) -> ExitCode {
    let verification = match verify_path(&args.path) {
        Ok(v) => v,
        Err(e) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({ "error": e.to_string(), "trustworthy": false })
                );
            } else {
                eprintln!("could not read or parse receipt at {}: {e}", args.path.display());
            }
            return ExitCode::FAILURE;
        }
    };

    let (seal_token, seal_detail) = match &verification.seal {
        SealVerdict::Holds => ("holds", None),
        SealVerdict::Mismatch => ("mismatch", None),
        SealVerdict::Uncomputable { detail } => ("uncomputable", Some(detail.clone())),
    };

    if args.json {
        let report = serde_json::json!({
            "seal": seal_token,
            "seal_detail": seal_detail,
            "defects": verification.defects.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "trustworthy": verification.is_trustworthy(),
        });
        println!("{report}");
    } else {
        println!(
            "seal: {seal_token}{}",
            seal_detail.map(|d| format!(" ({d})")).unwrap_or_default()
        );
        if verification.defects.is_empty() {
            println!("defects: none");
        } else {
            println!("defects:");
            for defect in &verification.defects {
                println!("  - {defect}");
            }
        }
        println!(
            "trustworthy: {} (the seal covers content integrity since write, never origin — see `aasm receipt \
             verify --help` / docs/src/cli/receipt.md)",
            verification.is_trustworthy()
        );
    }

    if verification.is_trustworthy() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
