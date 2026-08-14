//! `aasm alerts resolve` — resolve an alert.

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Args;

use super::models::{AlertResponse, ResolveAlertRequest};
use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm alerts resolve`.
#[derive(Args)]
pub struct ResolveArgs {
    /// Alert ID to resolve.
    pub alert_id: String,

    /// Optional resolution note.
    #[arg(long)]
    pub reason: Option<String>,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub force: bool,
}

/// Prompt the user for confirmation. Returns true if confirmed.
fn confirm_resolve(alert_id: &str) -> bool {
    eprint!("Are you sure you want to resolve alert {alert_id}? [y/N] ");
    io::stderr().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Run the `aasm alerts resolve` command.
pub fn run(args: ResolveArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    if !args.force && !confirm_resolve(&args.alert_id) {
        eprintln!("Aborted.");
        return ExitCode::FAILURE;
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let body = ResolveAlertRequest { reason: args.reason };
    let path = format!("/api/v1/alerts/{}/resolve", args.alert_id);
    match rt.block_on(client::post_opt_json::<ResolveAlertRequest, AlertResponse>(
        ctx,
        &path,
        Some(&body),
    )) {
        Ok(alert) => {
            match output {
                OutputFormat::Table => println!("Alert {} resolved.", sanitize_terminal(&alert.id)),
                OutputFormat::Json => match serde_json::to_string_pretty(&alert) {
                    Ok(json) => println!("{json}"),
                    Err(e) => eprintln!("error serializing JSON: {e}"),
                },
                OutputFormat::Yaml => match serde_yaml::to_string(&alert) {
                    Ok(yaml) => print!("{yaml}"),
                    Err(e) => eprintln!("error serializing YAML: {e}"),
                },
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
