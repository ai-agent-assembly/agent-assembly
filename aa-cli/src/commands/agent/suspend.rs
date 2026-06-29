//! `aasm agent suspend` — suspend a running agent.

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Args;
use serde::{Deserialize, Serialize};

use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm agent suspend`.
#[derive(Args)]
pub struct SuspendArgs {
    /// Hex-encoded agent UUID to suspend.
    pub agent_id: String,

    /// Reason for suspending the agent (logged for audit).
    #[arg(long)]
    pub reason: String,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub force: bool,
}

/// Request body sent to the suspend endpoint.
#[derive(Debug, Serialize)]
struct SuspendRequest {
    reason: String,
}

/// Response from the suspend endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuspendResponse {
    pub agent_id: String,
    pub previous_status: String,
    pub new_status: String,
}

/// Prompt the user for confirmation. Returns true if confirmed.
fn confirm_suspend(agent_id: &str) -> bool {
    eprint!("Are you sure you want to suspend agent {agent_id}? [y/N] ");
    io::stderr().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Run the `aasm agent suspend` command.
pub fn run(args: SuspendArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    if !args.force && !confirm_suspend(&args.agent_id) {
        eprintln!("Aborted.");
        return ExitCode::FAILURE;
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let path = format!("/api/v1/agents/{}/suspend", args.agent_id);
    let body = SuspendRequest { reason: args.reason };

    match rt.block_on(client::post_json::<_, SuspendResponse>(ctx, &path, &body)) {
        Ok(resp) => {
            render(&resp, output);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn render(resp: &SuspendResponse, output: OutputFormat) {
    match output {
        OutputFormat::Table => render_table(resp),
        OutputFormat::Json => render_json(resp),
        OutputFormat::Yaml => render_yaml(resp),
    }
}

fn render_table(resp: &SuspendResponse) {
    // resp fields are echoed from the server response; strip terminal escapes.
    println!("Agent {} suspended.", sanitize_terminal(&resp.agent_id));
    println!("  Previous status: {}", sanitize_terminal(&resp.previous_status));
    println!("  New status:      {}", sanitize_terminal(&resp.new_status));
}

fn render_json(resp: &SuspendResponse) {
    match serde_json::to_string_pretty(resp) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing JSON: {e}"),
    }
}

fn render_yaml(resp: &SuspendResponse) {
    match serde_yaml::to_string(resp) {
        Ok(yaml) => print!("{yaml}"),
        Err(e) => eprintln!("error serializing YAML: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_response_deserializes() {
        let json = r#"{
            "agent_id": "aabbccdd00112233",
            "previous_status": "Active",
            "new_status": "Suspended(Manual)"
        }"#;
        let resp: SuspendResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.agent_id, "aabbccdd00112233");
        assert_eq!(resp.previous_status, "Active");
        assert_eq!(resp.new_status, "Suspended(Manual)");
    }

    #[test]
    fn suspend_response_serializes_to_json() {
        let resp = SuspendResponse {
            agent_id: "abc123".to_string(),
            previous_status: "Active".to_string(),
            new_status: "Suspended(Manual)".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["agent_id"], "abc123");
        assert_eq!(json["new_status"], "Suspended(Manual)");
    }
}
