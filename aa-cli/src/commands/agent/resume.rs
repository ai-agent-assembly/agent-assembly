//! `aasm agent resume` — resume a suspended agent.

use std::process::ExitCode;

use clap::Args;
use serde::{Deserialize, Serialize};

use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm agent resume`.
#[derive(Args)]
pub struct ResumeArgs {
    /// Hex-encoded agent UUID to resume.
    pub agent_id: String,
}

/// Response from the resume endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResumeResponse {
    pub agent_id: String,
    pub previous_status: String,
    pub new_status: String,
}

/// Run the `aasm agent resume` command.
pub fn run(args: ResumeArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let path = format!("/api/v1/agents/{}/resume", args.agent_id);

    match rt.block_on(client::post_empty::<ResumeResponse>(ctx, &path)) {
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

fn render(resp: &ResumeResponse, output: OutputFormat) {
    match output {
        OutputFormat::Table => render_table(resp),
        OutputFormat::Json => render_json(resp),
        OutputFormat::Yaml => render_yaml(resp),
    }
}

fn render_table(resp: &ResumeResponse) {
    // resp fields are echoed from the server response; strip terminal escapes.
    println!("Agent {} resumed.", sanitize_terminal(&resp.agent_id));
    println!("  Previous status: {}", sanitize_terminal(&resp.previous_status));
    println!("  New status:      {}", sanitize_terminal(&resp.new_status));
}

fn render_json(resp: &ResumeResponse) {
    match serde_json::to_string_pretty(resp) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing JSON: {e}"),
    }
}

fn render_yaml(resp: &ResumeResponse) {
    match serde_yaml::to_string(resp) {
        Ok(yaml) => print!("{yaml}"),
        Err(e) => eprintln!("error serializing YAML: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_response_deserializes() {
        let json = r#"{
            "agent_id": "aabbccdd00112233",
            "previous_status": "Suspended(Manual)",
            "new_status": "Active"
        }"#;
        let resp: ResumeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.agent_id, "aabbccdd00112233");
        assert_eq!(resp.previous_status, "Suspended(Manual)");
        assert_eq!(resp.new_status, "Active");
    }

    #[test]
    fn resume_response_serializes_to_json() {
        let resp = ResumeResponse {
            agent_id: "abc123".to_string(),
            previous_status: "Suspended(Manual)".to_string(),
            new_status: "Active".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["agent_id"], "abc123");
        assert_eq!(json["new_status"], "Active");
    }
}
