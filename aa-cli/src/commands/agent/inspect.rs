//! `aasm agent inspect` — show detailed agent information.

use std::process::ExitCode;

use clap::Args;
use comfy_table::{Cell, Color, Table};

use super::AgentResponse;
use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm agent inspect`.
#[derive(Args)]
pub struct InspectArgs {
    /// Hex-encoded agent UUID to inspect.
    pub agent_id: String,
}

/// Render a detailed key-value view of an agent.
fn render_detail(agent: &AgentResponse) {
    let mut table = Table::new();
    table.set_header(vec!["Field", "Value"]);

    // All free-text fields below are server-supplied; strip terminal escapes.
    table.add_row(vec!["ID".to_string(), sanitize_terminal(&agent.id)]);
    table.add_row(vec!["Name".to_string(), sanitize_terminal(&agent.name)]);
    table.add_row(vec!["Framework".to_string(), sanitize_terminal(&agent.framework)]);
    table.add_row(vec!["Version".to_string(), sanitize_terminal(&agent.version)]);
    let status_color = match agent.status.to_lowercase().as_str() {
        "active" => Color::Green,
        s if s.starts_with("suspended") => Color::Yellow,
        "deregistered" => Color::Red,
        _ => Color::Reset,
    };
    table.add_row(vec![
        Cell::new("Status"),
        Cell::new(sanitize_terminal(&agent.status)).fg(status_color),
    ]);

    let tools = if agent.tool_names.is_empty() {
        "(none)".to_string()
    } else {
        agent
            .tool_names
            .iter()
            .map(|t| sanitize_terminal(t))
            .collect::<Vec<_>>()
            .join(", ")
    };
    table.add_row(vec!["Tools".to_string(), tools]);

    let pid_str = agent.pid.map_or("-".to_string(), |p| p.to_string());
    table.add_row(vec!["PID".to_string(), pid_str]);

    let sessions_str = agent.session_count.map_or("-".to_string(), |s| s.to_string());
    table.add_row(vec!["Sessions".to_string(), sessions_str]);

    let last_event_str = sanitize_terminal(agent.last_event.as_deref().unwrap_or("-"));
    table.add_row(vec!["Last Event".to_string(), last_event_str]);

    let violations_str = agent.policy_violations_count.map_or("-".to_string(), |v| v.to_string());
    table.add_row(vec!["Policy Violations".to_string(), violations_str]);

    if !agent.metadata.is_empty() {
        let meta = agent
            .metadata
            .iter()
            .map(|(k, v)| format!("{}={}", sanitize_terminal(k), sanitize_terminal(v)))
            .collect::<Vec<_>>()
            .join(", ");
        table.add_row(vec!["Metadata".to_string(), meta]);
    }

    println!("{table}");

    // Active sessions section
    if !agent.active_sessions.is_empty() {
        println!("\nActive Sessions:");
        let mut sessions_table = Table::new();
        sessions_table.set_header(vec!["SESSION_ID", "STARTED_AT", "STATUS"]);
        for s in &agent.active_sessions {
            sessions_table.add_row(vec![
                Cell::new(sanitize_terminal(&s.session_id)),
                Cell::new(sanitize_terminal(&s.started_at)),
                Cell::new(sanitize_terminal(&s.status)),
            ]);
        }
        println!("{sessions_table}");
    }

    // Recent events section
    if !agent.recent_events.is_empty() {
        println!("\nRecent Events:");
        let mut events_table = Table::new();
        events_table.set_header(vec!["TYPE", "SUMMARY", "TIMESTAMP"]);
        for e in &agent.recent_events {
            events_table.add_row(vec![
                Cell::new(sanitize_terminal(&e.event_type)),
                Cell::new(sanitize_terminal(&e.summary)),
                Cell::new(sanitize_terminal(&e.timestamp)),
            ]);
        }
        println!("{events_table}");
    }

    // Recent traces section
    if !agent.recent_traces.is_empty() {
        println!("\nRecent Traces:");
        let mut traces_table = Table::new();
        traces_table.set_header(vec!["SESSION_ID", "TIMESTAMP"]);
        for t in &agent.recent_traces {
            traces_table.add_row(vec![
                Cell::new(sanitize_terminal(&t.session_id)),
                Cell::new(sanitize_terminal(&t.timestamp)),
            ]);
        }
        println!("{traces_table}");
        println!("Tip: run `aasm trace <session-id>` to visualize a trace");
    }
}

/// Run the `aasm agent inspect` command.
pub fn run(args: InspectArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let path = format!("/api/v1/agents/{}", args.agent_id);
    let agent: AgentResponse = match rt.block_on(client::get_json(ctx, &path)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match output {
        OutputFormat::Table => render_detail(&agent),
        OutputFormat::Json => match serde_json::to_string_pretty(&agent) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("error serializing JSON: {e}"),
        },
        OutputFormat::Yaml => match serde_yaml::to_string(&agent) {
            Ok(yaml) => print!("{yaml}"),
            Err(e) => eprintln!("error serializing YAML: {e}"),
        },
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::commands::agent::RecentTraceResponse;

    fn base_agent() -> AgentResponse {
        AgentResponse {
            id: "aabb".to_string(),
            name: "test-agent".to_string(),
            framework: "custom".to_string(),
            version: "1.0.0".to_string(),
            status: "Active".to_string(),
            tool_names: vec![],
            metadata: BTreeMap::new(),
            pid: None,
            session_count: None,
            last_event: None,
            policy_violations_count: None,
            active_sessions: vec![],
            recent_events: vec![],
            recent_traces: vec![],
        }
    }

    #[test]
    fn render_detail_without_traces_does_not_panic() {
        let agent = base_agent();
        render_detail(&agent);
    }

    #[test]
    fn render_detail_with_traces_does_not_panic() {
        let mut agent = base_agent();
        agent.recent_traces = vec![
            RecentTraceResponse {
                session_id: "sess-abc123".to_string(),
                timestamp: "2026-04-30T10:00:00Z".to_string(),
            },
            RecentTraceResponse {
                session_id: "sess-def456".to_string(),
                timestamp: "2026-04-30T09:30:00Z".to_string(),
            },
        ];
        render_detail(&agent);
    }
}
