//! `aasm agent list` — list all registered agents.

use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use clap::Args;
use comfy_table::{Cell, Color, Table};

use super::{AgentResponse, PaginatedResponse};
use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm agent list`.
#[derive(Args)]
pub struct ListArgs {
    /// Filter by agent status (e.g. Active, Suspended, Deregistered).
    #[arg(long)]
    pub status: Option<String>,

    /// Filter by agent framework (e.g. langgraph, crewai).
    #[arg(long)]
    pub framework: Option<String>,

    /// Auto-refresh the table every 2 seconds.
    #[arg(long)]
    pub watch: bool,
}

/// Fetch agents from the gateway API.
async fn fetch_agents(ctx: &ResolvedContext) -> Result<Vec<AgentResponse>, crate::error::CliError> {
    let resp: PaginatedResponse<AgentResponse> = client::get_json(ctx, "/api/v1/agents").await?;
    Ok(resp.items)
}

/// Apply client-side filters for --status and --framework.
fn apply_filters(agents: Vec<AgentResponse>, args: &ListArgs) -> Vec<AgentResponse> {
    agents
        .into_iter()
        .filter(|a| {
            if let Some(ref s) = args.status {
                if !a.status.eq_ignore_ascii_case(s) {
                    return false;
                }
            }
            if let Some(ref f) = args.framework {
                if !a.framework.eq_ignore_ascii_case(f) {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Map an agent status string to a terminal color.
fn status_color(status: &str) -> Color {
    match status.to_lowercase().as_str() {
        "active" => Color::Green,
        s if s.starts_with("suspended") => Color::Yellow,
        "deregistered" => Color::Red,
        _ => Color::Reset,
    }
}

/// Render agents as a table using comfy-table.
fn render_table(agents: &[AgentResponse]) {
    let mut table = Table::new();
    table.set_header(vec![
        "AGENT_ID",
        "NAME",
        "FRAMEWORK",
        "VERSION",
        "STATUS",
        "PID",
        "SESSIONS",
        "LAST_EVENT",
    ]);

    for agent in agents {
        let pid_str = agent.pid.map_or("-".to_string(), |p| p.to_string());
        let sessions_str = agent.session_count.map_or("-".to_string(), |s| s.to_string());
        let last_event_str = agent.last_event.as_deref().unwrap_or("-");

        // id/name/framework/version/status/last_event are server-supplied;
        // strip terminal escapes (the colour is still chosen from the raw
        // status string, which never reaches the terminal).
        table.add_row(vec![
            Cell::new(sanitize_terminal(&agent.id)),
            Cell::new(sanitize_terminal(&agent.name)),
            Cell::new(sanitize_terminal(&agent.framework)),
            Cell::new(sanitize_terminal(&agent.version)),
            Cell::new(sanitize_terminal(&agent.status)).fg(status_color(&agent.status)),
            Cell::new(&pid_str),
            Cell::new(&sessions_str),
            Cell::new(sanitize_terminal(last_event_str)),
        ]);
    }

    println!("{table}");
}

/// Render agents as JSON.
fn render_json(agents: &[AgentResponse]) {
    match serde_json::to_string_pretty(agents) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing JSON: {e}"),
    }
}

/// Render agents as YAML.
fn render_yaml(agents: &[AgentResponse]) {
    match serde_yaml::to_string(agents) {
        Ok(yaml) => print!("{yaml}"),
        Err(e) => eprintln!("error serializing YAML: {e}"),
    }
}

/// Render agents in the requested output format.
fn render(agents: &[AgentResponse], output: OutputFormat) {
    match output {
        OutputFormat::Table => render_table(agents),
        OutputFormat::Json => render_json(agents),
        OutputFormat::Yaml => render_yaml(agents),
    }
}

/// Run the `aasm agent list` command.
pub fn run(args: ListArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    if args.watch {
        loop {
            let agents = match rt.block_on(fetch_agents(ctx)) {
                Ok(a) => apply_filters(a, &args),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };

            // Clear screen for flicker-free refresh.
            print!("\x1B[2J\x1B[H");
            render(&agents, output);

            thread::sleep(Duration::from_secs(2));
        }
    }

    let agents = match rt.block_on(fetch_agents(ctx)) {
        Ok(a) => apply_filters(a, &args),
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if agents.is_empty() {
        println!("No agents found.");
    } else {
        render(&agents, output);
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_agents() -> Vec<AgentResponse> {
        vec![
            AgentResponse {
                id: "aabbccdd00112233aabbccdd00112233".to_string(),
                name: "test-agent-1".to_string(),
                framework: "langgraph".to_string(),
                version: "0.1.0".to_string(),
                status: "Active".to_string(),
                tool_names: vec!["search".to_string()],
                metadata: Default::default(),
                pid: Some(1234),
                session_count: Some(3),
                last_event: Some("2025-01-15T10:30:00Z".to_string()),
                policy_violations_count: Some(0),
                active_sessions: vec![],
                recent_events: vec![],
                recent_traces: vec![],
            },
            AgentResponse {
                id: "11223344556677881122334455667788".to_string(),
                name: "test-agent-2".to_string(),
                framework: "crewai".to_string(),
                version: "1.0.0".to_string(),
                status: "Suspended".to_string(),
                tool_names: vec![],
                metadata: Default::default(),
                pid: None,
                session_count: None,
                last_event: None,
                policy_violations_count: Some(1),
                active_sessions: vec![],
                recent_events: vec![],
                recent_traces: vec![],
            },
        ]
    }

    #[test]
    fn filter_by_status() {
        let agents = sample_agents();
        let args = ListArgs {
            status: Some("Active".to_string()),
            framework: None,
            watch: false,
        };
        let filtered = apply_filters(agents, &args);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "test-agent-1");
    }

    #[test]
    fn filter_by_framework() {
        let agents = sample_agents();
        let args = ListArgs {
            status: None,
            framework: Some("crewai".to_string()),
            watch: false,
        };
        let filtered = apply_filters(agents, &args);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "test-agent-2");
    }

    #[test]
    fn filter_case_insensitive() {
        let agents = sample_agents();
        let args = ListArgs {
            status: Some("active".to_string()),
            framework: None,
            watch: false,
        };
        let filtered = apply_filters(agents, &args);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn filter_no_match() {
        let agents = sample_agents();
        let args = ListArgs {
            status: Some("Deregistered".to_string()),
            framework: None,
            watch: false,
        };
        let filtered = apply_filters(agents, &args);
        assert!(filtered.is_empty());
    }

    #[test]
    fn no_filter_returns_all() {
        let agents = sample_agents();
        let args = ListArgs {
            status: None,
            framework: None,
            watch: false,
        };
        let filtered = apply_filters(agents, &args);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn json_output_is_valid() {
        let agents = sample_agents();
        let json = serde_json::to_string_pretty(&agents).unwrap();
        let parsed: Vec<AgentResponse> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn status_color_active_is_green() {
        assert_eq!(status_color("Active"), Color::Green);
        assert_eq!(status_color("active"), Color::Green);
    }

    #[test]
    fn status_color_suspended_is_yellow() {
        assert_eq!(status_color("Suspended"), Color::Yellow);
        assert_eq!(status_color("Suspended(PolicyViolation)"), Color::Yellow);
    }

    #[test]
    fn status_color_deregistered_is_red() {
        assert_eq!(status_color("Deregistered"), Color::Red);
        assert_eq!(status_color("deregistered"), Color::Red);
    }

    #[test]
    fn status_color_unknown_is_reset() {
        assert_eq!(status_color("Unknown"), Color::Reset);
    }
}
