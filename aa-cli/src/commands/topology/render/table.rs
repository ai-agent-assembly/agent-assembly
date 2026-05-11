//! Table rendering for topology responses.

use comfy_table::{Cell, Color, Table};

use super::{AgentLineage, TeamTopology, TopologyOverview, TopologyStats};

/// Map an agent status string to a terminal colour.
pub fn status_color(status: &str) -> Color {
    match status.to_lowercase().as_str() {
        "active" => Color::Green,
        s if s.starts_with("suspended") => Color::Yellow,
        "deregistered" => Color::Red,
        _ => Color::Reset,
    }
}

/// Render a topology overview as a comfy-table.
pub fn render_overview_table(overview: &TopologyOverview) {
    println!(
        "Teams: {}  |  Agents: {}  |  Roots: {}\n",
        overview.team_count, overview.total_agent_count, overview.root_agent_count,
    );

    if !overview.teams.is_empty() {
        let mut table = Table::new();
        table.set_header(vec!["TEAM_ID", "AGENTS", "ROOT_AGENTS"]);
        for t in &overview.teams {
            table.add_row(vec![
                Cell::new(&t.team_id),
                Cell::new(t.agent_count),
                Cell::new(t.root_agent_count),
            ]);
        }
        println!("{table}");
    }

    if !overview.standalone_root_agents.is_empty() {
        println!("\nStandalone root agents:");
        let mut table = Table::new();
        table.set_header(vec!["AGENT_ID", "NAME", "STATUS"]);
        for a in &overview.standalone_root_agents {
            table.add_row(vec![
                Cell::new(&a.id),
                Cell::new(&a.name),
                Cell::new(&a.status).fg(status_color(&a.status)),
            ]);
        }
        println!("{table}");
    }
}
