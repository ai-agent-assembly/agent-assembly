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

/// Render a team topology as a comfy-table.
pub fn render_team_table(team: &TeamTopology) {
    println!("Team: {}  |  Agents: {}\n", team.team_id, team.agent_count);

    if team.members.is_empty() {
        println!("No agents in this team.");
        return;
    }

    let mut table = Table::new();
    table.set_header(vec!["AGENT_ID", "NAME", "DEPTH", "STATUS"]);
    for a in &team.members {
        table.add_row(vec![
            Cell::new(&a.id),
            Cell::new(&a.name),
            Cell::new(a.depth),
            Cell::new(&a.status).fg(status_color(&a.status)),
        ]);
    }
    println!("{table}");
}

/// Render an agent lineage as a flat comfy-table.
pub fn render_lineage_table(lineage: &AgentLineage) {
    println!(
        "Agent: {}  |  Ancestors: {}\n",
        lineage.agent_id, lineage.ancestor_count,
    );

    if lineage.ancestors.is_empty() {
        println!("No ancestry data.");
        return;
    }

    let mut table = Table::new();
    table.set_header(vec!["DEPTH", "AGENT_ID", "NAME", "TEAM", "DELEGATION_REASON"]);
    for step in &lineage.ancestors {
        table.add_row(vec![
            Cell::new(step.depth),
            Cell::new(&step.id),
            Cell::new(&step.name),
            Cell::new(step.team_id.as_deref().unwrap_or("-")),
            Cell::new(step.delegation_reason.as_deref().unwrap_or("-")),
        ]);
    }
    println!("{table}");
}

/// Render aggregate topology statistics as a comfy-table.
pub fn render_stats_table(stats: &TopologyStats) {
    let mut table = Table::new();
    table.set_header(vec!["METRIC", "VALUE"]);
    table.add_row(vec![Cell::new("Total agents"), Cell::new(stats.total_agents)]);
    table.add_row(vec![Cell::new("Root agents"), Cell::new(stats.root_agent_count)]);
    table.add_row(vec![Cell::new("Max depth"), Cell::new(stats.max_depth)]);
    table.add_row(vec![
        Cell::new("Active"),
        Cell::new(stats.active_count).fg(Color::Green),
    ]);
    table.add_row(vec![
        Cell::new("Suspended"),
        Cell::new(stats.suspended_count).fg(Color::Yellow),
    ]);
    table.add_row(vec![
        Cell::new("Deregistered"),
        Cell::new(stats.deregistered_count).fg(Color::Red),
    ]);
    table.add_row(vec![Cell::new("Teams"), Cell::new(stats.team_count)]);
    table.add_row(vec![Cell::new("Orphans"), Cell::new(stats.orphan_count)]);
    table.add_row(vec![
        Cell::new("Avg children/parent"),
        Cell::new(format!("{:.2}", stats.avg_children_per_parent)),
    ]);
    println!("{table}");

    if !stats.depth_histogram.is_empty() {
        println!("\nDepth histogram:");
        let mut htable = Table::new();
        htable.set_header(vec!["DEPTH", "COUNT"]);
        for (depth, count) in &stats.depth_histogram {
            htable.add_row(vec![Cell::new(depth), Cell::new(count)]);
        }
        println!("{htable}");
    }
}
