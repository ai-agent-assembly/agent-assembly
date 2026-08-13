//! Tree-style rendering for AgentTree and AgentLineage.

use super::{AgentLineage, AgentTree};
use crate::sanitize::sanitize_terminal;

/// Render an agent tree recursively using box-drawing characters.
pub fn render_agent_tree(node: &AgentTree, prefix: &str, is_last: bool) {
    let connector = if is_last { "└── " } else { "├── " };
    // status/team_id/name are server-supplied; strip terminal escapes.
    let status_tag = format!("[{}]", sanitize_terminal(&node.status));
    let team_tag = node
        .team_id
        .as_deref()
        .map(|t| format!(" <{}>", sanitize_terminal(t)))
        .unwrap_or_default();
    println!(
        "{prefix}{connector}{} {status_tag}{team_tag}",
        sanitize_terminal(&node.name)
    );

    let child_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });
    let count = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        render_agent_tree(child, &child_prefix, i + 1 == count);
    }
}

/// Render an agent lineage chain using box-drawing characters.
pub fn render_lineage_chain(lineage: &AgentLineage) {
    println!("Lineage for agent: {}\n", sanitize_terminal(&lineage.agent_id));
    let count = lineage.ancestors.len();
    for (i, step) in lineage.ancestors.iter().enumerate() {
        let is_last = i + 1 == count;
        let connector = if is_last { "└── " } else { "├── " };
        let indent = "│   ".repeat(i);
        // name/delegation_reason are server-supplied; strip terminal escapes.
        let reason = step
            .delegation_reason
            .as_deref()
            .map(|r| format!(" ({})", sanitize_terminal(r)))
            .unwrap_or_default();
        println!(
            "{indent}{connector}{} [depth={}]{reason}",
            sanitize_terminal(&step.name),
            step.depth
        );
    }
}
