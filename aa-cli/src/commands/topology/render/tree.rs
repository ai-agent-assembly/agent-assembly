//! Tree-style rendering for AgentTree and AgentLineage.

use super::AgentTree;

/// Render an agent tree recursively using box-drawing characters.
pub fn render_agent_tree(node: &AgentTree, prefix: &str, is_last: bool) {
    let connector = if is_last { "└── " } else { "├── " };
    let status_tag = format!("[{}]", node.status);
    let team_tag = node
        .team_id
        .as_deref()
        .map(|t| format!(" <{t}>"))
        .unwrap_or_default();
    println!("{prefix}{connector}{} {status_tag}{team_tag}", node.name);

    let child_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });
    let count = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        render_agent_tree(child, &child_prefix, i + 1 == count);
    }
}
