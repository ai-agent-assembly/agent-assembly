//! DFS-based cycle detection for the agent mesh graph (AAASM-940 AC 7a).
//!
//! Used by `GET /agents/{id}/graph` to detect cycles during subgraph traversal
//! before returning the response. Cycle detection is done on-read per spec.

use std::collections::{HashMap, HashSet};

use aa_core::identity::AgentId;

/// Detect whether the directed graph `adj` contains a cycle.
///
/// Returns `Some(path)` where `path` is the sequence of agent IDs forming the
/// cycle (first node repeated at the end), or `None` if the graph is a DAG.
///
/// Complexity: O(V + E).
pub fn detect_cycle(adj: &HashMap<AgentId, Vec<AgentId>>) -> Option<Vec<AgentId>> {
    let mut visited: HashSet<AgentId> = HashSet::new();
    let mut on_stack: HashSet<AgentId> = HashSet::new();
    let mut stack: Vec<AgentId> = Vec::new();

    for &start in adj.keys() {
        if !visited.contains(&start) {
            if let Some(path) = dfs(start, adj, &mut visited, &mut on_stack, &mut stack) {
                return Some(path);
            }
        }
    }
    None
}

fn dfs(
    node: AgentId,
    adj: &HashMap<AgentId, Vec<AgentId>>,
    visited: &mut HashSet<AgentId>,
    on_stack: &mut HashSet<AgentId>,
    stack: &mut Vec<AgentId>,
) -> Option<Vec<AgentId>> {
    visited.insert(node);
    on_stack.insert(node);
    stack.push(node);

    if let Some(neighbors) = adj.get(&node) {
        for &neighbor in neighbors {
            if !visited.contains(&neighbor) {
                if let Some(path) = dfs(neighbor, adj, visited, on_stack, stack) {
                    return Some(path);
                }
            } else if on_stack.contains(&neighbor) {
                // Found a back edge — build the cycle path.
                let cycle_start = stack.iter().position(|&n| n == neighbor).unwrap_or(0);
                let mut path: Vec<AgentId> = stack[cycle_start..].to_vec();
                path.push(neighbor); // repeat to close the cycle
                return Some(path);
            }
        }
    }

    stack.pop();
    on_stack.remove(&node);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> AgentId {
        let mut bytes = [0u8; 16];
        bytes[15] = b;
        AgentId::from_bytes(bytes)
    }

    #[test]
    fn dag_returns_none() {
        // A → B → C  (no cycle)
        let mut adj: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
        adj.insert(id(1), vec![id(2)]);
        adj.insert(id(2), vec![id(3)]);
        adj.insert(id(3), vec![]);
        assert!(detect_cycle(&adj).is_none());
    }

    #[test]
    fn self_loop_detected() {
        // A → A
        let mut adj: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
        adj.insert(id(1), vec![id(1)]);
        let result = detect_cycle(&adj);
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.contains(&id(1)));
    }

    #[test]
    fn indirect_cycle_detected() {
        // A → B → C → A
        let mut adj: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
        adj.insert(id(1), vec![id(2)]);
        adj.insert(id(2), vec![id(3)]);
        adj.insert(id(3), vec![id(1)]);
        let result = detect_cycle(&adj);
        assert!(result.is_some());
        let path = result.unwrap();
        // Cycle path must contain at least two nodes and end by repeating its start.
        assert!(path.len() >= 2);
        assert_eq!(path.first(), path.last());
    }

    #[test]
    fn empty_graph_returns_none() {
        let adj: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
        assert!(detect_cycle(&adj).is_none());
    }

    #[test]
    fn disconnected_graph_with_cycle_detected() {
        // Component 1: A → B (DAG)
        // Component 2: C → D → C (cycle)
        let mut adj: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
        adj.insert(id(1), vec![id(2)]);
        adj.insert(id(2), vec![]);
        adj.insert(id(3), vec![id(4)]);
        adj.insert(id(4), vec![id(3)]);
        assert!(detect_cycle(&adj).is_some());
    }
}
