//! Cycle detection for agent-topology graphs via Tarjan's SCC algorithm.

use std::collections::{HashMap, HashSet};

use crate::identity::AgentId;

use super::edge::Edge;

/// Detect a cycle in the directed graph described by `edges`.
///
/// Returns the node members of the first strongly-connected component (SCC)
/// that forms a cycle — either an SCC with more than one member, or a
/// single-member SCC whose sole node has a self-loop — or `None` when the
/// graph is acyclic (a DAG).
///
/// Uses Tarjan's SCC algorithm (linear time, O(V + E)).
#[cfg(feature = "std")]
pub fn cycle_detect(edges: &[Edge]) -> Option<Vec<AgentId>> {
    let mut adj: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
    let mut all_nodes: HashSet<AgentId> = HashSet::new();
    let mut self_loops: HashSet<AgentId> = HashSet::new();

    for edge in edges {
        all_nodes.insert(edge.source);
        all_nodes.insert(edge.target);
        if edge.source == edge.target {
            self_loops.insert(edge.source);
        }
        adj.entry(edge.source).or_default().push(edge.target);
    }

    let mut state = TarjanState {
        adj: &adj,
        self_loops: &self_loops,
        index_counter: 0,
        stack: Vec::new(),
        on_stack: HashSet::new(),
        index_map: HashMap::new(),
        lowlink: HashMap::new(),
    };

    for node in all_nodes {
        if !state.index_map.contains_key(&node) {
            if let Some(cycle) = state.strongconnect(node) {
                return Some(cycle);
            }
        }
    }

    None
}

struct TarjanState<'a> {
    adj: &'a HashMap<AgentId, Vec<AgentId>>,
    self_loops: &'a HashSet<AgentId>,
    index_counter: u32,
    stack: Vec<AgentId>,
    on_stack: HashSet<AgentId>,
    index_map: HashMap<AgentId, u32>,
    lowlink: HashMap<AgentId, u32>,
}

impl TarjanState<'_> {
    fn strongconnect(&mut self, v: AgentId) -> Option<Vec<AgentId>> {
        self.index_map.insert(v, self.index_counter);
        self.lowlink.insert(v, self.index_counter);
        self.index_counter += 1;
        self.stack.push(v);
        self.on_stack.insert(v);

        // Clone to avoid simultaneous borrow of self.adj and self.*
        let neighbors: Vec<AgentId> = self.adj.get(&v).cloned().unwrap_or_default();

        for w in neighbors {
            if !self.index_map.contains_key(&w) {
                if let Some(cycle) = self.strongconnect(w) {
                    return Some(cycle);
                }
                let w_low = self.lowlink[&w];
                *self.lowlink.get_mut(&v).unwrap() = self.lowlink[&v].min(w_low);
            } else if self.on_stack.contains(&w) {
                let w_idx = self.index_map[&w];
                *self.lowlink.get_mut(&v).unwrap() = self.lowlink[&v].min(w_idx);
            }
        }

        // v is the root of an SCC when its lowlink equals its discovery index.
        if self.lowlink[&v] == self.index_map[&v] {
            let mut scc: Vec<AgentId> = Vec::new();
            loop {
                let w = self.stack.pop().expect("Tarjan stack invariant violated");
                self.on_stack.remove(&w);
                scc.push(w);
                if w == v {
                    break;
                }
            }
            // A real cycle: SCC with > 1 member, or a single node with a self-loop.
            if scc.len() > 1 || self.self_loops.contains(&scc[0]) {
                return Some(scc);
            }
        }

        None
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use chrono::Utc;

    use crate::identity::AgentId;
    use crate::topology::edge::{Edge, EdgeType};

    use super::cycle_detect;

    fn agent(n: u8) -> AgentId {
        AgentId::from_bytes([n; 16])
    }

    fn edge(src: AgentId, tgt: AgentId) -> Edge {
        Edge {
            id: 0,
            source: src,
            target: tgt,
            edge_type: EdgeType::Messages,
            created_at: Utc::now(),
            metadata: None,
        }
    }

    #[test]
    fn dag_returns_none() {
        // A → B → C (no back edges)
        let a = agent(1);
        let b = agent(2);
        let c = agent(3);
        let edges = [edge(a, b), edge(b, c)];
        assert!(cycle_detect(&edges).is_none());
    }

    #[test]
    fn simple_two_node_cycle_returns_both() {
        // A → B → A
        let a = agent(1);
        let b = agent(2);
        let edges = [edge(a, b), edge(b, a)];
        let result = cycle_detect(&edges).expect("cycle must be detected");
        let mut ids: Vec<u8> = result.iter().map(|id| id.as_bytes()[0]).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn self_loop_returns_single_node() {
        // A → A
        let a = agent(1);
        let edges = [edge(a, a)];
        let result = cycle_detect(&edges).expect("self-loop is a cycle");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], a);
    }

    #[test]
    fn disconnected_graph_with_one_cycle_returns_the_cycle() {
        // DAG component: X → Y
        // Cycle component: A → B → C → A
        let x = agent(10);
        let y = agent(11);
        let a = agent(1);
        let b = agent(2);
        let c = agent(3);
        let edges = [edge(x, y), edge(a, b), edge(b, c), edge(c, a)];
        let result = cycle_detect(&edges).expect("cycle must be detected");
        assert!(result.len() >= 2, "cycle has at least 2 members");
        let ids: Vec<u8> = result.iter().map(|id| id.as_bytes()[0]).collect();
        // All cycle members must be from {a, b, c}
        for id in &ids {
            assert!([1u8, 2, 3].contains(id), "unexpected node {id} in cycle result");
        }
    }
}
