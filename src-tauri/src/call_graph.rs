//! Interactive call graph data structures for the web UI.
//!
//! Produces a JSON-serializable graph (nodes + edges) that the React/D3.js
//! frontend renders as an interactive force-directed call graph.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub address: u64,
    pub name: String,
    pub size: usize,
    pub is_named: bool,
    pub library: Option<String>,
    pub call_count: usize,
    pub called_by_count: usize,
    pub is_entry: bool,
    pub is_external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub callsite: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveCallGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub statistics: GraphStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStatistics {
    pub total_functions: usize,
    pub named_functions: usize,
    pub external_functions: usize,
    pub total_edges: usize,
    pub max_call_depth: usize,
    pub libraries: Vec<String>,
    pub hub_functions: Vec<HubFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubFunction {
    pub name: String,
    pub address: u64,
    pub call_count: usize,
    pub called_by_count: usize,
    pub score: usize,
}

pub fn build_interactive_graph(
    functions: &[(u64, String, usize, bool)],
    edges: &[(u64, u64, u64, String)],
    entry_point: u64,
    sdk_matches: &[(String, String)],
) -> InteractiveCallGraph {
    let mut sdk_map: HashMap<String, String> = HashMap::new();
    for (name, lib) in sdk_matches { sdk_map.insert(name.clone(), lib.clone()); }
    let mut node_ids: HashMap<u64, String> = HashMap::new();
    let mut external_addrs: HashSet<u64> = HashSet::new();

    let mut nodes: Vec<GraphNode> = functions.iter().map(|(addr, name, size, is_named)| {
        let id = format!("0x{:08X}", addr);
        node_ids.insert(*addr, id.clone());
        GraphNode {
            id, address: *addr, name: name.clone(), size: *size,
            is_named: *is_named, library: sdk_map.get(name).cloned(),
            call_count: 0, called_by_count: 0,
            is_entry: *addr == entry_point, is_external: false,
        }
    }).collect();

    let func_addrs: HashSet<u64> = functions.iter().map(|(a, _, _, _)| *a).collect();
    for (_, to, _, _) in edges { if !func_addrs.contains(to) { external_addrs.insert(*to); } }

    for addr in &external_addrs {
        let id = format!("0x{:08X}", addr);
        node_ids.insert(*addr, id.clone());
        nodes.push(GraphNode {
            id, address: *addr, name: format!("ext_0x{:08X}", addr),
            size: 0, is_named: false, library: None,
            call_count: 0, called_by_count: 0, is_entry: false, is_external: true,
        });
    }

    let mut graph_edges: Vec<GraphEdge> = Vec::new();
    let mut call_counts: HashMap<u64, usize> = HashMap::new();
    let mut called_by_counts: HashMap<u64, usize> = HashMap::new();

    for (from, to, callsite, kind) in edges {
        let src = node_ids.get(from).cloned().unwrap_or_else(|| format!("0x{:08X}", from));
        let tgt = node_ids.get(to).cloned().unwrap_or_else(|| format!("0x{:08X}", to));
        *call_counts.entry(*from).or_insert(0) += 1;
        *called_by_counts.entry(*to).or_insert(0) += 1;
        graph_edges.push(GraphEdge { source: src, target: tgt, callsite: *callsite, kind: kind.clone() });
    }

    for node in &mut nodes {
        node.call_count = *call_counts.get(&node.address).unwrap_or(&0);
        node.called_by_count = *called_by_counts.get(&node.address).unwrap_or(&0);
    }

    let named = nodes.iter().filter(|n| n.is_named).count();
    let ext = nodes.iter().filter(|n| n.is_external).count();
    let mut libs: Vec<String> = nodes.iter().filter_map(|n| n.library.clone())
        .collect::<HashSet<_>>().into_iter().collect();
    libs.sort();

    let mut hubs: Vec<HubFunction> = nodes.iter()
        .filter(|n| !n.is_external && (n.call_count + n.called_by_count) > 0)
        .map(|n| HubFunction {
            name: n.name.clone(), address: n.address,
            call_count: n.call_count, called_by_count: n.called_by_count,
            score: n.call_count + n.called_by_count,
        }).collect();
    hubs.sort_by(|a, b| b.score.cmp(&a.score));
    hubs.truncate(20);

    let max_depth = compute_max_depth(&nodes, &graph_edges);

    InteractiveCallGraph {
        nodes, edges: graph_edges.clone(),
        statistics: GraphStatistics {
            total_functions: functions.len(), named_functions: named,
            external_functions: ext, total_edges: graph_edges.len(),
            max_call_depth: max_depth, libraries: libs, hub_functions: hubs,
        },
    }
}

fn compute_max_depth(nodes: &[GraphNode], edges: &[GraphEdge]) -> usize {
    let entry = nodes.iter().find(|n| n.is_entry);
    if entry.is_none() { return 0; }
    let entry_id = entry.unwrap().id.clone();
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for e in edges { adj.entry(e.source.clone()).or_default().push(e.target.clone()); }
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<(String, usize)> = vec![(entry_id, 0)];
    let mut max_d = 0;
    while let Some((id, depth)) = queue.pop() {
        if depth > max_d { max_d = depth; }
        if visited.contains(&id) { continue; }
        visited.insert(id.clone());
        if let Some(targets) = adj.get(&id) {
            for t in targets { queue.push((t.clone(), depth + 1)); }
        }
    }
    max_d
}