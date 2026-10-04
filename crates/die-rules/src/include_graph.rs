//! Static include graph and cycle detection (ADR 0010).
//!
//! At database build time, literal `includeScript("name")` calls are parsed
//! from each rule file to construct a directed include graph. If a self-edge
//! or strongly connected component is found, the database is rejected with
//! `RuleError::IncludeCycle`.
//!
//! At runtime, an active include stack is maintained to prevent re-entering
//! a script that is already on the include path. The include depth and
//! total include evaluations are bounded by the budget profile.
//!
//! See `docs/design/decisions/0010-bounded-include-graph.md`.

use crate::error::{IncludeLimit, RuleError};
use std::collections::{HashMap, HashSet};

/// A directed include graph built from static analysis of rule files.
///
/// Nodes are script names (the argument to `includeScript()`). Edges
/// represent literal include relationships parsed at build time.
#[derive(Debug, Clone)]
pub struct IncludeGraph {
    /// Adjacency list: script_name -> list of included script names.
    edges: HashMap<String, Vec<String>>,
}

impl IncludeGraph {
    /// Create an empty include graph.
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }

    /// Add an edge: `from` includes `to`.
    pub fn add_edge(&mut self, from: &str, to: &str) {
        self.edges
            .entry(from.to_string())
            .or_default()
            .push(to.to_string());
    }

    /// Add a node with no outgoing edges (if not already present).
    pub fn add_node(&mut self, name: &str) {
        self.edges.entry(name.to_string()).or_default();
    }

    /// Get the scripts included by `name`.
    pub fn includes_of(&self, name: &str) -> &[String] {
        self.edges.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All node names in the graph.
    pub fn nodes(&self) -> impl Iterator<Item = &str> {
        self.edges.keys().map(|s| s.as_str())
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.edges.len()
    }

    /// Detect cycles using DFS.
    ///
    /// Returns `Err(RuleError::IncludeCycle)` if a cycle is found,
    /// `Ok(())` if the graph is acyclic.
    pub fn check_acyclic(&self) -> Result<(), RuleError> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut on_stack: HashSet<String> = HashSet::new();
        let mut path: Vec<String> = Vec::new();

        for node in self.edges.keys() {
            if !visited.contains(node) {
                self.dfs_check(node, &mut visited, &mut on_stack, &mut path)?;
            }
        }
        Ok(())
    }

    fn dfs_check(
        &self,
        node: &str,
        visited: &mut HashSet<String>,
        on_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> Result<(), RuleError> {
        visited.insert(node.to_string());
        on_stack.insert(node.to_string());
        path.push(node.to_string());

        if let Some(neighbors) = self.edges.get(node) {
            for neighbor in neighbors {
                if on_stack.contains(neighbor) {
                    // Found a cycle: reconstruct the cycle path.
                    let cycle_start = path.iter().position(|n| n == neighbor).unwrap_or(0);
                    let mut cycle: Vec<String> = path[cycle_start..].to_vec();
                    cycle.push(neighbor.to_string());
                    return Err(RuleError::IncludeCycle { cycle });
                }
                if !visited.contains(neighbor) {
                    self.dfs_check(neighbor, visited, on_stack, path)?;
                }
            }
        }

        on_stack.remove(node);
        path.pop();
        Ok(())
    }
}

impl Default for IncludeGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime include stack tracker.
///
/// Maintains the active include path to detect runtime cycles and enforce
/// the include depth limit. A script can be included again after it exits
/// the active path — ordinary duplicate includes are allowed, only cycles
/// (re-entering a script on the active stack) are rejected.
pub struct IncludeStack {
    /// Current active include path.
    stack: Vec<String>,
    /// Scripts currently on the active stack.
    on_stack: HashSet<String>,
    /// Total cumulative include evaluations.
    total_evaluations: u32,
    /// Maximum include depth.
    max_depth: u32,
    /// Maximum total include evaluations.
    max_evaluations: u32,
}

impl IncludeStack {
    /// Create a new include stack with the given budget limits.
    pub fn new(max_depth: u32, max_evaluations: u32) -> Self {
        Self {
            stack: Vec::new(),
            on_stack: HashSet::new(),
            total_evaluations: 0,
            max_depth,
            max_evaluations,
        }
    }

    /// Push a script onto the include stack.
    ///
    /// Returns `Err` if:
    /// - The script is already on the active stack (cycle).
    /// - The include depth limit is exceeded.
    /// - The total evaluations limit is exceeded.
    pub fn push(&mut self, name: &str) -> Result<(), RuleError> {
        self.total_evaluations += 1;
        if self.total_evaluations > self.max_evaluations {
            return Err(RuleError::IncludeBudgetExceeded {
                limit: IncludeLimit::TotalEvaluations,
                current: self.total_evaluations as u64,
                maximum: self.max_evaluations as u64,
            });
        }
        if self.on_stack.contains(name) {
            let mut cycle: Vec<String> = self.stack.clone();
            cycle.push(name.to_string());
            return Err(RuleError::IncludeCycle { cycle });
        }
        if self.stack.len() as u32 >= self.max_depth {
            return Err(RuleError::IncludeBudgetExceeded {
                limit: IncludeLimit::Depth,
                current: self.stack.len() as u64 + 1,
                maximum: self.max_depth as u64,
            });
        }
        self.stack.push(name.to_string());
        self.on_stack.insert(name.to_string());
        Ok(())
    }

    /// Pop the top script from the include stack.
    ///
    /// Returns `Err` if the stack is empty.
    pub fn pop(&mut self) -> Result<String, RuleError> {
        let name = self.stack.pop().ok_or_else(|| RuleError::Backend {
            detail: "include stack underflow".into(),
        })?;
        self.on_stack.remove(&name);
        Ok(name)
    }

    /// Current depth of the include stack.
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Total cumulative include evaluations so far.
    pub fn total_evaluations(&self) -> u32 {
        self.total_evaluations
    }

    /// Whether the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph_is_acyclic() {
        let g = IncludeGraph::new();
        assert!(g.check_acyclic().is_ok());
    }

    #[test]
    fn simple_chain_is_acyclic() {
        let mut g = IncludeGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "c");
        assert!(g.check_acyclic().is_ok());
    }

    #[test]
    fn self_edge_is_cycle() {
        let mut g = IncludeGraph::new();
        g.add_edge("a", "a");
        let err = g.check_acyclic().unwrap_err();
        assert!(matches!(err, RuleError::IncludeCycle { .. }));
    }

    #[test]
    fn two_node_cycle_is_detected() {
        let mut g = IncludeGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "a");
        let err = g.check_acyclic().unwrap_err();
        match err {
            RuleError::IncludeCycle { cycle } => {
                assert!(cycle.len() >= 3); // a -> b -> a
                assert_eq!(cycle.first().unwrap(), cycle.last().unwrap());
            }
            _ => panic!("expected IncludeCycle"),
        }
    }

    #[test]
    fn three_node_cycle_is_detected() {
        let mut g = IncludeGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "c");
        g.add_edge("c", "a");
        assert!(matches!(
            g.check_acyclic().unwrap_err(),
            RuleError::IncludeCycle { .. }
        ));
    }

    #[test]
    fn diamond_is_acyclic() {
        let mut g = IncludeGraph::new();
        g.add_edge("a", "b");
        g.add_edge("a", "c");
        g.add_edge("b", "d");
        g.add_edge("c", "d");
        assert!(g.check_acyclic().is_ok());
    }

    #[test]
    fn include_stack_push_pop() {
        let mut s = IncludeStack::new(16, 256);
        assert!(s.is_empty());
        s.push("a").unwrap();
        s.push("b").unwrap();
        assert_eq!(s.depth(), 2);
        assert_eq!(s.pop().unwrap(), "b");
        assert_eq!(s.pop().unwrap(), "a");
        assert!(s.is_empty());
    }

    #[test]
    fn include_stack_detects_cycle() {
        let mut s = IncludeStack::new(16, 256);
        s.push("a").unwrap();
        s.push("b").unwrap();
        let err = s.push("a").unwrap_err();
        match err {
            RuleError::IncludeCycle { cycle } => {
                assert_eq!(cycle, vec!["a", "b", "a"]);
            }
            _ => panic!("expected IncludeCycle"),
        }
    }

    #[test]
    fn include_stack_depth_limit() {
        let mut s = IncludeStack::new(2, 256);
        s.push("a").unwrap();
        s.push("b").unwrap();
        let err = s.push("c").unwrap_err();
        assert!(matches!(
            err,
            RuleError::IncludeBudgetExceeded {
                limit: IncludeLimit::Depth,
                ..
            }
        ));
    }

    #[test]
    fn include_stack_evaluations_limit() {
        let mut s = IncludeStack::new(16, 3);
        s.push("a").unwrap();
        s.pop().unwrap();
        s.push("a").unwrap();
        s.pop().unwrap();
        s.push("a").unwrap();
        s.pop().unwrap();
        let err = s.push("a").unwrap_err();
        assert!(matches!(
            err,
            RuleError::IncludeBudgetExceeded {
                limit: IncludeLimit::TotalEvaluations,
                ..
            }
        ));
    }

    #[test]
    fn include_stack_re_include_after_pop() {
        let mut s = IncludeStack::new(16, 256);
        s.push("a").unwrap();
        s.pop().unwrap();
        // Should succeed: "a" is no longer on the active stack.
        s.push("a").unwrap();
        assert_eq!(s.depth(), 1);
    }

    #[test]
    fn include_stack_pop_empty_returns_error() {
        let mut s = IncludeStack::new(16, 256);
        assert!(s.pop().is_err());
    }

    #[test]
    fn include_stack_evaluations_counter() {
        let mut s = IncludeStack::new(16, 256);
        assert_eq!(s.total_evaluations(), 0);
        s.push("a").unwrap();
        assert_eq!(s.total_evaluations(), 1);
        s.push("b").unwrap();
        assert_eq!(s.total_evaluations(), 2);
        s.pop().unwrap();
        // Evaluations counter is cumulative, not decremented on pop.
        assert_eq!(s.total_evaluations(), 2);
    }
}
