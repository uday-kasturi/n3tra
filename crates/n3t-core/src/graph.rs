//! The artifact dependency graph.
//!
//! Nodes are packages, files, processes, and network endpoints; edges record how
//! they came to be related. Every node carries which observation layers saw it,
//! which is the whole point: **the findings are the disagreements between
//! layers**, not the contents of any single one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::confidence::Confidence;
use crate::purl::Purl;

/// An observation layer.
///
/// Ordering reflects evidentiary strength, not chronology: L0 is what was
/// *claimed*, L1–L3 are what was *observed*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// Manifests and lockfiles. What the build claims it depends on.
    L0Declared,
    /// PATH shims and `LD_PRELOAD`. What the package managers were told to do.
    L1Interposed,
    /// eBPF. What the kernel saw happen.
    L2Kernel,
    /// Content-addressed filesystem and OCI layer diff. What landed on disk.
    L3Materialized,
}

impl Layer {
    /// Whether this layer observes reality rather than reporting a claim.
    pub fn is_observational(self) -> bool {
        !matches!(self, Layer::L0Declared)
    }

    /// INV-13: only L1 runs early enough to refuse. L2 and L3 see a fetch after
    /// the bytes are already on disk; blocking there would require
    /// `bpf_override_return` or a denying LSM hook, forfeiting the passivity
    /// guarantee (INV-3) that makes the collector safe to run at all.
    pub fn can_prevent(self) -> bool {
        matches!(self, Layer::L1Interposed)
    }
}

/// What a node is.
/// Adjacently rather than internally tagged: `Package` wraps a [`Purl`], which
/// serializes as a string, and serde's internal tagging cannot represent a
/// tagged newtype variant holding a non-map.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum NodeKind {
    /// A package, identified by PURL.
    Package(Purl),
    /// A file on disk.
    File {
        /// Absolute path as observed.
        path: String,
        /// SHA-256 of the contents, when computed.
        sha256: Option<String>,
    },
    /// A process in the build's process tree.
    Process {
        /// Container-scoped pid (already translated from the host namespace).
        pid: u32,
        /// The executable path.
        exe: String,
    },
    /// A network endpoint contacted during the build.
    Endpoint {
        /// Hostname as resolved, or the literal address if no DNS was seen.
        host: String,
        /// Destination port.
        port: u16,
    },
}

/// How two nodes are related.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// A manifest or lockfile named this package (L0).
    Declared,
    /// The package was written to disk (L1/L3).
    Installed,
    /// A file belonging to the package was actually read or mapped (L2).
    Loaded,
    /// One process started another (L2).
    Spawned,
    /// Bytes for this package came from this endpoint (L1/L2).
    FetchedFrom,
}

/// Stable handle to a node in a [`Graph`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(usize);

/// A node plus its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// What this node is.
    pub kind: NodeKind,
    /// Every layer that observed it. Never empty.
    pub sources: BTreeSet<Layer>,
    /// INV-8: how certain the file-to-package attribution is.
    pub attribution_confidence: Confidence,
    /// The first layer to report it.
    pub first_seen_by: Layer,
}

impl Node {
    /// INV-11 / the headline Stage 1 finding: observed on disk or in the kernel,
    /// but named by no manifest.
    pub fn is_undeclared(&self) -> bool {
        !self.sources.contains(&Layer::L0Declared)
            && self.sources.iter().any(|l| l.is_observational())
    }

    /// Declared by a manifest but never observed being read.
    ///
    /// INV-9: this is *not* "unused". It is scoped to one build, and callers must
    /// use [`crate::wording::NOT_LOADED`] when rendering it.
    pub fn declared_but_not_loaded(&self, loaded: bool) -> bool {
        self.sources.contains(&Layer::L0Declared) && !loaded
    }
}

/// An edge between two nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    /// Source node.
    pub from: NodeId,
    /// Target node.
    pub to: NodeId,
    /// Relationship.
    pub kind: EdgeKind,
    /// Which layer observed this relationship.
    pub observed_by: Layer,
}

/// The artifact dependency graph.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    #[serde(skip)]
    index: BTreeMap<NodeKind, NodeId>,
}

impl Graph {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a node, or merge provenance into the existing one.
    ///
    /// Merging is how the layer-disagreement findings arise: the same package
    /// observed by L0 and L3 ends up as one node with two sources, whereas one
    /// seen only by L3 stays undeclared.
    pub fn observe(&mut self, kind: NodeKind, layer: Layer, confidence: Confidence) -> NodeId {
        if let Some(&id) = self.index.get(&kind) {
            if let Some(node) = self.nodes.get_mut(id.0) {
                node.sources.insert(layer);
                // Confidence is a floor, not an average: one exact ownership
                // record is enough to trust the attribution, and a later
                // heuristic sighting must not downgrade it.
                node.attribution_confidence = node.attribution_confidence.max(confidence);
            }
            return id;
        }
        let id = NodeId(self.nodes.len());
        self.nodes.push(Node {
            kind: kind.clone(),
            sources: BTreeSet::from([layer]),
            attribution_confidence: confidence,
            first_seen_by: layer,
        });
        self.index.insert(kind, id);
        id
    }

    /// Record a relationship.
    pub fn relate(&mut self, from: NodeId, to: NodeId, kind: EdgeKind, observed_by: Layer) {
        self.edges.push(Edge {
            from,
            to,
            kind,
            observed_by,
        });
    }

    /// Look up a node.
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id.0)
    }

    /// All nodes.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// All edges.
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Nodes observed by an observational layer but declared by none.
    pub fn undeclared(&self) -> impl Iterator<Item = (NodeId, &Node)> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.is_undeclared())
            .map(|(i, n)| (NodeId(i), n))
    }

    /// Packages with at least one `Loaded` edge — actually read during the build.
    pub fn loaded_packages(&self) -> BTreeSet<NodeId> {
        self.edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Loaded)
            .map(|e| e.to)
            .collect()
    }

    /// Rebuild the lookup index after deserialization.
    pub fn reindex(&mut self) {
        self.index = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.kind.clone(), NodeId(i)))
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(s: &str) -> NodeKind {
        NodeKind::Package(
            Purl::parse(s).unwrap_or_else(|_| {
                Purl::parse("pkg:generic/x").unwrap_or_else(|_| unreachable!())
            }),
        )
    }

    #[test]
    fn observing_twice_merges_sources() {
        let mut g = Graph::new();
        let a = g.observe(
            pkg("pkg:npm/left-pad@1.0.0"),
            Layer::L0Declared,
            Confidence::High,
        );
        let b = g.observe(
            pkg("pkg:npm/left-pad@1.0.0"),
            Layer::L3Materialized,
            Confidence::Medium,
        );
        assert_eq!(a, b, "same PURL must be one node");
        assert_eq!(g.nodes().len(), 1);
        let node = g.node(a).unwrap_or_else(|| unreachable!());
        assert_eq!(node.sources.len(), 2);
        assert_eq!(node.first_seen_by, Layer::L0Declared);
    }

    // Confidence is a floor: an exact ownership record must not be downgraded by
    // a later heuristic sighting of the same package.
    #[test]
    fn confidence_never_downgrades_on_merge() {
        let mut g = Graph::new();
        let id = g.observe(pkg("pkg:npm/a@1"), Layer::L0Declared, Confidence::High);
        g.observe(pkg("pkg:npm/a@1"), Layer::L2Kernel, Confidence::Low);
        assert_eq!(
            g.node(id)
                .unwrap_or_else(|| unreachable!())
                .attribution_confidence,
            Confidence::High
        );
    }

    // The headline Stage 1 capability.
    #[test]
    fn observed_but_undeclared_is_flagged() {
        let mut g = Graph::new();
        g.observe(
            pkg("pkg:npm/declared@1"),
            Layer::L0Declared,
            Confidence::High,
        );
        g.observe(
            pkg("pkg:npm/declared@1"),
            Layer::L3Materialized,
            Confidence::High,
        );
        g.observe(
            pkg("pkg:npm/sneaky@6.6.6"),
            Layer::L3Materialized,
            Confidence::High,
        );

        let undeclared: Vec<_> = g.undeclared().map(|(_, n)| n.kind.clone()).collect();
        assert_eq!(undeclared, vec![pkg("pkg:npm/sneaky@6.6.6")]);
    }

    // A package named only by a lockfile is not "undeclared" — it is just not
    // yet observed. Conflating the two would make every unbuilt dep a finding.
    #[test]
    fn declared_only_is_not_undeclared() {
        let mut g = Graph::new();
        g.observe(pkg("pkg:npm/a@1"), Layer::L0Declared, Confidence::High);
        assert_eq!(g.undeclared().count(), 0);
    }

    // INV-13.
    #[test]
    fn only_l1_can_prevent() {
        assert!(Layer::L1Interposed.can_prevent());
        assert!(!Layer::L0Declared.can_prevent());
        assert!(!Layer::L2Kernel.can_prevent());
        assert!(!Layer::L3Materialized.can_prevent());
    }

    #[test]
    fn loaded_packages_tracked() {
        let mut g = Graph::new();
        let proc = g.observe(
            NodeKind::Process {
                pid: 1,
                exe: "/usr/bin/python3".into(),
            },
            Layer::L2Kernel,
            Confidence::High,
        );
        let used = g.observe(
            pkg("pkg:pypi/requests@2.31.0"),
            Layer::L0Declared,
            Confidence::High,
        );
        let unused = g.observe(
            pkg("pkg:pypi/boto3@1.34.0"),
            Layer::L0Declared,
            Confidence::High,
        );
        g.relate(proc, used, EdgeKind::Loaded, Layer::L2Kernel);

        let loaded = g.loaded_packages();
        assert!(loaded.contains(&used));
        assert!(!loaded.contains(&unused));
    }

    // Note the explicit `expect`s: an earlier version of this test used
    // `unwrap_or_default()`, which turned a real serialization failure into a
    // silently empty graph. Swallowing errors in a test that exists to catch
    // errors is worse than having no test.
    #[test]
    fn survives_serde_round_trip_with_reindex() {
        let mut g = Graph::new();
        g.observe(pkg("pkg:npm/a@1"), Layer::L0Declared, Confidence::High);
        let json = serde_json::to_string(&g).expect("graph must serialize");
        let mut back: Graph = serde_json::from_str(&json).expect("graph must deserialize");
        back.reindex();
        assert_eq!(g, back);
        // Index must work after reload, or observe() would duplicate nodes.
        back.observe(pkg("pkg:npm/a@1"), Layer::L3Materialized, Confidence::High);
        assert_eq!(back.nodes().len(), 1);
    }
}
