"""
Attack path finder - discovers paths from internet entry points to sensitive targets.

Uses Breadth-First Search (BFS) on the directed graph to find all paths an
attacker could follow from the Internet node to high-value targets like
storage accounts and key vaults.

This is the core security analysis component: it answers the question
"How could an attacker reach my sensitive data?"
"""

import networkx as nx

from azsploitmapper.graph.models import AttackPath, GraphEdge, EdgeType, NodeType


# Resource types that represent high-value targets for attackers.
# VMs are included because a publicly reachable VM is a direct compromise risk.
TARGET_NODE_TYPES = {
    NodeType.VM.value,
    NodeType.STORAGE.value,
    NodeType.KEYVAULT.value,
}


class AttackPathFinder:
    """
    Finds all attack paths from the internet to sensitive targets.

    Algorithm:
    1. Start from the 'internet' node
    2. Use BFS to explore all reachable nodes
    3. When a target node (Storage, KeyVault) is reached, record the path
    4. Score each path based on length, severity, and target value
    """

    def __init__(self, graph: nx.DiGraph, max_path_length: int = 8):
        """
        Args:
            graph: The NetworkX directed graph built by GraphBuilder
            max_path_length: Maximum number of hops in an attack path.
                             Paths longer than this are ignored (too complex
                             for a real attacker to exploit reliably).
        """
        self.graph = graph
        self.max_path_length = max_path_length

    def find_all_paths(self) -> list[AttackPath]:
        """
        Find all attack paths from Internet to target resources.

        Returns a list of AttackPath objects sorted by risk score (highest first).
        """
        if "internet" not in self.graph:
            return []

        paths = []

        # Find all target nodes in the graph
        target_nodes = [
            node_id for node_id, data in self.graph.nodes(data=True)
            if data.get("node_type") in TARGET_NODE_TYPES
        ]

        # For each target, find all simple paths from internet
        for target_id in target_nodes:
            try:
                # nx.all_simple_paths returns all paths without cycles
                raw_paths = nx.all_simple_paths(
                    self.graph,
                    source="internet",
                    target=target_id,
                    cutoff=self.max_path_length,
                )
                for node_list in raw_paths:
                    attack_path = self._build_attack_path(node_list)
                    if attack_path:
                        paths.append(attack_path)
            except nx.NetworkXError:
                # No path exists to this target
                continue

        # Sort by risk score, highest first
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def _build_attack_path(self, node_list: list[str]) -> AttackPath | None:
        """
        Convert a raw list of node IDs into an AttackPath with edges and metadata.
        """
        if len(node_list) < 2:
            return None

        edges = []
        for i in range(len(node_list) - 1):
            src = node_list[i]
            dst = node_list[i + 1]
            edge_data = self.graph.get_edge_data(src, dst, {})
            edge = GraphEdge(
                source=src,
                target=dst,
                edge_type=EdgeType(edge_data.get("edge_type", "exposes")),
                label=edge_data.get("label", ""),
            )
            edges.append(edge)

        # Build a human-readable description of the path
        description = self._describe_path(node_list)

        return AttackPath(
            nodes=node_list,
            edges=edges,
            entry_point=node_list[0],
            target=node_list[-1],
            risk_score=0.0,  # Scored later by RiskScorer
            description=description,
        )

    def _describe_path(self, node_list: list[str]) -> str:
        """
        Generate a human-readable description of an attack path.

        Example: "Internet -> PublicIP (10.0.0.1) -> NIC -> VM (vm-lab) ->
                  ManagedIdentity -> Role (Contributor) -> Storage (sa-data)"
        """
        parts = []
        for node_id in node_list:
            data = self.graph.nodes.get(node_id, {})
            name = data.get("name", node_id.split("/")[-1])
            parts.append(name)
        return " -> ".join(parts)

    def get_path_summary(self, paths: list[AttackPath]) -> dict:
        """
        Generate a summary of all discovered attack paths.

        Returns:
            Dict with total_paths, critical_paths (score >= 7.0),
            targets_reached, and average_path_length.
        """
        if not paths:
            return {
                "total_paths": 0,
                "critical_paths": 0,
                "targets_reached": 0,
                "avg_path_length": 0,
                "shortest_path": 0,
                "longest_path": 0,
            }

        unique_targets = set(p.target for p in paths)
        lengths = [len(p.nodes) for p in paths]

        return {
            "total_paths": len(paths),
            "critical_paths": sum(1 for p in paths if p.risk_score >= 7.0),
            "targets_reached": len(unique_targets),
            "avg_path_length": round(sum(lengths) / len(lengths), 1),
            "shortest_path": min(lengths),
            "longest_path": max(lengths),
        }
