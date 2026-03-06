"""
Risk scorer - assigns risk scores to attack paths and individual resources.

Risk scoring helps prioritize which attack paths and misconfigurations
need attention first. A score of 10.0 means maximum risk (critical path
to sensitive data), 0.0 means minimal risk.

The scoring formula considers three factors:
1. Path length (shorter = more exploitable = higher risk)
2. Misconfiguration severity along the path
3. Target value (key vault > storage > other)
"""

from azsploitmapper.graph.models import AttackPath, GraphNode, NodeType, Severity


# How valuable each target type is to an attacker (0.0 to 10.0)
TARGET_VALUE = {
    NodeType.KEYVAULT.value: 10.0,   # Secrets, keys, certificates
    NodeType.STORAGE.value: 8.0,      # Data, backups, logs
    NodeType.VM.value: 7.0,           # Compute access, lateral movement pivot
}

# Severity weight: how much each finding severity adds to path risk
SEVERITY_WEIGHT = {
    Severity.CRITICAL.value: 3.0,
    Severity.HIGH.value: 2.0,
    Severity.MEDIUM.value: 1.0,
    Severity.LOW.value: 0.5,
    Severity.INFO.value: 0.0,
}


class RiskScorer:
    """
    Scores attack paths and resources based on exploitability and impact.

    Score components (configurable weights):
    - path_length_weight: shorter paths are riskier
    - severity_weight: more severe misconfigs increase risk
    - target_value_weight: more valuable targets increase risk
    """

    def __init__(
        self,
        path_length_weight: float = 0.3,
        severity_weight: float = 0.5,
        target_value_weight: float = 0.2,
    ):
        self.path_length_weight = path_length_weight
        self.severity_weight = severity_weight
        self.target_value_weight = target_value_weight

    def score_paths(
        self,
        paths: list[AttackPath],
        nodes: dict[str, GraphNode],
    ) -> list[AttackPath]:
        """
        Score all attack paths and return them with updated risk_score fields.
        Also updates risk scores on individual nodes based on their own
        findings + their position on attack paths.
        """
        for path in paths:
            path.risk_score = self._calculate_path_score(path, nodes)

        self._score_individual_nodes(paths, nodes)
        return paths

    def _score_individual_nodes(
        self,
        paths: list[AttackPath],
        nodes: dict[str, GraphNode],
    ) -> None:
        """
        Calculate per-node risk based on own findings + path exposure.
        Nodes with more/worse findings get higher scores.
        Entry points (Internet) get risk from paths they enable.
        """
        on_attack_path: dict[str, float] = {}
        for path in paths:
            for node_id in path.nodes:
                on_attack_path[node_id] = max(
                    on_attack_path.get(node_id, 0.0), path.risk_score
                )

        for node_id, node in nodes.items():
            finding_score = 0.0
            for f in node.findings:
                sev = f.get("severity", "INFO")
                finding_score += SEVERITY_WEIGHT.get(sev, 0.0)
            finding_score = min(10.0, finding_score)

            target_bonus = TARGET_VALUE.get(node.node_type.value, 0.0)
            path_exposure = on_attack_path.get(node_id, 0.0)

            if finding_score > 0 or target_bonus > 0:
                raw = finding_score * 0.5 + target_bonus * 0.3 + path_exposure * 0.2
            elif path_exposure > 0:
                raw = path_exposure * 0.4
            else:
                raw = 0.0

            node.risk_score = round(min(10.0, max(0.0, raw)), 1)

    def _calculate_path_score(
        self,
        path: AttackPath,
        nodes: dict[str, GraphNode],
    ) -> float:
        """
        Calculate a risk score for a single attack path.

        Formula:
          score = (length_score * w1) + (severity_score * w2) + (target_score * w3)

        Each component is on a 0-10 scale, so the final score is also 0-10.
        """
        length_score = self._score_path_length(path)
        severity_score = self._score_severity(path, nodes)
        target_score = self._score_target_value(path, nodes)

        raw_score = (
            length_score * self.path_length_weight
            + severity_score * self.severity_weight
            + target_score * self.target_value_weight
        )

        # Clamp to 0.0 - 10.0
        return round(min(10.0, max(0.0, raw_score)), 1)

    def _score_path_length(self, path: AttackPath) -> float:
        """
        Shorter paths are more dangerous (easier to exploit).

        1 hop  = 10.0 (direct access)
        2 hops = 9.0
        3 hops = 8.0
        ...
        8 hops = 3.0
        """
        hops = len(path.nodes) - 1
        return max(0.0, 11.0 - hops)

    def _score_severity(
        self,
        path: AttackPath,
        nodes: dict[str, GraphNode],
    ) -> float:
        """
        Higher severity findings along the path increase risk.

        Sum the severity weights of all findings on nodes in the path,
        capped at 10.0.
        """
        total = 0.0
        for node_id in path.nodes:
            node = nodes.get(node_id)
            if not node:
                continue
            for finding in node.findings:
                severity = finding.get("severity", "INFO")
                total += SEVERITY_WEIGHT.get(severity, 0.0)

        return min(10.0, total)

    def _score_target_value(
        self,
        path: AttackPath,
        nodes: dict[str, GraphNode],
    ) -> float:
        """
        More valuable targets (Key Vault > Storage) get higher scores.
        """
        target_node = nodes.get(path.target)
        if not target_node:
            return 0.0
        return TARGET_VALUE.get(target_node.node_type.value, 2.0)
