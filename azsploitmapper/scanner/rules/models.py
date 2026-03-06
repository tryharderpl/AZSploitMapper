"""
Data models for the rule engine.

These dataclasses represent security rules loaded from YAML files
and the findings they produce when evaluated against Azure resources.
"""

from dataclasses import dataclass, field


@dataclass
class Rule:
    """
    A single security rule loaded from a YAML file.

    Rules define what misconfigurations to look for and how to report them.

    Attributes:
        id: Unique rule identifier (e.g. NSG_OPEN_SSH)
        name: Short human-readable name
        description: Detailed explanation of the misconfiguration
        resource_type: Azure resource type this rule applies to
        severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
        check: Name of the check function to run (e.g. "open_inbound_port")
        parameters: Dict of parameters for the check function
        remediation: How to fix the misconfiguration
        compliance: Dict mapping framework names to control IDs
    """
    id: str
    name: str
    description: str
    resource_type: str
    severity: str
    check: str
    parameters: dict = field(default_factory=dict)
    remediation: str = ""
    compliance: dict = field(default_factory=dict)


@dataclass
class Finding:
    """
    A finding produced when a rule matches a resource.

    Findings represent specific misconfigurations detected in the environment.

    Attributes:
        id: Unique finding identifier (rule_id + resource_id hash)
        rule_id: The rule that triggered this finding
        rule_name: Human-readable rule name
        severity: Inherited from the rule
        resource_id: Azure resource ID where the issue was found
        resource_name: Short resource name for display
        resource_type: Azure resource type
        description: The rule's description of the issue
        remediation: How to fix it
        compliance: Compliance framework mappings from the rule
    """
    id: str
    rule_id: str
    rule_name: str
    severity: str
    resource_id: str
    resource_name: str
    resource_type: str
    description: str
    remediation: str = ""
    compliance: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to a JSON-serializable dict for the API."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "description": self.description,
            "remediation": self.remediation,
            "compliance": self.compliance,
        }
