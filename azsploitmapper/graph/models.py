"""
Data models for the attack path graph.

These dataclasses define the structure of nodes, edges, and attack paths
that make up the security graph. The graph builder creates these from
discovered Azure resources, and the frontend renders them with Cytoscape.js.
"""

from dataclasses import dataclass, field
from enum import Enum


class NodeType(str, Enum):
    """Types of nodes in the attack graph."""
    INTERNET = "internet"
    VM = "vm"
    NSG = "nsg"
    PUBLIC_IP = "public_ip"
    NIC = "nic"
    STORAGE = "storage"
    KEYVAULT = "keyvault"
    MANAGED_IDENTITY = "managed_identity"
    ROLE_ASSIGNMENT = "role_assignment"
    VNET = "vnet"
    DISK = "disk"


class EdgeType(str, Enum):
    """Types of relationships (edges) between nodes."""
    EXPOSES = "exposes"                 # Internet -> Public IP (via open NSG)
    ATTACHED_TO = "attached_to"         # Public IP -> NIC, NIC -> VM
    PROTECTED_BY = "protected_by"       # NIC -> NSG
    HAS_IDENTITY = "has_identity"       # VM -> Managed Identity
    HAS_ROLE = "has_role"               # Identity -> Role Assignment
    CAN_ACCESS = "can_access"           # Role Assignment -> Storage/KeyVault
    ALLOWS_TRAFFIC = "allows_traffic"   # NSG -> NIC (via permissive rule)
    SAME_RG = "same_rg"                 # Resources in same resource group
    NETWORK_ACCESS = "network_access"   # VM -> Storage/KeyVault via network


class Severity(str, Enum):
    """Severity levels for findings and risk scores."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class GraphNode:
    """
    A node in the attack graph, representing an Azure resource or the internet.

    Attributes:
        id: Unique identifier (Azure resource ID or 'internet')
        name: Human-readable label shown in the graph
        node_type: Category of resource (VM, NSG, Storage, etc.)
        properties: Resource-specific data from the collector
        findings: List of misconfigurations found on this resource
        risk_score: Computed risk score (0.0 to 10.0)
    """
    id: str
    name: str
    node_type: NodeType
    properties: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class GraphEdge:
    """
    An edge in the attack graph, representing a relationship between resources.

    Edges are directed: source -> target means "source can reach target".
    For example: PublicIP -> VM means the VM is reachable via this Public IP.
    """
    source: str
    target: str
    edge_type: EdgeType
    label: str = ""
    properties: dict = field(default_factory=dict)


@dataclass
class AttackPath:
    """
    A complete attack path from an entry point to a target.

    An attack path is a sequence of nodes connected by edges that an attacker
    could follow to reach a sensitive resource. For example:

      Internet -> Public IP -> VM -> Managed Identity -> Storage Account

    Attributes:
        nodes: Ordered list of node IDs from entry point to target
        edges: List of edges connecting the nodes
        entry_point: ID of the first node (where the attacker starts)
        target: ID of the last node (what the attacker wants)
        risk_score: Combined risk score based on path length, severity, target value
        description: Human-readable summary of the path
    """
    nodes: list[str]
    edges: list[GraphEdge]
    entry_point: str
    target: str
    risk_score: float = 0.0
    description: str = ""
