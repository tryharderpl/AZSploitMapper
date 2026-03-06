"""
Graph builder - transforms discovered Azure resources into a NetworkX directed graph.

Nodes = Azure resources (VMs, NSGs, Storage, etc.) + Internet
Edges = exploitable relationships between them
"""

import networkx as nx

from azsploitmapper.graph.models import (
    GraphNode, GraphEdge, NodeType, EdgeType,
)


def _rg_from_id(resource_id: str) -> str:
    """Extract resource group name from an Azure resource ID (lowercase)."""
    if not resource_id or "resourceGroups/" not in resource_id:
        return ""
    try:
        start = resource_id.index("resourceGroups/") + len("resourceGroups/")
        rest = resource_id[start:]
        end = rest.index("/") if "/" in rest else len(rest)
        return rest[:end].lower()
    except (ValueError, IndexError):
        return ""


class GraphBuilder:
    """Builds a NetworkX DiGraph from discovered Azure resources."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self._resources_by_id = {}
        self._resources_by_type = {}
        self._nodes = {}
        self._nodes_lower = {}

    def _find_node_id(self, ref_id: str) -> str | None:
        """Find canonical node ID with case-insensitive match."""
        if ref_id in self._nodes:
            return ref_id
        return self._nodes_lower.get(ref_id.lower())

    def build(self, resources: list[dict]) -> nx.DiGraph:
        self._index_resources(resources)
        self._create_nodes(resources)
        self._add_internet_node()
        self._create_edges()
        return self.graph

    def get_nodes(self) -> dict[str, GraphNode]:
        return self._nodes

    def _index_resources(self, resources: list[dict]):
        for res in resources:
            self._resources_by_id[res["id"]] = res
            self._resources_by_id[res["id"].lower()] = res
            rtype = res["type"]
            if rtype not in self._resources_by_type:
                self._resources_by_type[rtype] = []
            self._resources_by_type[rtype].append(res)

    def _create_nodes(self, resources: list[dict]):
        type_map = {
            "Microsoft.Compute/virtualMachines": NodeType.VM,
            "Microsoft.Network/networkSecurityGroups": NodeType.NSG,
            "Microsoft.Network/publicIPAddresses": NodeType.PUBLIC_IP,
            "Microsoft.Network/networkInterfaces": NodeType.NIC,
            "Microsoft.Storage/storageAccounts": NodeType.STORAGE,
            "Microsoft.KeyVault/vaults": NodeType.KEYVAULT,
            "Microsoft.ManagedIdentity/userAssignedIdentities": NodeType.MANAGED_IDENTITY,
            "Microsoft.Network/virtualNetworks": NodeType.VNET,
            "Microsoft.Compute/disks": NodeType.DISK,
        }

        for res in resources:
            node_type = type_map.get(res["type"])
            if node_type is None:
                continue

            node = GraphNode(
                id=res["id"],
                name=res["name"],
                node_type=node_type,
                properties=res.get("properties", {}),
            )
            self._nodes[res["id"]] = node
            self._nodes_lower[res["id"].lower()] = res["id"]
            self.graph.add_node(
                res["id"],
                name=res["name"],
                node_type=node_type.value,
                resource_group=res.get("resource_group", ""),
                properties=res.get("properties", {}),
            )

    def _add_internet_node(self):
        internet_node = GraphNode(
            id="internet",
            name="Internet",
            node_type=NodeType.INTERNET,
        )
        self._nodes["internet"] = internet_node
        self._nodes_lower["internet"] = "internet"
        self.graph.add_node(
            "internet",
            name="Internet",
            node_type=NodeType.INTERNET.value,
            resource_group="",
            properties={},
        )

    def _create_edges(self):
        self._link_internet_to_public_ips()
        self._link_public_ips_to_nics()
        self._link_nics_to_vms()
        self._link_nsgs_to_nics()
        self._link_vms_to_same_rg_storage()

    def _link_internet_to_public_ips(self):
        """Internet -> Public IP when NSGs allow inbound from anywhere."""
        public_ips = self._resources_by_type.get(
            "Microsoft.Network/publicIPAddresses", []
        )
        nsgs = self._resources_by_type.get(
            "Microsoft.Network/networkSecurityGroups", []
        )

        open_nsg_ports = set()
        for nsg in nsgs:
            for rule in nsg.get("properties", {}).get("security_rules", []):
                if (
                    rule.get("direction") == "Inbound"
                    and rule.get("access") == "Allow"
                    and rule.get("source_address_prefix") in ("*", "0.0.0.0/0", "Internet")
                ):
                    port = rule.get("destination_port_range", "*")
                    open_nsg_ports.add(port)

        if open_nsg_ports:
            for pip in public_ips:
                ip_addr = pip.get("properties", {}).get("ip_address", "")
                if ip_addr:
                    ports_str = ", ".join(sorted(open_nsg_ports))
                    self._add_edge(GraphEdge(
                        source="internet",
                        target=pip["id"],
                        edge_type=EdgeType.EXPOSES,
                        label=f"open ports: {ports_str}",
                    ))
                else:
                    self._add_edge(GraphEdge(
                        source="internet",
                        target=pip["id"],
                        edge_type=EdgeType.EXPOSES,
                        label="public IP (dynamic)",
                    ))

    def _link_public_ips_to_nics(self):
        """Public IP -> NIC via ip_configuration association."""
        nics = self._resources_by_type.get(
            "Microsoft.Network/networkInterfaces", []
        )
        for nic in nics:
            public_ip_id = nic.get("properties", {}).get("public_ip_id", "")
            canonical_pip = self._find_node_id(public_ip_id) if public_ip_id else None
            if canonical_pip:
                self._add_edge(GraphEdge(
                    source=canonical_pip,
                    target=nic["id"],
                    edge_type=EdgeType.ATTACHED_TO,
                    label="attached to NIC",
                ))

    def _link_nics_to_vms(self):
        """NIC -> VM via virtual_machine association."""
        nics = self._resources_by_type.get(
            "Microsoft.Network/networkInterfaces", []
        )
        for nic in nics:
            vm_id = nic.get("properties", {}).get("vm_id", "")
            canonical_vm = self._find_node_id(vm_id) if vm_id else None
            if canonical_vm:
                self._add_edge(GraphEdge(
                    source=nic["id"],
                    target=canonical_vm,
                    edge_type=EdgeType.ATTACHED_TO,
                    label="attached to VM",
                ))

    def _link_nsgs_to_nics(self):
        """NIC -> NSG to show which NSG protects which NIC."""
        nics = self._resources_by_type.get(
            "Microsoft.Network/networkInterfaces", []
        )
        for nic in nics:
            nsg_id = nic.get("properties", {}).get("nsg_id", "")
            canonical_nsg = self._find_node_id(nsg_id) if nsg_id else None
            if canonical_nsg:
                self._add_edge(GraphEdge(
                    source=nic["id"],
                    target=canonical_nsg,
                    edge_type=EdgeType.PROTECTED_BY,
                    label="protected by NSG",
                ))

    def _link_vms_to_same_rg_storage(self):
        """
        VM -> Storage/KeyVault when both are in the same resource group.
        A compromised VM with network access can likely reach storage in the same RG.
        """
        vms = self._resources_by_type.get(
            "Microsoft.Compute/virtualMachines", []
        )
        storage = self._resources_by_type.get(
            "Microsoft.Storage/storageAccounts", []
        )
        keyvaults = self._resources_by_type.get(
            "Microsoft.KeyVault/vaults", []
        )
        targets = storage + keyvaults

        for vm in vms:
            vm_rg = _rg_from_id(vm["id"])
            if not vm_rg:
                continue
            for target in targets:
                target_rg = _rg_from_id(target["id"])
                if target_rg == vm_rg and vm["id"] in self._nodes and target["id"] in self._nodes:
                    target_type = "storage" if "storageAccounts" in target["type"] else "keyvault"
                    self._add_edge(GraphEdge(
                        source=vm["id"],
                        target=target["id"],
                        edge_type=EdgeType.NETWORK_ACCESS,
                        label=f"same RG -> {target_type}",
                    ))

    def _add_edge(self, edge: GraphEdge):
        self.graph.add_edge(
            edge.source,
            edge.target,
            edge_type=edge.edge_type.value,
            label=edge.label,
            properties=edge.properties,
        )

    def to_cytoscape_json(self) -> dict:
        """Export graph in Cytoscape.js JSON format for the frontend."""
        cy_nodes = []
        for node_id, data in self.graph.nodes(data=True):
            node_obj = self._nodes.get(node_id)
            cy_nodes.append({
                "data": {
                    "id": node_id,
                    "label": data.get("name", node_id),
                    "type": data.get("node_type", "unknown"),
                    "resource_group": data.get("resource_group", ""),
                    "risk_score": node_obj.risk_score if node_obj else 0.0,
                    "findings_count": len(node_obj.findings) if node_obj else 0,
                }
            })

        cy_edges = []
        for source, target, data in self.graph.edges(data=True):
            cy_edges.append({
                "data": {
                    "source": source,
                    "target": target,
                    "label": data.get("label", ""),
                    "type": data.get("edge_type", ""),
                }
            })

        return {"nodes": cy_nodes, "edges": cy_edges}
