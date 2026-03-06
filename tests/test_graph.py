"""
Tests for the graph builder and attack path finder.

These tests use mock resources (no Azure connection needed) to verify
that the graph correctly models resource relationships and finds
attack paths.
"""

from azsploitmapper.graph.builder import GraphBuilder
from azsploitmapper.graph.attack_paths import AttackPathFinder
from azsploitmapper.graph.risk_scorer import RiskScorer


def make_mock_resources():
    """
    Create a set of mock Azure resources that form a known attack path:
    Internet -> PublicIP -> NIC -> VM -> ManagedIdentity -> RoleAssignment -> Storage
    """
    return [
        {
            "id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Network/publicIPAddresses/pip-vm",
            "name": "pip-vm",
            "type": "Microsoft.Network/publicIPAddresses",
            "location": "westeurope",
            "resource_group": "rg-lab",
            "properties": {
                "ip_address": "20.1.2.3",
                "allocation_method": "Static",
                "associated_resource_id": "",
            },
        },
        {
            "id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Network/networkSecurityGroups/nsg-open",
            "name": "nsg-open",
            "type": "Microsoft.Network/networkSecurityGroups",
            "location": "westeurope",
            "resource_group": "rg-lab",
            "properties": {
                "security_rules": [
                    {
                        "name": "AllowSSH",
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source_address_prefix": "*",
                        "destination_port_range": "22",
                        "priority": 100,
                    }
                ]
            },
        },
        {
            "id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Network/networkInterfaces/nic-vm",
            "name": "nic-vm",
            "type": "Microsoft.Network/networkInterfaces",
            "location": "westeurope",
            "resource_group": "rg-lab",
            "properties": {
                "private_ip": "10.0.0.4",
                "public_ip_id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Network/publicIPAddresses/pip-vm",
                "nsg_id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Network/networkSecurityGroups/nsg-open",
                "vm_id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Compute/virtualMachines/vm-lab",
            },
        },
        {
            "id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Compute/virtualMachines/vm-lab",
            "name": "vm-lab",
            "type": "Microsoft.Compute/virtualMachines",
            "location": "westeurope",
            "resource_group": "rg-lab",
            "properties": {
                "size": "Standard_D2s_v3",
                "os_type": "Linux",
                "admin_username": "azureuser",
                "disable_password_authentication": False,
                "identity_type": "UserAssigned",
                "identity_ids": [
                    "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-lab"
                ],
                "network_interface_ids": [
                    "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Network/networkInterfaces/nic-vm"
                ],
            },
        },
        {
            "id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-lab",
            "name": "id-lab",
            "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
            "location": "westeurope",
            "resource_group": "rg-lab",
            "properties": {
                "client_id": "aaaa-bbbb",
                "principal_id": "pppp-1111",
                "tenant_id": "tttt-xxxx",
            },
        },
        {
            "id": "/subscriptions/xxx/providers/Microsoft.Authorization/roleAssignments/role-reader",
            "name": "role-reader",
            "type": "Microsoft.Authorization/roleAssignments",
            "location": "westeurope",
            "resource_group": "",
            "properties": {
                "principal_id": "pppp-1111",
                "role_name": "Reader",
                "role_definition_id": "/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/acdd72a7",
                "scope": "/subscriptions/xxx",
            },
        },
        {
            "id": "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Storage/storageAccounts/salabdata",
            "name": "salabdata",
            "type": "Microsoft.Storage/storageAccounts",
            "location": "westeurope",
            "resource_group": "rg-lab",
            "properties": {
                "kind": "StorageV2",
                "allow_blob_public_access": True,
                "enable_https_traffic_only": True,
            },
        },
    ]


def test_graph_builds_nodes():
    """Graph should create a node for each resource plus Internet."""
    builder = GraphBuilder()
    resources = make_mock_resources()
    graph = builder.build(resources)

    # 7 resources + 1 Internet node
    assert graph.number_of_nodes() >= 8
    assert "internet" in graph.nodes


def test_graph_creates_edges():
    """Graph should create edges linking resources together."""
    builder = GraphBuilder()
    resources = make_mock_resources()
    graph = builder.build(resources)

    # Should have edges (Internet->PIP, PIP->NIC, NIC->VM, VM->Identity, Identity->Role, Role->Storage)
    assert graph.number_of_edges() >= 5


def test_attack_path_found():
    """Should find at least one attack path from Internet to Storage."""
    builder = GraphBuilder()
    resources = make_mock_resources()
    graph = builder.build(resources)

    finder = AttackPathFinder(graph)
    paths = finder.find_all_paths()

    assert len(paths) >= 1

    # The path should start at internet and end at storage
    storage_id = "/subscriptions/xxx/resourceGroups/rg-lab/providers/Microsoft.Storage/storageAccounts/salabdata"
    targets = [p.target for p in paths]
    assert storage_id in targets


def test_risk_scoring():
    """Risk scorer should assign non-zero scores to paths."""
    builder = GraphBuilder()
    resources = make_mock_resources()
    graph = builder.build(resources)
    nodes = builder.get_nodes()

    finder = AttackPathFinder(graph)
    paths = finder.find_all_paths()

    scorer = RiskScorer()
    scored_paths = scorer.score_paths(paths, nodes)

    for path in scored_paths:
        assert path.risk_score > 0.0
        assert path.risk_score <= 10.0


def test_cytoscape_export():
    """Cytoscape JSON export should have nodes and edges arrays."""
    builder = GraphBuilder()
    resources = make_mock_resources()
    builder.build(resources)

    cy_json = builder.to_cytoscape_json()
    assert "nodes" in cy_json
    assert "edges" in cy_json
    assert len(cy_json["nodes"]) >= 8


def test_path_description():
    """Attack path should have a human-readable description."""
    builder = GraphBuilder()
    resources = make_mock_resources()
    graph = builder.build(resources)

    finder = AttackPathFinder(graph)
    paths = finder.find_all_paths()

    for path in paths:
        assert " -> " in path.description
        assert "Internet" in path.description


if __name__ == "__main__":
    test_graph_builds_nodes()
    test_graph_creates_edges()
    test_attack_path_found()
    test_risk_scoring()
    test_cytoscape_export()
    test_path_description()
    print("All tests passed!")
