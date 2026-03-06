"""
Base collector class for Azure resource discovery.

All resource collectors (VM, NSG, Storage, Key Vault, etc.) inherit from
BaseCollector. This ensures a consistent structure for every discovered
resource, which the graph builder and rule engine can rely on.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from azsploitmapper.scanner.auth import AzureClients


class BaseCollector(ABC):
    """
    Abstract base class for Azure resource collectors.

    Each concrete collector (e.g. VMCollector, NSGCollector) implements
    the collect() method to fetch resources of a specific type from Azure
    and return them in a standardized format.
    """

    def __init__(self, clients: "AzureClients", resource_group: str = ""):
        """
        Initialize the collector with Azure clients and optional scope.

        Args:
            clients: The AzureClients instance providing access to all
                     Azure management clients (compute, network, etc.).
            resource_group: If non-empty, limit collection to this resource
                            group only. Empty string means scan entire subscription.
        """
        self._clients = clients
        self._resource_group = resource_group

    @abstractmethod
    def collect(self) -> list[dict]:
        """
        Discover and return resources from Azure.

        Each collector implements this to call the appropriate Azure API
        (e.g. compute_client.virtual_machines.list_all) and convert the
        results into the standard resource dict format.

        Returns:
            A list of resource dicts, each with: id, name, type, location,
            resource_group, and properties (type-specific data).
        """
        pass

    def _make_resource(
        self,
        resource_id: str,
        name: str,
        resource_type: str,
        location: str,
        resource_group: str,
        properties: dict,
    ) -> dict:
        """
        Build a standardized resource dict for the graph and rule engine.

        All collectors use this helper so every resource has the same shape,
        making downstream processing (graph building, rule evaluation) simpler.

        Args:
            resource_id: Full Azure resource ID (e.g. /subscriptions/.../resourceGroups/.../providers/.../name).
            name: Short resource name.
            resource_type: Azure resource type (e.g. Microsoft.Compute/virtualMachines).
            location: Azure region (e.g. eastus).
            resource_group: Name of the resource group.
            properties: Dict of type-specific attributes (e.g. for a VM: size, os_type, public_ips).

        Returns:
            A dict with keys: id, name, type, location, resource_group, properties.
        """
        return {
            "id": resource_id,
            "name": name,
            "type": resource_type,
            "location": location,
            "resource_group": resource_group,
            "properties": properties,
        }
