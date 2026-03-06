"""
Azure authentication module for AZSploitMapper.

Uses Service Principal authentication (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
AZURE_TENANT_ID environment variables) as the primary auth method.

When running on Azure with a Managed Identity, it falls back to
ManagedIdentityCredential. DefaultAzureCredential is only used in
development when no Service Principal is configured.

This ensures the scanner always uses explicitly configured credentials
rather than accidentally using a developer's personal Azure session.
"""

import os
import logging

from azure.identity import (
    ClientSecretCredential,
    ManagedIdentityCredential,
    DefaultAzureCredential,
)
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient

logger = logging.getLogger("azsploitmapper.scanner.auth")


def get_azure_credential():
    """
    Returns an Azure credential based on available configuration.

    Priority order:
    1. Service Principal (AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID)
       -- Recommended for production. Scoped RBAC with Reader role only.
    2. Managed Identity (when running on Azure infrastructure)
       -- Used by ACI/AKS deployments with user-assigned identity.
    3. DefaultAzureCredential (development fallback)
       -- Uses az login, environment, or interactive browser.
       -- WARNING: This may use overprivileged personal credentials.

    For production: always set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
    and AZURE_TENANT_ID with a Service Principal that has minimal RBAC
    (Reader role on the target subscription only).
    """
    client_id = os.getenv("AZURE_CLIENT_ID", "")
    client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
    tenant_id = os.getenv("AZURE_TENANT_ID", "")

    # Option 1: Service Principal with client secret (recommended)
    if client_id and client_secret and tenant_id:
        logger.info("Using Service Principal authentication (client_id=%s...)", client_id[:8])
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    # Option 2: Managed Identity (Azure-hosted only)
    if os.getenv("IDENTITY_ENDPOINT"):
        logger.info("Using Managed Identity authentication")
        return ManagedIdentityCredential(
            client_id=client_id if client_id else None,
        )

    # Option 3: Development fallback
    logger.warning(
        "No Service Principal configured. Falling back to DefaultAzureCredential. "
        "This is NOT recommended for production -- set AZURE_CLIENT_ID, "
        "AZURE_CLIENT_SECRET, and AZURE_TENANT_ID environment variables."
    )
    return DefaultAzureCredential()


class AzureClients:
    """
    Factory class that creates and caches Azure management clients.

    Clients are created lazily (on first access) to avoid unnecessary
    API calls and memory usage when only a subset of clients is needed.
    Each client is used to discover and inspect a specific type of
    Azure resource (VMs, networks, storage, etc.).
    """

    def __init__(self, subscription_id: str):
        """
        Initialize the client factory with subscription ID and credential.

        Args:
            subscription_id: The Azure subscription ID to scan.
        """
        self._subscription_id = subscription_id
        self._credential = get_azure_credential()
        # Cache for lazy-initialized clients
        self._resource_client = None
        self._compute_client = None
        self._network_client = None
        self._storage_client = None
        self._authorization_client = None
        self._keyvault_client = None
        self._msi_client = None

    @property
    def subscription_id(self) -> str:
        """The Azure subscription ID being scanned."""
        return self._subscription_id

    @property
    def resource_client(self) -> ResourceManagementClient:
        """Client for listing resource groups and generic resources."""
        if self._resource_client is None:
            self._resource_client = ResourceManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._resource_client

    @property
    def compute_client(self) -> ComputeManagementClient:
        """Client for VMs, VM extensions, disks, and availability sets."""
        if self._compute_client is None:
            self._compute_client = ComputeManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._compute_client

    @property
    def network_client(self) -> NetworkManagementClient:
        """Client for VNets, subnets, NSGs, public IPs, and load balancers."""
        if self._network_client is None:
            self._network_client = NetworkManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._network_client

    @property
    def storage_client(self) -> StorageManagementClient:
        """Client for storage accounts, blob containers, and access policies."""
        if self._storage_client is None:
            self._storage_client = StorageManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._storage_client

    @property
    def authorization_client(self) -> AuthorizationManagementClient:
        """Client for role assignments and role definitions (RBAC)."""
        if self._authorization_client is None:
            self._authorization_client = AuthorizationManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._authorization_client

    @property
    def keyvault_client(self) -> KeyVaultManagementClient:
        """Client for Key Vaults and their access policies."""
        if self._keyvault_client is None:
            self._keyvault_client = KeyVaultManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._keyvault_client

    @property
    def msi_client(self) -> ManagedServiceIdentityClient:
        """Client for user-assigned and system-assigned managed identities."""
        if self._msi_client is None:
            self._msi_client = ManagedServiceIdentityClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._msi_client
