"""
Compute resource collector for AZSploitMapper.

Collects Virtual Machines from Azure using the Compute Management API.
Each VM is described with properties relevant to security assessment:
size, OS type, authentication settings, network interfaces, and managed identity.
"""

from azsploitmapper.scanner.collectors.base import BaseCollector


def _parse_resource_group_from_id(resource_id: str) -> str:
    """
    Extract resource group name from an Azure resource ID.

    Azure resource IDs follow the pattern:
    /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}

    Args:
        resource_id: Full Azure resource ID string.

    Returns:
        Resource group name, or empty string if parsing fails.
    """
    if not resource_id or "resourceGroups/" not in resource_id:
        return ""
    try:
        # Find the segment between "resourceGroups/" and "/providers"
        start = resource_id.index("resourceGroups/") + len("resourceGroups/")
        end = resource_id.index("/providers/", start) if "/providers/" in resource_id[start:] else len(resource_id)
        return resource_id[start:end]
    except (ValueError, IndexError):
        return ""


class ComputeCollector(BaseCollector):
    """
    Collector for Azure Virtual Machines.

    Uses the Compute Management Client to list VMs either in a specific
    resource group or across the entire subscription. Extracts properties
    that matter for security: authentication method, exposed interfaces,
    and managed identity configuration.
    """

    def collect(self) -> list[dict]:
        """
        Discover all Virtual Machines in scope and return them as resource dicts.

        Scope is determined by self._resource_group:
        - If set: list only VMs in that resource group.
        - If empty: list all VMs in the subscription.

        Returns:
            List of resource dicts, each with id, name, type, location,
            resource_group, and properties (VM-specific security-relevant data).
        """
        compute_client = self._clients.compute_client

        # Choose list method based on scope
        if self._resource_group:
            vm_iterator = compute_client.virtual_machines.list(self._resource_group)
        else:
            vm_iterator = compute_client.virtual_machines.list_all()

        resources = []
        for vm in vm_iterator:
            # Parse resource group from the full resource ID
            resource_group = _parse_resource_group_from_id(vm.id) if vm.id else ""

            # Extract OS type: Windows or Linux (affects attack surface and tools)
            os_type = None
            if vm.os_profile:
                # os_profile.os_type exists in newer API versions
                os_type = getattr(vm.os_profile, "os_type", None)
                if os_type is None:
                    # Infer from presence of windows_configuration vs linux_configuration
                    if getattr(vm.os_profile, "windows_configuration", None):
                        os_type = "Windows"
                    elif getattr(vm.os_profile, "linux_configuration", None):
                        os_type = "Linux"
                    else:
                        os_type = "Unknown"

            # Admin username: primary credential target for brute-force or phishing
            admin_username = None
            if vm.os_profile:
                admin_username = getattr(vm.os_profile, "admin_username", None)

            # Password auth disabled = SSH key only (Linux). Reduces password spray risk.
            disable_password_authentication = None
            if vm.os_profile and getattr(vm.os_profile, "linux_configuration", None):
                lc = vm.os_profile.linux_configuration
                disable_password_authentication = getattr(
                    lc, "disable_password_authentication", None
                )

            # Network interface IDs: used to link VM to NICs, public IPs, NSGs
            network_interface_ids = []
            if vm.network_profile:
                nics = getattr(vm.network_profile, "network_interfaces", None) or []
                for nic_ref in nics:
                    if hasattr(nic_ref, "id") and nic_ref.id:
                        network_interface_ids.append(nic_ref.id)

            # Managed identity: system-assigned or user-assigned. Important for
            # privilege escalation and lateral movement (identity can access other Azure resources).
            identity_type = None
            identity_ids = []
            if vm.identity:
                identity_type = getattr(vm.identity, "type", None)
                if identity_type and hasattr(vm.identity, "user_assigned_identities"):
                    uai = vm.identity.user_assigned_identities or {}
                    identity_ids = list(uai.keys())

            properties = {
                # VM size (e.g. Standard_B2s): affects cost and performance; some sizes have GPU/accelerators
                "size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                # Windows vs Linux: different attack tools and common misconfigurations
                "os_type": os_type,
                # Default admin account name: often targeted in credential attacks
                "admin_username": admin_username,
                # True = SSH keys only; False = password auth enabled (weaker)
                "disable_password_authentication": disable_password_authentication,
                # Links to NICs; each NIC can have public IP and NSG
                "network_interface_ids": network_interface_ids,
                # "SystemAssigned", "UserAssigned", "SystemAssigned,UserAssigned", or None
                "identity_type": identity_type,
                # Resource IDs of user-assigned managed identities
                "identity_ids": identity_ids,
            }

            resources.append(
                self._make_resource(
                    resource_id=vm.id,
                    name=vm.name,
                    resource_type="Microsoft.Compute/virtualMachines",
                    location=vm.location or "",
                    resource_group=resource_group,
                    properties=properties,
                )
            )

        return resources
