"""
Network resource collector for AZSploitMapper.

Collects Network Security Groups (NSGs), Public IP addresses, and Network
Interfaces from Azure. These resources define network exposure and access
controls, which are critical for understanding attack surface.
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
        start = resource_id.index("resourceGroups/") + len("resourceGroups/")
        end = resource_id.index("/providers/", start) if "/providers/" in resource_id[start:] else len(resource_id)
        return resource_id[start:end]
    except (ValueError, IndexError):
        return ""


class NetworkCollector(BaseCollector):
    """
    Collector for Azure network resources: NSGs, Public IPs, and NICs.

    Combines three resource types into one list so the graph builder can
    establish relationships (e.g. NIC -> NSG, NIC -> Public IP, Public IP -> VM).
    """

    def collect(self) -> list[dict]:
        """
        Discover NSGs, Public IPs, and Network Interfaces in scope.

        For each resource type, scope is determined by self._resource_group:
        - If set: list only resources in that resource group.
        - If empty: list all resources in the subscription.

        Returns:
            Combined list of resource dicts for all three types.
        """
        network_client = self._clients.network_client
        rg = self._resource_group
        resources = []

        # 1. Network Security Groups (NSGs)
        # NSGs define firewall rules: which ports are open, from where, and to where.
        if rg:
            nsg_iterator = network_client.network_security_groups.list(rg)
        else:
            nsg_iterator = network_client.network_security_groups.list_all()

        for nsg in nsg_iterator:
            resource_group = _parse_resource_group_from_id(nsg.id) if nsg.id else ""

            # Extract security rules: each rule defines allow/deny, direction, ports, prefixes
            security_rules = []
            for rule in (nsg.security_rules or []):
                security_rules.append({
                    # Rule name for reference
                    "name": rule.name,
                    # Inbound or Outbound: Inbound = traffic from internet/VNet to resource
                    "direction": rule.direction,
                    # Allow or Deny
                    "access": rule.access,
                    # TCP, UDP, *, etc. * means all protocols
                    "protocol": rule.protocol,
                    # Source CIDR: * or 0.0.0.0/0 = any (dangerous if Allow)
                    "source_address_prefix": rule.source_address_prefix,
                    # Destination port range: 22 = SSH, 3389 = RDP, * = all ports
                    "destination_port_range": rule.destination_port_range,
                    # Lower number = higher priority; first match wins
                    "priority": rule.priority,
                })

            properties = {
                "security_rules": security_rules,
            }

            resources.append(
                self._make_resource(
                    resource_id=nsg.id,
                    name=nsg.name,
                    resource_type="Microsoft.Network/networkSecurityGroups",
                    location=nsg.location or "",
                    resource_group=resource_group,
                    properties=properties,
                )
            )

        # 2. Public IP Addresses
        # Public IPs expose resources to the internet. Critical for attack surface mapping.
        if rg:
            pip_iterator = network_client.public_ip_addresses.list(rg)
        else:
            pip_iterator = network_client.public_ip_addresses.list_all()

        for pip in pip_iterator:
            resource_group = _parse_resource_group_from_id(pip.id) if pip.id else ""

            # The actual IP address (if allocated)
            ip_address = pip.ip_address if pip.ip_address else None

            # Static = reserved; Dynamic = assigned when resource starts
            allocation_method = pip.public_ip_allocation_method if hasattr(pip, "public_ip_allocation_method") else None

            # Resource using this public IP (e.g. NIC, Load Balancer)
            associated_resource_id = None
            if pip.ip_configuration and hasattr(pip.ip_configuration, "id"):
                associated_resource_id = pip.ip_configuration.id

            properties = {
                "ip_address": ip_address,
                "allocation_method": allocation_method,
                "associated_resource_id": associated_resource_id,
            }

            resources.append(
                self._make_resource(
                    resource_id=pip.id,
                    name=pip.name,
                    resource_type="Microsoft.Network/publicIPAddresses",
                    location=pip.location or "",
                    resource_group=resource_group,
                    properties=properties,
                )
            )

        # 3. Network Interfaces (NICs)
        # NICs connect VMs to subnets. They can have private IP, public IP, and NSG.
        if rg:
            nic_iterator = network_client.network_interfaces.list(rg)
        else:
            nic_iterator = network_client.network_interfaces.list_all()

        for nic in nic_iterator:
            resource_group = _parse_resource_group_from_id(nic.id) if nic.id else ""

            # Primary private IP (used for internal communication)
            private_ip = None
            public_ip_id = None
            for ip_config in (nic.ip_configurations or []):
                private_ip = ip_config.private_ip_address if ip_config.private_ip_address else private_ip
                # Public IP reference: if set, this NIC is exposed to the internet
                if ip_config.public_ip_address and hasattr(ip_config.public_ip_address, "id"):
                    public_ip_id = ip_config.public_ip_address.id
                if private_ip and public_ip_id:
                    break

            # NSG attached to this NIC (defines inbound/outbound rules for this interface)
            nsg_id = None
            if nic.network_security_group and hasattr(nic.network_security_group, "id"):
                nsg_id = nic.network_security_group.id

            # VM this NIC is attached to (for linking NIC -> VM in the graph)
            vm_id = None
            if nic.virtual_machine and hasattr(nic.virtual_machine, "id"):
                vm_id = nic.virtual_machine.id

            properties = {
                "private_ip": private_ip,
                "public_ip_id": public_ip_id,
                "nsg_id": nsg_id,
                "vm_id": vm_id,
            }

            resources.append(
                self._make_resource(
                    resource_id=nic.id,
                    name=nic.name,
                    resource_type="Microsoft.Network/networkInterfaces",
                    location=nic.location or "",
                    resource_group=resource_group,
                    properties=properties,
                )
            )

        return resources
