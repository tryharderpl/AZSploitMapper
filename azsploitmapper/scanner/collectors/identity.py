"""
Identity and RBAC collector for AZSploitMapper.

Collects Managed Identities (user-assigned) and RBAC Role Assignments.
These resources define who (or what) can access Azure resources; understanding
identity and permissions is critical for privilege escalation and lateral movement.
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
        end = (
            resource_id.index("/providers/", start)
            if "/providers/" in resource_id[start:]
            else len(resource_id)
        )
        return resource_id[start:end]
    except (ValueError, IndexError):
        return ""


class IdentityCollector(BaseCollector):
    """
    Collector for Azure Managed Identities and RBAC Role Assignments.

    Combines two resource types into one list:
    1. User-assigned Managed Identities (can be attached to VMs, apps, etc.)
    2. Role Assignments (who has what permission at what scope)

    RBAC read may be restricted for some principals; errors are caught and
    logged so the scan continues with partial data.
    """

    def collect(self) -> list[dict]:
        """
        Discover Managed Identities and Role Assignments in scope.

        Managed Identities: listed by resource group or subscription.
        Role Assignments: listed at subscription scope (may require elevated permissions).

        Returns:
            Combined list of resource dicts for identities and role assignments.
        """
        resources = []

        # 1. User-assigned Managed Identities
        # These identities can be assigned to VMs, App Services, etc. and grant
        # access to other Azure resources (Key Vault, Storage, etc.) without secrets.
        try:
            msi_client = self._clients.msi_client
            if self._resource_group:
                identity_iterator = msi_client.user_assigned_identities.list_by_resource_group(
                    self._resource_group
                )
            else:
                identity_iterator = msi_client.user_assigned_identities.list_by_subscription()

            for identity in identity_iterator:
                resource_group = _parse_resource_group_from_id(identity.id) if identity.id else ""

                resources.append(
                    self._make_resource(
                        resource_id=identity.id,
                        name=identity.name,
                        resource_type="Microsoft.ManagedIdentity/userAssignedIdentities",
                        location=identity.location or "",
                        resource_group=resource_group,
                        properties={
                            # client_id: used by apps to request tokens for this identity
                            "client_id": identity.client_id,
                            # principal_id: used in RBAC role assignments
                            "principal_id": identity.principal_id,
                            # tenant_id: Azure AD tenant where the identity lives
                            "tenant_id": identity.tenant_id,
                        },
                    )
                )
        except Exception as e:
            # Log but continue; MSI read might fail if permissions are limited
            pass  # In production, log: "Failed to list managed identities: {e}"

        # 2. RBAC Role Assignments
        # Each assignment grants a principal (user, group, service principal, managed identity)
        # a role (e.g. Owner, Contributor) at a scope (subscription, RG, or resource).
        try:
            auth_client = self._clients.authorization_client
            subscription_id = self._clients.subscription_id
            scope = f"/subscriptions/{subscription_id}"

            assignment_iterator = auth_client.role_assignments.list_for_scope(scope)

            for assignment in assignment_iterator:
                # Resolve role_definition_id to human-readable role name
                role_name = None
                try:
                    role_def = auth_client.role_definitions.get_by_id(
                        assignment.role_definition_id
                    )
                    role_name = role_def.role_name if role_def else None
                except Exception:
                    role_name = None  # Keep None if we cannot resolve

                # principal_type: User, Group, ServicePrincipal, ForeignGroup
                principal_type = getattr(assignment, "principal_type", None)

                resources.append(
                    self._make_resource(
                        resource_id=assignment.id,
                        name=assignment.name or assignment.id,
                        resource_type="Microsoft.Authorization/roleAssignments",
                        location="",  # Role assignments are subscription-level, no region
                        resource_group="",
                        properties={
                            "principal_id": assignment.principal_id,
                            "principal_type": principal_type,
                            "role_name": role_name,
                            "role_definition_id": assignment.role_definition_id,
                            "scope": assignment.scope,
                        },
                    )
                )
        except Exception as e:
            # RBAC read often requires Reader or User Access Administrator;
            # limited principals may not have permission to list role assignments
            pass  # In production, log: "Failed to list role assignments: {e}"

        return resources
