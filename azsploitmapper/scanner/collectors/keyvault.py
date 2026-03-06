"""
Key Vault collector for AZSploitMapper.

Collects Azure Key Vaults and their access policies. Key Vaults store secrets,
keys, and certificates; misconfigurations can lead to credential theft or
unauthorized access to sensitive data.
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


def _extract_access_policies(access_policies: list) -> list[dict]:
    """
    Extract access policy details for security assessment.

    Each policy defines which principal (tenant_id + object_id) can perform
    which operations on secrets, keys, and certificates.

    Args:
        access_policies: List of AccessPolicyEntry objects from the vault.

    Returns:
        List of dicts with tenant_id, object_id, permissions (secrets, keys).
    """
    result = []
    for policy in access_policies or []:
        perms = policy.permissions if hasattr(policy, "permissions") else None
        secrets = []
        keys = []
        if perms:
            secrets = list(perms.secrets) if hasattr(perms, "secrets") and perms.secrets else []
            keys = list(perms.keys) if hasattr(perms, "keys") and perms.keys else []
        result.append({
            "tenant_id": getattr(policy, "tenant_id", None),
            "object_id": getattr(policy, "object_id", None),
            "permissions": {
                "secrets": secrets,
                "keys": keys,
            },
        })
    return result


class KeyVaultCollector(BaseCollector):
    """
    Collector for Azure Key Vaults.

    Uses the Key Vault Management Client to list vaults either in a specific
    resource group or across the subscription. When list_by_subscription
    returns limited data (e.g. GenericResource), fetches full vault details
    with vaults.get() for complete security properties.
    """

    def collect(self) -> list[dict]:
        """
        Discover all Key Vaults in scope and return them as resource dicts.

        Scope is determined by self._resource_group:
        - If set: list only vaults in that resource group.
        - If empty: list all vaults in the subscription.

        When listing by subscription, some SDK versions return limited data;
        we fetch full vault properties with get() when needed.

        Returns:
            List of resource dicts, each with id, name, type, location,
            resource_group, and properties (vault-specific security data).
        """
        keyvault_client = self._clients.keyvault_client
        resources = []

        if self._resource_group:
            # List by resource group: returns full Vault objects
            vault_iterator = keyvault_client.vaults.list_by_resource_group(
                self._resource_group
            )
            for vault in vault_iterator:
                resources.append(self._vault_to_resource(vault))
        else:
            # List by subscription: may return GenericResource or limited Vault objects
            vault_iterator = keyvault_client.vaults.list_by_subscription()

            for item in vault_iterator:
                # Check if we have full vault data (has properties with sku, etc.)
                if hasattr(item, "properties") and hasattr(item.properties, "sku"):
                    resources.append(self._vault_to_resource(item))
                else:
                    # Limited data: parse id to get resource_group and name, then fetch full vault
                    resource_id = getattr(item, "id", None) or ""
                    name = getattr(item, "name", None)
                    resource_group = _parse_resource_group_from_id(resource_id)
                    if resource_group and name:
                        try:
                            full_vault = keyvault_client.vaults.get(
                                resource_group, name
                            )
                            resources.append(self._vault_to_resource(full_vault))
                        except Exception:
                            # Fallback: create minimal resource from what we have
                            resources.append(
                                self._make_resource(
                                    resource_id=resource_id,
                                    name=name,
                                    resource_type="Microsoft.KeyVault/vaults",
                                    location=getattr(item, "location", "") or "",
                                    resource_group=resource_group,
                                    properties={"incomplete": True},
                                )
                            )
                    else:
                        # Cannot parse; skip
                        continue

        return resources

    def _vault_to_resource(self, vault) -> dict:
        """
        Convert a Vault object to the standard resource dict format.

        Extracts security-relevant properties: SKU, soft delete, purge protection,
        RBAC mode, and access policies.
        """
        resource_id = vault.id if vault.id else ""
        name = vault.name if vault.name else ""
        location = vault.location if vault.location else ""
        resource_group = _parse_resource_group_from_id(resource_id)

        props = vault.properties if hasattr(vault, "properties") else None

        sku_name = None
        tenant_id = None
        soft_delete_enabled = None
        purge_protection_enabled = None
        enable_rbac_authorization = None
        access_policies = []

        if props:
            sku_name = props.sku.name if hasattr(props, "sku") and props.sku else None
            tenant_id = getattr(props, "tenant_id", None)
            soft_delete_enabled = getattr(props, "soft_delete_enabled", None)
            purge_protection_enabled = getattr(props, "purge_protection_enabled", None)
            enable_rbac_authorization = getattr(
                props, "enable_rbac_authorization", None
            )
            access_policies = _extract_access_policies(
                getattr(props, "access_policies", None)
            )

        properties = {
            # sku_name: standard or premium. Premium supports HSM-backed keys
            "sku_name": sku_name,
            # tenant_id: Azure AD tenant for the vault
            "tenant_id": tenant_id,
            # soft_delete_enabled: True = deleted vaults retained for recovery period.
            # SECURITY: Enables recovery; without it, accidental delete is permanent
            "soft_delete_enabled": soft_delete_enabled,
            # purge_protection_enabled: True = cannot purge even after soft-delete period.
            # SECURITY: Prevents permanent deletion of secrets/keys
            "purge_protection_enabled": purge_protection_enabled,
            # enable_rbac_authorization: True = RBAC only; False = access policies used.
            # SECURITY: RBAC is more granular and auditable
            "enable_rbac_authorization": enable_rbac_authorization,
            # access_policies: legacy model; each entry grants object_id permissions.
            # SECURITY: Broad permissions (e.g. all secrets) = high risk
            "access_policies": access_policies,
        }

        return self._make_resource(
            resource_id=resource_id,
            name=name,
            resource_type="Microsoft.KeyVault/vaults",
            location=location,
            resource_group=resource_group,
            properties=properties,
        )
