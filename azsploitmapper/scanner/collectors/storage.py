"""
Storage account collector for AZSploitMapper.

Collects Azure Storage accounts and extracts security-relevant properties.
Storage accounts hold blobs, files, queues, and tables; misconfigurations
can lead to data exposure, unauthorized access, or weak encryption.
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


class StorageCollector(BaseCollector):
    """
    Collector for Azure Storage accounts.

    Uses the Storage Management Client to list storage accounts either in a
    specific resource group or across the entire subscription. Extracts
    properties that matter for security: public access, encryption, TLS,
    and network rules.
    """

    def collect(self) -> list[dict]:
        """
        Discover all Storage accounts in scope and return them as resource dicts.

        Scope is determined by self._resource_group:
        - If set: list only storage accounts in that resource group.
        - If empty: list all storage accounts in the subscription.

        Returns:
            List of resource dicts, each with id, name, type, location,
            resource_group, and properties (storage-specific security data).
        """
        storage_client = self._clients.storage_client

        # Choose list method based on scope
        if self._resource_group:
            account_iterator = storage_client.storage_accounts.list_by_resource_group(
                self._resource_group
            )
        else:
            account_iterator = storage_client.storage_accounts.list()

        resources = []
        for account in account_iterator:
            resource_group = _parse_resource_group_from_id(account.id) if account.id else ""

            # Extract encryption details (who manages keys, which services are encrypted)
            encryption_services = None
            encryption_key_source = None
            if account.encryption:
                encryption_services = {}
                if account.encryption.services:
                    # blob, file, queue, table - which are encrypted
                    for svc in ["blob", "file", "queue", "table"]:
                        s = getattr(account.encryption.services, svc, None)
                        if s and getattr(s, "enabled", None):
                            encryption_services[svc] = True
                        else:
                            encryption_services[svc] = False
                encryption_key_source = getattr(
                    account.encryption, "key_source", "Microsoft.Storage"
                )
            encryption = {
                "services": encryption_services,
                "key_source": encryption_key_source,
            }

            # Extract network rule set (who can access: default, IP rules count)
            network_default_action = None
            network_ip_rules_count = 0
            if account.network_rule_set:
                network_default_action = getattr(
                    account.network_rule_set, "default_action", None
                )
                ip_rules = getattr(account.network_rule_set, "ip_rules", None) or []
                network_ip_rules_count = len(ip_rules)
            network_rule_set = {
                "default_action": network_default_action,
                "ip_rules_count": network_ip_rules_count,
            }

            blob_service_props = {}
            try:
                blob_svc = storage_client.blob_services.get_service_properties(
                    resource_group, account.name
                )
                if blob_svc and blob_svc.delete_retention_policy:
                    blob_service_props = {
                        "delete_retention_policy": {
                            "enabled": blob_svc.delete_retention_policy.enabled or False,
                            "days": blob_svc.delete_retention_policy.days or 0,
                        }
                    }
            except Exception:
                pass

            properties = {
                # kind: Storage, StorageV2, BlobStorage. BlobStorage = blob-only storage
                "kind": account.kind,
                # sku_name: Standard_LRS, Premium_LRS, etc. Affects redundancy and cost
                "sku_name": account.sku.name if account.sku else None,
                # allow_blob_public_access: True = anonymous read of blobs if container allows it.
                # SECURITY: False is recommended; True enables accidental data exposure
                "allow_blob_public_access": getattr(
                    account, "allow_blob_public_access", None
                ),
                # enable_https_traffic_only: True = HTTPS only. SECURITY: False allows unencrypted HTTP
                "enable_https_traffic_only": getattr(
                    account, "enable_https_traffic_only", None
                ),
                # encryption: which services use encryption and key source (Microsoft.Storage vs KeyVault)
                # SECURITY: KeyVault keys give more control; Microsoft.Storage is managed by Azure
                "encryption": encryption,
                # minimum_tls_version: TLS1_0, TLS1_1, TLS1_2. SECURITY: TLS1_2 recommended
                "minimum_tls_version": getattr(
                    account, "minimum_tls_version", None
                ),
                # network_rule_set: default_action Allow = any network; Deny = only whitelisted IPs/VNets
                # SECURITY: Allow + public blob access = high exposure risk
                "network_rule_set": network_rule_set,
                # allow_shared_key_access: True = storage account keys can be used for auth.
                # SECURITY: False forces Azure AD only; keys are long-lived and hard to rotate
                "allow_shared_key_access": getattr(
                    account, "allow_shared_key_access", None
                ),
                "blob_service_properties": blob_service_props,
            }

            resources.append(
                self._make_resource(
                    resource_id=account.id,
                    name=account.name,
                    resource_type="Microsoft.Storage/storageAccounts",
                    location=account.location or "",
                    resource_group=resource_group,
                    properties=properties,
                )
            )

        return resources
