"""
Rule engine - loads YAML rules and evaluates them against discovered resources.

The engine:
1. Loads all .yaml files from the rules directory
2. For each resource, finds rules matching its type
3. Runs the appropriate check function
4. Produces Finding objects for each match

Check functions are implemented as methods on the RuleEngine class.
Each check examines resource properties to determine if a misconfiguration exists.
"""

import hashlib
from pathlib import Path

import yaml

from azsploitmapper.scanner.rules.models import Rule, Finding


class RuleEngine:
    """
    Evaluates security rules against Azure resources.

    Usage:
        engine = RuleEngine(rules_dir="config/rules")
        engine.load_rules()
        findings = engine.evaluate(resources)
    """

    def __init__(self, rules_dir: str = "config/rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: list[Rule] = []
        # Map of check function names to their implementations
        self._checks = {
            "open_inbound_port": self._check_open_inbound_port,
            "public_ip_attached": self._check_public_ip_attached,
            "storage_public_access": self._check_storage_public_access,
            "storage_no_https": self._check_storage_no_https,
            "storage_no_cmk": self._check_storage_no_cmk,
            "storage_no_soft_delete": self._check_storage_no_soft_delete,
            "storage_weak_tls": self._check_storage_weak_tls,
            "identity_overprivileged": self._check_identity_overprivileged,
            "rbac_broad_scope": self._check_rbac_broad_scope,
            "identity_unused": self._check_identity_unused,
            "vm_password_auth": self._check_vm_password_auth,
            "vm_unmanaged_disk": self._check_vm_unmanaged_disk,
            "vm_internet_exposed": self._check_vm_internet_exposed,
            "kv_no_soft_delete": self._check_kv_no_soft_delete,
            "kv_no_purge_protection": self._check_kv_no_purge_protection,
            "kv_broad_access": self._check_kv_broad_access,
        }
        self._all_resources: list[dict] = []

    def load_rules(self) -> int:
        """
        Load all YAML rule files from the rules directory.

        Returns the total number of rules loaded.
        """
        self.rules = []
        if not self.rules_dir.exists():
            return 0

        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)

            if not data or "rules" not in data:
                continue

            for rule_data in data["rules"]:
                rule = Rule(
                    id=rule_data["id"],
                    name=rule_data["name"],
                    description=rule_data["description"],
                    resource_type=rule_data["resource_type"],
                    severity=rule_data["severity"],
                    check=rule_data["check"],
                    parameters=rule_data.get("parameters", {}),
                    remediation=rule_data.get("remediation", ""),
                    compliance=rule_data.get("compliance", {}),
                )
                self.rules.append(rule)

        return len(self.rules)

    def evaluate(self, resources: list[dict]) -> list[Finding]:
        """
        Evaluate all loaded rules against a list of resources.

        For each resource, finds matching rules (by resource_type) and
        runs the check function. If the check returns True, a Finding is created.
        """
        self._all_resources = resources
        findings = []

        for resource in resources:
            resource_type = resource.get("type", "")
            props = resource.get("properties", {})

            for rule in self.rules:
                if rule.resource_type != resource_type:
                    continue

                check_fn = self._checks.get(rule.check)
                if check_fn is None:
                    continue

                if check_fn(props, rule.parameters):
                    finding_id = hashlib.sha256(
                        f"{rule.id}:{resource['id']}".encode()
                    ).hexdigest()[:12]

                    finding = Finding(
                        id=finding_id,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        resource_id=resource["id"],
                        resource_name=resource["name"],
                        resource_type=resource_type,
                        description=rule.description,
                        remediation=rule.remediation,
                        compliance=rule.compliance,
                    )
                    findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Check functions: each returns True if the misconfiguration exists
    # ------------------------------------------------------------------

    def _check_open_inbound_port(self, props: dict, params: dict) -> bool:
        """Check if an NSG allows inbound traffic on a specific port from internet."""
        target_port = params.get("port", "*")
        target_source = params.get("source", "*")

        for rule in props.get("security_rules", []):
            if rule.get("direction") != "Inbound":
                continue
            if rule.get("access") != "Allow":
                continue

            source = rule.get("source_address_prefix", "")
            if source not in ("*", "0.0.0.0/0", "Internet", target_source):
                continue

            port = rule.get("destination_port_range", "")
            if port == "*" or port == target_port or target_port == "*":
                return True

        return False

    def _check_public_ip_attached(self, props: dict, _params: dict) -> bool:
        """Check if a public IP has an allocated address (is in use)."""
        return bool(props.get("ip_address"))

    def _check_storage_public_access(self, props: dict, _params: dict) -> bool:
        """Check if storage account allows public blob access."""
        return props.get("allow_blob_public_access", False) is True

    def _check_storage_no_https(self, props: dict, _params: dict) -> bool:
        """Check if storage account does not enforce HTTPS."""
        return props.get("enable_https_traffic_only", True) is False

    def _check_storage_no_cmk(self, props: dict, _params: dict) -> bool:
        """Check if storage uses Microsoft-managed keys instead of CMK."""
        encryption = props.get("encryption", {})
        return encryption.get("key_source", "").lower() == "microsoft.storage"

    def _check_storage_no_soft_delete(self, props: dict, _params: dict) -> bool:
        """Check if blob soft delete is not enabled."""
        blob_svc = props.get("blob_service_properties", {})
        if blob_svc:
            policy = blob_svc.get("delete_retention_policy", {})
            return not policy.get("enabled", False)
        return props.get("soft_delete_enabled", False) is False

    def _check_storage_weak_tls(self, props: dict, _params: dict) -> bool:
        """Check if storage account allows TLS 1.0 or 1.1."""
        tls = props.get("minimum_tls_version", "TLS1_2")
        return tls in ("TLS1_0", "TLS1_1")

    def _check_identity_overprivileged(self, props: dict, params: dict) -> bool:
        """Check if a managed identity has dangerous broad roles."""
        role_name = props.get("role_name", "")
        dangerous = params.get("dangerous_roles", [])
        return role_name in dangerous

    def _check_rbac_broad_scope(self, props: dict, _params: dict) -> bool:
        """Check if RBAC assignment is at subscription scope (not resource group)."""
        scope = props.get("scope", "")
        parts = scope.strip("/").split("/")
        # Subscription scope: /subscriptions/{id} (2 parts only)
        return len(parts) <= 2

    def _check_identity_unused(self, _props: dict, _params: dict) -> bool:
        """Placeholder: would check sign-in logs (requires Graph API)."""
        return False

    def _check_vm_password_auth(self, props: dict, _params: dict) -> bool:
        """Check if a Linux VM allows password authentication."""
        return props.get("disable_password_authentication", True) is False

    def _check_vm_unmanaged_disk(self, props: dict, _params: dict) -> bool:
        """Check if VM uses unmanaged disks."""
        return props.get("managed_disk", True) is False

    def _check_vm_internet_exposed(self, props: dict, _params: dict) -> bool:
        """Check if VM is reachable from internet via NIC -> Public IP chain."""
        nic_ids = props.get("network_interface_ids", [])
        if not nic_ids:
            return False
        pip_type = "Microsoft.Network/publicIPAddresses"
        nic_type = "Microsoft.Network/networkInterfaces"
        for res in self._all_resources:
            if res["type"] != nic_type:
                continue
            if res["id"] not in nic_ids:
                continue
            pip_id = res.get("properties", {}).get("public_ip_id", "")
            if pip_id:
                for pip_res in self._all_resources:
                    if pip_res["type"] == pip_type and pip_res["id"] == pip_id:
                        if pip_res.get("properties", {}).get("ip_address"):
                            return True
        return False

    def _check_kv_no_soft_delete(self, props: dict, _params: dict) -> bool:
        """Check if Key Vault has soft delete disabled."""
        return props.get("soft_delete_enabled", True) is False

    def _check_kv_no_purge_protection(self, props: dict, _params: dict) -> bool:
        """Check if Key Vault purge protection is disabled."""
        return props.get("purge_protection_enabled", False) is False

    def _check_kv_broad_access(self, props: dict, _params: dict) -> bool:
        """Check if Key Vault has access policies granting broad access."""
        policies = props.get("access_policies", [])
        return len(policies) > 3
