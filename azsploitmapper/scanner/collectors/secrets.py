"""
Basic secret scanner for Azure resources.

Checks resource properties and metadata for exposed secrets such as API keys,
connection strings, private keys, and other sensitive values that should be
stored in Azure Key Vault instead of inline.
"""

import hashlib
import re

from azsploitmapper.scanner.rules.models import Finding

PATTERNS = [
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    ("AZURE_STORAGE_KEY", r"[A-Za-z0-9+/]{86}=="),
    ("GENERIC_API_KEY", r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})"),
    ("GENERIC_SECRET", r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})"),
    ("JWT_TOKEN", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
    ("PRIVATE_KEY", r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    ("CONNECTION_STRING", r"(?i)(DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)="),
]


class SecretScanner:
    """Scans resource properties and metadata for exposed secrets."""

    def __init__(self):
        self.compiled = [(name, re.compile(pat)) for name, pat in PATTERNS]

    def _make_id(self, rule_id: str, resource_id: str) -> str:
        """Generate a deterministic finding ID from rule + resource."""
        raw = f"{rule_id}:{resource_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def scan_resource(self, resource: dict) -> list[Finding]:
        """Scan a single resource dict for secret patterns."""
        findings: list[Finding] = []
        props_str = str(resource.get("properties", {}))
        resource_id = resource.get("id", "unknown")
        resource_name = resource_id.rsplit("/", 1)[-1] if "/" in resource_id else resource_id
        resource_type = resource.get("type", "")

        for secret_type, pattern in self.compiled:
            if pattern.search(props_str):
                rule_id = f"SECRET_{secret_type}"
                findings.append(Finding(
                    id=self._make_id(rule_id, resource_id),
                    rule_id=rule_id,
                    rule_name=f"Exposed {secret_type.replace('_', ' ').title()}",
                    severity="CRITICAL",
                    resource_id=resource_id,
                    resource_name=resource_name,
                    resource_type=resource_type,
                    description=(
                        f"Potential {secret_type.replace('_', ' ').lower()} "
                        f"detected in resource properties"
                    ),
                    remediation=(
                        "Remove the secret from resource properties. Use Azure "
                        "Key Vault to store secrets securely. Rotate the "
                        "exposed credential immediately."
                    ),
                    compliance={"cis_azure": "8.1", "nist": "IA-5"},
                ))
        return findings

    def scan_all(self, resources: list[dict]) -> list[Finding]:
        """Scan a list of resource dicts and return all findings."""
        all_findings: list[Finding] = []
        for resource in resources:
            all_findings.extend(self.scan_resource(resource))
        return all_findings
