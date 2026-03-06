"""
Tests for the YAML rule engine.

Verifies that rules correctly detect misconfigurations in mock resources
without needing an Azure connection.
"""

from pathlib import Path

from azsploitmapper.scanner.rules.engine import RuleEngine


# Resolve the config/rules directory relative to the project root
RULES_DIR = Path(__file__).resolve().parent.parent / "config" / "rules"


def test_load_rules():
    """Rule engine should load all YAML rules from the config directory."""
    engine = RuleEngine(rules_dir=str(RULES_DIR))
    count = engine.load_rules()
    assert count > 0, "No rules loaded from config/rules/"


def test_detect_open_ssh():
    """Should detect an NSG with SSH open to the internet."""
    engine = RuleEngine(rules_dir=str(RULES_DIR))
    engine.load_rules()

    resources = [
        {
            "id": "/nsg/open-ssh",
            "name": "nsg-open-ssh",
            "type": "Microsoft.Network/networkSecurityGroups",
            "location": "westeurope",
            "resource_group": "rg-test",
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
        }
    ]

    findings = engine.evaluate(resources)
    rule_ids = [f.rule_id for f in findings]
    assert "NSG_OPEN_SSH" in rule_ids


def test_detect_storage_public_access():
    """Should detect a storage account with public blob access."""
    engine = RuleEngine(rules_dir=str(RULES_DIR))
    engine.load_rules()

    resources = [
        {
            "id": "/storage/public",
            "name": "sa-public",
            "type": "Microsoft.Storage/storageAccounts",
            "location": "westeurope",
            "resource_group": "rg-test",
            "properties": {
                "allow_blob_public_access": True,
                "enable_https_traffic_only": True,
            },
        }
    ]

    findings = engine.evaluate(resources)
    rule_ids = [f.rule_id for f in findings]
    assert "STORAGE_PUBLIC_ACCESS" in rule_ids


def test_detect_vm_password_auth():
    """Should detect a VM using password authentication."""
    engine = RuleEngine(rules_dir=str(RULES_DIR))
    engine.load_rules()

    resources = [
        {
            "id": "/vm/password",
            "name": "vm-weak",
            "type": "Microsoft.Compute/virtualMachines",
            "location": "westeurope",
            "resource_group": "rg-test",
            "properties": {
                "disable_password_authentication": False,
                "os_type": "Linux",
            },
        }
    ]

    findings = engine.evaluate(resources)
    rule_ids = [f.rule_id for f in findings]
    assert "VM_PASSWORD_AUTH" in rule_ids


def test_no_false_positive_on_secure_nsg():
    """Should NOT flag a properly configured NSG."""
    engine = RuleEngine(rules_dir=str(RULES_DIR))
    engine.load_rules()

    resources = [
        {
            "id": "/nsg/secure",
            "name": "nsg-secure",
            "type": "Microsoft.Network/networkSecurityGroups",
            "location": "westeurope",
            "resource_group": "rg-test",
            "properties": {
                "security_rules": [
                    {
                        "name": "AllowSSHFromOffice",
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source_address_prefix": "10.0.0.0/24",
                        "destination_port_range": "22",
                        "priority": 100,
                    }
                ]
            },
        }
    ]

    findings = engine.evaluate(resources)
    assert len(findings) == 0, f"False positive: {[f.rule_id for f in findings]}"


if __name__ == "__main__":
    test_load_rules()
    test_detect_open_ssh()
    test_detect_storage_public_access()
    test_detect_vm_password_auth()
    test_no_false_positive_on_secure_nsg()
    print("All rule engine tests passed!")
