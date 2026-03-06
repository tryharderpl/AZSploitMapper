"""
Compliance mapper - maps findings to security frameworks.

Supported frameworks:
- CIS Azure Benchmark v2.1.0: Industry-standard security configuration guidelines
- NIST SP 800-53 Rev. 5: Federal cybersecurity framework
- PCI DSS v4.0.1: Payment Card Industry Data Security Standard for financial industry

The mapper starts with the FULL set of controls from benchmarks.py (all PASS),
then marks controls as FAIL when a matching finding is encountered.  Controls
with no matching findings remain PASS, giving a complete compliance picture.
"""

from azsploitmapper.compliance.benchmarks import (
    CIS_AZURE_CONTROLS,
    NIST_CONTROLS,
    PCI_DSS_CONTROLS,
)


class ComplianceMapper:
    """
    Maps security findings to compliance framework controls.

    Usage:
        mapper = ComplianceMapper()
        report = mapper.map_findings(findings, total_resources)
    """

    FRAMEWORK_DEFS = {
        "cis_azure": {
            "name": "CIS Azure Benchmark v2.1.0",
            "controls": CIS_AZURE_CONTROLS,
            "group_key": "category",
        },
        "nist": {
            "name": "NIST SP 800-53",
            "controls": NIST_CONTROLS,
            "group_key": "family",
        },
        "pci_dss": {
            "name": "PCI DSS v4.0.1",
            "controls": PCI_DSS_CONTROLS,
            "group_key": "category",
        },
    }

    def map_findings(self, findings: list[dict], total_resources: int) -> dict:
        """
        Generate a compliance report from findings.

        Args:
            findings: List of finding dicts (each with 'compliance' key)
            total_resources: Total number of resources scanned

        Returns:
            {
              "frameworks": {
                "cis_azure": {
                  "name": "...",
                  "controls": { control_id: { title, category, status, fail_count, affected_resources, description } },
                  "categories": { cat: { total, passing, failing } },
                  "summary": { total, passing, failing, pass_rate }
                },
                "nist": { ... }
              },
              "summary": { total_controls, passing, failing, overall_pass_rate, total_resources, total_findings }
            }
        """
        frameworks = {}

        for fw_key, fw_def in self.FRAMEWORK_DEFS.items():
            controls_out = {}
            group_key = fw_def["group_key"]

            # Seed every control as PASS
            for ctrl_id, meta in fw_def["controls"].items():
                controls_out[ctrl_id] = {
                    "title": meta["title"],
                    "category": meta.get(group_key, "Other"),
                    "status": "PASS",
                    "findings_count": 0,
                    "affected_resources": [],
                    "description": meta["description"],
                }

            # Walk findings and mark matched controls as FAIL
            for finding in findings:
                compliance = finding.get("compliance", {})
                ctrl_id = compliance.get(fw_key)
                if ctrl_id is None or ctrl_id not in controls_out:
                    continue

                ctrl = controls_out[ctrl_id]
                ctrl["status"] = "FAIL"
                ctrl["findings_count"] += 1

                resource_id = finding.get("resource_id", "unknown")
                if resource_id not in ctrl["affected_resources"]:
                    ctrl["affected_resources"].append(resource_id)

            # Build category / family grouping
            categories: dict[str, dict] = {}
            for ctrl in controls_out.values():
                cat = ctrl["category"]
                if cat not in categories:
                    categories[cat] = {"total": 0, "passing": 0, "failing": 0}
                categories[cat]["total"] += 1
                if ctrl["status"] == "PASS":
                    categories[cat]["passing"] += 1
                else:
                    categories[cat]["failing"] += 1

            total = len(controls_out)
            failing = sum(1 for c in controls_out.values() if c["status"] == "FAIL")
            passing = total - failing
            pass_rate = round(passing / total * 100, 1) if total > 0 else 100.0

            frameworks[fw_key] = {
                "name": fw_def["name"],
                "controls": controls_out,
                "categories": categories,
                "summary": {
                    "total": total,
                    "passing": passing,
                    "failing": failing,
                    "pass_rate": pass_rate,
                },
            }

        # Overall summary across all frameworks
        total_controls = sum(
            fw["summary"]["total"] for fw in frameworks.values()
        )
        total_passing = sum(
            fw["summary"]["passing"] for fw in frameworks.values()
        )
        total_failing = sum(
            fw["summary"]["failing"] for fw in frameworks.values()
        )
        overall_pass_rate = (
            round(total_passing / total_controls * 100, 1)
            if total_controls > 0
            else 100.0
        )

        return {
            "frameworks": frameworks,
            "summary": {
                "total_controls": total_controls,
                "passing": total_passing,
                "failing": total_failing,
                "overall_pass_rate": overall_pass_rate,
                "total_resources": total_resources,
                "total_findings": len(findings),
            },
        }
