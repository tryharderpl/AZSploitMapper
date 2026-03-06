"""
Findings API routes - access security findings from a scan.

Findings are misconfigurations detected on resources (e.g. open SSH port,
missing encryption). Each finding has severity, description, and remediation.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException, Query


findings_router = APIRouter(prefix="/api", tags=["findings"])


@findings_router.get("/findings/{scan_id}")
def get_findings(
    request: Request,
    scan_id: str,
    severity: str | None = Query(
        default=None,
        description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    ),
    resource_type: str | None = Query(
        default=None,
        description="Filter by Azure resource type (e.g. Microsoft.Compute/virtualMachines)",
    ),
) -> dict:
    """
    Get all findings from a scan.

    Returns {"findings": [...]} with optional severity and resource_type filters.
    """
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = request.app.state.scan_results[scan_id]
    all_findings = data.get("findings", [])

    filtered = []
    for f in all_findings:
        if severity and f.get("severity") != severity:
            continue
        if resource_type and f.get("resource_type") != resource_type:
            continue
        filtered.append(f)

    return {"findings": filtered}
