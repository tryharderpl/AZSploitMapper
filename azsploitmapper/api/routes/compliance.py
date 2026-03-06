"""Compliance API routes."""
from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException
from azsploitmapper.compliance.mapper import ComplianceMapper

compliance_router = APIRouter(prefix="/api", tags=["compliance"])

@compliance_router.get("/compliance/{scan_id}")
def get_compliance(request: Request, scan_id: str) -> dict:
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = request.app.state.scan_results[scan_id]
    findings = data.get("findings", [])
    resources = data.get("resources", [])
    mapper = ComplianceMapper()
    return mapper.map_findings(findings, total_resources=len(resources))
