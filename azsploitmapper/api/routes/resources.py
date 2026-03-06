"""
Resource API routes - access discovered Azure resources from a scan.

These endpoints allow you to:
- GET /api/resources/{scan_id}: List all resources from a scan
- GET /api/resources/{scan_id}/{resource_id}: Get details for a single resource
"""

from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException


resources_router = APIRouter(prefix="/api", tags=["resources"])


@resources_router.get("/resources/{scan_id}")
def list_resources(request: Request, scan_id: str) -> list[dict]:
    """
    List all Azure resources discovered in a scan.

    Returns the full list of resources with id, name, type, location,
    resource_group, and properties.
    """
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = request.app.state.scan_results[scan_id]
    return data["resources"]


@resources_router.get("/resources/{scan_id}/{resource_id:path}")
def get_resource(
    request: Request, scan_id: str, resource_id: str
) -> dict:
    """
    Get details for a single resource by its Azure resource ID.

    The resource_id is a path parameter (can contain slashes) since
    Azure resource IDs have the form:
    /subscriptions/.../resourceGroups/.../providers/.../resourceName
    """
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = request.app.state.scan_results[scan_id]
    resources = data["resources"]

    # Find resource by ID (Azure IDs are case-insensitive for comparison)
    for res in resources:
        if res["id"].lower() == resource_id.lower():
            return res

    raise HTTPException(
        status_code=404, detail="Resource not found in scan"
    )
