"""
API route modules - export all routers for inclusion in the FastAPI app.

Each router handles a specific domain:
- scans: Create and list security scans
- resources: Access discovered Azure resources
- paths: Attack paths and graph visualization data
- findings: Security findings and misconfigurations
- compliance: Compliance framework summaries
"""

from __future__ import annotations

from azsploitmapper.api.routes.scans import scans_router
from azsploitmapper.api.routes.resources import resources_router
from azsploitmapper.api.routes.paths import paths_router
from azsploitmapper.api.routes.findings import findings_router
from azsploitmapper.api.routes.compliance import compliance_router

__all__ = [
    "scans_router",
    "resources_router",
    "paths_router",
    "findings_router",
    "compliance_router",
]
