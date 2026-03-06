"""
AZSploitMapper API - FastAPI REST endpoints and web dashboard.

The API provides endpoints for:
- Creating and retrieving security scans
- Accessing resources, attack paths, findings, and compliance data
- Serving the web frontend (dashboard, graph, findings, compliance pages)
"""

from __future__ import annotations

from azsploitmapper.api.app import create_app

__all__ = ["create_app"]
