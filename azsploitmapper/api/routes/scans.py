"""
Scan API routes - create and retrieve security scans.

Security features:
- Subscription ID validated as UUID format
- Subscription ID checked against configured AZURE_SUBSCRIPTION_ID
- Resource group name validated (alphanumeric, hyphens, underscores, max 90 chars)
- Rate limiting via in-memory counter (max 5 scans per minute)
- Audit logging of all scan triggers
- Generic error messages (no internal details leaked)
"""

from __future__ import annotations

import os
import re
import time
from uuid import uuid4

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, field_validator

from azsploitmapper.scanner.orchestrator import ScanOrchestrator
from azsploitmapper.graph.builder import GraphBuilder
from azsploitmapper.graph.attack_paths import AttackPathFinder
from azsploitmapper.graph.risk_scorer import RiskScorer
from azsploitmapper.db.database import save_scan
from azsploitmapper.logging_config import get_audit_logger

audit = get_audit_logger()
scans_router = APIRouter(prefix="/api", tags=["scans"])

# Simple in-memory rate limiter for scan endpoint
_scan_timestamps: list[float] = []
SCAN_RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "5"))  # max scans per minute

# UUID regex pattern for subscription ID validation
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Resource group name validation (Azure rules: 1-90 chars, alphanumeric/hyphens/underscores/periods/parens)
RG_PATTERN = re.compile(r"^[a-zA-Z0-9._\-()]{1,90}$")


class ScanRequest(BaseModel):
    """Request body for creating a new scan with input validation."""

    subscription_id: str
    resource_group: str = ""

    @field_validator("subscription_id")
    @classmethod
    def validate_subscription_id(cls, v: str) -> str:
        """Ensure subscription_id is a valid UUID format."""
        v = v.strip()
        if not UUID_PATTERN.match(v):
            raise ValueError(
                "subscription_id must be a valid UUID "
                "(e.g. 12345678-1234-1234-1234-123456789abc)"
            )
        return v

    @field_validator("resource_group")
    @classmethod
    def validate_resource_group(cls, v: str) -> str:
        """Validate resource group name format if provided."""
        v = v.strip()
        if v and not RG_PATTERN.match(v):
            raise ValueError(
                "resource_group must be 1-90 characters, "
                "alphanumeric, hyphens, underscores, periods, or parentheses"
            )
        return v


def _check_rate_limit():
    """Check if the scan rate limit has been exceeded."""
    now = time.time()
    # Remove timestamps older than 60 seconds
    while _scan_timestamps and _scan_timestamps[0] < now - 60:
        _scan_timestamps.pop(0)

    if len(_scan_timestamps) >= SCAN_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {SCAN_RATE_LIMIT} scans per minute.",
        )

    _scan_timestamps.append(now)


def _validate_subscription_access(subscription_id: str):
    """
    Verify the requested subscription matches the configured one.

    This prevents users from scanning arbitrary subscriptions
    using the server's Azure credentials (SSRF prevention).
    """
    allowed_sub = os.getenv("AZURE_SUBSCRIPTION_ID", "")
    if allowed_sub and subscription_id.lower() != allowed_sub.lower():
        audit.warning(
            "Scan blocked: requested sub=%s does not match configured sub=%s",
            subscription_id, allowed_sub,
        )
        raise HTTPException(
            status_code=403,
            detail="Subscription ID does not match the configured subscription. "
                   "Set AZURE_SUBSCRIPTION_ID to allow scanning this subscription.",
        )


@scans_router.post("/scan")
def create_scan(request: Request, body: ScanRequest) -> dict:
    """
    Start a new Azure security scan.

    Request body (JSON):
        subscription_id (required): Azure subscription UUID to scan
        resource_group (optional): Limit scan to a specific resource group

    Returns:
        scan_id, resource_count, path_count, findings_count
    """
    # Rate limiting
    _check_rate_limit()

    subscription_id = body.subscription_id
    resource_group = body.resource_group

    # Authorization check -- only scan the configured subscription
    _validate_subscription_access(subscription_id)

    # Get user identity for audit log
    user = getattr(request.state, "user_email", "unknown")
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip and request.client:
        client_ip = request.client.host

    audit.info(
        "Scan triggered: user=%s ip=%s sub=%s rg=%s",
        user, client_ip, subscription_id, resource_group or "(all)",
    )

    try:
        # Create orchestrator and run the scan
        orchestrator = ScanOrchestrator(
            subscription_id=subscription_id,
            resource_group=resource_group,
        )
        scan_output = orchestrator.run_scan()
    except Exception:
        audit.error(
            "Scan failed: user=%s sub=%s", user, subscription_id,
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail="Scan failed. Check server logs for details.",
        )

    resources = scan_output["resources"]
    resource_counts = scan_output["resource_counts"]
    findings = scan_output.get("findings", [])

    # Build the attack graph from discovered resources
    graph_builder = GraphBuilder()
    graph = graph_builder.build(resources)
    nodes = graph_builder.get_nodes()

    # Attach findings to their respective graph nodes
    for finding in findings:
        node = nodes.get(finding.resource_id)
        if node:
            node.findings.append(finding.to_dict())

    # Find all attack paths from Internet to sensitive targets
    path_finder = AttackPathFinder(graph=graph)
    paths = path_finder.find_all_paths()

    # Score each path based on length, severity, and target value
    risk_scorer = RiskScorer()
    scored_paths = risk_scorer.score_paths(paths, nodes)

    findings_count = len(findings)

    # Generate unique scan ID
    scan_id = str(uuid4())

    # Store results in app state (LimitedScanStore handles eviction)
    scan_store = {
        "scan_id": scan_id,
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "resources": resources,
        "resource_counts": resource_counts,
        "graph": graph,
        "nodes": nodes,
        "paths": scored_paths,
        "findings": [f.to_dict() for f in findings],
        "cytoscape_json": graph_builder.to_cytoscape_json(),
    }
    request.app.state.scan_results[scan_id] = scan_store

    # Persist to SQLite so the scan survives restarts
    save_scan(request.app.state.db_engine, scan_id, scan_store)

    audit.info(
        "Scan complete: scan_id=%s resources=%d paths=%d findings=%d",
        scan_id[:8], len(resources), len(scored_paths), findings_count,
    )

    return {
        "scan_id": scan_id,
        "resource_count": len(resources),
        "path_count": len(scored_paths),
        "findings_count": findings_count,
    }


@scans_router.get("/scans")
def list_scans(request: Request) -> dict:
    """List all scans with summary information."""
    results = request.app.state.scan_results
    summaries = []
    for sid, data in results.items():
        summaries.append({
            "scan_id": sid,
            "subscription_id": data.get("subscription_id", ""),
            "resource_group": data.get("resource_group", ""),
            "resource_count": len(data.get("resources", [])),
            "path_count": len(data.get("paths", [])),
        })
    return {"scans": summaries}


@scans_router.get("/scans/{scan_id}")
def get_scan(request: Request, scan_id: str) -> dict:
    """Get full scan results for a specific scan."""
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = request.app.state.scan_results[scan_id]

    # Build serializable response (exclude NetworkX graph and complex objects)
    return {
        "scan_id": data["scan_id"],
        "subscription_id": data["subscription_id"],
        "resource_group": data["resource_group"],
        "resources": data["resources"],
        "resource_counts": data["resource_counts"],
        "path_count": len(data["paths"]),
        "cytoscape_json": data["cytoscape_json"],
        "paths": [
            {
                "nodes": p.nodes,
                "description": p.description,
                "risk_score": p.risk_score,
                "entry_point": p.entry_point,
                "target": p.target,
            }
            for p in data["paths"]
        ],
    }
