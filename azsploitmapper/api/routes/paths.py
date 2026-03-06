"""
Attack path API routes - access attack paths and graph data.

These endpoints allow you to:
- GET /api/attack-paths/{scan_id}: List all attack paths with risk scores
- GET /api/graph/{scan_id}: Get Cytoscape.js JSON for graph visualization
"""

from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException


paths_router = APIRouter(prefix="/api", tags=["paths"])


@paths_router.get("/attack-paths/{scan_id}")
def get_attack_paths(request: Request, scan_id: str) -> dict:
    """
    Get all attack paths for a scan.

    Returns {"paths": [...]} where each path has:
    nodes, description, risk_score, entry_point name, target name.
    """
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = request.app.state.scan_results[scan_id]
    paths = data["paths"]
    nodes = data["nodes"]

    node_names = {nid: n.name for nid, n in nodes.items()}

    result = []
    for path in paths:
        result.append({
            "nodes": path.nodes,
            "description": path.description,
            "risk_score": path.risk_score,
            "entry_point": node_names.get(path.entry_point, path.entry_point),
            "target": node_names.get(path.target, path.target),
        })

    return {"paths": result}


@paths_router.get("/graph/{scan_id}")
def get_graph(request: Request, scan_id: str) -> dict:
    """
    Get the graph in Cytoscape.js JSON format.

    Returns a dict with 'nodes' and 'edges' arrays that can be passed
    directly to Cytoscape.js for interactive visualization. Each node
    includes id, label, type, risk_score, and findings_count.
    """
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = request.app.state.scan_results[scan_id]
    return data["cytoscape_json"]
