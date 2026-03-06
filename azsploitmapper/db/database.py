"""
Database setup for scan result persistence.

Uses SQLite via SQLAlchemy for zero-setup local storage.
Scan results, findings, and resources are stored so you can
view historical scans without re-running them.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from azsploitmapper.db.models import Base, ScanRecord, ResourceRecord, FindingRecord
from azsploitmapper.graph.models import GraphNode, NodeType, AttackPath, GraphEdge, EdgeType

# Default SQLite database path (relative to project root)
DEFAULT_DB_PATH = "data/azsploitmapper.db"

logger = logging.getLogger("azsploitmapper")


def get_engine(db_url: str = ""):
    """
    Create a SQLAlchemy engine.

    If no URL is provided, uses SQLite with the default path.
    Creates the data directory and all tables if they don't exist.
    """
    if not db_url:
        db_path = Path(DEFAULT_DB_PATH)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite:///{db_path}"

    engine = create_engine(db_url, echo=False)
    Base.metadata.create_all(engine)
    return engine


def get_session(engine) -> Session:
    """Create a new database session."""
    session_factory = sessionmaker(bind=engine)
    return session_factory()


def save_scan(engine, scan_id: str, scan_data: dict):
    """
    Save a completed scan to the database.

    Serializes resources, findings, paths, cytoscape_json, and nodes
    so the scan can be restored after restart.
    """
    session = get_session(engine)
    try:
        # Serialize paths (AttackPath objects) to JSON
        paths = scan_data.get("paths", [])
        paths_list = []
        for p in paths:
            paths_list.append({
                "nodes": p.nodes,
                "entry_point": p.entry_point,
                "target": p.target,
                "risk_score": p.risk_score,
                "description": p.description,
            })

        # Serialize nodes (GraphNode objects) to JSON
        nodes = scan_data.get("nodes", {})
        nodes_dict = {}
        for nid, node in nodes.items():
            nodes_dict[nid] = {
                "id": node.id,
                "name": node.name,
                "node_type": node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type),
                "properties": node.properties,
                "findings": node.findings,
                "risk_score": node.risk_score,
            }

        # Build the full data blob (everything the routes need)
        full_data = {
            "resources": scan_data.get("resources", []),
            "resource_counts": scan_data.get("resource_counts", {}),
            "findings": scan_data.get("findings", []),
            "cytoscape_json": scan_data.get("cytoscape_json", {}),
            "nodes": nodes_dict,
            "paths": paths_list,
        }

        record = ScanRecord(
            id=scan_id,
            subscription_id=scan_data.get("subscription_id", ""),
            resource_group=scan_data.get("resource_group", ""),
            created_at=datetime.now(timezone.utc),
            resource_count=len(scan_data.get("resources", [])),
            finding_count=len(scan_data.get("findings", [])),
            path_count=len(paths),
            critical_paths=sum(1 for p in paths if p.risk_score >= 7.0),
        )
        record.set_graph_json(full_data)

        # Replace existing scan with same ID if any
        existing = session.get(ScanRecord, scan_id)
        if existing:
            session.delete(existing)
            session.flush()

        session.add(record)
        session.commit()
        logger.info("Scan %s saved to database", scan_id[:8])
    except Exception:
        session.rollback()
        logger.error("Failed to save scan %s to database", scan_id[:8], exc_info=True)
    finally:
        session.close()


def load_all_scans(engine) -> dict:
    """
    Load all saved scans from the database.

    Returns a dict of {scan_id: scan_data} in the same format
    that routes expect (with reconstructed AttackPath and GraphNode objects).
    """
    session = get_session(engine)
    results = {}
    try:
        records = session.query(ScanRecord).order_by(ScanRecord.created_at).all()
        for record in records:
            full_data = record.get_graph_json()
            if not full_data:
                continue

            # Reconstruct GraphNode objects from saved JSON
            nodes_raw = full_data.get("nodes", {})
            nodes = {}
            for nid, ndata in nodes_raw.items():
                node_type_str = ndata.get("node_type", "vm")
                try:
                    node_type = NodeType(node_type_str)
                except ValueError:
                    node_type = NodeType.VM
                nodes[nid] = GraphNode(
                    id=ndata.get("id", nid),
                    name=ndata.get("name", nid),
                    node_type=node_type,
                    properties=ndata.get("properties", {}),
                    findings=ndata.get("findings", []),
                    risk_score=ndata.get("risk_score", 0.0),
                )

            # Reconstruct AttackPath objects from saved JSON
            paths_raw = full_data.get("paths", [])
            paths = []
            for pdata in paths_raw:
                paths.append(AttackPath(
                    nodes=pdata.get("nodes", []),
                    edges=[],  # edges are not needed by the routes
                    entry_point=pdata.get("entry_point", ""),
                    target=pdata.get("target", ""),
                    risk_score=pdata.get("risk_score", 0.0),
                    description=pdata.get("description", ""),
                ))

            results[record.id] = {
                "scan_id": record.id,
                "subscription_id": record.subscription_id,
                "resource_group": record.resource_group or "",
                "resources": full_data.get("resources", []),
                "resource_counts": full_data.get("resource_counts", {}),
                "graph": None,  # NetworkX graph is not persisted
                "nodes": nodes,
                "paths": paths,
                "findings": full_data.get("findings", []),
                "cytoscape_json": full_data.get("cytoscape_json", {}),
            }

        logger.info("Loaded %d scan(s) from database", len(results))
    except Exception:
        logger.error("Failed to load scans from database", exc_info=True)
    finally:
        session.close()

    return results
