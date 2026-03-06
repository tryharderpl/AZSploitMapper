"""
SQLAlchemy ORM models for persisting scan results.

Tables:
- scans: Top-level scan metadata (subscription, timestamp, summary stats)
- resources: Discovered Azure resources with their properties
- findings: Security misconfigurations found during the scan
- attack_paths: Discovered attack paths with risk scores
"""

import json
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    """A completed scan with summary statistics."""
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    subscription_id = Column(String, nullable=False)
    resource_group = Column(String, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resource_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    path_count = Column(Integer, default=0)
    critical_paths = Column(Integer, default=0)

    # JSON-serialized data for full results (graph, paths, etc.)
    graph_json = Column(Text, default="{}")
    paths_json = Column(Text, default="[]")

    resources = relationship("ResourceRecord", back_populates="scan", cascade="all, delete")
    findings = relationship("FindingRecord", back_populates="scan", cascade="all, delete")

    def set_graph_json(self, data: dict):
        self.graph_json = json.dumps(data)

    def get_graph_json(self) -> dict:
        return json.loads(self.graph_json) if self.graph_json else {}

    def set_paths_json(self, data: list):
        self.paths_json = json.dumps(data)

    def get_paths_json(self) -> list:
        return json.loads(self.paths_json) if self.paths_json else []


class ResourceRecord(Base):
    """A discovered Azure resource."""
    __tablename__ = "resources"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    name = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    location = Column(String, default="")
    resource_group = Column(String, default="")
    properties_json = Column(Text, default="{}")

    scan = relationship("ScanRecord", back_populates="resources")

    def set_properties(self, data: dict):
        self.properties_json = json.dumps(data)

    def get_properties(self) -> dict:
        return json.loads(self.properties_json) if self.properties_json else {}


class FindingRecord(Base):
    """A security finding (misconfiguration) detected during a scan."""
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    rule_id = Column(String, nullable=False)
    rule_name = Column(String, default="")
    severity = Column(String, nullable=False)
    resource_id = Column(String, default="")
    resource_name = Column(String, default="")
    resource_type = Column(String, default="")
    description = Column(Text, default="")
    remediation = Column(Text, default="")
    compliance_json = Column(Text, default="{}")

    scan = relationship("ScanRecord", back_populates="findings")

    def set_compliance(self, data: dict):
        self.compliance_json = json.dumps(data)

    def get_compliance(self) -> dict:
        return json.loads(self.compliance_json) if self.compliance_json else {}
