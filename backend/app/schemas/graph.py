from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class GraphSummaryResponse(BaseModel):
    project_id: int
    application_count: int
    package_count: int
    dependency_count: int
    direct_dependency_count: int
    transitive_package_count: int
    unresolved_reference_count: int
    latest_spec_version: Optional[str] = None
    latest_ingestion_id: Optional[int] = None
    applications: List[str]


class GraphNodeItem(BaseModel):
    id: str  # e.g., "app:1" or "pkg:42"
    node_type: str  # "application" | "package"
    db_id: int
    name: str
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    purl: Optional[str] = None
    bom_ref: Optional[str] = None
    package_type: Optional[str] = None


class GraphNodesResponse(BaseModel):
    project_id: int
    total_nodes: int
    nodes: List[GraphNodeItem]


class GraphEdgeItem(BaseModel):
    id: int
    source: str  # e.g. "app:1" or "pkg:12"
    target: str  # e.g. "pkg:34"
    source_name: str
    target_name: str
    direct: bool
    dependency_type: str


class GraphEdgesResponse(BaseModel):
    project_id: int
    total_edges: int
    edges: List[GraphEdgeItem]
