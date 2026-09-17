from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RippleSimulationRequest(BaseModel):
    seed_package_id: int = Field(..., description="Database ID of the compromised package.")
    seed_vulnerability_id: Optional[int] = Field(
        None, description="Optional database ID of the associated vulnerability."
    )


class SeedPackageInfo(BaseModel):
    id: int
    name: str
    version: str
    ecosystem: str
    purl: Optional[str] = None


class SeedVulnerabilityInfo(BaseModel):
    id: int
    osv_id: str
    summary: Optional[str] = None


class RippleSummary(BaseModel):
    max_depth: int
    affected_package_count: int
    affected_application_count: int
    direct_dependent_count: int
    transitive_dependent_count: int
    truncated: bool
    truncation_reason: Optional[str] = None


class RippleAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analysis_id: int
    project_id: int
    status: str
    seed_package: SeedPackageInfo
    seed_vulnerability: Optional[SeedVulnerabilityInfo] = None
    sbom_ingestion_id: Optional[int] = None
    vulnerability_scan_id: Optional[int] = None
    summary: RippleSummary
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime


class RippleAnalysisHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    status: str
    seed_package_id: int
    seed_package_name: str
    seed_package_version: str
    seed_vulnerability_osv_id: Optional[str] = None
    max_depth: int
    affected_package_count: int
    affected_application_count: int
    direct_dependent_count: int
    transitive_dependent_count: int
    truncated: bool
    truncation_reason: Optional[str] = None
    created_at: datetime


class RippleAnalysisHistoryResponse(BaseModel):
    project_id: int
    total: int
    analyses: List[RippleAnalysisHistoryItem]


class RippleNodeItem(BaseModel):
    node_type: str  # "package" | "application"
    id: str  # e.g. "pkg:12" or "app:1"
    db_id: int
    name: str
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    depth: int
    is_seed: bool
    is_direct: bool
    shortest_path_length: Optional[int] = None


class RippleNodesResponse(BaseModel):
    analysis_id: int
    total_nodes: int
    seed_package_id: int
    nodes: List[RippleNodeItem]


class TargetNodeInfo(BaseModel):
    node_type: str
    id: str
    db_id: int
    name: str
    version: Optional[str] = None


class RipplePathNode(BaseModel):
    node_type: str
    id: str
    db_id: int
    name: str
    version: Optional[str] = None
    depth: int


class RipplePathItem(BaseModel):
    id: int
    target: TargetNodeInfo
    path: List[RipplePathNode]
    path_length: int


class RipplePathsResponse(BaseModel):
    analysis_id: int
    total_paths: int
    paths: List[RipplePathItem]
