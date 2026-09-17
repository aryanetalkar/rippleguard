from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskProfileWeights(BaseModel):
    severity_weight: float = Field(0.30, ge=0.0, le=1.0)
    centrality_weight: float = Field(0.25, ge=0.0, le=1.0)
    blast_radius_weight: float = Field(0.25, ge=0.0, le=1.0)
    application_criticality_weight: float = Field(0.20, ge=0.0, le=1.0)

    @field_validator("application_criticality_weight")
    @classmethod
    def validate_sum(cls, v: float, info) -> float:
        data = info.data
        sev = data.get("severity_weight", 0.30)
        cent = data.get("centrality_weight", 0.25)
        blast = data.get("blast_radius_weight", 0.25)
        total = sev + cent + blast + v
        if abs(total - 1.0) > 1e-4:
            raise ValueError(f"Weights must sum to 1.0 (100%). Current sum: {round(total * 100, 2)}%.")
        return v


class RiskProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    name: str
    severity_weight: float
    centrality_weight: float
    blast_radius_weight: float
    application_criticality_weight: float
    created_at: datetime
    updated_at: datetime


class RiskProfileUpdateRequest(BaseModel):
    severity_weight: float = Field(..., ge=0.0, le=1.0)
    centrality_weight: float = Field(..., ge=0.0, le=1.0)
    blast_radius_weight: float = Field(..., ge=0.0, le=1.0)
    application_criticality_weight: float = Field(..., ge=0.0, le=1.0)

    @field_validator("application_criticality_weight")
    @classmethod
    def validate_sum(cls, v: float, info) -> float:
        data = info.data
        sev = data.get("severity_weight")
        cent = data.get("centrality_weight")
        blast = data.get("blast_radius_weight")
        if sev is not None and cent is not None and blast is not None:
            total = sev + cent + blast + v
            if abs(total - 1.0) > 1e-4:
                raise ValueError(f"Weights must sum to 1.0 (100%). Current sum: {round(total * 100, 2)}%.")
        return v


class ApplicationCriticalityUpdateRequest(BaseModel):
    tier: str = Field(..., description="Criticality tier: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")

    @field_validator("tier")
    @classmethod
    def validate_tier(cls, v: str) -> str:
        norm = v.strip().upper()
        if norm not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Tier must be one of: LOW, MEDIUM, HIGH, CRITICAL.")
        return norm


class ApplicationCriticalityResponse(BaseModel):
    application_id: int
    name: str
    version: Optional[str] = None
    criticality_tier: str
    criticality_score: float
    criticality_source: str


class RiskAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analysis_id: int
    project_id: int
    status: str
    vulnerability_count: int
    scored_count: int
    unscored_count: int
    weight_snapshot: Dict[str, Any]
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime


class RiskAnalysisHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    status: str
    vulnerability_count: int
    scored_count: int
    unscored_count: int
    weight_snapshot: Dict[str, Any]
    created_at: datetime


class RiskAnalysisHistoryResponse(BaseModel):
    project_id: int
    total: int
    analyses: List[RiskAnalysisHistoryItem]


class MitigationEvidence(BaseModel):
    fixed_versions: List[str]
    fix_guidance: str
    references: List[Any]
    aliases: List[str]


class RiskResultItem(BaseModel):
    id: int
    analysis_id: int
    package_id: int
    package_name: str
    package_version: str
    package_ecosystem: str
    package_purl: Optional[str] = None

    vulnerability_id: int
    vulnerability_osv_id: str
    vulnerability_summary: Optional[str] = None

    # Severity Metric
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    severity_normalized: Optional[float] = None

    # Centrality Metric
    pagerank: Optional[float] = None
    betweenness: Optional[float] = None
    centrality_score: Optional[float] = None
    centrality_approximate: bool = False

    # Blast Radius Metric
    affected_downstream_package_count: int
    affected_application_count: int
    package_reach: float
    application_reach: float
    blast_radius_score: Optional[float] = None

    # Application Criticality Metric
    max_application_criticality: Optional[str] = None
    application_criticality_score: Optional[float] = None

    # Explanatory depth
    dependency_depth: int

    # Overall Score & Priority
    risk_score: Optional[float] = None
    priority_rank: Optional[int] = None
    priority_band: Optional[str] = None
    reason: Optional[str] = None

    # Mitigation Guidance
    mitigation_evidence: MitigationEvidence


class RiskResultsListResponse(BaseModel):
    analysis_id: int
    project_id: int
    total: int
    scored_count: int
    unscored_count: int
    results: List[RiskResultItem]
