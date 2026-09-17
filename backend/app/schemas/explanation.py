from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ExplanationResponse(BaseModel):
    """Strict structured JSON response schema returned by Gemini."""

    summary: str = Field(..., description="High-level technical summary of why this finding matters.")
    why_priority: str = Field(
        ...,
        description="Detailed rationale connecting deterministic reach, centrality, and severity to the assigned priority.",
    )
    key_factors: List[str] = Field(
        ...,
        description="Primary contributing risk factors grounded in the supplied deterministic metrics.",
    )
    mitigation_guidance: str = Field(
        ...,
        description="Actionable mitigation or upgrade guidance strictly derived from OSV fixed-version evidence.",
    )
    limitations: List[str] = Field(
        ...,
        description="Analytical boundaries, model assumptions, and organizational context limitations.",
    )
    evidence_ids: List[str] = Field(
        ...,
        description="List of stable evidence IDs referenced in this explanation. Must be a subset of provided IDs.",
    )


class ExplanationDetailResponse(BaseModel):
    """API response model for an AI risk explanation."""

    model_config = ConfigDict(from_attributes=True)

    explanation_id: int
    risk_result_id: int
    status: str
    model_name: str
    prompt_version: str
    evidence_version: str
    evidence_hash: str
    summary: Optional[str] = None
    why_priority: Optional[str] = None
    key_factors: Optional[List[str]] = None
    mitigation_guidance: Optional[str] = None
    limitations: Optional[List[str]] = None
    evidence_ids: Optional[List[str]] = None
    failed_reason: Optional[str] = None
    generated_at: datetime


class BatchExplanationResponse(BaseModel):
    """API response model for batch explanation of risk analysis results."""

    model_config = ConfigDict(from_attributes=True)

    analysis_id: int
    total_requested: int
    successful_count: int
    failed_count: int
    explanations: List[ExplanationDetailResponse]
