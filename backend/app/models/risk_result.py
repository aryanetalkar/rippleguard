from datetime import datetime
from typing import List, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RiskResult(Base):
    __tablename__ = "risk_results"
    __table_args__ = (
        UniqueConstraint(
            "analysis_id",
            "package_id",
            "vulnerability_id",
            name="uq_risk_result_analysis_package_vuln",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("risk_analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    package_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("packages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Metric 1: Severity (OSV CVSS)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity_normalized: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Metric 2: Centrality (Package Graph Only)
    pagerank: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    betweenness: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    centrality_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    centrality_approximate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Metric 3: Blast Radius (Downstream Structural Reach)
    affected_downstream_package_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    affected_application_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    package_reach: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    application_reach: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    blast_radius_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Metric 4: Application Criticality (Max affected application)
    max_application_criticality: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    application_criticality_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Explanatory metric
    dependency_depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Final Combined Proposed Score & Priority
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    priority_rank: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    priority_band: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # CRITICAL, HIGH, MODERATE, LOW, UNSCORED
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    analysis: Mapped["RiskAnalysis"] = relationship("RiskAnalysis", back_populates="results")
    package: Mapped["Package"] = relationship("Package", foreign_keys=[package_id])
    vulnerability: Mapped["Vulnerability"] = relationship("Vulnerability", foreign_keys=[vulnerability_id])
    explanations: Mapped[List["RiskExplanation"]] = relationship(
        "RiskExplanation", back_populates="risk_result", cascade="all, delete-orphan"
    )
