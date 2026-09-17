from datetime import datetime
from typing import List, Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RippleAnalysis(Base):
    __tablename__ = "ripple_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    seed_package_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("packages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    seed_vulnerability_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True, index=True
    )
    sbom_ingestion_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("sbom_ingestions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    vulnerability_scan_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("vulnerability_scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(
        String(50), default="pending", nullable=False
    )  # pending, running, success, partial, failed
    max_depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    affected_package_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    affected_application_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    direct_dependent_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    transitive_dependent_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    truncation_reason: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    seed_package: Mapped["Package"] = relationship("Package", foreign_keys=[seed_package_id])
    seed_vulnerability: Mapped[Optional["Vulnerability"]] = relationship(
        "Vulnerability", foreign_keys=[seed_vulnerability_id]
    )
    sbom_ingestion: Mapped[Optional["SBOMIngestion"]] = relationship(
        "SBOMIngestion", foreign_keys=[sbom_ingestion_id]
    )
    vulnerability_scan: Mapped[Optional["VulnerabilityScan"]] = relationship(
        "VulnerabilityScan", foreign_keys=[vulnerability_scan_id]
    )
    nodes: Mapped[List["RippleNode"]] = relationship(
        "RippleNode", back_populates="analysis", cascade="all, delete-orphan"
    )
    paths: Mapped[List["RipplePath"]] = relationship(
        "RipplePath", back_populates="analysis", cascade="all, delete-orphan"
    )
