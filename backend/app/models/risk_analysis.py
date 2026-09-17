from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RiskAnalysis(Base):
    __tablename__ = "risk_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_scan_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("vulnerability_scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    risk_profile_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("risk_profiles.id", ondelete="SET NULL"), nullable=True, index=True
    )
    weight_snapshot: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), default="pending", nullable=False
    )  # pending, running, success, partial, failed
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scored_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unscored_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
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
    vulnerability_scan: Mapped[Optional["VulnerabilityScan"]] = relationship("VulnerabilityScan")
    risk_profile: Mapped[Optional["RiskProfile"]] = relationship("RiskProfile")
    results: Mapped[List["RiskResult"]] = relationship(
        "RiskResult", back_populates="analysis", cascade="all, delete-orphan"
    )
