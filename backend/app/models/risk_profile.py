from datetime import datetime
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RiskProfile(Base):
    __tablename__ = "risk_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), default="Default RippleGuard", nullable=False)
    severity_weight: Mapped[float] = mapped_column(Float, default=0.30, nullable=False)
    centrality_weight: Mapped[float] = mapped_column(Float, default=0.25, nullable=False)
    blast_radius_weight: Mapped[float] = mapped_column(Float, default=0.25, nullable=False)
    application_criticality_weight: Mapped[float] = mapped_column(Float, default=0.20, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationship
    project: Mapped["Project"] = relationship("Project")
