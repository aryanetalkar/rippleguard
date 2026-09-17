from datetime import datetime
from typing import List, Optional
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Application(Base):
    __tablename__ = "applications"
    __table_args__ = (
        UniqueConstraint("project_id", "name", "version", name="uq_application_project_name_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    criticality_tier: Mapped[str] = mapped_column(String(50), server_default="MEDIUM", default="MEDIUM", nullable=False)
    criticality_score: Mapped[float] = mapped_column(Float, server_default="0.50", default=0.50, nullable=False)
    criticality_source: Mapped[str] = mapped_column(String(50), server_default="default", default="default", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="applications")
    dependencies: Mapped[List["Dependency"]] = relationship(
        "Dependency", back_populates="application", cascade="all, delete-orphan"
    )
    sbom_ingestions: Mapped[List["SBOMIngestion"]] = relationship(
        "SBOMIngestion", back_populates="application"
    )
