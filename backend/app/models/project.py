from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    applications: Mapped[List["Application"]] = relationship(
        "Application", back_populates="project", cascade="all, delete-orphan"
    )
    sbom_ingestions: Mapped[List["SBOMIngestion"]] = relationship(
        "SBOMIngestion", back_populates="project", cascade="all, delete-orphan"
    )
