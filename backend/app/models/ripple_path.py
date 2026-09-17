from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RipplePath(Base):
    __tablename__ = "ripple_paths"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ripple_analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_node_type: Mapped[str] = mapped_column(String(50), nullable=False)  # package, application
    target_package_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("packages.id", ondelete="CASCADE"), nullable=True, index=True
    )
    target_application_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=True, index=True
    )
    path_nodes: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False)
    path_length: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    analysis: Mapped["RippleAnalysis"] = relationship("RippleAnalysis", back_populates="paths")
    target_package: Mapped[Optional["Package"]] = relationship(
        "Package", foreign_keys=[target_package_id]
    )
    target_application: Mapped[Optional["Application"]] = relationship(
        "Application", foreign_keys=[target_application_id]
    )
