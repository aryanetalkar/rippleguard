from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RippleNode(Base):
    __tablename__ = "ripple_nodes"
    __table_args__ = (
        CheckConstraint(
            "(node_type = 'package' AND package_id IS NOT NULL AND application_id IS NULL) OR "
            "(node_type = 'application' AND application_id IS NOT NULL AND package_id IS NULL)",
            name="ck_ripple_node_reference",
        ),
        UniqueConstraint(
            "analysis_id",
            "node_type",
            "package_id",
            "application_id",
            name="uq_ripple_node_identity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ripple_analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)  # package, application
    package_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("packages.id", ondelete="CASCADE"), nullable=True, index=True
    )
    application_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=True, index=True
    )
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
    is_seed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_direct: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    shortest_path_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    analysis: Mapped["RippleAnalysis"] = relationship("RippleAnalysis", back_populates="nodes")
    package: Mapped[Optional["Package"]] = relationship("Package", foreign_keys=[package_id])
    application: Mapped[Optional["Application"]] = relationship(
        "Application", foreign_keys=[application_id]
    )
