from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RiskExplanation(Base):
    __tablename__ = "risk_explanations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    risk_result_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("risk_results.id", ondelete="CASCADE"), nullable=False, index=True
    )
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(50), nullable=False)
    evidence_version: Mapped[str] = mapped_column(String(50), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # pending, success, failed, validation_failed

    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    why_priority: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    key_factors: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    mitigation_guidance: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    limitations: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    evidence_ids: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    input_evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    failed_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    risk_result: Mapped["RiskResult"] = relationship("RiskResult", back_populates="explanations")
