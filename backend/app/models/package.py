from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Package(Base):
    __tablename__ = "packages"
    __table_args__ = (
        UniqueConstraint("ecosystem", "name", "version", name="uq_package_ecosystem_name_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    purl: Mapped[Optional[str]] = mapped_column(String(500), nullable=True, index=True)
    bom_ref: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    package_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
