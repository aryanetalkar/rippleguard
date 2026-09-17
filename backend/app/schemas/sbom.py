from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class SBOMIngestionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ingestion_id: int
    project_id: int
    application_id: Optional[int] = None
    application_name: Optional[str] = None
    application_version: Optional[str] = None
    filename: str
    sha256: str
    spec_version: str
    status: str
    package_count: int
    dependency_count: int
    error_message: Optional[str] = None
    created_at: datetime


class SBOMIngestionHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    application_id: Optional[int] = None
    filename: str
    sha256: str
    spec_version: str
    status: str
    package_count: int
    dependency_count: int
    error_message: Optional[str] = None
    created_at: datetime


class SBOMIngestionHistoryResponse(BaseModel):
    items: List[SBOMIngestionHistoryItem]
    total: int
