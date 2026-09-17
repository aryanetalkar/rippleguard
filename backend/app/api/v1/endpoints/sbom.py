from typing import List
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.application import Application
from app.models.project import Project
from app.models.sbom_ingestion import SBOMIngestion
from app.schemas.sbom import (
    SBOMIngestionHistoryItem,
    SBOMIngestionHistoryResponse,
    SBOMIngestionResponse,
)
from app.services.cyclonedx_parser import CycloneDXParser, CycloneDXValidationError
from app.services.graph_service import GraphService

router = APIRouter()


@router.post(
    "/{project_id}/sbom",
    response_model=SBOMIngestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest CycloneDX JSON SBOM",
    description="Validates, normalizes, and persists dependency graph from a CycloneDX JSON SBOM.",
)
async def ingest_sbom(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> SBOMIngestionResponse:
    # 1. Verify project exists
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    # 2. Read file content safely
    filename = file.filename or "uploaded_sbom.json"
    content_bytes = await file.read()

    # File size check
    if len(content_bytes) > settings.MAX_SBOM_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_SBOM_FILE_SIZE_BYTES} bytes.",
        )
    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded SBOM file is empty.",
        )

    # 3. Parse and validate CycloneDX SBOM
    try:
        parsed_sbom = CycloneDXParser.parse(content_bytes, filename=filename)
    except CycloneDXValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SBOM Validation Error: {str(err)}",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to parse SBOM: {str(err)}",
        ) from err

    # 4. Atomically persist graph
    try:
        ingestion, metadata = GraphService.persist_graph(
            db=db,
            project_id=project_id,
            parsed_sbom=parsed_sbom,
        )
    except CycloneDXValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Graph Persistence Error: {str(err)}",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred during graph persistence.",
        ) from err

    # Resolve application details
    app = db.get(Application, ingestion.application_id) if ingestion.application_id else None

    return SBOMIngestionResponse(
        ingestion_id=ingestion.id,
        project_id=project_id,
        application_id=ingestion.application_id,
        application_name=app.name if app else None,
        application_version=app.version if app else None,
        filename=ingestion.filename,
        sha256=ingestion.sha256,
        spec_version=ingestion.spec_version,
        status=ingestion.status,
        package_count=ingestion.package_count,
        dependency_count=ingestion.dependency_count,
        error_message=ingestion.error_message,
        created_at=ingestion.created_at,
    )


@router.get(
    "/{project_id}/sbom",
    response_model=SBOMIngestionHistoryResponse,
    summary="List SBOM Ingestion History",
)
def get_sbom_history(
    project_id: int,
    db: Session = Depends(get_db),
) -> SBOMIngestionHistoryResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    stmt = (
        select(SBOMIngestion)
        .where(SBOMIngestion.project_id == project_id)
        .order_by(SBOMIngestion.created_at.desc())
    )
    results = db.scalars(stmt).all()

    items = [
        SBOMIngestionHistoryItem(
            id=item.id,
            project_id=item.project_id,
            application_id=item.application_id,
            filename=item.filename,
            sha256=item.sha256,
            spec_version=item.spec_version,
            status=item.status,
            package_count=item.package_count,
            dependency_count=item.dependency_count,
            error_message=item.error_message,
            created_at=item.created_at,
        )
        for item in results
    ]
    return SBOMIngestionHistoryResponse(items=items, total=len(items))
