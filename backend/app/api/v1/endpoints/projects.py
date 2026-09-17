from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.application import Application
from app.models.project import Project
from app.schemas.project import ProjectCreate, ProjectResponse
from app.schemas.risk import ApplicationCriticalityResponse, ApplicationCriticalityUpdateRequest

router = APIRouter()


@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Project",
)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)) -> Project:
    existing = db.scalars(select(Project).where(Project.name == payload.name)).first()
    if existing:
        return existing

    project = Project(name=payload.name, description=payload.description)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get(
    "",
    response_model=List[ProjectResponse],
    summary="List Projects",
)
def list_projects(db: Session = Depends(get_db)) -> List[Project]:
    return list(db.scalars(select(Project).order_by(Project.created_at.desc())).all())


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Get Project",
)
def get_project(project_id: int, db: Session = Depends(get_db)) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )
    return project


@router.patch(
    "/{project_id}/applications/{application_id}/criticality",
    response_model=ApplicationCriticalityResponse,
    summary="Update Application Criticality Tier",
)
def update_application_criticality(
    project_id: int,
    application_id: int,
    payload: ApplicationCriticalityUpdateRequest,
    db: Session = Depends(get_db),
) -> ApplicationCriticalityResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    app = db.get(Application, application_id)
    if not app or app.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Application with ID {application_id} not found for project {project_id}.",
        )

    scores = {"LOW": 0.25, "MEDIUM": 0.50, "HIGH": 0.75, "CRITICAL": 1.00}
    app.criticality_tier = payload.tier
    app.criticality_score = scores[payload.tier]
    app.criticality_source = "manual"
    db.commit()
    db.refresh(app)

    return ApplicationCriticalityResponse(
        application_id=app.id,
        name=app.name,
        version=app.version,
        criticality_tier=app.criticality_tier,
        criticality_score=app.criticality_score,
        criticality_source=app.criticality_source,
    )


@router.get(
    "/{project_id}/applications",
    response_model=List[ApplicationCriticalityResponse],
    summary="List Applications with Criticality",
)
def list_project_applications(
    project_id: int,
    db: Session = Depends(get_db),
) -> List[ApplicationCriticalityResponse]:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )
    apps = list(db.scalars(select(Application).where(Application.project_id == project_id)).all())
    return [
        ApplicationCriticalityResponse(
            application_id=a.id,
            name=a.name,
            version=a.version,
            criticality_tier=a.criticality_tier,
            criticality_score=a.criticality_score,
            criticality_source=a.criticality_source,
        )
        for a in apps
    ]
