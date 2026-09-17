from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.application import Application
from app.models.dependency import Dependency
from app.models.package import Package
from app.models.package_vulnerability import PackageVulnerability
from app.models.project import Project
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_scan import VulnerabilityScan
from app.schemas.vulnerability import (
    PackageVulnerabilitiesResponse,
    VulnerabilityListItem,
    VulnerabilityListResponse,
    VulnerabilityScanHistoryItem,
    VulnerabilityScanHistoryResponse,
    VulnerabilityScanResponse,
    VulnerablePackageInfo,
)
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter()


@router.post(
    "/projects/{project_id}/vulnerabilities/scan",
    response_model=VulnerabilityScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger Vulnerability Scan",
    description="Queries OSV.dev for vulnerabilities affecting the project's current packages and persists results.",
)
async def trigger_vulnerability_scan(
    project_id: int,
    db: Session = Depends(get_db),
) -> VulnerabilityScanResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    service = VulnerabilityService()
    try:
        scan = await service.scan_project(db=db, project_id=project_id)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Vulnerability scan failed: {str(err)}",
        ) from err

    return VulnerabilityScanResponse(
        scan_id=scan.id,
        project_id=scan.project_id,
        status=scan.status,
        package_count=scan.package_count,
        vulnerable_package_count=scan.vulnerable_package_count,
        vulnerability_count=scan.vulnerability_count,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
    )


@router.get(
    "/projects/{project_id}/vulnerabilities/scans",
    response_model=VulnerabilityScanHistoryResponse,
    summary="List Vulnerability Scans",
)
def list_vulnerability_scans(
    project_id: int,
    db: Session = Depends(get_db),
) -> VulnerabilityScanHistoryResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    stmt = (
        select(VulnerabilityScan)
        .where(VulnerabilityScan.project_id == project_id)
        .order_by(VulnerabilityScan.started_at.desc())
    )
    scans = db.scalars(stmt).all()

    items = [
        VulnerabilityScanHistoryItem(
            id=s.id,
            project_id=s.project_id,
            status=s.status,
            package_count=s.package_count,
            vulnerable_package_count=s.vulnerable_package_count,
            vulnerability_count=s.vulnerability_count,
            started_at=s.started_at,
            completed_at=s.completed_at,
            error_message=s.error_message,
        )
        for s in scans
    ]
    return VulnerabilityScanHistoryResponse(
        project_id=project_id,
        total=len(items),
        items=items,
    )


@router.get(
    "/projects/{project_id}/vulnerabilities",
    response_model=VulnerabilityListResponse,
    summary="List Project Vulnerabilities",
    description="Returns normalized vulnerabilities affecting packages in the given project with optional filtering.",
)
def list_project_vulnerabilities(
    project_id: int,
    status_filter: Optional[str] = Query(
        None,
        alias="status",
        description="Filter by advisory status: 'active', 'withdrawn', or 'all'. Defaults to 'all'.",
    ),
    package_name: Optional[str] = Query(
        None,
        alias="package",
        description="Filter by package name substring (case-insensitive).",
    ),
    ecosystem: Optional[str] = Query(
        None,
        description="Filter by ecosystem (e.g. 'npm', 'pypi').",
    ),
    has_severity: Optional[bool] = Query(
        None,
        description="If true, returns only advisories with severity data.",
    ),
    db: Session = Depends(get_db),
) -> VulnerabilityListResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    # 1. Identify packages belonging to this project
    app_ids = db.scalars(
        select(Application.id).where(Application.project_id == project_id)
    ).all()

    if not app_ids:
        return VulnerabilityListResponse(
            project_id=project_id,
            total=0,
            active_count=0,
            withdrawn_count=0,
            items=[],
        )

    dep_pkg_ids_stmt = select(Dependency.target_package_id).where(
        Dependency.application_id.in_(app_ids)
    )
    dep_src_ids_stmt = select(Dependency.source_package_id).where(
        Dependency.application_id.in_(app_ids),
        Dependency.source_package_id.isnot(None),
    )
    all_pkg_ids = list(db.scalars(dep_pkg_ids_stmt.union(dep_src_ids_stmt)).all())

    if not all_pkg_ids:
        return VulnerabilityListResponse(
            project_id=project_id,
            total=0,
            active_count=0,
            withdrawn_count=0,
            items=[],
        )

    # 2. Query package-vulnerability links
    links_stmt = select(PackageVulnerability).where(
        PackageVulnerability.package_id.in_(all_pkg_ids)
    )
    links = db.scalars(links_stmt).all()

    if not links:
        return VulnerabilityListResponse(
            project_id=project_id,
            total=0,
            active_count=0,
            withdrawn_count=0,
            items=[],
        )

    # Group package IDs by vulnerability_id
    vuln_to_pkg_ids: dict[int, set[int]] = {}
    for link in links:
        if link.vulnerability_id not in vuln_to_pkg_ids:
            vuln_to_pkg_ids[link.vulnerability_id] = set()
        vuln_to_pkg_ids[link.vulnerability_id].add(link.package_id)

    # Load packages
    packages_map = {
        p.id: p for p in db.scalars(select(Package).where(Package.id.in_(all_pkg_ids))).all()
    }

    # Query vulnerabilities
    vuln_ids = list(vuln_to_pkg_ids.keys())
    vulns_stmt = select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))
    vulns = db.scalars(vulns_stmt).all()

    items: List[VulnerabilityListItem] = []
    active_count = 0
    withdrawn_count = 0

    for v in vulns:
        is_withdrawn = v.withdrawn_at is not None
        if is_withdrawn:
            withdrawn_count += 1
        else:
            active_count += 1

        # Apply status filter
        if status_filter == "active" and is_withdrawn:
            continue
        if status_filter == "withdrawn" and not is_withdrawn:
            continue

        # Check severity filter
        if has_severity is True and not v.severity_data:
            continue

        # Build package list
        associated_pkgs: List[VulnerablePackageInfo] = []
        for pkg_id in vuln_to_pkg_ids.get(v.id, set()):
            pkg_obj = packages_map.get(pkg_id)
            if pkg_obj:
                associated_pkgs.append(
                    VulnerablePackageInfo(
                        id=pkg_obj.id,
                        name=pkg_obj.name,
                        version=pkg_obj.version,
                        ecosystem=pkg_obj.ecosystem,
                        purl=pkg_obj.purl,
                    )
                )

        # Apply package name filter
        if package_name:
            norm_q = package_name.strip().lower()
            if not any(norm_q in p.name.lower() for p in associated_pkgs):
                continue

        # Apply ecosystem filter
        if ecosystem:
            norm_eco = ecosystem.strip().lower()
            if not any(norm_eco == p.ecosystem.lower() for p in associated_pkgs):
                continue

        items.append(
            VulnerabilityListItem(
                id=v.id,
                osv_id=v.osv_id,
                summary=v.summary,
                details=v.details,
                published_at=v.published_at,
                modified_at=v.modified_at,
                withdrawn_at=v.withdrawn_at,
                is_withdrawn=is_withdrawn,
                aliases=v.aliases or [],
                references=v.references or [],
                severity_data=v.severity_data or [],
                affected_data=v.affected_data or [],
                schema_version=v.schema_version,
                packages=associated_pkgs,
            )
        )

    return VulnerabilityListResponse(
        project_id=project_id,
        total=len(items),
        active_count=active_count,
        withdrawn_count=withdrawn_count,
        items=items,
    )


@router.get(
    "/packages/{package_id}/vulnerabilities",
    response_model=PackageVulnerabilitiesResponse,
    summary="Get Vulnerabilities for Single Package",
)
def get_package_vulnerabilities(
    package_id: int,
    db: Session = Depends(get_db),
) -> PackageVulnerabilitiesResponse:
    pkg = db.get(Package, package_id)
    if not pkg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Package with ID {package_id} not found.",
        )

    links = db.scalars(
        select(PackageVulnerability).where(PackageVulnerability.package_id == package_id)
    ).all()

    vuln_ids = [link.vulnerability_id for link in links]
    vulns = db.scalars(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))).all() if vuln_ids else []

    pkg_info = VulnerablePackageInfo(
        id=pkg.id,
        name=pkg.name,
        version=pkg.version,
        ecosystem=pkg.ecosystem,
        purl=pkg.purl,
    )

    items = [
        VulnerabilityListItem(
            id=v.id,
            osv_id=v.osv_id,
            summary=v.summary,
            details=v.details,
            published_at=v.published_at,
            modified_at=v.modified_at,
            withdrawn_at=v.withdrawn_at,
            is_withdrawn=v.withdrawn_at is not None,
            aliases=v.aliases or [],
            references=v.references or [],
            severity_data=v.severity_data or [],
            affected_data=v.affected_data or [],
            schema_version=v.schema_version,
            packages=[pkg_info],
        )
        for v in vulns
    ]

    return PackageVulnerabilitiesResponse(
        package_id=pkg.id,
        package_name=pkg.name,
        package_version=pkg.version,
        package_ecosystem=pkg.ecosystem,
        package_purl=pkg.purl,
        total=len(items),
        vulnerabilities=items,
    )
