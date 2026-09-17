from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.application import Application
from app.models.package import Package
from app.models.project import Project
from app.models.ripple_analysis import RippleAnalysis
from app.models.ripple_node import RippleNode
from app.models.ripple_path import RipplePath
from app.models.vulnerability import Vulnerability
from app.schemas.ripple import (
    RippleAnalysisHistoryItem,
    RippleAnalysisHistoryResponse,
    RippleAnalysisResponse,
    RippleNodeItem,
    RippleNodesResponse,
    RipplePathItem,
    RipplePathNode,
    RipplePathsResponse,
    RippleSimulationRequest,
    RippleSummary,
    SeedPackageInfo,
    SeedVulnerabilityInfo,
    TargetNodeInfo,
)
from app.services.ripple_service import (
    PackageNotBelongingToProjectError,
    PackageNotFoundError,
    ProjectNotFoundError,
    RipplePropagationEngine,
    VulnerabilityNotAssociatedError,
)

router = APIRouter()


@router.post(
    "/{project_id}/ripple/analyses",
    response_model=RippleAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Ripple Propagation Analysis",
    description="Synchronously executes reverse BFS impact propagation from a compromised seed package.",
)
def trigger_ripple_analysis(
    project_id: int,
    payload: RippleSimulationRequest,
    db: Session = Depends(get_db),
) -> RippleAnalysisResponse:
    try:
        analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
            db=db,
            project_id=project_id,
            seed_package_id=payload.seed_package_id,
            seed_vulnerability_id=payload.seed_vulnerability_id,
        )
    except ProjectNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except PackageNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except PackageNotBelongingToProjectError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except VulnerabilityNotAssociatedError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ripple simulation failed: {str(err)}",
        ) from err

    seed_pkg = analysis.seed_package
    seed_pkg_info = SeedPackageInfo(
        id=seed_pkg.id,
        name=seed_pkg.name,
        version=seed_pkg.version,
        ecosystem=seed_pkg.ecosystem,
        purl=seed_pkg.purl,
    )

    seed_vuln_info: Optional[SeedVulnerabilityInfo] = None
    if analysis.seed_vulnerability:
        seed_vuln_info = SeedVulnerabilityInfo(
            id=analysis.seed_vulnerability.id,
            osv_id=analysis.seed_vulnerability.osv_id,
            summary=analysis.seed_vulnerability.summary,
        )

    summary = RippleSummary(
        max_depth=analysis.max_depth,
        affected_package_count=analysis.affected_package_count,
        affected_application_count=analysis.affected_application_count,
        direct_dependent_count=analysis.direct_dependent_count,
        transitive_dependent_count=analysis.transitive_dependent_count,
        truncated=analysis.truncated,
        truncation_reason=analysis.truncation_reason,
    )

    return RippleAnalysisResponse(
        analysis_id=analysis.id,
        project_id=analysis.project_id,
        status=analysis.status,
        seed_package=seed_pkg_info,
        seed_vulnerability=seed_vuln_info,
        sbom_ingestion_id=analysis.sbom_ingestion_id,
        vulnerability_scan_id=analysis.vulnerability_scan_id,
        summary=summary,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_message=analysis.error_message,
        created_at=analysis.created_at,
    )


@router.get(
    "/{project_id}/ripple/analyses",
    response_model=RippleAnalysisHistoryResponse,
    summary="List Project Ripple Analyses",
)
def list_ripple_analyses(
    project_id: int,
    db: Session = Depends(get_db),
) -> RippleAnalysisHistoryResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    stmt = (
        select(RippleAnalysis)
        .where(RippleAnalysis.project_id == project_id)
        .order_by(RippleAnalysis.created_at.desc())
    )
    analyses = db.scalars(stmt).all()

    items = []
    for a in analyses:
        seed_pkg = a.seed_package
        items.append(
            RippleAnalysisHistoryItem(
                id=a.id,
                project_id=a.project_id,
                status=a.status,
                seed_package_id=a.seed_package_id,
                seed_package_name=seed_pkg.name if seed_pkg else f"pkg:{a.seed_package_id}",
                seed_package_version=seed_pkg.version if seed_pkg else "",
                seed_vulnerability_osv_id=(
                    a.seed_vulnerability.osv_id if a.seed_vulnerability else None
                ),
                max_depth=a.max_depth,
                affected_package_count=a.affected_package_count,
                affected_application_count=a.affected_application_count,
                direct_dependent_count=a.direct_dependent_count,
                transitive_dependent_count=a.transitive_dependent_count,
                truncated=a.truncated,
                truncation_reason=a.truncation_reason,
                created_at=a.created_at,
            )
        )

    return RippleAnalysisHistoryResponse(
        project_id=project_id,
        total=len(items),
        analyses=items,
    )


@router.get(
    "/{project_id}/ripple/analyses/{analysis_id}",
    response_model=RippleAnalysisResponse,
    summary="Get Single Ripple Analysis",
)
def get_ripple_analysis(
    project_id: int,
    analysis_id: int,
    db: Session = Depends(get_db),
) -> RippleAnalysisResponse:
    analysis = db.get(RippleAnalysis, analysis_id)
    if not analysis or analysis.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Ripple analysis {analysis_id} not found for project {project_id}.",
        )

    seed_pkg = analysis.seed_package
    seed_pkg_info = SeedPackageInfo(
        id=seed_pkg.id,
        name=seed_pkg.name,
        version=seed_pkg.version,
        ecosystem=seed_pkg.ecosystem,
        purl=seed_pkg.purl,
    )

    seed_vuln_info = (
        SeedVulnerabilityInfo(
            id=analysis.seed_vulnerability.id,
            osv_id=analysis.seed_vulnerability.osv_id,
            summary=analysis.seed_vulnerability.summary,
        )
        if analysis.seed_vulnerability
        else None
    )

    summary = RippleSummary(
        max_depth=analysis.max_depth,
        affected_package_count=analysis.affected_package_count,
        affected_application_count=analysis.affected_application_count,
        direct_dependent_count=analysis.direct_dependent_count,
        transitive_dependent_count=analysis.transitive_dependent_count,
        truncated=analysis.truncated,
        truncation_reason=analysis.truncation_reason,
    )

    return RippleAnalysisResponse(
        analysis_id=analysis.id,
        project_id=analysis.project_id,
        status=analysis.status,
        seed_package=seed_pkg_info,
        seed_vulnerability=seed_vuln_info,
        sbom_ingestion_id=analysis.sbom_ingestion_id,
        vulnerability_scan_id=analysis.vulnerability_scan_id,
        summary=summary,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_message=analysis.error_message,
        created_at=analysis.created_at,
    )


@router.get(
    "/{project_id}/ripple/analyses/{analysis_id}/nodes",
    response_model=RippleNodesResponse,
    summary="Get Ripple Analysis Affected Nodes",
)
def get_ripple_analysis_nodes(
    project_id: int,
    analysis_id: int,
    db: Session = Depends(get_db),
) -> RippleNodesResponse:
    analysis = db.get(RippleAnalysis, analysis_id)
    if not analysis or analysis.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Ripple analysis {analysis_id} not found for project {project_id}.",
        )

    stmt = (
        select(RippleNode)
        .where(RippleNode.analysis_id == analysis_id)
        .order_by(RippleNode.depth.asc(), RippleNode.node_type.desc())
    )
    rnodes = db.scalars(stmt).all()

    # Hydrate package and application details
    pkg_ids = [n.package_id for n in rnodes if n.package_id is not None]
    app_ids = [n.application_id for n in rnodes if n.application_id is not None]

    pkg_map = {p.id: p for p in db.scalars(select(Package).where(Package.id.in_(pkg_ids))).all()} if pkg_ids else {}
    app_map = {a.id: a for a in db.scalars(select(Application).where(Application.id.in_(app_ids))).all()} if app_ids else {}

    items: List[RippleNodeItem] = []
    for n in rnodes:
        if n.node_type == "package" and n.package_id is not None:
            p = pkg_map.get(n.package_id)
            items.append(
                RippleNodeItem(
                    node_type="package",
                    id=f"pkg:{n.package_id}",
                    db_id=n.package_id,
                    name=p.name if p else f"Package #{n.package_id}",
                    version=p.version if p else None,
                    ecosystem=p.ecosystem if p else None,
                    depth=n.depth,
                    is_seed=n.is_seed,
                    is_direct=n.is_direct,
                    shortest_path_length=n.shortest_path_length,
                )
            )
        elif n.node_type == "application" and n.application_id is not None:
            a = app_map.get(n.application_id)
            items.append(
                RippleNodeItem(
                    node_type="application",
                    id=f"app:{n.application_id}",
                    db_id=n.application_id,
                    name=a.name if a else f"Application #{n.application_id}",
                    version=a.version if a else None,
                    ecosystem=None,
                    depth=n.depth,
                    is_seed=False,
                    is_direct=False,
                    shortest_path_length=n.shortest_path_length,
                )
            )

    return RippleNodesResponse(
        analysis_id=analysis_id,
        total_nodes=len(items),
        seed_package_id=analysis.seed_package_id,
        nodes=items,
    )


@router.get(
    "/{project_id}/ripple/analyses/{analysis_id}/paths",
    response_model=RipplePathsResponse,
    summary="Get Ripple Analysis Shortest Propagation Paths",
)
def get_ripple_analysis_paths(
    project_id: int,
    analysis_id: int,
    db: Session = Depends(get_db),
) -> RipplePathsResponse:
    analysis = db.get(RippleAnalysis, analysis_id)
    if not analysis or analysis.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Ripple analysis {analysis_id} not found for project {project_id}.",
        )

    stmt = (
        select(RipplePath)
        .where(RipplePath.analysis_id == analysis_id)
        .order_by(RipplePath.path_length.asc())
    )
    rpaths = db.scalars(stmt).all()

    # Hydrate targets
    pkg_ids = [p.target_package_id for p in rpaths if p.target_package_id is not None]
    app_ids = [p.target_application_id for p in rpaths if p.target_application_id is not None]

    pkg_map = {p.id: p for p in db.scalars(select(Package).where(Package.id.in_(pkg_ids))).all()} if pkg_ids else {}
    app_map = {a.id: a for a in db.scalars(select(Application).where(Application.id.in_(app_ids))).all()} if app_ids else {}

    items: List[RipplePathItem] = []
    for rp in rpaths:
        if rp.target_node_type == "package" and rp.target_package_id:
            pkg = pkg_map.get(rp.target_package_id)
            target = TargetNodeInfo(
                node_type="package",
                id=f"pkg:{rp.target_package_id}",
                db_id=rp.target_package_id,
                name=pkg.name if pkg else f"Package #{rp.target_package_id}",
                version=pkg.version if pkg else None,
            )
        else:
            app = app_map.get(rp.target_application_id) if rp.target_application_id else None
            target = TargetNodeInfo(
                node_type="application",
                id=f"app:{rp.target_application_id}",
                db_id=rp.target_application_id or 0,
                name=app.name if app else f"Application #{rp.target_application_id}",
                version=app.version if app else None,
            )

        steps = [
            RipplePathNode(
                node_type=step["node_type"],
                id=step["id"],
                db_id=step["db_id"],
                name=step["name"],
                version=step.get("version"),
                depth=step["depth"],
            )
            for step in rp.path_nodes
        ]

        items.append(
            RipplePathItem(
                id=rp.id,
                target=target,
                path=steps,
                path_length=rp.path_length,
            )
        )

    return RipplePathsResponse(
        analysis_id=analysis_id,
        total_paths=len(items),
        paths=items,
    )
