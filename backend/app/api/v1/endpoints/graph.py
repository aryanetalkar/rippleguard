from typing import List, Set
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.application import Application
from app.models.dependency import Dependency
from app.models.package import Package
from app.models.project import Project
from app.models.sbom_ingestion import SBOMIngestion
from app.schemas.graph import (
    GraphEdgeItem,
    GraphEdgesResponse,
    GraphNodeItem,
    GraphNodesResponse,
    GraphSummaryResponse,
)

router = APIRouter()


@router.get(
    "/{project_id}/graph",
    response_model=GraphSummaryResponse,
    summary="Get Dependency Graph Summary",
)
def get_graph_summary(
    project_id: int,
    db: Session = Depends(get_db),
) -> GraphSummaryResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    # Fetch applications
    apps = db.scalars(select(Application).where(Application.project_id == project_id)).all()
    app_ids = [a.id for a in apps]
    app_names = [f"{a.name}@{a.version or '0.0.0'}" for a in apps]

    if not app_ids:
        return GraphSummaryResponse(
            project_id=project_id,
            application_count=0,
            package_count=0,
            dependency_count=0,
            direct_dependency_count=0,
            transitive_package_count=0,
            unresolved_reference_count=0,
            latest_spec_version=None,
            latest_ingestion_id=None,
            applications=[],
        )

    # Dependencies for these applications
    deps = db.scalars(
        select(Dependency).where(Dependency.application_id.in_(app_ids))
    ).all()

    # Collect packages involved
    package_ids: Set[int] = set()
    direct_deps_count = 0
    direct_target_pkg_ids: Set[int] = set()

    for d in deps:
        if d.source_package_id:
            package_ids.add(d.source_package_id)
        if d.target_package_id:
            package_ids.add(d.target_package_id)
        if d.direct:
            direct_deps_count += 1
            if d.target_package_id:
                direct_target_pkg_ids.add(d.target_package_id)

    # Transitive packages: packages in the graph that are not direct dependencies of application
    transitive_pkg_ids = package_ids - direct_target_pkg_ids

    # Latest ingestion metadata
    latest_ingestion = db.scalars(
        select(SBOMIngestion)
        .where(SBOMIngestion.project_id == project_id, SBOMIngestion.status == "success")
        .order_by(SBOMIngestion.created_at.desc())
    ).first()

    return GraphSummaryResponse(
        project_id=project_id,
        application_count=len(apps),
        package_count=len(package_ids),
        dependency_count=len(deps),
        direct_dependency_count=direct_deps_count,
        transitive_package_count=len(transitive_pkg_ids),
        unresolved_reference_count=0,
        latest_spec_version=latest_ingestion.spec_version if latest_ingestion else None,
        latest_ingestion_id=latest_ingestion.id if latest_ingestion else None,
        applications=app_names,
    )


@router.get(
    "/{project_id}/graph/nodes",
    response_model=GraphNodesResponse,
    summary="Get Graph Nodes",
)
def get_graph_nodes(
    project_id: int,
    db: Session = Depends(get_db),
) -> GraphNodesResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    apps = db.scalars(select(Application).where(Application.project_id == project_id)).all()
    app_ids = [a.id for a in apps]

    nodes: List[GraphNodeItem] = []

    # Application nodes
    for a in apps:
        nodes.append(
            GraphNodeItem(
                id=f"app:{a.id}",
                node_type="application",
                db_id=a.id,
                name=a.name,
                version=a.version,
                ecosystem=None,
                purl=None,
                bom_ref=None,
                package_type="application",
            )
        )

    if app_ids:
        # Get all distinct package IDs linked to these applications
        deps = db.scalars(
            select(Dependency).where(Dependency.application_id.in_(app_ids))
        ).all()

        pkg_ids: Set[int] = set()
        for d in deps:
            if d.source_package_id:
                pkg_ids.add(d.source_package_id)
            if d.target_package_id:
                pkg_ids.add(d.target_package_id)

        if pkg_ids:
            packages = db.scalars(
                select(Package).where(Package.id.in_(pkg_ids))
            ).all()

            for p in packages:
                nodes.append(
                    GraphNodeItem(
                        id=f"pkg:{p.id}",
                        node_type="package",
                        db_id=p.id,
                        name=p.name,
                        version=p.version,
                        ecosystem=p.ecosystem,
                        purl=p.purl,
                        bom_ref=p.bom_ref,
                        package_type=p.package_type,
                    )
                )

    return GraphNodesResponse(
        project_id=project_id,
        total_nodes=len(nodes),
        nodes=nodes,
    )


@router.get(
    "/{project_id}/graph/edges",
    response_model=GraphEdgesResponse,
    summary="Get Graph Edges",
)
def get_graph_edges(
    project_id: int,
    db: Session = Depends(get_db),
) -> GraphEdgesResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    apps = db.scalars(select(Application).where(Application.project_id == project_id)).all()
    app_map = {a.id: a for a in apps}
    app_ids = list(app_map.keys())

    edges: List[GraphEdgeItem] = []

    if app_ids:
        deps = db.scalars(
            select(Dependency).where(Dependency.application_id.in_(app_ids))
        ).all()

        pkg_ids: Set[int] = set()
        for d in deps:
            if d.source_package_id:
                pkg_ids.add(d.source_package_id)
            if d.target_package_id:
                pkg_ids.add(d.target_package_id)

        packages = db.scalars(select(Package).where(Package.id.in_(pkg_ids))).all() if pkg_ids else []
        pkg_map = {p.id: p for p in packages}

        for d in deps:
            tgt_pkg = pkg_map.get(d.target_package_id)
            if not tgt_pkg:
                continue

            if d.source_package_id:
                src_pkg = pkg_map.get(d.source_package_id)
                src_id = f"pkg:{d.source_package_id}"
                src_name = f"{src_pkg.name}@{src_pkg.version}" if src_pkg else f"pkg:{d.source_package_id}"
            else:
                app_obj = app_map.get(d.application_id)
                src_id = f"app:{d.application_id}"
                src_name = f"{app_obj.name}@{app_obj.version or '0.0.0'}" if app_obj else f"app:{d.application_id}"

            tgt_id = f"pkg:{d.target_package_id}"
            tgt_name = f"{tgt_pkg.name}@{tgt_pkg.version}"

            edges.append(
                GraphEdgeItem(
                    id=d.id,
                    source=src_id,
                    target=tgt_id,
                    source_name=src_name,
                    target_name=tgt_name,
                    direct=d.direct,
                    dependency_type=d.dependency_type,
                )
            )

    return GraphEdgesResponse(
        project_id=project_id,
        total_edges=len(edges),
        edges=edges,
    )
