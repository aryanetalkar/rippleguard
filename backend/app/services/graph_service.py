import logging
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.application import Application
from app.models.dependency import Dependency
from app.models.package import Package
from app.models.project import Project
from app.models.sbom_ingestion import SBOMIngestion
from app.services.cyclonedx_parser import ParsedSBOM, CycloneDXValidationError

logger = logging.getLogger(__name__)


@dataclass
class GraphMetadata:
    total_nodes: int
    total_edges: int
    application_name: str
    application_version: Optional[str]
    package_count: int
    dependency_count: int
    direct_dependency_count: int
    transitive_package_count: int
    unresolved_references: List[str]


class GraphService:
    """Service to construct dependency graphs and persist them transactionally."""

    @classmethod
    def compute_graph_structure(
        cls, parsed_sbom: ParsedSBOM
    ) -> Tuple[Set[str], Set[str], List[Tuple[Optional[str], str, bool]]]:
        """Classify direct vs transitive dependencies with cycle protection.

        Returns:
            Tuple of:
            - direct_package_canon_ids
            - transitive_package_canon_ids
            - resolved_edges: List of (source_canon_id_or_none, target_canon_id, is_direct)
        """
        app_bom_ref = parsed_sbom.application.bom_ref
        pkg_map = parsed_sbom.packages  # bom_ref -> NormalizedPackage

        # 1. Identify direct dependencies
        direct_canon_ids: Set[str] = set()
        adj_list: Dict[str, Set[str]] = {}  # source_canon_id -> set of target_canon_ids

        # Build adjacency list for canonical IDs
        for source_ref, target_ref in parsed_sbom.raw_dependencies:
            # Check if source is application root
            if app_bom_ref and source_ref == app_bom_ref:
                if target_ref in pkg_map:
                    direct_canon_ids.add(pkg_map[target_ref].canonical_id)
            else:
                if source_ref in pkg_map and target_ref in pkg_map:
                    src_canon = pkg_map[source_ref].canonical_id
                    tgt_canon = pkg_map[target_ref].canonical_id
                    if src_canon not in adj_list:
                        adj_list[src_canon] = set()
                    adj_list[src_canon].add(tgt_canon)

        # Fallback: if no dependencies were attached to app_bom_ref, find in-degree 0 components
        if not direct_canon_ids and parsed_sbom.unique_packages:
            all_target_canons: Set[str] = set()
            for targets in adj_list.values():
                all_target_canons.update(targets)

            for pkg in parsed_sbom.unique_packages:
                if pkg.canonical_id not in all_target_canons:
                    direct_canon_ids.add(pkg.canonical_id)

            # If still empty (e.g. pure cycle with no root reference), treat all top components as direct
            if not direct_canon_ids:
                for pkg in parsed_sbom.unique_packages:
                    direct_canon_ids.add(pkg.canonical_id)

        # 2. Identify transitive packages using BFS with visited set (Cycle-Safe)
        visited_transitive: Set[str] = set()
        queue: deque = deque()

        for d_id in direct_canon_ids:
            for child in adj_list.get(d_id, set()):
                if child not in direct_canon_ids:
                    queue.append(child)
                    visited_transitive.add(child)

        while queue:
            current = queue.popleft()
            for neighbor in adj_list.get(current, set()):
                if neighbor not in direct_canon_ids and neighbor not in visited_transitive:
                    visited_transitive.add(neighbor)
                    queue.append(neighbor)

        # 3. Build resolved edge list
        resolved_edges: List[Tuple[Optional[str], str, bool]] = []
        seen_resolved: Set[Tuple[Optional[str], str]] = set()

        # Application -> direct package edges
        for d_id in direct_canon_ids:
            edge = (None, d_id)
            if edge not in seen_resolved:
                seen_resolved.add(edge)
                resolved_edges.append((None, d_id, True))

        # Package -> Package edges (transitive relative to application root)
        for src_canon, targets in adj_list.items():
            for tgt_canon in targets:
                edge = (src_canon, tgt_canon)
                if edge not in seen_resolved:
                    seen_resolved.add(edge)
                    resolved_edges.append((src_canon, tgt_canon, False))

        return direct_canon_ids, visited_transitive, resolved_edges

    @classmethod
    def persist_graph(
        cls,
        db: Session,
        project_id: int,
        parsed_sbom: ParsedSBOM,
    ) -> Tuple[SBOMIngestion, GraphMetadata]:
        """Atomically persist parsed SBOM, packages, and dependency graph into the database."""
        # Verify project exists
        project = db.get(Project, project_id)
        if not project:
            raise ValueError(f"Project with ID {project_id} does not exist.")

        direct_canons, transitive_canons, resolved_edges = cls.compute_graph_structure(parsed_sbom)

        try:
            # 1. Upsert or find Application
            stmt_app = select(Application).where(
                Application.project_id == project_id,
                Application.name == parsed_sbom.application.name,
                Application.version == parsed_sbom.application.version,
            )
            app = db.scalars(stmt_app).first()
            if not app:
                app = Application(
                    project_id=project_id,
                    name=parsed_sbom.application.name,
                    version=parsed_sbom.application.version,
                )
                db.add(app)
                db.flush()

            # 2. Upsert Packages
            canon_to_db_pkg: Dict[str, Package] = {}
            for norm_pkg in parsed_sbom.unique_packages:
                stmt_pkg = select(Package).where(
                    Package.ecosystem == norm_pkg.ecosystem,
                    Package.name == norm_pkg.name,
                    Package.version == norm_pkg.version,
                )
                db_pkg = db.scalars(stmt_pkg).first()
                if not db_pkg:
                    db_pkg = Package(
                        ecosystem=norm_pkg.ecosystem,
                        name=norm_pkg.name,
                        version=norm_pkg.version,
                        purl=norm_pkg.purl,
                        bom_ref=norm_pkg.bom_ref,
                        package_type=norm_pkg.package_type,
                    )
                    db.add(db_pkg)
                    db.flush()
                canon_to_db_pkg[norm_pkg.canonical_id] = db_pkg

            # 3. Clean previous dependencies for this application before re-importing
            # This ensures idempotency when re-uploading an SBOM for the same application
            existing_deps = db.scalars(
                select(Dependency).where(Dependency.application_id == app.id)
            ).all()
            for ed in existing_deps:
                db.delete(ed)
            db.flush()

            # 4. Insert Dependency Edges
            persisted_edges_count = 0
            for src_canon, tgt_canon, is_direct in resolved_edges:
                tgt_pkg = canon_to_db_pkg.get(tgt_canon)
                if not tgt_pkg:
                    continue

                src_pkg_id: Optional[int] = None
                if src_canon is not None:
                    src_pkg = canon_to_db_pkg.get(src_canon)
                    if not src_pkg:
                        continue
                    src_pkg_id = src_pkg.id

                dep_record = Dependency(
                    application_id=app.id,
                    source_package_id=src_pkg_id,
                    target_package_id=tgt_pkg.id,
                    dependency_type="direct" if is_direct else "transitive",
                    direct=is_direct,
                )
                db.add(dep_record)
                persisted_edges_count += 1

            # 5. Record Successful Ingestion
            ingestion = SBOMIngestion(
                project_id=project_id,
                application_id=app.id,
                filename=parsed_sbom.filename,
                sha256=parsed_sbom.sha256,
                spec_version=parsed_sbom.spec_version,
                status="success",
                package_count=len(parsed_sbom.unique_packages),
                dependency_count=persisted_edges_count,
                error_message=None,
            )
            db.add(ingestion)
            db.commit()
            db.refresh(ingestion)

            metadata = GraphMetadata(
                total_nodes=1 + len(parsed_sbom.unique_packages),
                total_edges=persisted_edges_count,
                application_name=app.name,
                application_version=app.version,
                package_count=len(parsed_sbom.unique_packages),
                dependency_count=persisted_edges_count,
                direct_dependency_count=len(direct_canons),
                transitive_package_count=len(transitive_canons),
                unresolved_references=parsed_sbom.unresolved_references,
            )
            return ingestion, metadata

        except Exception as err:
            db.rollback()
            logger.exception("Failed to persist SBOM graph")
            # Save failed ingestion record in a separate transaction
            try:
                failed_ingestion = SBOMIngestion(
                    project_id=project_id,
                    application_id=None,
                    filename=parsed_sbom.filename,
                    sha256=parsed_sbom.sha256,
                    spec_version=parsed_sbom.spec_version,
                    status="failed",
                    package_count=0,
                    dependency_count=0,
                    error_message=str(err),
                )
                db.add(failed_ingestion)
                db.commit()
            except Exception:
                db.rollback()
            raise CycloneDXValidationError(f"Database persistence error: {str(err)}") from err
