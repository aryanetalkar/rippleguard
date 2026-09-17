from collections import deque
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.application import Application
from app.models.dependency import Dependency
from app.models.package import Package
from app.models.package_vulnerability import PackageVulnerability
from app.models.project import Project
from app.models.ripple_analysis import RippleAnalysis
from app.models.ripple_node import RippleNode
from app.models.ripple_path import RipplePath
from app.models.sbom_ingestion import SBOMIngestion
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_scan import VulnerabilityScan

logger = logging.getLogger(__name__)


class RippleError(Exception):
    """Base exception for ripple propagation errors."""
    pass


class ProjectNotFoundError(RippleError):
    pass


class PackageNotFoundError(RippleError):
    pass


class PackageNotBelongingToProjectError(RippleError):
    pass


class VulnerabilityNotAssociatedError(RippleError):
    pass


class RipplePropagationEngine:
    """Deterministic in-memory graph analysis engine using NetworkX.

    Graph Direction Semantics:
      - Stored Database Edge: Source DEPENDS ON Target (A -> B or App -> B).
      - Reverse Impact Traversal: If B is compromised, impact propagates B -> A -> App.
    """

    @classmethod
    def validate_seed(
        cls,
        db: Session,
        project_id: int,
        seed_package_id: int,
        seed_vulnerability_id: Optional[int] = None,
    ) -> Tuple[Project, Package, Optional[Vulnerability], Set[int]]:
        """Validate that project, package, and optional vulnerability exist and belong together."""
        # 1. Verify project exists
        project = db.get(Project, project_id)
        if not project:
            raise ProjectNotFoundError(f"Project with ID {project_id} not found.")

        # 2. Verify package exists
        pkg = db.get(Package, seed_package_id)
        if not pkg:
            raise PackageNotFoundError(f"Package with ID {seed_package_id} not found.")

        # 3. Check that package belongs to this project
        apps = db.scalars(select(Application).where(Application.project_id == project_id)).all()
        app_ids = [a.id for a in apps]

        project_package_ids: Set[int] = set()
        if app_ids:
            deps = db.scalars(
                select(Dependency).where(Dependency.application_id.in_(app_ids))
            ).all()
            for d in deps:
                if d.source_package_id:
                    project_package_ids.add(d.source_package_id)
                if d.target_package_id:
                    project_package_ids.add(d.target_package_id)

        if seed_package_id not in project_package_ids:
            raise PackageNotBelongingToProjectError(
                f"Package '{pkg.name}@{pkg.version}' (ID: {seed_package_id}) does not belong to project {project_id}."
            )

        # 4. If vulnerability provided, verify association
        vuln: Optional[Vulnerability] = None
        if seed_vulnerability_id is not None:
            vuln = db.get(Vulnerability, seed_vulnerability_id)
            if not vuln:
                raise VulnerabilityNotAssociatedError(
                    f"Vulnerability with ID {seed_vulnerability_id} not found."
                )

            link = db.scalars(
                select(PackageVulnerability).where(
                    PackageVulnerability.package_id == seed_package_id,
                    PackageVulnerability.vulnerability_id == seed_vulnerability_id,
                )
            ).first()
            if not link:
                raise VulnerabilityNotAssociatedError(
                    f"Vulnerability '{vuln.osv_id}' is not associated with package '{pkg.name}@{pkg.version}'."
                )

        return project, pkg, vuln, project_package_ids

    @classmethod
    def build_networkx_graph(
        cls,
        db: Session,
        project_id: int,
    ) -> Tuple[nx.DiGraph, Dict[int, Application], Dict[int, Package]]:
        """Construct the forward directed graph from database records.

        Edges represent:
          - app:<id> -> pkg:<id> (Application depends on target package)
          - pkg:<src_id> -> pkg:<tgt_id> (Source package depends on target package)
        """
        G = nx.DiGraph()

        apps = db.scalars(select(Application).where(Application.project_id == project_id)).all()
        app_map = {a.id: a for a in apps}
        app_ids = list(app_map.keys())

        if not app_ids:
            return G, app_map, {}

        # Add application nodes
        for a in apps:
            G.add_node(
                f"app:{a.id}",
                type="application",
                id=a.id,
                name=a.name,
                version=a.version,
                ecosystem=None,
            )

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

        # Add package nodes
        for p in packages:
            G.add_node(
                f"pkg:{p.id}",
                type="package",
                id=p.id,
                name=p.name,
                version=p.version,
                ecosystem=p.ecosystem,
            )

        # Add edges representing stored dependencies
        for d in deps:
            tgt_id = f"pkg:{d.target_package_id}"
            if d.source_package_id is not None:
                src_id = f"pkg:{d.source_package_id}"
            else:
                src_id = f"app:{d.application_id}"

            if src_id in G and tgt_id in G:
                G.add_edge(src_id, tgt_id, direct=d.direct)

        return G, app_map, pkg_map

    @classmethod
    def traverse_impact(
        cls,
        forward_graph: nx.DiGraph,
        seed_package_id: int,
    ) -> Tuple[Dict[str, dict], Dict[str, List[str]], bool, Optional[str]]:
        """Perform reverse BFS traversal from compromised seed.

        Returns:
          - node_records: Dict[node_key, record_dict]
          - shortest_paths: Dict[node_key, List[node_key]]
          - truncated: bool
          - truncation_reason: Optional[str]
        """
        # Reverse dependency graph for impact propagation:
        # If A depends on B, compromise in B propagates to A (B -> A).
        R = forward_graph.reverse()

        seed_node = f"pkg:{seed_package_id}"
        if seed_node not in R:
            raise PackageNotFoundError(f"Seed node {seed_node} not present in graph.")

        visited: Set[str] = set()
        node_records: Dict[str, dict] = {}
        shortest_paths: Dict[str, List[str]] = {}

        truncated = False
        truncation_reason: Optional[str] = None

        # Record seed node at depth 0
        seed_data = R.nodes.get(seed_node, {})
        visited.add(seed_node)
        node_records[seed_node] = {
            "node_type": "package",
            "id": seed_node,
            "db_id": seed_package_id,
            "name": seed_data.get("name", ""),
            "version": seed_data.get("version"),
            "ecosystem": seed_data.get("ecosystem"),
            "depth": 0,
            "is_seed": True,
            "is_direct": False,
            "shortest_path_length": 0,
        }
        shortest_paths[seed_node] = [seed_node]

        # BFS Queue: (current_node, current_depth, current_path)
        queue: deque = deque([(seed_node, 0, [seed_node])])

        while queue:
            current_node, current_depth, current_path = queue.popleft()

            # Check node limit
            if len(node_records) >= settings.MAX_RIPPLE_NODES:
                truncated = True
                truncation_reason = "MAX_NODES_REACHED"
                break

            # Depth limit boundary check
            if current_depth >= settings.MAX_RIPPLE_DEPTH:
                # Check if there are further unexplored neighbors
                unexplored = [
                    nbr for nbr in sorted(R.successors(current_node)) if nbr not in visited
                ]
                if unexplored:
                    truncated = True
                    truncation_reason = "MAX_DEPTH_REACHED"
                continue

            # Deterministic neighbor order (sort by node ID)
            neighbors = sorted(R.successors(current_node))

            for nbr in neighbors:
                if nbr in visited:
                    continue

                if len(node_records) >= settings.MAX_RIPPLE_NODES:
                    truncated = True
                    truncation_reason = "MAX_NODES_REACHED"
                    break

                visited.add(nbr)
                next_depth = current_depth + 1
                next_path = current_path + [nbr]

                nbr_data = R.nodes.get(nbr, {})
                ntype = nbr_data.get("type", "package")
                db_id = nbr_data.get("id")

                # Direct dependents: depth 1 package dependents
                is_direct = (next_depth == 1 and ntype == "package")

                node_records[nbr] = {
                    "node_type": ntype,
                    "id": nbr,
                    "db_id": db_id,
                    "name": nbr_data.get("name", ""),
                    "version": nbr_data.get("version"),
                    "ecosystem": nbr_data.get("ecosystem"),
                    "depth": next_depth,
                    "is_seed": False,
                    "is_direct": is_direct,
                    "shortest_path_length": len(next_path) - 1,
                }
                shortest_paths[nbr] = next_path
                queue.append((nbr, next_depth, next_path))

            if truncated:
                break

        # Check path limit
        if len(shortest_paths) - 1 > settings.MAX_RIPPLE_PATHS:
            truncated = True
            if not truncation_reason:
                truncation_reason = "MAX_PATHS_REACHED"

        return node_records, shortest_paths, truncated, truncation_reason

    @classmethod
    def execute_simulation(
        cls,
        db: Session,
        project_id: int,
        seed_package_id: int,
        seed_vulnerability_id: Optional[int] = None,
    ) -> Tuple[RippleAnalysis, List[RippleNode], List[RipplePath]]:
        """Run end-to-end synchronous simulation and persist results transactionally."""
        started_at = datetime.now(timezone.utc)

        # 1. Validate inputs
        project, seed_pkg, vuln, _ = cls.validate_seed(
            db=db,
            project_id=project_id,
            seed_package_id=seed_package_id,
            seed_vulnerability_id=seed_vulnerability_id,
        )

        # 2. Build graph
        G, app_map, pkg_map = cls.build_networkx_graph(db=db, project_id=project_id)

        # 3. Perform reverse impact traversal
        node_records, shortest_paths, truncated, truncation_reason = cls.traverse_impact(
            forward_graph=G,
            seed_package_id=seed_package_id,
        )

        # 4. Compute summary metrics
        max_depth = max((rec["depth"] for rec in node_records.values()), default=0)
        affected_pkgs = [rec for rec in node_records.values() if rec["node_type"] == "package"]
        affected_apps = [rec for rec in node_records.values() if rec["node_type"] == "application"]

        direct_count = sum(1 for rec in affected_pkgs if rec["is_direct"])
        transitive_count = sum(
            1 for rec in affected_pkgs if not rec["is_seed"] and not rec["is_direct"]
        )

        # 5. Fetch associated latest ingestion and scan metadata
        latest_ingestion = db.scalars(
            select(SBOMIngestion)
            .where(SBOMIngestion.project_id == project_id, SBOMIngestion.status == "success")
            .order_by(SBOMIngestion.created_at.desc())
        ).first()

        latest_scan = db.scalars(
            select(VulnerabilityScan)
            .where(VulnerabilityScan.project_id == project_id)
            .order_by(VulnerabilityScan.started_at.desc())
        ).first()

        completed_at = datetime.now(timezone.utc)
        analysis_status = "partial" if truncated else "success"

        try:
            analysis = RippleAnalysis(
                project_id=project_id,
                seed_package_id=seed_package_id,
                seed_vulnerability_id=seed_vulnerability_id,
                sbom_ingestion_id=latest_ingestion.id if latest_ingestion else None,
                vulnerability_scan_id=latest_scan.id if latest_scan else None,
                status=analysis_status,
                max_depth=max_depth,
                affected_package_count=len(affected_pkgs),
                affected_application_count=len(affected_apps),
                direct_dependent_count=direct_count,
                transitive_dependent_count=transitive_count,
                truncated=truncated,
                truncation_reason=truncation_reason,
                started_at=started_at,
                completed_at=completed_at,
                error_message=None,
            )
            db.add(analysis)
            db.flush()

            # Persist affected nodes
            persisted_nodes: List[RippleNode] = []
            for rec in node_records.values():
                rnode = RippleNode(
                    analysis_id=analysis.id,
                    node_type=rec["node_type"],
                    package_id=rec["db_id"] if rec["node_type"] == "package" else None,
                    application_id=rec["db_id"] if rec["node_type"] == "application" else None,
                    depth=rec["depth"],
                    is_seed=rec["is_seed"],
                    is_direct=rec["is_direct"],
                    shortest_path_length=rec["shortest_path_length"],
                )
                db.add(rnode)
                persisted_nodes.append(rnode)

            # Persist deterministic shortest paths (excluding seed itself)
            persisted_paths: List[RipplePath] = []
            path_targets = [k for k in shortest_paths.keys() if k != f"pkg:{seed_package_id}"]
            path_targets.sort()  # deterministic ordering

            for target_key in path_targets[: settings.MAX_RIPPLE_PATHS]:
                rec = node_records[target_key]
                path_steps = shortest_paths[target_key]

                path_nodes_payload = [
                    {
                        "node_type": node_records[step]["node_type"],
                        "id": step,
                        "db_id": node_records[step]["db_id"],
                        "name": node_records[step]["name"],
                        "version": node_records[step]["version"],
                        "depth": node_records[step]["depth"],
                    }
                    for step in path_steps
                ]

                rpath = RipplePath(
                    analysis_id=analysis.id,
                    target_node_type=rec["node_type"],
                    target_package_id=rec["db_id"] if rec["node_type"] == "package" else None,
                    target_application_id=rec["db_id"] if rec["node_type"] == "application" else None,
                    path_nodes=path_nodes_payload,
                    path_length=len(path_steps) - 1,
                )
                db.add(rpath)
                persisted_paths.append(rpath)

            db.commit()
            db.refresh(analysis)
            return analysis, persisted_nodes, persisted_paths

        except Exception as err:
            db.rollback()
            logger.exception("Failed to persist ripple analysis")
            raise err
