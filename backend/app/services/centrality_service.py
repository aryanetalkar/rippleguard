from dataclasses import dataclass
import logging
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.application import Application
from app.models.dependency import Dependency
from app.models.package import Package

logger = logging.getLogger(__name__)


@dataclass
class PackageCentralityMetrics:
    package_id: int
    raw_pagerank: float
    normalized_pagerank: float
    raw_betweenness: float
    normalized_betweenness: float
    centrality_score: float
    centrality_approximate: bool
    dependency_depth: int


class CentralityService:
    """Calculates PageRank and Betweenness Centrality on the PACKAGE-ONLY dependency graph.

    Graph Direction Semantics:
      - A -> B means A DEPENDS ON B.
      - Application nodes are explicitly excluded from centrality calculations.
      - Combined centrality = 0.50 * normalized_pagerank + 0.50 * normalized_betweenness.
    """

    @classmethod
    def compute_project_centrality(
        cls,
        db: Session,
        project_id: int,
    ) -> Tuple[Dict[int, PackageCentralityMetrics], bool]:
        """Compute centrality metrics for all packages belonging to a project.

        Returns:
          (metrics_by_pkg_id, centrality_approximate)
        """
        apps = db.scalars(select(Application).where(Application.project_id == project_id)).all()
        app_ids = [a.id for a in apps]

        if not app_ids:
            return {}, False

        deps = db.scalars(
            select(Dependency).where(Dependency.application_id.in_(app_ids))
        ).all()

        # Collect distinct package IDs
        pkg_ids: Set[int] = set()
        for d in deps:
            if d.source_package_id:
                pkg_ids.add(d.source_package_id)
            if d.target_package_id:
                pkg_ids.add(d.target_package_id)

        if not pkg_ids:
            return {}, False

        # Build Package-Only DiGraph
        G_pkg = nx.DiGraph()
        for pid in pkg_ids:
            G_pkg.add_node(pid)

        # Edges: source_package DEPENDS ON target_package
        for d in deps:
            if d.source_package_id is not None and d.target_package_id is not None:
                G_pkg.add_edge(d.source_package_id, d.target_package_id)

        num_nodes = len(G_pkg)
        centrality_approximate = False

        # 1. PageRank Calculation
        try:
            raw_pr: Dict[int, float] = nx.pagerank(
                G_pkg,
                alpha=settings.PAGERANK_ALPHA,
                max_iter=settings.PAGERANK_MAX_ITER,
                tol=settings.PAGERANK_TOLERANCE,
            )
        except Exception as err:
            logger.warning("PageRank failed to converge on package graph: %s. Using uniform distribution.", err)
            raw_pr = {pid: 1.0 / num_nodes for pid in pkg_ids}
            centrality_approximate = True

        # 2. Betweenness Centrality Calculation with safeguards
        if num_nodes > settings.CENTRALITY_EXACT_NODE_LIMIT:
            centrality_approximate = True
            k_sample = min(settings.BETWEENNESS_SAMPLE_SIZE, num_nodes)
            raw_bc: Dict[int, float] = nx.betweenness_centrality(
                G_pkg,
                k=k_sample,
                normalized=True,
                seed=settings.BETWEENNESS_RANDOM_SEED,
            )
        else:
            raw_bc = nx.betweenness_centrality(G_pkg, normalized=True)

        # 3. Calculate Explanatory Dependency Depth from Application roots
        # Build full graph including applications to find min distance from App
        G_full = nx.DiGraph()
        for a in apps:
            G_full.add_node(f"app:{a.id}")
        for pid in pkg_ids:
            G_full.add_node(f"pkg:{pid}")

        for d in deps:
            src = f"pkg:{d.source_package_id}" if d.source_package_id else f"app:{d.application_id}"
            tgt = f"pkg:{d.target_package_id}"
            G_full.add_edge(src, tgt)

        depth_by_pkg: Dict[int, int] = {}
        for pid in pkg_ids:
            target_node = f"pkg:{pid}"
            min_dist = 999
            for a in apps:
                app_node = f"app:{a.id}"
                if nx.has_path(G_full, app_node, target_node):
                    dist = nx.shortest_path_length(G_full, app_node, target_node)
                    if dist < min_dist:
                        min_dist = dist
            depth_by_pkg[pid] = min_dist if min_dist != 999 else 1

        # 4. Normalize PageRank to [0, 1]
        pr_values = list(raw_pr.values())
        min_pr = min(pr_values) if pr_values else 0.0
        max_pr = max(pr_values) if pr_values else 0.0

        norm_pr: Dict[int, float] = {}
        if max_pr == min_pr:
            # If all nodes have identical value, normalize to 0.0
            norm_pr = {pid: 0.0 for pid in pkg_ids}
        else:
            denom_pr = max_pr - min_pr
            norm_pr = {pid: (raw_pr[pid] - min_pr) / denom_pr for pid in pkg_ids}

        # 5. Normalize Betweenness to [0, 1]
        bc_values = list(raw_bc.values())
        min_bc = min(bc_values) if bc_values else 0.0
        max_bc = max(bc_values) if bc_values else 0.0

        norm_bc: Dict[int, float] = {}
        if max_bc == min_bc:
            norm_bc = {pid: 0.0 for pid in pkg_ids}
        else:
            denom_bc = max_bc - min_bc
            norm_bc = {pid: (raw_bc[pid] - min_bc) / denom_bc for pid in pkg_ids}

        # 6. Combine Centrality = 0.50 * normalized_pr + 0.50 * normalized_bc
        result: Dict[int, PackageCentralityMetrics] = {}
        for pid in pkg_ids:
            p_pr = norm_pr[pid]
            p_bc = norm_bc[pid]
            cent_score = round(0.50 * p_pr + 0.50 * p_bc, 4)
            result[pid] = PackageCentralityMetrics(
                package_id=pid,
                raw_pagerank=round(raw_pr[pid], 6),
                normalized_pagerank=round(p_pr, 4),
                raw_betweenness=round(raw_bc[pid], 6),
                normalized_betweenness=round(p_bc, 4),
                centrality_score=cent_score,
                centrality_approximate=centrality_approximate,
                dependency_depth=depth_by_pkg.get(pid, 1),
            )

        return result, centrality_approximate
