from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.application import Application
from app.models.package import Package
from app.models.package_vulnerability import PackageVulnerability
from app.models.project import Project
from app.models.risk_analysis import RiskAnalysis
from app.models.risk_profile import RiskProfile
from app.models.risk_result import RiskResult
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_scan import VulnerabilityScan
from app.services.centrality_service import CentralityService
from app.services.ripple_service import RipplePropagationEngine
from app.services.severity_service import SeverityService

logger = logging.getLogger(__name__)


class RiskProfileError(Exception):
    pass


class RiskService:
    """Orchestrates structural risk calculation and deterministic mitigation prioritization.

    Proposed Decision Model:
      Risk = (w_sev * severity) + (w_cent * centrality) + (w_blast * blast_radius) + (w_crit * app_criticality)
      Risk Score = Risk * 100
    """

    CRITICALITY_TIER_SCORES = {
        "LOW": 0.25,
        "MEDIUM": 0.50,
        "HIGH": 0.75,
        "CRITICAL": 1.00,
    }

    @classmethod
    def get_or_create_default_profile(cls, db: Session, project_id: int) -> RiskProfile:
        """Retrieve existing active profile or create default 30/25/25/20 profile."""
        stmt = (
            select(RiskProfile)
            .where(RiskProfile.project_id == project_id)
            .order_by(RiskProfile.created_at.desc())
        )
        profile = db.scalars(stmt).first()
        if not profile:
            profile = RiskProfile(
                project_id=project_id,
                name="Default RippleGuard",
                severity_weight=0.30,
                centrality_weight=0.25,
                blast_radius_weight=0.25,
                application_criticality_weight=0.20,
            )
            db.add(profile)
            db.commit()
            db.refresh(profile)
        return profile

    @classmethod
    def validate_weights(
        cls,
        severity_weight: float,
        centrality_weight: float,
        blast_radius_weight: float,
        application_criticality_weight: float,
    ) -> None:
        """Ensure all weights are non-negative and sum to 1.0 within float tolerance."""
        weights = [
            severity_weight,
            centrality_weight,
            blast_radius_weight,
            application_criticality_weight,
        ]
        for w in weights:
            if w < 0.0 or w > 1.0:
                raise RiskProfileError(f"Weight {w} must be between 0.0 and 1.0.")

        total = sum(weights)
        if abs(total - 1.0) > 1e-4:
            raise RiskProfileError(
                f"Weights must sum to 1.0 (100%). Current sum: {round(total * 100, 2)}%."
            )

    @classmethod
    def update_profile(
        cls,
        db: Session,
        project_id: int,
        severity_weight: float,
        centrality_weight: float,
        blast_radius_weight: float,
        application_criticality_weight: float,
    ) -> RiskProfile:
        """Update or create risk profile weights."""
        cls.validate_weights(
            severity_weight=severity_weight,
            centrality_weight=centrality_weight,
            blast_radius_weight=blast_radius_weight,
            application_criticality_weight=application_criticality_weight,
        )
        profile = cls.get_or_create_default_profile(db, project_id)
        profile.severity_weight = round(severity_weight, 4)
        profile.centrality_weight = round(centrality_weight, 4)
        profile.blast_radius_weight = round(blast_radius_weight, 4)
        profile.application_criticality_weight = round(application_criticality_weight, 4)
        db.commit()
        db.refresh(profile)
        return profile

    @classmethod
    def extract_mitigation_evidence(cls, vuln: Vulnerability) -> Dict[str, Any]:
        """Extract fix events, affected versions, and references from OSV advisory data."""
        fixed_versions: List[str] = []
        affected_ranges: List[str] = []

        affected_data = vuln.affected_data or []
        for aff in affected_data:
            ranges = aff.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                for ev in events:
                    if "fixed" in ev:
                        fixed_versions.append(ev["fixed"])

        unique_fixes = sorted(list(set(fixed_versions)))
        fix_text = (
            f"Fixed in version(s): {', '.join(unique_fixes)}"
            if unique_fixes
            else "Review the upstream advisory for available remediation options."
        )

        return {
            "fixed_versions": unique_fixes,
            "fix_guidance": fix_text,
            "references": (vuln.references or [])[:5],
            "aliases": vuln.aliases or [],
        }

    @classmethod
    def generate_reason(
        cls,
        app_reach: float,
        cent_score: float,
        sev_norm: Optional[float],
        app_crit_score: float,
    ) -> str:
        """Generate deterministic rationale derived from computed metric contributions."""
        parts: List[str] = []

        # Reach factor
        if app_reach >= 0.5:
            parts.append("high downstream application reach")
        elif app_reach > 0.0:
            parts.append("moderate downstream reach")
        else:
            parts.append("isolated reach")

        # Centrality factor
        if cent_score >= 0.6:
            parts.append("high structural centrality")
        elif cent_score >= 0.3:
            parts.append("moderate structural centrality")
        else:
            parts.append("low structural centrality")

        # Severity factor
        if sev_norm is not None:
            if sev_norm >= 0.7:
                parts.append("high vulnerability severity")
            elif sev_norm >= 0.4:
                parts.append("moderate vulnerability severity")
            else:
                parts.append("low vulnerability severity")
        else:
            parts.append("unscored severity")

        # Application Criticality factor
        if app_crit_score >= 0.75:
            parts.append("critical application asset impact")

        return " + ".join(parts).capitalize() + "."

    @classmethod
    def execute_risk_analysis(
        cls,
        db: Session,
        project_id: int,
    ) -> Tuple[RiskAnalysis, List[RiskResult]]:
        """Synchronously execute structural risk modeling and deterministic ranking."""
        started_at = datetime.now(timezone.utc)

        # 1. Verify project exists
        project = db.get(Project, project_id)
        if not project:
            raise ValueError(f"Project with ID {project_id} not found.")

        # 2. Retrieve active profile
        profile = cls.get_or_create_default_profile(db, project_id)
        weights_snapshot = {
            "severity_weight": profile.severity_weight,
            "centrality_weight": profile.centrality_weight,
            "blast_radius_weight": profile.blast_radius_weight,
            "application_criticality_weight": profile.application_criticality_weight,
        }

        # 3. Retrieve latest successful vulnerability scan
        scan = db.scalars(
            select(VulnerabilityScan)
            .where(VulnerabilityScan.project_id == project_id, VulnerabilityScan.status == "success")
            .order_by(VulnerabilityScan.started_at.desc())
        ).first()

        # 4. Load all applications and their criticality
        apps = db.scalars(select(Application).where(Application.project_id == project_id)).all()
        app_map = {a.id: a for a in apps}
        total_apps = len(apps)

        # 5. Load all project packages
        G_full, _, pkg_map = RipplePropagationEngine.build_networkx_graph(db, project_id)
        total_pkgs = len(pkg_map)

        # 6. If no applications, packages, or scan, handle clean empty analysis
        if not apps or not pkg_map or not scan:
            analysis = RiskAnalysis(
                project_id=project_id,
                vulnerability_scan_id=scan.id if scan else None,
                risk_profile_id=profile.id,
                weight_snapshot=weights_snapshot,
                status="success",
                vulnerability_count=0,
                scored_count=0,
                unscored_count=0,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error_message=None,
            )
            db.add(analysis)
            db.commit()
            db.refresh(analysis)
            return analysis, []

        # 7. Collect package-vulnerability links belonging to this project
        links = db.scalars(
            select(PackageVulnerability).where(PackageVulnerability.package_id.in_(list(pkg_map.keys())))
        ).all()

        if not links:
            # 0 vulnerable packages found in this project
            analysis = RiskAnalysis(
                project_id=project_id,
                vulnerability_scan_id=scan.id,
                risk_profile_id=profile.id,
                weight_snapshot=weights_snapshot,
                status="success",
                vulnerability_count=0,
                scored_count=0,
                unscored_count=0,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error_message=None,
            )
            db.add(analysis)
            db.commit()
            db.refresh(analysis)
            return analysis, []

        # 8. Compute Centrality ONCE for the project package graph
        centrality_map, cent_approx = CentralityService.compute_project_centrality(db, project_id)

        # 9. Compute reach for each distinct vulnerable package (Phase 4 Consistency)
        distinct_vuln_pkg_ids = list(set(link.package_id for link in links))
        reach_cache: Dict[int, Dict[str, Any]] = {}

        for pid in distinct_vuln_pkg_ids:
            try:
                node_records, _, _, _ = RipplePropagationEngine.traverse_impact(G_full, pid)
                affected_apps = [r for r in node_records.values() if r["node_type"] == "application"]
                affected_pkgs = [
                    r for r in node_records.values() if r["node_type"] == "package" and not r["is_seed"]
                ]

                app_count = len(affected_apps)
                pkg_count = len(affected_pkgs)

                app_reach = min(1.0, max(0.0, app_count / max(1, total_apps)))
                pkg_reach = (
                    min(1.0, max(0.0, pkg_count / max(1, total_pkgs - 1)))
                    if total_pkgs > 1
                    else 0.0
                )
                blast_radius = round(0.70 * app_reach + 0.30 * pkg_reach, 4)

                # Application criticality calculation
                app_scores = [
                    app_map[r["db_id"]].criticality_score
                    for r in affected_apps
                    if r["db_id"] in app_map
                ]
                app_tiers = [
                    app_map[r["db_id"]].criticality_tier
                    for r in affected_apps
                    if r["db_id"] in app_map
                ]

                tier_ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                if app_scores:
                    max_crit_score = max(app_scores)
                    max_crit_tier = max(app_tiers, key=lambda t: tier_ranks.get(t.upper(), 0))
                else:
                    max_crit_score = 0.0
                    max_crit_tier = "LOW"

                reach_cache[pid] = {
                    "affected_downstream_package_count": pkg_count,
                    "affected_application_count": app_count,
                    "package_reach": round(pkg_reach, 4),
                    "application_reach": round(app_reach, 4),
                    "blast_radius_score": blast_radius,
                    "max_application_criticality": max_crit_tier,
                    "application_criticality_score": round(max_crit_score, 4),
                }
            except Exception as err:
                logger.warning("Reach computation failed for package %s: %s", pid, err)
                reach_cache[pid] = {
                    "affected_downstream_package_count": 0,
                    "affected_application_count": 0,
                    "package_reach": 0.0,
                    "application_reach": 0.0,
                    "blast_radius_score": 0.0,
                    "max_application_criticality": "LOW",
                    "application_criticality_score": 0.0,
                }

        # 10. Process each package-vulnerability pair
        vuln_ids = list(set(link.vulnerability_id for link in links))
        vulns_map = {
            v.id: v
            for v in db.scalars(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))).all()
        }

        w_sev = profile.severity_weight
        w_cent = profile.centrality_weight
        w_blast = profile.blast_radius_weight
        w_crit = profile.application_criticality_weight

        computed_items: List[Dict[str, Any]] = []

        for link in links:
            v_obj = vulns_map.get(link.vulnerability_id)
            if not v_obj:
                continue

            pid = link.package_id
            reach_info = reach_cache.get(pid, {})
            cent_info = centrality_map.get(pid)

            cent_score = cent_info.centrality_score if cent_info else 0.0
            pr_val = cent_info.normalized_pagerank if cent_info else 0.0
            bc_val = cent_info.normalized_betweenness if cent_info else 0.0
            depth_val = cent_info.dependency_depth if cent_info else 1

            # Severity Resolution
            cvss_score, cvss_ver, sev_norm = SeverityService.resolve_severity(v_obj.severity_data)

            # Combined Risk Calculation
            if sev_norm is not None:
                risk = (
                    w_sev * sev_norm
                    + w_cent * cent_score
                    + w_blast * reach_info["blast_radius_score"]
                    + w_crit * reach_info["application_criticality_score"]
                )
                risk_score = round(risk * 100.0, 2)

                # Priority Band
                if risk_score >= 75.0:
                    band = "CRITICAL"
                elif risk_score >= 50.0:
                    band = "HIGH"
                elif risk_score >= 25.0:
                    band = "MODERATE"
                else:
                    band = "LOW"
            else:
                risk_score = None
                band = "UNSCORED"

            reason = cls.generate_reason(
                app_reach=reach_info["application_reach"],
                cent_score=cent_score,
                sev_norm=sev_norm,
                app_crit_score=reach_info["application_criticality_score"],
            )

            computed_items.append({
                "package_id": pid,
                "vulnerability_id": v_obj.id,
                "cvss_score": cvss_score,
                "cvss_version": cvss_ver,
                "severity_normalized": sev_norm,
                "pagerank": pr_val,
                "betweenness": bc_val,
                "centrality_score": cent_score,
                "centrality_approximate": cent_approx,
                "affected_downstream_package_count": reach_info["affected_downstream_package_count"],
                "affected_application_count": reach_info["affected_application_count"],
                "package_reach": reach_info["package_reach"],
                "application_reach": reach_info["application_reach"],
                "blast_radius_score": reach_info["blast_radius_score"],
                "max_application_criticality": reach_info["max_application_criticality"],
                "application_criticality_score": reach_info["application_criticality_score"],
                "dependency_depth": depth_val,
                "risk_score": risk_score,
                "priority_band": band,
                "reason": reason,
            })

        # 11. Deterministic Ranking
        # Scored items sorted: -risk_score, -blast_radius, -centrality, -severity, package_id, vuln_id
        scored_items = [item for item in computed_items if item["risk_score"] is not None]
        unscored_items = [item for item in computed_items if item["risk_score"] is None]

        scored_items.sort(
            key=lambda x: (
                -x["risk_score"],
                -x["blast_radius_score"],
                -x["centrality_score"],
                -x["severity_normalized"],
                x["package_id"],
                x["vulnerability_id"],
            )
        )

        for rank, item in enumerate(scored_items, start=1):
            item["priority_rank"] = rank

        for item in unscored_items:
            item["priority_rank"] = None

        final_items = scored_items + unscored_items

        # 12. Transactional Persistence
        try:
            analysis = RiskAnalysis(
                project_id=project_id,
                vulnerability_scan_id=scan.id,
                risk_profile_id=profile.id,
                weight_snapshot=weights_snapshot,
                status="success",
                vulnerability_count=len(final_items),
                scored_count=len(scored_items),
                unscored_count=len(unscored_items),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error_message=None,
            )
            db.add(analysis)
            db.flush()

            persisted_results: List[RiskResult] = []
            for item in final_items:
                r_result = RiskResult(
                    analysis_id=analysis.id,
                    package_id=item["package_id"],
                    vulnerability_id=item["vulnerability_id"],
                    cvss_score=item["cvss_score"],
                    cvss_version=item["cvss_version"],
                    severity_normalized=item["severity_normalized"],
                    pagerank=item["pagerank"],
                    betweenness=item["betweenness"],
                    centrality_score=item["centrality_score"],
                    centrality_approximate=item["centrality_approximate"],
                    affected_downstream_package_count=item["affected_downstream_package_count"],
                    affected_application_count=item["affected_application_count"],
                    package_reach=item["package_reach"],
                    application_reach=item["application_reach"],
                    blast_radius_score=item["blast_radius_score"],
                    max_application_criticality=item["max_application_criticality"],
                    application_criticality_score=item["application_criticality_score"],
                    dependency_depth=item["dependency_depth"],
                    risk_score=item["risk_score"],
                    priority_rank=item["priority_rank"],
                    priority_band=item["priority_band"],
                    reason=item["reason"],
                )
                db.add(r_result)
                persisted_results.append(r_result)

            db.commit()
            db.refresh(analysis)
            return analysis, persisted_results

        except Exception as err:
            db.rollback()
            logger.exception("Failed to persist risk analysis")
            raise err
