import hashlib
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.package import Package
from app.models.risk_analysis import RiskAnalysis
from app.models.risk_result import RiskResult
from app.models.vulnerability import Vulnerability


class EvidencePackService:
    """Constructs deterministic, canonically hashed snapshots of security analysis facts."""

    EVIDENCE_VERSION = "1.0"

    # Recognized standard evidence IDs defined in RippleGuard specification
    STANDARD_EVIDENCE_IDS = [
        "risk_score",
        "priority_rank",
        "priority_band",
        "cvss_score",
        "cvss_version",
        "pagerank",
        "betweenness",
        "centrality_score",
        "affected_package_count",
        "affected_application_count",
        "application_reach",
        "package_reach",
        "application_criticality",
        "dependency_depth",
        "fixed_versions",
        "advisory_reference",
    ]

    @classmethod
    def extract_mitigation_data(cls, vuln: Optional[Vulnerability]) -> Dict[str, Any]:
        """Extract fixed versions, references, and aliases from OSV advisory data."""
        if not vuln:
            return {
                "fixed_versions": [],
                "fix_guidance": "Review the upstream advisory for available remediation options.",
                "references": [],
                "aliases": [],
            }

        fixed_versions: List[str] = []
        affected_data = vuln.affected_data or []
        for aff in affected_data:
            ranges = aff.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                for ev in events:
                    if "fixed" in ev and ev["fixed"]:
                        fixed_versions.append(str(ev["fixed"]).strip())

        unique_fixes = sorted(list(set(fixed_versions)))
        fix_text = (
            f"Fixed in version(s): {', '.join(unique_fixes)}"
            if unique_fixes
            else "Review the upstream advisory for available remediation options."
        )

        ref_urls = [
            r.get("url") for r in (vuln.references or []) if isinstance(r, dict) and r.get("url")
        ]

        return {
            "fixed_versions": unique_fixes,
            "fix_guidance": fix_text,
            "references": ref_urls[:5],
            "aliases": vuln.aliases or [],
        }

    @classmethod
    def build_evidence_pack(
        cls,
        db: Session,
        risk_result: RiskResult,
    ) -> Dict[str, Any]:
        """Builds a deterministic evidence pack snapshot for a given RiskResult."""
        pkg = db.get(Package, risk_result.package_id)
        vuln = db.get(Vulnerability, risk_result.vulnerability_id)
        analysis = db.get(RiskAnalysis, risk_result.analysis_id)

        mitigation = cls.extract_mitigation_data(vuln)

        # Assemble available evidence IDs
        present_evidence_ids: List[str] = []
        if risk_result.risk_score is not None:
            present_evidence_ids.append("risk_score")
        if risk_result.priority_rank is not None:
            present_evidence_ids.append("priority_rank")
        if risk_result.priority_band is not None:
            present_evidence_ids.append("priority_band")
        if risk_result.cvss_score is not None:
            present_evidence_ids.append("cvss_score")
        if risk_result.cvss_version is not None:
            present_evidence_ids.append("cvss_version")
        if risk_result.pagerank is not None:
            present_evidence_ids.append("pagerank")
        if risk_result.betweenness is not None:
            present_evidence_ids.append("betweenness")
        if risk_result.centrality_score is not None:
            present_evidence_ids.append("centrality_score")

        present_evidence_ids.extend([
            "affected_package_count",
            "affected_application_count",
            "application_reach",
            "package_reach",
            "application_criticality",
            "dependency_depth",
        ])

        if mitigation["fixed_versions"]:
            present_evidence_ids.append("fixed_versions")
        if mitigation["references"]:
            present_evidence_ids.append("advisory_reference")

        # Stable sorted evidence IDs
        present_evidence_ids = sorted(list(set(present_evidence_ids)))

        pack = {
            "evidence_version": cls.EVIDENCE_VERSION,
            "risk_result": {
                "id": risk_result.id,
                "analysis_id": risk_result.analysis_id,
                "risk_score": risk_result.risk_score,
                "priority_rank": risk_result.priority_rank,
                "priority_band": risk_result.priority_band,
                "cvss_score": risk_result.cvss_score,
                "cvss_version": risk_result.cvss_version,
                "severity_normalized": risk_result.severity_normalized,
                "pagerank": risk_result.pagerank,
                "betweenness": risk_result.betweenness,
                "centrality_score": risk_result.centrality_score,
                "centrality_approximate": risk_result.centrality_approximate,
                "affected_downstream_package_count": risk_result.affected_downstream_package_count,
                "affected_application_count": risk_result.affected_application_count,
                "package_reach": risk_result.package_reach,
                "application_reach": risk_result.application_reach,
                "blast_radius_score": risk_result.blast_radius_score,
                "max_application_criticality": risk_result.max_application_criticality,
                "application_criticality_score": risk_result.application_criticality_score,
                "dependency_depth": risk_result.dependency_depth,
            },
            "package": {
                "id": pkg.id if pkg else risk_result.package_id,
                "name": pkg.name if pkg else f"Package #{risk_result.package_id}",
                "version": pkg.version if pkg else "",
                "ecosystem": pkg.ecosystem if pkg else "",
                "purl": pkg.purl if pkg else None,
            },
            "vulnerability": {
                "id": vuln.id if vuln else risk_result.vulnerability_id,
                "osv_id": vuln.osv_id if vuln else f"Vuln #{risk_result.vulnerability_id}",
                "summary": vuln.summary if vuln else None,
                "details": vuln.details if vuln else None,
                "aliases": vuln.aliases if vuln else [],
                "references": mitigation["references"],
            },
            "mitigation": mitigation,
            "ranking": {
                "priority_rank": risk_result.priority_rank,
                "priority_band": risk_result.priority_band,
                "total_scored_in_analysis": analysis.scored_count if analysis else 0,
                "total_unscored_in_analysis": analysis.unscored_count if analysis else 0,
            },
            "available_evidence_ids": present_evidence_ids,
        }

        return pack

    @classmethod
    def compute_evidence_hash(cls, evidence_pack: Dict[str, Any]) -> str:
        """Computes SHA-256 hash over canonical JSON representation."""
        canonical_json = json.dumps(
            evidence_pack,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        )
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
