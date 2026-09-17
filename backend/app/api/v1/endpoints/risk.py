from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.package import Package
from app.models.project import Project
from app.models.risk_analysis import RiskAnalysis
from app.models.risk_explanation import RiskExplanation
from app.models.risk_profile import RiskProfile
from app.models.risk_result import RiskResult
from app.models.vulnerability import Vulnerability
from app.schemas.explanation import (
    BatchExplanationResponse,
    ExplanationDetailResponse,
)
from app.schemas.risk import (
    MitigationEvidence,
    RiskAnalysisHistoryItem,
    RiskAnalysisHistoryResponse,
    RiskAnalysisResponse,
    RiskProfileResponse,
    RiskProfileUpdateRequest,
    RiskResultItem,
    RiskResultsListResponse,
)
from app.services.gemini_service import GeminiService
from app.services.risk_service import RiskProfileError, RiskService

router = APIRouter()


@router.get(
    "/{project_id}/risk/profile",
    response_model=RiskProfileResponse,
    summary="Get Project Risk Profile",
)
def get_risk_profile(
    project_id: int,
    db: Session = Depends(get_db),
) -> RiskProfileResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )
    profile = RiskService.get_or_create_default_profile(db, project_id)
    return RiskProfileResponse(
        id=profile.id,
        project_id=profile.project_id,
        name=profile.name,
        severity_weight=profile.severity_weight,
        centrality_weight=profile.centrality_weight,
        blast_radius_weight=profile.blast_radius_weight,
        application_criticality_weight=profile.application_criticality_weight,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.put(
    "/{project_id}/risk/profile",
    response_model=RiskProfileResponse,
    summary="Update Project Risk Profile Weights",
)
def update_risk_profile(
    project_id: int,
    payload: RiskProfileUpdateRequest,
    db: Session = Depends(get_db),
) -> RiskProfileResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    try:
        profile = RiskService.update_profile(
            db=db,
            project_id=project_id,
            severity_weight=payload.severity_weight,
            centrality_weight=payload.centrality_weight,
            blast_radius_weight=payload.blast_radius_weight,
            application_criticality_weight=payload.application_criticality_weight,
        )
    except RiskProfileError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(err),
        ) from err

    return RiskProfileResponse(
        id=profile.id,
        project_id=profile.project_id,
        name=profile.name,
        severity_weight=profile.severity_weight,
        centrality_weight=profile.centrality_weight,
        blast_radius_weight=profile.blast_radius_weight,
        application_criticality_weight=profile.application_criticality_weight,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.post(
    "/{project_id}/risk/analyses",
    response_model=RiskAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Structural Risk Analysis",
    description="Synchronously computes severity, centrality, blast radius, and application criticality, and ranks mitigations.",
)
def trigger_risk_analysis(
    project_id: int,
    db: Session = Depends(get_db),
) -> RiskAnalysisResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    try:
        analysis, _ = RiskService.execute_risk_analysis(db, project_id)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Risk analysis execution failed: {str(err)}",
        ) from err

    return RiskAnalysisResponse(
        analysis_id=analysis.id,
        project_id=analysis.project_id,
        status=analysis.status,
        vulnerability_count=analysis.vulnerability_count,
        scored_count=analysis.scored_count,
        unscored_count=analysis.unscored_count,
        weight_snapshot=analysis.weight_snapshot,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        created_at=analysis.created_at,
    )


@router.get(
    "/{project_id}/risk/analyses",
    response_model=RiskAnalysisHistoryResponse,
    summary="List Risk Analyses History",
)
def list_risk_analyses(
    project_id: int,
    db: Session = Depends(get_db),
) -> RiskAnalysisHistoryResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    stmt = (
        select(RiskAnalysis)
        .where(RiskAnalysis.project_id == project_id)
        .order_by(RiskAnalysis.created_at.desc())
    )
    analyses = db.scalars(stmt).all()

    items = [
        RiskAnalysisHistoryItem(
            id=a.id,
            project_id=a.project_id,
            status=a.status,
            vulnerability_count=a.vulnerability_count,
            scored_count=a.scored_count,
            unscored_count=a.unscored_count,
            weight_snapshot=a.weight_snapshot,
            created_at=a.created_at,
        )
        for a in analyses
    ]

    return RiskAnalysisHistoryResponse(
        project_id=project_id,
        total=len(items),
        analyses=items,
    )


@router.get(
    "/{project_id}/risk/analyses/{analysis_id}",
    response_model=RiskAnalysisResponse,
    summary="Get Single Risk Analysis",
)
def get_risk_analysis(
    project_id: int,
    analysis_id: int,
    db: Session = Depends(get_db),
) -> RiskAnalysisResponse:
    analysis = db.get(RiskAnalysis, analysis_id)
    if not analysis or analysis.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk analysis with ID {analysis_id} not found for project {project_id}.",
        )

    return RiskAnalysisResponse(
        analysis_id=analysis.id,
        project_id=analysis.project_id,
        status=analysis.status,
        vulnerability_count=analysis.vulnerability_count,
        scored_count=analysis.scored_count,
        unscored_count=analysis.unscored_count,
        weight_snapshot=analysis.weight_snapshot,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        created_at=analysis.created_at,
    )


@router.get(
    "/{project_id}/risk/analyses/{analysis_id}/results",
    response_model=RiskResultsListResponse,
    summary="Get Risk Analysis Results",
)
def get_risk_analysis_results(
    project_id: int,
    analysis_id: int,
    priority_band: Optional[str] = Query(None, description="Filter by band: CRITICAL, HIGH, MODERATE, LOW, UNSCORED"),
    package: Optional[str] = Query(None, description="Filter by package name substring"),
    vulnerability: Optional[str] = Query(None, description="Filter by vulnerability OSV ID substring"),
    db: Session = Depends(get_db),
) -> RiskResultsListResponse:
    analysis = db.get(RiskAnalysis, analysis_id)
    if not analysis or analysis.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk analysis with ID {analysis_id} not found for project {project_id}.",
        )

    stmt = select(RiskResult).where(RiskResult.analysis_id == analysis_id)
    if priority_band:
        stmt = stmt.where(RiskResult.priority_band == priority_band.strip().upper())

    results = db.scalars(stmt).all()

    # Hydrate packages and vulnerabilities
    pkg_ids = list(set(r.package_id for r in results))
    vuln_ids = list(set(r.vulnerability_id for r in results))

    pkg_map = {p.id: p for p in db.scalars(select(Package).where(Package.id.in_(pkg_ids))).all()} if pkg_ids else {}
    vuln_map = {v.id: v for v in db.scalars(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))).all()} if vuln_ids else {}

    items: List[RiskResultItem] = []
    for r in results:
        pkg = pkg_map.get(r.package_id)
        vuln = vuln_map.get(r.vulnerability_id)

        pkg_name = pkg.name if pkg else f"Package #{r.package_id}"
        pkg_version = pkg.version if pkg else ""
        pkg_eco = pkg.ecosystem if pkg else ""
        pkg_purl = pkg.purl if pkg else None

        osv_id = vuln.osv_id if vuln else f"Vuln #{r.vulnerability_id}"
        summary = vuln.summary if vuln else None

        # Filter by package name
        if package and package.strip().lower() not in pkg_name.lower():
            continue

        # Filter by vulnerability osv_id
        if vulnerability and vulnerability.strip().lower() not in osv_id.lower():
            continue

        evidence_payload = RiskService.extract_mitigation_evidence(vuln) if vuln else {
            "fixed_versions": [],
            "fix_guidance": "Review the upstream advisory for available remediation options.",
            "references": [],
            "aliases": [],
        }

        items.append(
            RiskResultItem(
                id=r.id,
                analysis_id=r.analysis_id,
                package_id=r.package_id,
                package_name=pkg_name,
                package_version=pkg_version,
                package_ecosystem=pkg_eco,
                package_purl=pkg_purl,
                vulnerability_id=r.vulnerability_id,
                vulnerability_osv_id=osv_id,
                vulnerability_summary=summary,
                cvss_score=r.cvss_score,
                cvss_version=r.cvss_version,
                severity_normalized=r.severity_normalized,
                pagerank=r.pagerank,
                betweenness=r.betweenness,
                centrality_score=r.centrality_score,
                centrality_approximate=r.centrality_approximate,
                affected_downstream_package_count=r.affected_downstream_package_count,
                affected_application_count=r.affected_application_count,
                package_reach=r.package_reach,
                application_reach=r.application_reach,
                blast_radius_score=r.blast_radius_score,
                max_application_criticality=r.max_application_criticality,
                application_criticality_score=r.application_criticality_score,
                dependency_depth=r.dependency_depth,
                risk_score=r.risk_score,
                priority_rank=r.priority_rank,
                priority_band=r.priority_band,
                reason=r.reason,
                mitigation_evidence=MitigationEvidence(**evidence_payload),
            )
        )

    # Sort results: scored by priority_rank ascending, then unscored
    items.sort(key=lambda x: (x.priority_rank is None, x.priority_rank or 999999, x.package_name))

    return RiskResultsListResponse(
        analysis_id=analysis.id,
        project_id=project_id,
        total=len(items),
        scored_count=sum(1 for i in items if i.risk_score is not None),
        unscored_count=sum(1 for i in items if i.risk_score is None),
        results=items,
    )


@router.get(
    "/{project_id}/risk/priority",
    response_model=RiskResultsListResponse,
    summary="Get Latest Ranked Mitigation Priorities",
    description="Returns the prioritized risk results from the most recent successful risk analysis.",
)
def get_latest_priority(
    project_id: int,
    db: Session = Depends(get_db),
) -> RiskResultsListResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    latest_analysis = db.scalars(
        select(RiskAnalysis)
        .where(RiskAnalysis.project_id == project_id, RiskAnalysis.status == "success")
        .order_by(RiskAnalysis.created_at.desc())
    ).first()

    if not latest_analysis:
        return RiskResultsListResponse(
            analysis_id=0,
            project_id=project_id,
            total=0,
            scored_count=0,
            unscored_count=0,
            results=[],
        )

    return get_risk_analysis_results(
        project_id=project_id,
        analysis_id=latest_analysis.id,
        priority_band=None,
        package=None,
        vulnerability=None,
        db=db,
    )


@router.post(
    "/{project_id}/risk/results/{risk_result_id}/explanation",
    response_model=ExplanationDetailResponse,
    summary="Generate AI Risk Explanation",
    description="Generates or retrieves a cached evidence-grounded AI explanation for a specific risk result.",
)
def generate_risk_explanation(
    project_id: int,
    risk_result_id: int,
    db: Session = Depends(get_db),
) -> ExplanationDetailResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    risk_result = db.get(RiskResult, risk_result_id)
    if not risk_result or risk_result.analysis.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk result with ID {risk_result_id} not found for project {project_id}.",
        )

    explanation = GeminiService.explain_risk_result(db, risk_result)
    return ExplanationDetailResponse(
        explanation_id=explanation.id,
        risk_result_id=explanation.risk_result_id,
        status=explanation.status,
        model_name=explanation.model_name,
        prompt_version=explanation.prompt_version,
        evidence_version=explanation.evidence_version,
        evidence_hash=explanation.evidence_hash,
        summary=explanation.summary,
        why_priority=explanation.why_priority,
        key_factors=explanation.key_factors,
        mitigation_guidance=explanation.mitigation_guidance,
        limitations=explanation.limitations,
        evidence_ids=explanation.evidence_ids,
        failed_reason=explanation.failed_reason,
        generated_at=explanation.generated_at,
    )


@router.get(
    "/{project_id}/risk/results/{risk_result_id}/explanation",
    response_model=ExplanationDetailResponse,
    summary="Get Latest AI Risk Explanation",
    description="Retrieves the latest successful AI explanation for a risk result.",
)
def get_risk_explanation(
    project_id: int,
    risk_result_id: int,
    db: Session = Depends(get_db),
) -> ExplanationDetailResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    risk_result = db.get(RiskResult, risk_result_id)
    if not risk_result or risk_result.analysis.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk result with ID {risk_result_id} not found for project {project_id}.",
        )

    stmt = (
        select(RiskExplanation)
        .where(
            RiskExplanation.risk_result_id == risk_result.id,
            RiskExplanation.status == "success",
        )
        .order_by(RiskExplanation.generated_at.desc())
    )
    explanation = db.scalars(stmt).first()
    if not explanation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No successful explanation found for risk result {risk_result_id}.",
        )

    return ExplanationDetailResponse(
        explanation_id=explanation.id,
        risk_result_id=explanation.risk_result_id,
        status=explanation.status,
        model_name=explanation.model_name,
        prompt_version=explanation.prompt_version,
        evidence_version=explanation.evidence_version,
        evidence_hash=explanation.evidence_hash,
        summary=explanation.summary,
        why_priority=explanation.why_priority,
        key_factors=explanation.key_factors,
        mitigation_guidance=explanation.mitigation_guidance,
        limitations=explanation.limitations,
        evidence_ids=explanation.evidence_ids,
        failed_reason=explanation.failed_reason,
        generated_at=explanation.generated_at,
    )


@router.post(
    "/{project_id}/risk/analyses/{analysis_id}/explanations",
    response_model=BatchExplanationResponse,
    summary="Batch Generate Explanations for Analysis Results",
    description="Generates explanations for all scored risk results in an analysis, bounded by MAX_EXPLANATIONS_PER_REQUEST.",
)
def batch_generate_explanations(
    project_id: int,
    analysis_id: int,
    db: Session = Depends(get_db),
) -> BatchExplanationResponse:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID {project_id} not found.",
        )

    analysis = db.get(RiskAnalysis, analysis_id)
    if not analysis or analysis.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk analysis with ID {analysis_id} not found for project {project_id}.",
        )

    # Fetch scored risk results
    stmt = (
        select(RiskResult)
        .where(
            RiskResult.analysis_id == analysis_id,
            RiskResult.risk_score.is_not(None),
        )
        .order_by(RiskResult.priority_rank.asc())
    )
    results = db.scalars(stmt).all()

    if len(results) > settings.MAX_EXPLANATIONS_PER_REQUEST:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Analysis contains {len(results)} scored findings, which exceeds the maximum limit of "
                f"{settings.MAX_EXPLANATIONS_PER_REQUEST} explanations per request. "
                "Please generate individual explanations for specific high-priority findings."
            ),
        )

    explanations: List[ExplanationDetailResponse] = []
    success_count = 0
    failed_count = 0

    for r in results:
        exp = GeminiService.explain_risk_result(db, r)
        if exp.status == "success":
            success_count += 1
        else:
            failed_count += 1

        explanations.append(
            ExplanationDetailResponse(
                explanation_id=exp.id,
                risk_result_id=exp.risk_result_id,
                status=exp.status,
                model_name=exp.model_name,
                prompt_version=exp.prompt_version,
                evidence_version=exp.evidence_version,
                evidence_hash=exp.evidence_hash,
                summary=exp.summary,
                why_priority=exp.why_priority,
                key_factors=exp.key_factors,
                mitigation_guidance=exp.mitigation_guidance,
                limitations=exp.limitations,
                evidence_ids=exp.evidence_ids,
                failed_reason=exp.failed_reason,
                generated_at=exp.generated_at,
            )
        )

    return BatchExplanationResponse(
        analysis_id=analysis_id,
        total_requested=len(results),
        successful_count=success_count,
        failed_count=failed_count,
        explanations=explanations,
    )
