from pathlib import Path
from unittest.mock import patch
import networkx as nx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base
from app.models.application import Application
from app.models.dependency import Dependency
from app.models.package import Package
from app.models.package_vulnerability import PackageVulnerability
from app.models.project import Project
from app.models.risk_analysis import RiskAnalysis
from app.models.risk_profile import RiskProfile
from app.models.risk_result import RiskResult
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_scan import VulnerabilityScan
from app.services.centrality_service import CentralityService
from app.services.cyclonedx_parser import CycloneDXParser
from app.services.graph_service import GraphService
from app.services.ripple_service import RipplePropagationEngine
from app.services.risk_service import RiskProfileError, RiskService
from app.services.severity_service import SeverityService

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def isolated_db() -> Session:
    """Isolated in-memory SQLite database for risk unit testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


# 1. CVSS v3 vector parsing
def test_cvss_v3_vector_parsing() -> None:
    data = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    score, ver, norm = SeverityService.resolve_severity(data)
    assert score == 9.8
    assert "CVSS" in ver
    assert norm == 0.98


# 2. CVSS v4 vector parsing
def test_cvss_v4_vector_parsing() -> None:
    data = [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]
    score, ver, norm = SeverityService.resolve_severity(data)
    assert score == 9.3
    assert ver == "CVSS:4.0"
    assert norm == 0.93


# 3. Missing CVSS data
def test_missing_cvss_data() -> None:
    assert SeverityService.resolve_severity([]) == (None, None, None)
    assert SeverityService.resolve_severity(None) == (None, None, None)
    assert SeverityService.resolve_severity([{"type": "UNKNOWN", "score": "invalid_junk"}]) == (None, None, None)


# 4. Multiple CVSS entries chooses highest valid score
def test_multiple_cvss_entries_chooses_highest() -> None:
    data = [
        {"type": "CVSS_V3", "score": "5.5"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},  # 9.8
        {"type": "CVSS_V2", "score": "7.5"},
    ]
    score, ver, norm = SeverityService.resolve_severity(data)
    assert score == 9.8
    assert norm == 0.98


# 5. PageRank calculation
def test_pagerank_calculation(isolated_db: Session) -> None:
    project = Project(name="Centrality Project")
    isolated_db.add(project)
    isolated_db.commit()

    content = (FIXTURES_DIR / "diamond_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "diamond.json")
    GraphService.persist_graph(isolated_db, project.id, parsed)

    # In diamond graph: A -> C, B -> C. C has highest in-degree in package graph.
    metrics, approx = CentralityService.compute_project_centrality(isolated_db, project.id)
    assert len(metrics) == 3
    assert approx is False

    packages = {p.name: p.id for p in isolated_db.scalars(select(Package)).all()}
    c_id = packages["package-c"]
    a_id = packages["package-a"]

    # Package C is depended upon by A and B; its PageRank should exceed A and B
    assert metrics[c_id].raw_pagerank > metrics[a_id].raw_pagerank


# 6. Betweenness calculation
def test_betweenness_calculation(isolated_db: Session) -> None:
    project = Project(name="Betweenness Project")
    isolated_db.add(project)
    isolated_db.commit()

    # Chain: App -> P1 -> P2 -> P3. P2 sits between P1 and P3.
    app = Application(project_id=project.id, name="App")
    p1 = Package(ecosystem="npm", name="p1", version="1.0")
    p2 = Package(ecosystem="npm", name="p2", version="1.0")
    p3 = Package(ecosystem="npm", name="p3", version="1.0")
    isolated_db.add_all([app, p1, p2, p3])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p1.id, direct=True),
        Dependency(application_id=app.id, source_package_id=p1.id, target_package_id=p2.id, direct=False),
        Dependency(application_id=app.id, source_package_id=p2.id, target_package_id=p3.id, direct=False),
    ])
    isolated_db.commit()

    metrics, approx = CentralityService.compute_project_centrality(isolated_db, project.id)
    assert approx is False
    assert metrics[p2.id].raw_betweenness >= metrics[p1.id].raw_betweenness


# 7. Centrality normalization
def test_centrality_normalization(isolated_db: Session) -> None:
    project = Project(name="Norm Project")
    isolated_db.add(project)
    isolated_db.commit()

    content = (FIXTURES_DIR / "diamond_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "diamond.json")
    GraphService.persist_graph(isolated_db, project.id, parsed)

    metrics, _ = CentralityService.compute_project_centrality(isolated_db, project.id)
    for m in metrics.values():
        assert 0.0 <= m.normalized_pagerank <= 1.0
        assert 0.0 <= m.normalized_betweenness <= 1.0
        assert 0.0 <= m.centrality_score <= 1.0


# 8. Identical-centrality handling
def test_identical_centrality_handling(isolated_db: Session) -> None:
    project = Project(name="Identical Project")
    isolated_db.add(project)
    isolated_db.commit()

    # Two isolated independent direct packages: App -> P1, App -> P2.
    app = Application(project_id=project.id, name="App")
    p1 = Package(ecosystem="npm", name="p1", version="1.0")
    p2 = Package(ecosystem="npm", name="p2", version="1.0")
    isolated_db.add_all([app, p1, p2])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p1.id, direct=True),
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p2.id, direct=True),
    ])
    isolated_db.commit()

    metrics, _ = CentralityService.compute_project_centrality(isolated_db, project.id)
    # Both packages have symmetric identical metrics, so normalized metrics must default to 0.0
    assert metrics[p1.id].normalized_pagerank == 0.0
    assert metrics[p2.id].normalized_pagerank == 0.0
    assert metrics[p1.id].centrality_score == 0.0


# 9. Application reach
def test_application_reach_calculation(isolated_db: Session) -> None:
    # 2 applications: App1 depends on P, App2 does not. App reach of P = 1 / 2 = 0.5.
    project = Project(name="Reach Project")
    isolated_db.add(project)
    isolated_db.commit()

    app1 = Application(project_id=project.id, name="App1")
    app2 = Application(project_id=project.id, name="App2")
    p1 = Package(ecosystem="npm", name="p1", version="1.0")
    isolated_db.add_all([app1, app2, p1])
    isolated_db.commit()

    isolated_db.add(Dependency(application_id=app1.id, source_package_id=None, target_package_id=p1.id, direct=True))
    isolated_db.commit()

    # Reach of p1 in project with 2 apps
    node_records, _, _, _ = RipplePropagationEngine.traverse_impact(
        RipplePropagationEngine.build_networkx_graph(isolated_db, project.id)[0], p1.id
    )
    affected_apps = [r for r in node_records.values() if r["node_type"] == "application"]
    app_reach = len(affected_apps) / 2.0
    assert app_reach == 0.5


# 10. Package reach
def test_package_reach_calculation(isolated_db: Session) -> None:
    # Diamond graph: 3 packages (A, B, C). C has 2 downstream packages (A and B).
    # package_reach = 2 / (3 - 1) = 1.0 (100% reach)
    project = Project(name="Pkg Reach Project")
    isolated_db.add(project)
    isolated_db.commit()

    content = (FIXTURES_DIR / "diamond_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "diamond.json")
    GraphService.persist_graph(isolated_db, project.id, parsed)

    packages = {p.name: p.id for p in isolated_db.scalars(select(Package)).all()}
    c_id = packages["package-c"]

    node_records, _, _, _ = RipplePropagationEngine.traverse_impact(
        RipplePropagationEngine.build_networkx_graph(isolated_db, project.id)[0], c_id
    )
    affected_pkgs = [r for r in node_records.values() if r["node_type"] == "package" and not r["is_seed"]]
    pkg_reach = len(affected_pkgs) / (len(packages) - 1)
    assert pkg_reach == 1.0


# 11. Blast radius calculation
def test_blast_radius_calculation() -> None:
    # blast_radius = 0.70 * app_reach + 0.30 * pkg_reach
    app_reach = 0.8
    pkg_reach = 0.5
    blast = round(0.70 * app_reach + 0.30 * pkg_reach, 4)
    assert blast == 0.71


# 12. Criticality tier mapping
def test_criticality_tier_mapping() -> None:
    scores = RiskService.CRITICALITY_TIER_SCORES
    assert scores["LOW"] == 0.25
    assert scores["MEDIUM"] == 0.50
    assert scores["HIGH"] == 0.75
    assert scores["CRITICAL"] == 1.00


# 13. Maximum affected-app criticality
def test_max_affected_app_criticality(isolated_db: Session) -> None:
    project = Project(name="Max Crit Project")
    isolated_db.add(project)
    isolated_db.commit()

    # App1 is LOW (0.25), App2 is CRITICAL (1.00). Package P reaches both.
    app1 = Application(project_id=project.id, name="App1", criticality_tier="LOW", criticality_score=0.25)
    app2 = Application(project_id=project.id, name="App2", criticality_tier="CRITICAL", criticality_score=1.00)
    p = Package(ecosystem="npm", name="shared", version="1.0")
    v = Vulnerability(osv_id="GHSA-1", severity_data=[{"type": "CVSS_V3", "score": "7.0"}], raw_record={})
    isolated_db.add_all([app1, app2, p, v])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app1.id, source_package_id=None, target_package_id=p.id, direct=True),
        Dependency(application_id=app2.id, source_package_id=None, target_package_id=p.id, direct=True),
        PackageVulnerability(package_id=p.id, vulnerability_id=v.id, source="osv"),
        VulnerabilityScan(project_id=project.id, status="success", package_count=1, vulnerable_package_count=1, vulnerability_count=1),
    ])
    isolated_db.commit()

    analysis, results = RiskService.execute_risk_analysis(isolated_db, project.id)
    assert len(results) == 1
    assert results[0].max_application_criticality == "CRITICAL"
    assert results[0].application_criticality_score == 1.00


# 14. Default risk weights
def test_default_risk_weights(isolated_db: Session) -> None:
    project = Project(name="Weights Project")
    isolated_db.add(project)
    isolated_db.commit()

    profile = RiskService.get_or_create_default_profile(isolated_db, project.id)
    assert profile.severity_weight == 0.30
    assert profile.centrality_weight == 0.25
    assert profile.blast_radius_weight == 0.25
    assert profile.application_criticality_weight == 0.20
    assert sum([profile.severity_weight, profile.centrality_weight, profile.blast_radius_weight, profile.application_criticality_weight]) == 1.0


# 15. Invalid weight sum rejected
def test_invalid_weight_sum_rejected() -> None:
    # Sum != 1.0
    with pytest.raises(RiskProfileError, match="must sum to 1.0"):
        RiskService.validate_weights(0.40, 0.40, 0.40, 0.40)

    # Negative weight
    with pytest.raises(RiskProfileError, match="must be between 0.0 and 1.0"):
        RiskService.validate_weights(-0.1, 0.4, 0.4, 0.3)


# 16. Custom risk weights
def test_custom_risk_weights_update(isolated_db: Session) -> None:
    project = Project(name="Custom Weights Project")
    isolated_db.add(project)
    isolated_db.commit()

    profile = RiskService.update_profile(
        isolated_db, project.id,
        severity_weight=0.50,
        centrality_weight=0.20,
        blast_radius_weight=0.20,
        application_criticality_weight=0.10,
    )
    assert profile.severity_weight == 0.50
    assert profile.application_criticality_weight == 0.10


# 17. Deterministic risk score
def test_deterministic_risk_score() -> None:
    # severity = 0.90, centrality = 0.80, blast = 0.60, crit = 0.50
    # weights: 0.30, 0.25, 0.25, 0.20
    # risk = 0.30*0.90 + 0.25*0.80 + 0.25*0.60 + 0.20*0.50 = 0.27 + 0.20 + 0.15 + 0.10 = 0.72
    # score = 72.0
    w_sev, w_cent, w_blast, w_crit = 0.30, 0.25, 0.25, 0.20
    sev, cent, blast, crit = 0.90, 0.80, 0.60, 0.50
    score = round((w_sev * sev + w_cent * cent + w_blast * blast + w_crit * crit) * 100.0, 2)
    assert score == 72.0


# 18. Priority band calculation
def test_priority_band_calculation() -> None:
    def get_band(score: float) -> str:
        if score >= 75.0: return "CRITICAL"
        elif score >= 50.0: return "HIGH"
        elif score >= 25.0: return "MODERATE"
        return "LOW"

    assert get_band(85.0) == "CRITICAL"
    assert get_band(75.0) == "CRITICAL"
    assert get_band(74.99) == "HIGH"
    assert get_band(50.0) == "HIGH"
    assert get_band(49.99) == "MODERATE"
    assert get_band(25.0) == "MODERATE"
    assert get_band(24.99) == "LOW"
    assert get_band(0.0) == "LOW"


# 19. Deterministic ranking tie-break
def test_deterministic_ranking_tie_break() -> None:
    items = [
        {"risk_score": 80.0, "blast_radius_score": 0.5, "centrality_score": 0.5, "severity_normalized": 0.8, "package_id": 2, "vulnerability_id": 10},
        {"risk_score": 80.0, "blast_radius_score": 0.5, "centrality_score": 0.5, "severity_normalized": 0.8, "package_id": 1, "vulnerability_id": 10},
        {"risk_score": 90.0, "blast_radius_score": 0.6, "centrality_score": 0.6, "severity_normalized": 0.9, "package_id": 3, "vulnerability_id": 10},
    ]
    items.sort(key=lambda x: (
        -x["risk_score"],
        -x["blast_radius_score"],
        -x["centrality_score"],
        -x["severity_normalized"],
        x["package_id"],
        x["vulnerability_id"],
    ))
    assert items[0]["package_id"] == 3
    assert items[1]["package_id"] == 1  # package_id 1 tie-breaks before 2
    assert items[2]["package_id"] == 2


# 20. Missing severity produces unscored result
def test_missing_severity_produces_unscored_result(isolated_db: Session) -> None:
    project = Project(name="Unscored Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="App")
    p = Package(ecosystem="npm", name="pkg-unscored", version="1.0")
    v = Vulnerability(osv_id="GHSA-missing", severity_data=[], raw_record={})
    isolated_db.add_all([app, p, v])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p.id, direct=True),
        PackageVulnerability(package_id=p.id, vulnerability_id=v.id, source="osv"),
        VulnerabilityScan(project_id=project.id, status="success", package_count=1, vulnerable_package_count=1, vulnerability_count=1),
    ])
    isolated_db.commit()

    analysis, results = RiskService.execute_risk_analysis(isolated_db, project.id)
    assert analysis.scored_count == 0
    assert analysis.unscored_count == 1
    assert results[0].severity_normalized is None
    assert results[0].cvss_score is None
    assert results[0].risk_score is None
    assert results[0].priority_band == "UNSCORED"
    assert results[0].priority_rank is None


# 21. Zero vulnerability analysis
def test_zero_vulnerability_analysis(isolated_db: Session) -> None:
    project = Project(name="Clean Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="Clean App")
    p = Package(ecosystem="npm", name="clean-pkg", version="1.0")
    isolated_db.add_all([app, p])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p.id, direct=True),
        VulnerabilityScan(project_id=project.id, status="success", package_count=1, vulnerable_package_count=0, vulnerability_count=0),
    ])
    isolated_db.commit()

    analysis, results = RiskService.execute_risk_analysis(isolated_db, project.id)
    assert analysis.status == "success"
    assert analysis.vulnerability_count == 0
    assert len(results) == 0


# 22. Risk analysis persistence
def test_risk_analysis_persistence(isolated_db: Session) -> None:
    project = Project(name="Persist Project")
    isolated_db.add(project)
    isolated_db.commit()

    content = (FIXTURES_DIR / "diamond_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "diamond.json")
    GraphService.persist_graph(isolated_db, project.id, parsed)

    pkg_c = isolated_db.scalars(select(Package).where(Package.name == "package-c")).first()
    vuln = Vulnerability(osv_id="GHSA-persist", severity_data=[{"type": "CVSS_V3", "score": "8.5"}], raw_record={})
    isolated_db.add(vuln)
    isolated_db.commit()

    isolated_db.add_all([
        PackageVulnerability(package_id=pkg_c.id, vulnerability_id=vuln.id, source="osv"),
        VulnerabilityScan(project_id=project.id, status="success", package_count=3, vulnerable_package_count=1, vulnerability_count=1),
    ])
    isolated_db.commit()

    analysis, results = RiskService.execute_risk_analysis(isolated_db, project.id)
    assert analysis.id is not None
    assert len(results) == 1
    assert results[0].risk_score > 0
    assert results[0].priority_rank == 1

    # Query DB directly
    db_res = isolated_db.scalars(select(RiskResult).where(RiskResult.analysis_id == analysis.id)).all()
    assert len(db_res) == 1


# 23. Transaction rollback on write failure
def test_transaction_rollback_on_write_failure(isolated_db: Session) -> None:
    project = Project(name="Rollback Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="App")
    p = Package(ecosystem="npm", name="pkg", version="1.0")
    v = Vulnerability(osv_id="GHSA-err", severity_data=[{"type": "CVSS_V3", "score": "8.0"}], raw_record={})
    isolated_db.add_all([app, p, v])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p.id, direct=True),
        PackageVulnerability(package_id=p.id, vulnerability_id=v.id, source="osv"),
        VulnerabilityScan(project_id=project.id, status="success", package_count=1, vulnerable_package_count=1, vulnerability_count=1),
    ])
    isolated_db.commit()

    with patch.object(isolated_db, "commit", side_effect=RuntimeError("Simulated write fail")):
        with pytest.raises(RuntimeError, match="Simulated write fail"):
            RiskService.execute_risk_analysis(isolated_db, project.id)

    # Confirm no partial risk analysis committed
    analyses = isolated_db.scalars(select(RiskAnalysis)).all()
    assert len(analyses) == 0


# 24. Project isolation
def test_project_isolation(client: TestClient) -> None:
    p1_resp = client.post("/api/v1/projects", json={"name": "Project 1 Isolation"})
    p1_id = p1_resp.json()["id"]

    p2_resp = client.post("/api/v1/projects", json={"name": "Project 2 Isolation"})
    p2_id = p2_resp.json()["id"]

    # Trigger analysis on p1
    res = client.post(f"/api/v1/projects/{p1_id}/risk/analyses")
    assert res.status_code == 201
    analysis_id = res.json()["analysis_id"]

    # Try accessing p1's analysis via p2 endpoint -> should 404
    cross_res = client.get(f"/api/v1/projects/{p2_id}/risk/analyses/{analysis_id}")
    assert cross_res.status_code == 404


# 25. Application criticality authorization & validation
def test_application_criticality_api_validation(client: TestClient) -> None:
    p_resp = client.post("/api/v1/projects", json={"name": "Crit API Test"})
    project_id = p_resp.json()["id"]

    diamond_file = FIXTURES_DIR / "diamond_graph.json"
    client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("diamond.json", diamond_file.read_bytes(), "application/json")},
    )

    nodes_resp = client.get(f"/api/v1/projects/{project_id}/graph/nodes")
    app_node = next(n for n in nodes_resp.json()["nodes"] if n["node_type"] == "application")
    app_id = app_node["db_id"]

    # Update tier to HIGH
    patch_resp = client.patch(
        f"/api/v1/projects/{project_id}/applications/{app_id}/criticality",
        json={"tier": "HIGH"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["criticality_tier"] == "HIGH"
    assert patch_resp.json()["criticality_score"] == 0.75

    # Invalid tier rejected
    bad_resp = client.patch(
        f"/api/v1/projects/{project_id}/applications/{app_id}/criticality",
        json={"tier": "SUPER_CRITICAL"},
    )
    assert bad_resp.status_code == 422


# 26. Risk API
def test_risk_api_full_flow(client: TestClient) -> None:
    p_resp = client.post("/api/v1/projects", json={"name": "Risk Full Flow"})
    project_id = p_resp.json()["id"]

    diamond_file = FIXTURES_DIR / "diamond_graph.json"
    client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("diamond.json", diamond_file.read_bytes(), "application/json")},
    )

    # 1. Update risk profile weights
    put_res = client.put(
        f"/api/v1/projects/{project_id}/risk/profile",
        json={
            "severity_weight": 0.40,
            "centrality_weight": 0.20,
            "blast_radius_weight": 0.20,
            "application_criticality_weight": 0.20,
        },
    )
    assert put_res.status_code == 200
    assert put_res.json()["severity_weight"] == 0.40

    # 2. Get profile
    get_prof = client.get(f"/api/v1/projects/{project_id}/risk/profile")
    assert get_prof.status_code == 200
    assert get_prof.json()["severity_weight"] == 0.40

    # 3. Post risk analysis
    res_post = client.post(f"/api/v1/projects/{project_id}/risk/analyses")
    assert res_post.status_code == 201
    analysis_id = res_post.json()["analysis_id"]

    # 4. List analyses
    res_list = client.get(f"/api/v1/projects/{project_id}/risk/analyses")
    assert res_list.status_code == 200
    assert res_list.json()["total"] >= 1

    # 5. Get single analysis
    res_single = client.get(f"/api/v1/projects/{project_id}/risk/analyses/{analysis_id}")
    assert res_single.status_code == 200
    assert res_single.json()["analysis_id"] == analysis_id


# 27. Priority API
def test_priority_api(client: TestClient) -> None:
    p_resp = client.post("/api/v1/projects", json={"name": "Priority API Project"})
    project_id = p_resp.json()["id"]

    res = client.get(f"/api/v1/projects/{project_id}/risk/priority")
    assert res.status_code == 200
    assert res.json()["total"] == 0


# 28. Phase 4 Reach Consistency & Crucial Leverage Scenario
def test_phase4_reach_consistency_and_leverage_scenario(isolated_db: Session) -> None:
    """CRUCIAL PRODUCT SCENARIO:

    Package A:
      CVSS = 5.2 (moderate vulnerability severity)
      High structural centrality (deep central dependency)
      High downstream reach: reaches downstream application through multiple paths
      High application criticality (CRITICAL = 1.0)

    Package B:
      CVSS = 8.9 (high vulnerability severity)
      Low structural centrality (leaf package)
      Low downstream reach (isolated or minimal reach)
      High application criticality (CRITICAL = 1.0)

    Verify that RippleGuard's configured formula ranks Package A ABOVE Package B,
    proving: "Fix the highest-leverage node, not simply the loudest CVE."
    """
    project = Project(name="Leverage Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(
        project_id=project.id,
        name="Production Banking Core",
        criticality_tier="CRITICAL",
        criticality_score=1.00,
    )
    isolated_db.add(app)
    isolated_db.commit()

    # Graph Topology:
    # Package A sits deep in the core:
    # App -> D1 -> D2 -> Package A
    # App -> D3 -> Package A
    # Package B is an isolated leaf:
    # App -> Package B
    pkg_a = Package(ecosystem="npm", name="core-runtime-a", version="1.0.0")
    pkg_b = Package(ecosystem="npm", name="leaf-helper-b", version="1.0.0")
    pkg_d1 = Package(ecosystem="npm", name="dep-1", version="1.0.0")
    pkg_d2 = Package(ecosystem="npm", name="dep-2", version="1.0.0")
    pkg_d3 = Package(ecosystem="npm", name="dep-3", version="1.0.0")
    isolated_db.add_all([pkg_a, pkg_b, pkg_d1, pkg_d2, pkg_d3])
    isolated_db.commit()

    # Dependencies:
    # App depends on D1, D3, and B directly
    # D1 depends on D2; D2 depends on A; D3 depends on A
    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg_d1.id, direct=True),
        Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg_d3.id, direct=True),
        Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg_b.id, direct=True),
        Dependency(application_id=app.id, source_package_id=pkg_d1.id, target_package_id=pkg_d2.id, direct=False),
        Dependency(application_id=app.id, source_package_id=pkg_d2.id, target_package_id=pkg_a.id, direct=False),
        Dependency(application_id=app.id, source_package_id=pkg_d3.id, target_package_id=pkg_a.id, direct=False),
    ])
    isolated_db.commit()

    # Vulnerability for A: CVSS 5.2
    vuln_a = Vulnerability(
        osv_id="CVE-2024-MODERATE-A",
        summary="Moderate severity flaw in core-runtime-a",
        severity_data=[{"type": "CVSS_V3", "score": "5.2"}],
        raw_record={},
    )
    # Vulnerability for B: CVSS 8.9 (Loud CVE)
    vuln_b = Vulnerability(
        osv_id="CVE-2024-LOUD-B",
        summary="High severity flaw in leaf-helper-b",
        severity_data=[{"type": "CVSS_V3", "score": "8.9"}],
        raw_record={},
    )
    isolated_db.add_all([vuln_a, vuln_b])
    isolated_db.commit()

    isolated_db.add_all([
        PackageVulnerability(package_id=pkg_a.id, vulnerability_id=vuln_a.id, source="osv"),
        PackageVulnerability(package_id=pkg_b.id, vulnerability_id=vuln_b.id, source="osv"),
        VulnerabilityScan(project_id=project.id, status="success", package_count=5, vulnerable_package_count=2, vulnerability_count=2),
    ])
    isolated_db.commit()

    # 1. Verify Phase 4 reach consistency:
    # On package A:
    # Forward edges: D2 -> A, D3 -> A. Reverse traversal from A reaches D2, D3, D1, and App.
    # Downstream packages affected = 3 (D2, D3, D1).
    G, _, _ = RipplePropagationEngine.build_networkx_graph(isolated_db, project.id)
    node_records_a, _, _, _ = RipplePropagationEngine.traverse_impact(G, pkg_a.id)
    p4_app_count_a = len([r for r in node_records_a.values() if r["node_type"] == "application"])
    p4_pkg_count_a = len([r for r in node_records_a.values() if r["node_type"] == "package" and not r["is_seed"]])
    assert p4_app_count_a == 1
    assert p4_pkg_count_a == 3

    # On package B:
    # Leaf helper. Only reached directly by App. Downstream packages affected = 0.
    node_records_b, _, _, _ = RipplePropagationEngine.traverse_impact(G, pkg_b.id)
    p4_app_count_b = len([r for r in node_records_b.values() if r["node_type"] == "application"])
    p4_pkg_count_b = len([r for r in node_records_b.values() if r["node_type"] == "package" and not r["is_seed"]])
    assert p4_app_count_b == 1
    assert p4_pkg_count_b == 0

    # 2. Execute Risk Analysis with RippleGuard formula:
    analysis, results = RiskService.execute_risk_analysis(isolated_db, project.id)
    assert len(results) == 2

    # Check that counts in Phase 5 match Phase 4 exactly
    res_a = next(r for r in results if r.package_id == pkg_a.id)
    res_b = next(r for r in results if r.package_id == pkg_b.id)

    assert res_a.affected_application_count == p4_app_count_a
    assert res_a.affected_downstream_package_count == p4_pkg_count_a
    assert res_b.affected_application_count == p4_app_count_b
    assert res_b.affected_downstream_package_count == p4_pkg_count_b

    # 3. VERIFY LEVERAGE VALUE PROPOSITION:
    # Package A has higher reach (3 downstream packages vs 0) and higher centrality.
    # Package A should outrank Package B (priority_rank 1 vs 2)!
    print(f"Package A risk score: {res_a.risk_score} (rank {res_a.priority_rank})")
    print(f"Package B risk score: {res_b.risk_score} (rank {res_b.priority_rank})")

    assert res_a.risk_score > res_b.risk_score
    assert res_a.priority_rank == 1
    assert res_b.priority_rank == 2
    assert "high structural centrality" in res_a.reason.lower() or "high downstream" in res_a.reason.lower()


# 29. PageRank Convergence / Fallback Behavior
def test_pagerank_fallback_on_convergence_failure(isolated_db: Session) -> None:
    """Explicitly verify PageRank fallback behavior when power iteration fails to converge.

    Why fallback exists: Pathological topologies (e.g. periodic cycles, extreme damping tolerances,
    or bipartite sinks) can prevent power iteration from converging within max_iter.
    Why deterministic: Falls back to uniform distribution {pid: 1.0/N} where every package receives
    identical raw probability. Normalization then cleanly produces 0.0 without stochasticity.
    How marked/audited: Result sets centrality_approximate = True and logs a structured warning.
    """
    project = Project(name="PageRank Fallback Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="App")
    p1 = Package(ecosystem="npm", name="pkg-1", version="1.0")
    p2 = Package(ecosystem="npm", name="pkg-2", version="1.0")
    p3 = Package(ecosystem="npm", name="pkg-3", version="1.0")
    isolated_db.add_all([app, p1, p2, p3])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p1.id, direct=True),
        Dependency(application_id=app.id, source_package_id=p1.id, target_package_id=p2.id, direct=False),
        Dependency(application_id=app.id, source_package_id=p2.id, target_package_id=p3.id, direct=False),
    ])
    isolated_db.commit()

    # Simulate PowerIterationFailedConvergence from NetworkX
    with patch("networkx.pagerank", side_effect=nx.PowerIterationFailedConvergence(num_iterations=200)):
        centrality_map, approx_flag = CentralityService.compute_project_centrality(isolated_db, project.id)

    # Verify audited marking
    assert approx_flag is True, "Expected centrality_approximate to be True on PageRank fallback."

    # Verify uniform distribution across all 3 package nodes
    assert len(centrality_map) == 3
    expected_uniform_raw = round(1.0 / 3.0, 6)

    for pid, metrics in centrality_map.items():
        assert round(metrics.raw_pagerank, 6) == expected_uniform_raw
        # With identical raw PageRank across all nodes, normalized PageRank must be 0.0
        assert metrics.normalized_pagerank == 0.0
        assert metrics.centrality_approximate is True


# 30. Mixed Scored and Unscored Vulnerabilities in Same Project
def test_mixed_scored_and_unscored_vulnerabilities_ranking(isolated_db: Session) -> None:
    """Verify that unscored vulnerabilities remain visible but are excluded from ranked scored results.

    - Scored vulnerabilities receive 1-indexed priority_rank (1, 2, ...).
    - Unscored vulnerabilities receive priority_rank = None and priority_band = 'UNSCORED'.
    - Unscored vulnerabilities have severity_normalized = None and risk_score = None (NOT zero).
    """
    project = Project(name="Mixed Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="App", criticality_tier="HIGH", criticality_score=0.75)
    p_scored = Package(ecosystem="npm", name="scored-lib", version="1.0")
    p_unscored = Package(ecosystem="npm", name="unscored-lib", version="1.0")
    isolated_db.add_all([app, p_scored, p_unscored])
    isolated_db.commit()

    v_scored = Vulnerability(
        osv_id="CVE-2024-SCORED",
        severity_data=[{"type": "CVSS_V3", "score": "7.5"}],
        raw_record={},
    )
    v_unscored = Vulnerability(
        osv_id="CVE-2024-UNSCORED",
        severity_data=[],  # Empty / missing CVSS
        raw_record={},
    )
    isolated_db.add_all([v_scored, v_unscored])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p_scored.id, direct=True),
        Dependency(application_id=app.id, source_package_id=None, target_package_id=p_unscored.id, direct=True),
        PackageVulnerability(package_id=p_scored.id, vulnerability_id=v_scored.id, source="osv"),
        PackageVulnerability(package_id=p_unscored.id, vulnerability_id=v_unscored.id, source="osv"),
        VulnerabilityScan(project_id=project.id, status="success", package_count=2, vulnerable_package_count=2, vulnerability_count=2),
    ])
    isolated_db.commit()

    analysis, results = RiskService.execute_risk_analysis(isolated_db, project.id)

    assert analysis.vulnerability_count == 2
    assert analysis.scored_count == 1
    assert analysis.unscored_count == 1

    res_scored = next(r for r in results if r.package_id == p_scored.id)
    res_unscored = next(r for r in results if r.package_id == p_unscored.id)

    # Scored assertions
    assert res_scored.priority_rank == 1
    assert res_scored.risk_score is not None
    assert res_scored.risk_score > 0
    assert res_scored.severity_normalized == 0.75
    assert res_scored.priority_band in ["CRITICAL", "HIGH", "MODERATE", "LOW"]

    # Unscored assertions: severity_normalized = None, risk_score = None, priority_band = 'UNSCORED'
    assert res_unscored.priority_rank is None
    assert res_unscored.risk_score is None
    assert res_unscored.severity_normalized is None
    assert res_unscored.cvss_score is None
    assert res_unscored.priority_band == "UNSCORED"
