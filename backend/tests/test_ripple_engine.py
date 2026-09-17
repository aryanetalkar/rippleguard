from pathlib import Path
from unittest.mock import patch
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
from app.models.ripple_analysis import RippleAnalysis
from app.models.ripple_node import RippleNode
from app.models.ripple_path import RipplePath
from app.models.vulnerability import Vulnerability
from app.services.cyclonedx_parser import CycloneDXParser
from app.services.graph_service import GraphService
from app.services.ripple_service import (
    PackageNotBelongingToProjectError,
    PackageNotFoundError,
    ProjectNotFoundError,
    RipplePropagationEngine,
    VulnerabilityNotAssociatedError,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def isolated_db() -> Session:
    """Create an isolated in-memory database for engine unit tests."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def setup_project_with_diamond(db: Session) -> tuple[Project, dict]:
    project = Project(name="Diamond Project", description="Testing diamond graph ripple")
    db.add(project)
    db.commit()

    content = (FIXTURES_DIR / "diamond_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "diamond.json")
    GraphService.persist_graph(db, project.id, parsed)

    # In diamond graph:
    # app -> package-a -> package-c
    # app -> package-b -> package-c
    packages = {p.name: p for p in db.scalars(select(Package)).all()}
    return project, packages


# 1. Single compromised package with no dependents
def test_single_compromised_package_with_no_dependents(isolated_db: Session) -> None:
    # Setup App -> pkg-root. pkg-root has no dependents pointing to it from other packages.
    project = Project(name="No Dependents Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="TestApp", version="1.0.0")
    pkg = Package(ecosystem="npm", name="standalone", version="1.0.0")
    isolated_db.add_all([app, pkg])
    isolated_db.commit()

    # app depends on standalone, but standalone has no other dependents
    dep = Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg.id, direct=True)
    isolated_db.add(dep)
    isolated_db.commit()

    # If app is the only dependent, let's create a package that nothing depends on:
    # App -> pkg1; pkg2 exists in project
    pkg2 = Package(ecosystem="npm", name="leaf", version="1.0.0")
    isolated_db.add(pkg2)
    isolated_db.commit()

    dep2 = Dependency(application_id=app.id, source_package_id=pkg.id, target_package_id=pkg2.id, direct=False)
    isolated_db.add(dep2)
    isolated_db.commit()

    # If pkg (not leaf) was compromised, leaf wouldn't depend on pkg; pkg depends on leaf!
    # So if pkg is compromised: App depends on pkg, but no packages depend on pkg.
    # Leaf has dependents = pkg, App.
    # What about leaf compromised? Leaf -> pkg -> App!
    # What has NO dependents? App is root. No package depends on App.
    # For a package with no dependents: pkg has nothing depending on it except App.
    # Let's test leaf compromise vs pkg compromise:
    # In graph: App -> pkg -> leaf.
    # If pkg is compromised: R has edge pkg -> App. Dependents: 0 packages, 1 App.
    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg.id,
    )
    assert analysis.affected_package_count == 1  # only seed itself
    assert analysis.direct_dependent_count == 0
    assert analysis.transitive_dependent_count == 0
    assert analysis.affected_application_count == 1  # reaches App


# 2. One direct dependent
def test_one_direct_dependent(isolated_db: Session) -> None:
    # App -> A -> B (compromised B)
    # B has 1 direct dependent: A
    project = Project(name="One Direct")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="App", version="1.0")
    pkg_a = Package(ecosystem="npm", name="pkg-a", version="1.0")
    pkg_b = Package(ecosystem="npm", name="pkg-b", version="1.0")
    isolated_db.add_all([app, pkg_a, pkg_b])
    isolated_db.commit()

    # App depends on A; A depends on B
    isolated_db.add(Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg_a.id, direct=True))
    isolated_db.add(Dependency(application_id=app.id, source_package_id=pkg_a.id, target_package_id=pkg_b.id, direct=False))
    isolated_db.commit()

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_b.id,
    )
    assert analysis.affected_package_count == 2  # B (seed) + A
    assert analysis.direct_dependent_count == 1  # A
    assert analysis.transitive_dependent_count == 0
    assert analysis.affected_application_count == 1


# 3. Two direct dependents
def test_two_direct_dependents(isolated_db: Session) -> None:
    # App -> A -> C, App -> B -> C
    # C has two direct dependents: A and B
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_c = packages["package-c"]

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_c.id,
    )
    assert analysis.affected_package_count == 3  # C, A, B
    assert analysis.direct_dependent_count == 2  # A and B
    assert analysis.transitive_dependent_count == 0
    assert analysis.affected_application_count == 1


# 4. Transitive chain
def test_transitive_chain(isolated_db: Session) -> None:
    # App -> A -> B -> C -> Seed (D)
    # Seed compromised:
    # C is depth 1 (direct)
    # B is depth 2 (transitive)
    # A is depth 3 (transitive)
    # App is depth 4 (application)
    project = Project(name="Chain Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="App", version="1.0")
    pkg_a = Package(ecosystem="npm", name="pkg-a", version="1.0")
    pkg_b = Package(ecosystem="npm", name="pkg-b", version="1.0")
    pkg_c = Package(ecosystem="npm", name="pkg-c", version="1.0")
    pkg_d = Package(ecosystem="npm", name="pkg-d", version="1.0")
    isolated_db.add_all([app, pkg_a, pkg_b, pkg_c, pkg_d])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg_a.id, direct=True),
        Dependency(application_id=app.id, source_package_id=pkg_a.id, target_package_id=pkg_b.id, direct=False),
        Dependency(application_id=app.id, source_package_id=pkg_b.id, target_package_id=pkg_c.id, direct=False),
        Dependency(application_id=app.id, source_package_id=pkg_c.id, target_package_id=pkg_d.id, direct=False),
    ])
    isolated_db.commit()

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_d.id,
    )
    assert analysis.max_depth == 4
    assert analysis.affected_package_count == 4  # D, C, B, A
    assert analysis.direct_dependent_count == 1  # C
    assert analysis.transitive_dependent_count == 2  # B, A
    assert analysis.affected_application_count == 1  # App

    node_by_id = {n.package_id: n for n in nodes if n.node_type == "package"}
    assert node_by_id[pkg_d.id].depth == 0
    assert node_by_id[pkg_d.id].is_seed is True
    assert node_by_id[pkg_c.id].depth == 1
    assert node_by_id[pkg_c.id].is_direct is True
    assert node_by_id[pkg_b.id].depth == 2
    assert node_by_id[pkg_b.id].is_direct is False
    assert node_by_id[pkg_a.id].depth == 3
    assert node_by_id[pkg_a.id].is_direct is False


# 5. Diamond graph
def test_diamond_graph_simulation(isolated_db: Session) -> None:
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_c = packages["package-c"]

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_c.id,
    )
    # Expected core fixture:
    # Application
    #  ├── package-a ── package-c
    #  └── package-b ── package-c
    # Compromised: package-c
    # depth 0: package-c
    # depth 1: package-a, package-b
    # downstream application: Application
    # affected packages: 3
    # direct dependents: 2
    # transitive dependent packages: 0
    assert analysis.affected_package_count == 3
    assert analysis.direct_dependent_count == 2
    assert analysis.transitive_dependent_count == 0
    assert analysis.affected_application_count == 1
    assert analysis.max_depth == 2  # App is at depth 2


# 6. Shared dependency
def test_shared_dependency_simulation(isolated_db: Session) -> None:
    # 3 packages share seed C
    project = Project(name="Shared Dep Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="App", version="1.0")
    pkg_seed = Package(ecosystem="pypi", name="shared-core", version="1.0")
    pkg_1 = Package(ecosystem="pypi", name="pkg-1", version="1.0")
    pkg_2 = Package(ecosystem="pypi", name="pkg-2", version="1.0")
    pkg_3 = Package(ecosystem="pypi", name="pkg-3", version="1.0")
    isolated_db.add_all([app, pkg_seed, pkg_1, pkg_2, pkg_3])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg_1.id, direct=True),
        Dependency(application_id=app.id, source_package_id=pkg_1.id, target_package_id=pkg_seed.id, direct=False),
        Dependency(application_id=app.id, source_package_id=pkg_2.id, target_package_id=pkg_seed.id, direct=False),
        Dependency(application_id=app.id, source_package_id=pkg_3.id, target_package_id=pkg_seed.id, direct=False),
        Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg_2.id, direct=True),
        Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg_3.id, direct=True),
    ])
    isolated_db.commit()

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_seed.id,
    )
    assert analysis.direct_dependent_count == 3
    assert analysis.affected_package_count == 4
    assert analysis.affected_application_count == 1


# 7. Cyclic graph
def test_cyclic_graph_termination(isolated_db: Session) -> None:
    project = Project(name="Cyclic Project")
    isolated_db.add(project)
    isolated_db.commit()

    content = (FIXTURES_DIR / "cyclic_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "cyclic.json")
    GraphService.persist_graph(isolated_db, project.id, parsed)

    packages = {p.name: p for p in isolated_db.scalars(select(Package)).all()}
    pkg_x = packages["package-x"]

    # In cycle X <-> Y:
    # Traversal must terminate safely with no infinite loop
    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_x.id,
    )
    assert analysis.status == "success"
    assert analysis.truncated is False
    # Only 2 packages + 1 app
    assert analysis.affected_package_count == 2
    assert analysis.affected_application_count == 1


# 8. Multiple applications
def test_multiple_applications_reach(isolated_db: Session) -> None:
    project = Project(name="Multi App Project")
    isolated_db.add(project)
    isolated_db.commit()

    app1 = Application(project_id=project.id, name="Frontend App", version="1.0")
    app2 = Application(project_id=project.id, name="Backend App", version="2.0")
    pkg = Package(ecosystem="npm", name="shared-lib", version="1.0")
    isolated_db.add_all([app1, app2, pkg])
    isolated_db.commit()

    isolated_db.add_all([
        Dependency(application_id=app1.id, source_package_id=None, target_package_id=pkg.id, direct=True),
        Dependency(application_id=app2.id, source_package_id=None, target_package_id=pkg.id, direct=True),
    ])
    isolated_db.commit()

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg.id,
    )
    assert analysis.affected_application_count == 2
    app_nodes = [n for n in nodes if n.node_type == "application"]
    assert len(app_nodes) == 2


# 9. Seed package validation
def test_seed_package_validation_success(isolated_db: Session) -> None:
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_a = packages["package-a"]

    p, pkg, vuln, ids = RipplePropagationEngine.validate_seed(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_a.id,
    )
    assert p.id == project.id
    assert pkg.id == pkg_a.id
    assert vuln is None


# 10. Package outside project rejected
def test_package_outside_project_rejected(isolated_db: Session) -> None:
    p1 = Project(name="Project 1")
    p2 = Project(name="Project 2")
    isolated_db.add_all([p1, p2])
    isolated_db.commit()

    app = Application(project_id=p1.id, name="App 1", version="1.0")
    pkg1 = Package(ecosystem="npm", name="p1-pkg", version="1.0")
    isolated_db.add_all([app, pkg1])
    isolated_db.commit()

    isolated_db.add(Dependency(application_id=app.id, source_package_id=None, target_package_id=pkg1.id, direct=True))
    isolated_db.commit()

    # Try simulating p1-pkg inside project 2
    with pytest.raises(PackageNotBelongingToProjectError):
        RipplePropagationEngine.execute_simulation(
            db=isolated_db,
            project_id=p2.id,
            seed_package_id=pkg1.id,
        )


# 11. Vulnerability/package association validation
def test_vulnerability_package_association_validation(isolated_db: Session) -> None:
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_c = packages["package-c"]

    vuln = Vulnerability(
        osv_id="GHSA-fake-1234",
        aliases=[],
        references=[],
        severity_data=[],
        affected_data=[],
        raw_record={},
    )
    isolated_db.add(vuln)
    isolated_db.commit()

    # Vuln exists, but is NOT linked to pkg_c
    with pytest.raises(VulnerabilityNotAssociatedError):
        RipplePropagationEngine.validate_seed(
            db=isolated_db,
            project_id=project.id,
            seed_package_id=pkg_c.id,
            seed_vulnerability_id=vuln.id,
        )

    # Link it properly
    pv = PackageVulnerability(package_id=pkg_c.id, vulnerability_id=vuln.id, source="osv")
    isolated_db.add(pv)
    isolated_db.commit()

    # Now it should validate cleanly
    _, _, resolved_vuln, _ = RipplePropagationEngine.validate_seed(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_c.id,
        seed_vulnerability_id=vuln.id,
    )
    assert resolved_vuln is not None
    assert resolved_vuln.id == vuln.id


# 12. Maximum depth limit truncation
def test_maximum_depth_limit_truncation(isolated_db: Session) -> None:
    project = Project(name="Deep Chain Project")
    isolated_db.add(project)
    isolated_db.commit()

    app = Application(project_id=project.id, name="App", version="1.0")
    pkgs = [Package(ecosystem="npm", name=f"pkg-{i}", version="1.0") for i in range(5)]
    isolated_db.add(app)
    isolated_db.add_all(pkgs)
    isolated_db.commit()

    # App -> pkg-0 -> pkg-1 -> pkg-2 -> pkg-3 -> pkg-4
    isolated_db.add(Dependency(application_id=app.id, source_package_id=None, target_package_id=pkgs[0].id, direct=True))
    for i in range(4):
        isolated_db.add(Dependency(application_id=app.id, source_package_id=pkgs[i].id, target_package_id=pkgs[i+1].id, direct=False))
    isolated_db.commit()

    # Seed is pkg-4. Path back: pkg-4 -> pkg-3 -> pkg-2 -> pkg-1 -> pkg-0 -> App (length 5)
    # Set MAX_RIPPLE_DEPTH = 2
    with patch.object(settings, "MAX_RIPPLE_DEPTH", 2):
        analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
            db=isolated_db,
            project_id=project.id,
            seed_package_id=pkgs[4].id,
        )
        assert analysis.status == "partial"
        assert analysis.truncated is True
        assert analysis.truncation_reason == "MAX_DEPTH_REACHED"
        assert analysis.max_depth <= 2


# 13. Maximum node limit truncation
def test_maximum_node_limit_truncation(isolated_db: Session) -> None:
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_c = packages["package-c"]

    # Diamond has 4 nodes total (1 seed + 2 direct pkgs + 1 app).
    # If limit is 2 nodes, it should truncate cleanly:
    with patch.object(settings, "MAX_RIPPLE_NODES", 2):
        analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
            db=isolated_db,
            project_id=project.id,
            seed_package_id=pkg_c.id,
        )
        assert analysis.status == "partial"
        assert analysis.truncated is True
        assert analysis.truncation_reason == "MAX_NODES_REACHED"
        assert len(nodes) <= 2


# 14. Deterministic shortest path
def test_deterministic_shortest_path(isolated_db: Session) -> None:
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_c = packages["package-c"]

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_c.id,
    )
    # Target Application has shortest path length 2 (pkg-c -> pkg-a/b -> App)
    app_paths = [p for p in paths if p.target_node_type == "application"]
    assert len(app_paths) == 1
    assert app_paths[0].path_length == 2
    assert len(app_paths[0].path_nodes) == 3
    assert app_paths[0].path_nodes[0]["id"] == f"pkg:{pkg_c.id}"
    assert app_paths[0].path_nodes[-1]["node_type"] == "application"


# 15. Duplicate impact-node prevention
def test_duplicate_impact_node_prevention(isolated_db: Session) -> None:
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_c = packages["package-c"]

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_c.id,
    )

    node_keys = [f"{n.node_type}:{n.package_id or n.application_id}" for n in nodes]
    assert len(node_keys) == len(set(node_keys))
    # Exactly 4 distinct nodes: pkg-c, pkg-a, pkg-b, App
    assert len(node_keys) == 4


# 16. Successful persistence
def test_successful_persistence(isolated_db: Session) -> None:
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_c = packages["package-c"]

    analysis, nodes, paths = RipplePropagationEngine.execute_simulation(
        db=isolated_db,
        project_id=project.id,
        seed_package_id=pkg_c.id,
    )

    # Check database query directly
    db_analysis = isolated_db.get(RippleAnalysis, analysis.id)
    assert db_analysis is not None
    assert db_analysis.status == "success"
    assert db_analysis.affected_package_count == 3

    db_nodes = isolated_db.scalars(
        select(RippleNode).where(RippleNode.analysis_id == analysis.id)
    ).all()
    assert len(db_nodes) == 4

    db_paths = isolated_db.scalars(
        select(RipplePath).where(RipplePath.analysis_id == analysis.id)
    ).all()
    assert len(db_paths) == 3


# 17. Persistence rollback on database error
def test_persistence_rollback_on_database_error(isolated_db: Session) -> None:
    project, packages = setup_project_with_diamond(isolated_db)
    pkg_c = packages["package-c"]

    with patch.object(isolated_db, "commit", side_effect=RuntimeError("Simulated DB Write Error")):
        with pytest.raises(RuntimeError, match="Simulated DB Write Error"):
            RipplePropagationEngine.execute_simulation(
                db=isolated_db,
                project_id=project.id,
                seed_package_id=pkg_c.id,
            )

    # Verify no partial analysis was committed
    analyses = isolated_db.scalars(select(RippleAnalysis)).all()
    assert len(analyses) == 0


# 18. Project ripple analysis API
def test_project_ripple_analysis_api(client: TestClient) -> None:
    p_resp = client.post("/api/v1/projects", json={"name": "API Test Project"})
    project_id = p_resp.json()["id"]

    diamond_file = FIXTURES_DIR / "diamond_graph.json"
    client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("diamond.json", diamond_file.read_bytes(), "application/json")},
    )

    # Get nodes to find package-c ID
    nodes_resp = client.get(f"/api/v1/projects/{project_id}/graph/nodes")
    pkg_c = next(n for n in nodes_resp.json()["nodes"] if n["name"] == "package-c")

    # POST analysis
    post_resp = client.post(
        f"/api/v1/projects/{project_id}/ripple/analyses",
        json={"seed_package_id": pkg_c["db_id"]},
    )
    assert post_resp.status_code == 201
    post_data = post_resp.json()
    assert post_data["status"] == "success"
    assert post_data["summary"]["affected_package_count"] == 3
    assert post_data["summary"]["direct_dependent_count"] == 2
    assert post_data["summary"]["affected_application_count"] == 1
    assert post_data["summary"]["truncated"] is False

    analysis_id = post_data["analysis_id"]

    # GET analysis history
    history_resp = client.get(f"/api/v1/projects/{project_id}/ripple/analyses")
    assert history_resp.status_code == 200
    assert history_resp.json()["total"] >= 1

    # GET single analysis
    single_resp = client.get(f"/api/v1/projects/{project_id}/ripple/analyses/{analysis_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["analysis_id"] == analysis_id


# 19. Ripple nodes API
def test_ripple_nodes_api(client: TestClient) -> None:
    p_resp = client.post("/api/v1/projects", json={"name": "API Nodes Test"})
    project_id = p_resp.json()["id"]

    diamond_file = FIXTURES_DIR / "diamond_graph.json"
    client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("diamond.json", diamond_file.read_bytes(), "application/json")},
    )

    nodes_resp = client.get(f"/api/v1/projects/{project_id}/graph/nodes")
    pkg_c = next(n for n in nodes_resp.json()["nodes"] if n["name"] == "package-c")

    sim_resp = client.post(
        f"/api/v1/projects/{project_id}/ripple/analyses",
        json={"seed_package_id": pkg_c["db_id"]},
    )
    analysis_id = sim_resp.json()["analysis_id"]

    # Query nodes endpoint
    rnodes_resp = client.get(f"/api/v1/projects/{project_id}/ripple/analyses/{analysis_id}/nodes")
    assert rnodes_resp.status_code == 200
    rnodes_data = rnodes_resp.json()
    assert rnodes_data["analysis_id"] == analysis_id
    assert rnodes_data["total_nodes"] == 4

    seed_node = next(n for n in rnodes_data["nodes"] if n["is_seed"])
    assert seed_node["name"] == "package-c"
    assert seed_node["depth"] == 0
    assert seed_node["shortest_path_length"] == 0


# 20. Ripple paths API
def test_ripple_paths_api(client: TestClient) -> None:
    p_resp = client.post("/api/v1/projects", json={"name": "API Paths Test"})
    project_id = p_resp.json()["id"]

    diamond_file = FIXTURES_DIR / "diamond_graph.json"
    client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("diamond.json", diamond_file.read_bytes(), "application/json")},
    )

    nodes_resp = client.get(f"/api/v1/projects/{project_id}/graph/nodes")
    pkg_c = next(n for n in nodes_resp.json()["nodes"] if n["name"] == "package-c")

    sim_resp = client.post(
        f"/api/v1/projects/{project_id}/ripple/analyses",
        json={"seed_package_id": pkg_c["db_id"]},
    )
    analysis_id = sim_resp.json()["analysis_id"]

    # Query paths endpoint
    paths_resp = client.get(f"/api/v1/projects/{project_id}/ripple/analyses/{analysis_id}/paths")
    assert paths_resp.status_code == 200
    paths_data = paths_resp.json()
    assert paths_data["analysis_id"] == analysis_id
    assert paths_data["total_paths"] == 3

    for item in paths_data["paths"]:
        assert "target" in item
        assert "path" in item
        assert item["path_length"] >= 1
        assert item["path"][0]["id"] == f"pkg:{pkg_c['db_id']}"
