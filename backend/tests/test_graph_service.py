from pathlib import Path
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.models.application import Application
from app.models.dependency import Dependency
from app.models.package import Package
from app.models.project import Project
from app.models.sbom_ingestion import SBOMIngestion
from app.services.cyclonedx_parser import CycloneDXParser
from app.services.graph_service import GraphService

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def test_db() -> Session:
    """Create an isolated in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_diamond_graph_classification() -> None:
    content = (FIXTURES_DIR / "diamond_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "diamond.json")

    direct_canons, transitive_canons, resolved_edges = GraphService.compute_graph_structure(parsed)

    # In diamond graph:
    # app-a -> pkg-a, pkg-b
    # pkg-a -> pkg-c
    # pkg-b -> pkg-c
    assert "pkg:npm/package-a@1.0.0" in direct_canons
    assert "pkg:npm/package-b@1.0.0" in direct_canons
    assert "pkg:npm/package-c@1.0.0" not in direct_canons
    assert "pkg:npm/package-c@1.0.0" in transitive_canons

    # Verify shared dependency target
    targets_for_c = [
        edge for edge in resolved_edges if edge[1] == "pkg:npm/package-c@1.0.0"
    ]
    assert len(targets_for_c) == 2


def test_cyclic_graph_safety() -> None:
    content = (FIXTURES_DIR / "cyclic_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "cycle.json")

    # Compute graph structure must terminate cleanly and safely without infinite loop
    direct_canons, transitive_canons, resolved_edges = GraphService.compute_graph_structure(parsed)

    assert "pkg:npm/package-x@1.0.0" in direct_canons
    # package-y is reached from package-x
    assert "pkg:npm/package-y@1.0.0" in transitive_canons

    # Check edges contain both directions
    x_to_y = any(
        e[0] == "pkg:npm/package-x@1.0.0" and e[1] == "pkg:npm/package-y@1.0.0"
        for e in resolved_edges
    )
    y_to_x = any(
        e[0] == "pkg:npm/package-y@1.0.0" and e[1] == "pkg:npm/package-x@1.0.0"
        for e in resolved_edges
    )
    assert x_to_y is True
    assert y_to_x is True


def test_graph_persistence_and_rollback(test_db: Session) -> None:
    # 1. Setup project
    project = Project(name="Test Project", description="Testing graph persistence")
    test_db.add(project)
    test_db.commit()
    test_db.refresh(project)

    # 2. Persist diamond graph
    content = (FIXTURES_DIR / "diamond_graph.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "diamond.json")

    ingestion, meta = GraphService.persist_graph(test_db, project.id, parsed)

    assert ingestion.status == "success"
    assert ingestion.package_count == 3
    assert meta.package_count == 3
    assert meta.direct_dependency_count == 2
    assert meta.transitive_package_count == 1

    # Verify DB records
    app = test_db.scalars(select(Application).where(Application.project_id == project.id)).first()
    assert app is not None
    assert app.name == "Application A"

    packages = test_db.scalars(select(Package)).all()
    assert len(packages) == 3

    dependencies = test_db.scalars(select(Dependency).where(Dependency.application_id == app.id)).all()
    # 2 app direct edges + 2 package-to-package edges = 4 edges
    assert len(dependencies) == 4

    # 3. Test non-existent project rollback
    with pytest.raises(ValueError, match="does not exist"):
        GraphService.persist_graph(test_db, project_id=99999, parsed_sbom=parsed)
