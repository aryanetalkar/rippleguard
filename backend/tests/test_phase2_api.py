from pathlib import Path
import pytest
from fastapi.testclient import TestClient

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_project_creation_and_listing(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/projects",
        json={"name": "Test Web App", "description": "Supply chain test project"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Web App"
    project_id = data["id"]

    # Re-posting same name returns existing
    resp_dup = client.post("/api/v1/projects", json={"name": "Test Web App"})
    assert resp_dup.status_code == 201
    assert resp_dup.json()["id"] == project_id

    # List projects
    resp_list = client.get("/api/v1/projects")
    assert resp_list.status_code == 200
    assert any(p["id"] == project_id for p in resp_list.json())


def test_sbom_upload_and_graph_query_flow(client: TestClient) -> None:
    # 1. Create project
    p_resp = client.post(
        "/api/v1/projects",
        json={"name": "Diamond Graph Project", "description": "Diamond graph testing"},
    )
    assert p_resp.status_code == 201
    project_id = p_resp.json()["id"]

    # 2. Upload diamond graph SBOM
    diamond_bytes = (FIXTURES_DIR / "diamond_graph.json").read_bytes()
    upload_resp = client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("diamond_graph.json", diamond_bytes, "application/json")},
    )
    assert upload_resp.status_code == 201
    ingest_data = upload_resp.json()
    assert ingest_data["status"] == "success"
    assert ingest_data["package_count"] == 3
    assert ingest_data["application_name"] == "Application A"
    assert ingest_data["spec_version"] == "1.5"
    assert "sha256" in ingest_data

    # 3. Query Graph Summary
    summary_resp = client.get(f"/api/v1/projects/{project_id}/graph")
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert summary["project_id"] == project_id
    assert summary["application_count"] == 1
    assert summary["package_count"] == 3
    assert summary["direct_dependency_count"] == 2
    assert summary["transitive_package_count"] == 1
    assert summary["latest_spec_version"] == "1.5"

    # 4. Query Graph Nodes
    nodes_resp = client.get(f"/api/v1/projects/{project_id}/graph/nodes")
    assert nodes_resp.status_code == 200
    nodes_data = nodes_resp.json()
    assert nodes_data["total_nodes"] == 4  # 1 Application + 3 Packages
    app_nodes = [n for n in nodes_data["nodes"] if n["node_type"] == "application"]
    pkg_nodes = [n for n in nodes_data["nodes"] if n["node_type"] == "package"]
    assert len(app_nodes) == 1
    assert len(pkg_nodes) == 3
    pkg_names = {p["name"] for p in pkg_nodes}
    assert pkg_names == {"package-a", "package-b", "package-c"}

    # 5. Query Graph Edges
    edges_resp = client.get(f"/api/v1/projects/{project_id}/graph/edges")
    assert edges_resp.status_code == 200
    edges_data = edges_resp.json()
    assert edges_data["total_edges"] == 4
    # All edges have source, target, direct flag
    for edge in edges_data["edges"]:
        assert "source" in edge
        assert "target" in edge
        assert "direct" in edge
        assert "dependency_type" in edge

    # 6. Query Ingestion History
    history_resp = client.get(f"/api/v1/projects/{project_id}/sbom")
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert history["total"] >= 1
    assert history["items"][0]["status"] == "success"


def test_sbom_upload_validation_errors(client: TestClient) -> None:
    p_resp = client.post("/api/v1/projects", json={"name": "Error Validation Project"})
    project_id = p_resp.json()["id"]

    # 1. Invalid JSON
    broken_bytes = (FIXTURES_DIR / "invalid_json.json").read_bytes()
    resp_invalid = client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("invalid.json", broken_bytes, "application/json")},
    )
    assert resp_invalid.status_code == 400
    assert "Invalid JSON" in resp_invalid.json()["detail"]

    # 2. Unsupported Version
    unsupported_bytes = (FIXTURES_DIR / "unsupported_version.json").read_bytes()
    resp_unsupported = client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("legacy.json", unsupported_bytes, "application/json")},
    )
    assert resp_unsupported.status_code == 400
    assert "Unsupported CycloneDX version" in resp_unsupported.json()["detail"]

    # 3. Empty File
    resp_empty = client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("empty.json", b"", "application/json")},
    )
    assert resp_empty.status_code == 400
    assert "empty" in resp_empty.json()["detail"].lower()

    # 4. Non-existent Project
    resp_404 = client.post(
        "/api/v1/projects/99999/sbom",
        files={"file": ("test.json", b'{"bomFormat":"CycloneDX"}', "application/json")},
    )
    assert resp_404.status_code == 404
