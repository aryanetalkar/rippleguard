import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

from app.services.osv_client import OSVBatchItemMatch

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "osv"


@pytest.fixture
def populated_project(client: TestClient) -> dict:
    """Create a project and ingest diamond graph to populate packages."""
    p_resp = client.post(
        "/api/v1/projects",
        json={"name": "Vuln API Test Project", "description": "For API testing"},
    )
    project_id = p_resp.json()["id"]

    diamond_file = Path(__file__).parent / "fixtures" / "diamond_graph.json"
    client.post(
        f"/api/v1/projects/{project_id}/sbom",
        files={"file": ("diamond.json", diamond_file.read_bytes(), "application/json")},
    )
    return {"project_id": project_id}


def test_vulnerability_scan_and_list_api(client: TestClient, populated_project: dict) -> None:
    project_id = populated_project["project_id"]

    advisory1 = json.loads((FIXTURES_DIR / "advisory_with_aliases.json").read_text())
    advisory2 = json.loads((FIXTURES_DIR / "advisory_with_severity.json").read_text())
    advisory3 = json.loads((FIXTURES_DIR / "advisory_withdrawn.json").read_text())

    # Mock OSV batch and hydration
    batch_return = [
        [OSVBatchItemMatch(osv_id="GHSA-test-1234", modified="2024-04-01T10:00:00Z")],
        [OSVBatchItemMatch(osv_id="GHSA-test-5678", modified="2024-04-05T12:00:00Z")],
        [OSVBatchItemMatch(osv_id="GHSA-withdrawn-9999", modified="2024-05-02T10:00:00Z")],
    ]

    def mock_hyd(osv_id: str):
        if osv_id == "GHSA-test-1234":
            return advisory1
        elif osv_id == "GHSA-test-5678":
            return advisory2
        return advisory3

    with patch("app.services.vulnerability_service.OSVClient.query_batch", new_callable=AsyncMock) as mock_batch, \
         patch("app.services.vulnerability_service.OSVClient.get_vulnerability", new_callable=AsyncMock) as mock_get_vuln:

        mock_batch.return_value = batch_return
        mock_get_vuln.side_effect = mock_hyd

        # 1. Trigger Vulnerability Scan
        scan_resp = client.post(f"/api/v1/projects/{project_id}/vulnerabilities/scan")
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert scan_data["status"] == "success"
        assert scan_data["package_count"] == 3
        assert scan_data["vulnerable_package_count"] == 3
        assert scan_data["vulnerability_count"] == 3

        # 2. List Scans History
        scans_hist = client.get(f"/api/v1/projects/{project_id}/vulnerabilities/scans")
        assert scans_hist.status_code == 200
        assert scans_hist.json()["total"] >= 1

        # 3. List Project Vulnerabilities (All)
        vuln_list = client.get(f"/api/v1/projects/{project_id}/vulnerabilities")
        assert vuln_list.status_code == 200
        data = vuln_list.json()
        assert data["total"] == 3
        assert data["active_count"] == 2
        assert data["withdrawn_count"] == 1

        # 4. Filter by status: active
        active_list = client.get(f"/api/v1/projects/{project_id}/vulnerabilities?status=active")
        assert active_list.status_code == 200
        assert active_list.json()["total"] == 2
        for item in active_list.json()["items"]:
            assert item["is_withdrawn"] is False

        # 5. Filter by status: withdrawn
        withdrawn_list = client.get(f"/api/v1/projects/{project_id}/vulnerabilities?status=withdrawn")
        assert withdrawn_list.status_code == 200
        assert withdrawn_list.json()["total"] == 1
        assert withdrawn_list.json()["items"][0]["osv_id"] == "GHSA-withdrawn-9999"

        # 6. Filter by severity presence
        sev_list = client.get(f"/api/v1/projects/{project_id}/vulnerabilities?has_severity=true")
        assert sev_list.status_code == 200
        assert sev_list.json()["total"] == 1
        assert sev_list.json()["items"][0]["osv_id"] == "GHSA-test-5678"

        # 7. Filter by package name
        pkg_filter = client.get(f"/api/v1/projects/{project_id}/vulnerabilities?package=package-a")
        assert pkg_filter.status_code == 200
        assert pkg_filter.json()["total"] == 1
        assert pkg_filter.json()["items"][0]["osv_id"] == "GHSA-test-1234"

        # 8. Single package vulnerabilities
        first_pkg_id = data["items"][0]["packages"][0]["id"]
        pkg_vulns = client.get(f"/api/v1/packages/{first_pkg_id}/vulnerabilities")
        assert pkg_vulns.status_code == 200
        assert pkg_vulns.json()["package_id"] == first_pkg_id
        assert pkg_vulns.json()["total"] >= 1


def test_vulnerability_api_404(client: TestClient) -> None:
    resp = client.post("/api/v1/projects/999999/vulnerabilities/scan")
    assert resp.status_code == 404

    resp2 = client.get("/api/v1/packages/999999/vulnerabilities")
    assert resp2.status_code == 404
