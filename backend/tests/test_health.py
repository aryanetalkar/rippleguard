import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import get_db


def test_root_health_endpoint(client: TestClient) -> None:
    """Verify that GET /health returns 200 and the deterministic payload."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "rippleguard-api",
    }


def test_api_v1_health_endpoint(client: TestClient) -> None:
    """Verify that GET /api/v1/health returns 200 and identical deterministic payload."""
    response = client.get(f"{settings.API_V1_STR}/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "rippleguard-api",
    }


def test_openapi_spec_generation(client: TestClient) -> None:
    """Verify application starts, generates OpenAPI spec, and registers health route."""
    response = client.get(f"{settings.API_V1_STR}/openapi.json")
    assert response.status_code == 200
    spec = response.json()
    assert spec["info"]["title"] == settings.PROJECT_NAME
    assert "/health" in spec["paths"]


def test_database_session_behavior_unconfigured() -> None:
    """Verify get_db raises RuntimeError when DATABASE_URL is not set."""
    if settings.DATABASE_URL is None:
        with pytest.raises(RuntimeError, match="DATABASE_URL is not configured"):
            next(get_db())
