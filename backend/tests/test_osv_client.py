import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest
import httpx2

from app.services.osv_client import (
    OSVClient,
    OSVClientError,
    OSVResponseError,
    OSVTimeoutError,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "osv"


@pytest.mark.anyio
async def test_query_batch_mapping() -> None:
    client = OSVClient(base_url="https://api.osv.dev/v1")
    vulnerable_json = json.loads((FIXTURES_DIR / "vulnerable_package.json").read_text())

    with patch.object(client, "_send_request_with_retry", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = vulnerable_json

        queries = [
            {"package": {"purl": "pkg:npm/package-a@1.0.0"}}
        ]
        results = await client.query_batch(queries)

        assert len(results) == 1
        assert len(results[0]) == 2
        assert results[0][0].osv_id == "GHSA-test-1234"
        assert results[0][1].osv_id == "GHSA-test-5678"


@pytest.mark.anyio
async def test_query_batch_pagination() -> None:
    """Dedicated test verifying querybatch pagination loops through next_page_token."""
    client = OSVClient(base_url="https://api.osv.dev/v1")
    page1 = json.loads((FIXTURES_DIR / "paginated_batch_page1.json").read_text())
    page2 = json.loads((FIXTURES_DIR / "paginated_batch_page2.json").read_text())

    with patch.object(client, "_send_request_with_retry", new_callable=AsyncMock) as mock_send:
        mock_send.side_effect = [page1, page2]

        queries = [
            {"package": {"name": "paged-lib", "ecosystem": "npm"}, "version": "1.0.0"}
        ]
        results = await client.query_batch(queries)

        assert mock_send.call_count == 2
        # Page 1 had GHSA-page1-item1 and Page 2 had GHSA-page2-item2
        assert len(results[0]) == 2
        assert results[0][0].osv_id == "GHSA-page1-item1"
        assert results[0][1].osv_id == "GHSA-page2-item2"


@pytest.mark.anyio
async def test_get_vulnerability_hydration() -> None:
    client = OSVClient(base_url="https://api.osv.dev/v1")
    advisory_data = json.loads((FIXTURES_DIR / "advisory_with_aliases.json").read_text())

    with patch.object(client, "_send_request_with_retry", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = advisory_data

        record = await client.get_vulnerability("GHSA-test-1234")
        assert record["id"] == "GHSA-test-1234"
        assert record["aliases"] == ["CVE-2024-99999"]


@pytest.mark.anyio
async def test_osv_timeout_handling() -> None:
    client = OSVClient(base_url="https://api.osv.dev/v1", max_retries=1)

    with patch("httpx2.AsyncClient.request", side_effect=httpx2.ConnectTimeout("Connection timed out")):
        with pytest.raises(OSVTimeoutError, match="timed out"):
            await client.query_batch([{"package": {"name": "foo", "ecosystem": "npm"}, "version": "1.0"}])


@pytest.mark.anyio
async def test_osv_5xx_retry_and_failure() -> None:
    client = OSVClient(base_url="https://api.osv.dev/v1", max_retries=1)

    mock_resp = AsyncMock()
    mock_resp.status_code = 503
    mock_resp.text = "Service Unavailable"

    with patch("httpx2.AsyncClient.request", return_value=mock_resp) as mock_req:
        with pytest.raises(OSVResponseError) as exc_info:
            await client.get_vulnerability("GHSA-503-fail")
        assert exc_info.value.status_code == 503
        # Verified retried up to max_retries + 1 times
        assert mock_req.call_count == 2


@pytest.mark.anyio
async def test_osv_malformed_json_handling() -> None:
    from unittest.mock import MagicMock

    client = OSVClient(base_url="https://api.osv.dev/v1", max_retries=0)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Corrupted JSON")

    with patch.object(httpx2.AsyncClient, "request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_resp
        with pytest.raises(OSVResponseError, match="Malformed JSON"):
            await client.get_vulnerability("GHSA-bad-json")

