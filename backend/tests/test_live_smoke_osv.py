import os
import pytest

from app.services.osv_client import OSVClient


@pytest.mark.skipif(
    os.getenv("RUN_LIVE_OSV_TEST") != "1",
    reason="Optional manual live smoke test against api.osv.dev. Set RUN_LIVE_OSV_TEST=1 to run.",
)
@pytest.mark.anyio
async def test_live_osv_smoke_query() -> None:
    """Optional manual smoke test against official OSV.dev REST API.

    Verifies batch querying and advisory hydration with an authentic package.
    """
    client = OSVClient()

    # Query for express@4.19.0 via versioned PURL
    query = client.build_query(
        name="express",
        version="4.19.0",
        ecosystem="npm",
        purl="pkg:npm/express@4.19.0",
    )
    results = await client.query_batch([query])
    assert len(results) == 1
    assert len(results[0]) >= 1, "Expected at least one advisory for express@4.19.0 from OSV"

    first_osv_id = results[0][0].osv_id
    assert first_osv_id.startswith("GHSA-") or first_osv_id.startswith("CVE-")

    # Hydrate full record
    advisory = await client.get_vulnerability(first_osv_id)
    assert advisory["id"] == first_osv_id
    assert "affected" in advisory
