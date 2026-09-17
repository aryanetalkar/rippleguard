import pytest
from app.services.osv_client import OSVClient


def test_query_generation_with_versioned_purl() -> None:
    """CASE 1: Versioned PURL must produce {"package": {"purl": ...}} and NO top-level version."""
    query = OSVClient.build_query(
        name="express",
        version="4.19.2",
        ecosystem="npm",
        purl="pkg:npm/express@4.19.2",
    )
    assert "package" in query
    assert "purl" in query["package"]
    assert query["package"]["purl"] == "pkg:npm/express@4.19.2"
    # CRITICAL RULE: Never send top-level version when sending versioned PURL
    assert "version" not in query


def test_query_generation_without_purl_fallback() -> None:
    """CASE 2: No versioned PURL must produce {"package": {"name": ..., "ecosystem": ...}, "version": ...}."""
    query = OSVClient.build_query(
        name="requests",
        version="2.31.0",
        ecosystem="pypi",
        purl=None,
    )
    assert "package" in query
    assert query["package"]["name"] == "requests"
    assert query["package"]["ecosystem"] == "pypi"
    assert "purl" not in query["package"]
    assert query["version"] == "2.31.0"


def test_query_generation_unversioned_purl_falls_back_to_name_version() -> None:
    """PURL without version must not be treated as a versioned PURL."""
    query = OSVClient.build_query(
        name="lodash",
        version="4.17.21",
        ecosystem="npm",
        purl="pkg:npm/lodash",
    )
    assert query["package"]["name"] == "lodash"
    assert query["package"]["ecosystem"] == "npm"
    assert query["version"] == "4.17.21"
    assert "purl" not in query["package"]


def test_never_combine_version_and_versioned_purl() -> None:
    """Dedicated test guaranteeing no query payload combines top-level version with versioned purl."""
    test_cases = [
        ("express", "4.19.2", "npm", "pkg:npm/express@4.19.2"),
        ("flask", "3.0.0", "pypi", "pkg:pypi/flask@3.0.0"),
        ("commons-io", "2.11.0", "maven", "pkg:maven/commons-io/commons-io@2.11.0"),
        ("unversioned", "1.0.0", "generic", None),
    ]
    for name, version, eco, purl in test_cases:
        q = OSVClient.build_query(name=name, version=version, ecosystem=eco, purl=purl)
        has_top_version = "version" in q
        has_purl = "purl" in q.get("package", {})
        # Mutual exclusion
        assert not (has_top_version and has_purl), (
            f"Query violated mutual exclusion for {name}: {q}"
        )
