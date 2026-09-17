import pytest
from app.services.normalization import NormalizationService


def test_normalize_with_valid_purl() -> None:
    norm = NormalizationService.normalize(
        name="express",
        version="4.19.2",
        purl="pkg:npm/express@4.19.2",
        bom_ref="pkg-1",
        package_type="library",
    )
    assert norm.ecosystem == "npm"
    assert norm.name == "express"
    assert norm.version == "4.19.2"
    assert norm.canonical_id == "pkg:npm/express@4.19.2"
    assert norm.bom_ref == "pkg-1"


def test_normalize_scoped_purl() -> None:
    norm = NormalizationService.normalize(
        purl="pkg:npm/%40types/node@20.11.0",
    )
    assert norm.ecosystem == "npm"
    assert norm.name == "@types/node"
    assert norm.version == "20.11.0"
    assert norm.canonical_id == "pkg:npm/%40types/node@20.11.0"


def test_normalize_without_purl_fallback() -> None:
    norm = NormalizationService.normalize(
        name="requests",
        version="2.31.0",
        ecosystem="pypi",
    )
    assert norm.ecosystem == "pypi"
    assert norm.name == "requests"
    assert norm.version == "2.31.0"
    assert norm.canonical_id == "pypi:requests@2.31.0"
    assert norm.purl is None


def test_normalize_missing_name_raises() -> None:
    with pytest.raises(ValueError, match="package name is required"):
        NormalizationService.normalize(name="", version="1.0.0")


def test_normalize_missing_version_raises() -> None:
    with pytest.raises(ValueError, match="missing a version"):
        NormalizationService.normalize(name="my-lib", version="")


def test_normalization_determinism() -> None:
    norm1 = NormalizationService.normalize(
        name="lodash", version="4.17.21", ecosystem="npm"
    )
    norm2 = NormalizationService.normalize(
        name="lodash", version="4.17.21", ecosystem="npm"
    )
    assert norm1.canonical_id == norm2.canonical_id
    assert norm1 == norm2
