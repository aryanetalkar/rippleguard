from pathlib import Path
import pytest

from app.services.cyclonedx_parser import CycloneDXParser, CycloneDXValidationError

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_valid_minimal_sbom() -> None:
    content = (FIXTURES_DIR / "minimal_cyclonedx.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "minimal.json")

    assert parsed.spec_version == "1.5"
    assert parsed.application.name == "minimal-app"
    assert parsed.application.version == "1.0.0"
    assert len(parsed.unique_packages) == 1
    assert "pkg-a" in parsed.packages
    assert parsed.packages["pkg-a"].name == "express"
    assert len(parsed.raw_dependencies) == 1
    assert parsed.raw_dependencies[0] == ("app-root", "pkg-a")
    assert len(parsed.unresolved_references) == 0


def test_parse_duplicate_entries() -> None:
    content = (FIXTURES_DIR / "duplicate_entries.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "dup.json")

    # 2 components defined with identical identity -> deduplicated to 1 canonical package
    assert len(parsed.unique_packages) == 1
    assert parsed.unique_packages[0].name == "shared-lib"
    # Both comp-1 and comp-2 bom-refs resolve to the same canonical package
    assert parsed.packages["comp-1"] == parsed.packages["comp-2"]
    # Dependencies deduplicated
    assert len(parsed.raw_dependencies) == 2


def test_parse_unresolved_reference() -> None:
    content = (FIXTURES_DIR / "unresolved_ref.json").read_bytes()
    parsed = CycloneDXParser.parse(content, "unresolved.json")

    assert "ghost-package-missing" in parsed.unresolved_references
    assert len(parsed.unique_packages) == 1


def test_parse_invalid_json() -> None:
    content = (FIXTURES_DIR / "invalid_json.json").read_bytes()
    with pytest.raises(CycloneDXValidationError, match="Invalid JSON content"):
        CycloneDXParser.parse(content, "broken.json")


def test_parse_unsupported_version() -> None:
    content = (FIXTURES_DIR / "unsupported_version.json").read_bytes()
    with pytest.raises(CycloneDXValidationError, match="Unsupported CycloneDX version: '1.1'"):
        CycloneDXParser.parse(content, "legacy.json")


def test_parse_empty_content() -> None:
    with pytest.raises(CycloneDXValidationError, match="SBOM content is empty"):
        CycloneDXParser.parse(b"", "empty.json")


def test_parse_oversized_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "MAX_SBOM_FILE_SIZE_BYTES", 10)
    with pytest.raises(CycloneDXValidationError, match="exceeds maximum allowed size"):
        CycloneDXParser.parse(b"123456789012345", "huge.json")
