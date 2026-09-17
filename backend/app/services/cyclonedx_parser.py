import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from app.core.config import settings
from app.services.normalization import NormalizationService, NormalizedPackage

SUPPORTED_CYCLONEDX_VERSIONS = {"1.4", "1.5", "1.6"}


class CycloneDXValidationError(ValueError):
    """Raised when an SBOM fails format, schema, or security validation."""
    pass


@dataclass
class ExtractedApplication:
    name: str
    version: Optional[str] = None
    bom_ref: Optional[str] = None
    is_fallback: bool = False


@dataclass
class ParsedSBOM:
    filename: str
    sha256: str
    spec_version: str
    application: ExtractedApplication
    packages: Dict[str, NormalizedPackage]  # bom_ref -> NormalizedPackage
    unique_packages: List[NormalizedPackage]
    raw_dependencies: List[Tuple[str, str]]  # (source_bom_ref, target_bom_ref)
    unresolved_references: List[str] = field(default_factory=list)


class CycloneDXParser:
    """Parser and validator for CycloneDX JSON Software Bill of Materials (SBOM)."""

    @classmethod
    def parse(cls, content_bytes: bytes, filename: str) -> ParsedSBOM:
        # 1. File size check
        if len(content_bytes) > settings.MAX_SBOM_FILE_SIZE_BYTES:
            raise CycloneDXValidationError(
                f"Uploaded file exceeds maximum allowed size of {settings.MAX_SBOM_FILE_SIZE_BYTES} bytes."
            )
        if len(content_bytes) == 0:
            raise CycloneDXValidationError("Uploaded SBOM content is empty.")

        # 2. SHA-256 calculation
        content_hash = hashlib.sha256(content_bytes).hexdigest()

        # 3. Safe JSON parsing
        try:
            data = json.loads(content_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise CycloneDXValidationError(f"Invalid JSON content: {str(err)}") from err

        if not isinstance(data, dict):
            raise CycloneDXValidationError("Malformed SBOM: root JSON must be an object.")

        # 4. CycloneDX format and specVersion validation
        bom_format = data.get("bomFormat")
        if bom_format != "CycloneDX":
            raise CycloneDXValidationError(
                f"Unsupported BOM format: '{bom_format}'. Expected 'CycloneDX'."
            )

        spec_version = str(data.get("specVersion", "")).strip()
        if spec_version not in SUPPORTED_CYCLONEDX_VERSIONS:
            raise CycloneDXValidationError(
                f"Unsupported CycloneDX version: '{spec_version}'. "
                f"Supported versions are: {', '.join(sorted(SUPPORTED_CYCLONEDX_VERSIONS))}."
            )

        # 5. Extract Application (Root Metadata)
        metadata = data.get("metadata", {})
        meta_component = metadata.get("component") if isinstance(metadata, dict) else None

        if meta_component and isinstance(meta_component, dict) and meta_component.get("name"):
            app = ExtractedApplication(
                name=meta_component["name"].strip(),
                version=meta_component.get("version", "").strip() or None,
                bom_ref=meta_component.get("bom-ref", "").strip() or None,
                is_fallback=False,
            )
        else:
            # Deterministic fallback application name from filename
            clean_filename = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            fallback_name = clean_filename.replace(".json", "").replace(".cdx", "").strip() or "unnamed-application"
            app = ExtractedApplication(
                name=f"app:{fallback_name}",
                version="0.0.0",
                bom_ref=None,
                is_fallback=True,
            )

        # 6. Extract Components
        raw_components = data.get("components", [])
        if not isinstance(raw_components, list):
            raise CycloneDXValidationError("'components' field must be an array.")

        bom_ref_to_package: Dict[str, NormalizedPackage] = {}
        canonical_id_to_package: Dict[str, NormalizedPackage] = {}

        for idx, comp in enumerate(raw_components):
            if not isinstance(comp, dict):
                continue

            raw_bom_ref = comp.get("bom-ref")
            raw_name = comp.get("name")
            raw_version = comp.get("version")
            raw_purl = comp.get("purl")
            raw_type = comp.get("type")

            # Validate component identity
            try:
                norm_pkg = NormalizationService.normalize(
                    name=raw_name,
                    version=raw_version,
                    purl=raw_purl,
                    bom_ref=raw_bom_ref,
                    package_type=raw_type,
                )
            except ValueError as val_err:
                raise CycloneDXValidationError(
                    f"Component at index {idx} failed validation: {str(val_err)}"
                ) from val_err

            # Deduplicate by canonical identity
            if norm_pkg.canonical_id in canonical_id_to_package:
                canonical_pkg = canonical_id_to_package[norm_pkg.canonical_id]
            else:
                canonical_id_to_package[norm_pkg.canonical_id] = norm_pkg
                canonical_pkg = norm_pkg

            # Map bom-ref to package (components can have distinct bom-refs pointing to identical packages)
            if raw_bom_ref:
                bom_ref_to_package[str(raw_bom_ref).strip()] = canonical_pkg

        unique_packages = list(canonical_id_to_package.values())

        # 7. Extract Dependencies
        raw_dependencies = data.get("dependencies", [])
        if not isinstance(raw_dependencies, list):
            raise CycloneDXValidationError("'dependencies' field must be an array.")

        dependency_edges: List[Tuple[str, str]] = []
        unresolved_refs: Set[str] = set()
        seen_edges: Set[Tuple[str, str]] = set()

        for entry in raw_dependencies:
            if not isinstance(entry, dict):
                continue
            source_ref = entry.get("ref")
            if not source_ref:
                continue
            source_ref = str(source_ref).strip()

            depends_on = entry.get("dependsOn", [])
            if not isinstance(depends_on, list):
                continue

            for target_ref in depends_on:
                if not target_ref:
                    continue
                target_ref = str(target_ref).strip()

                # Verify target reference exists either in components or application
                target_known = target_ref in bom_ref_to_package or (
                    app.bom_ref and target_ref == app.bom_ref
                )
                if not target_known:
                    unresolved_refs.add(target_ref)

                edge_key = (source_ref, target_ref)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    dependency_edges.append(edge_key)

        return ParsedSBOM(
            filename=filename,
            sha256=content_hash,
            spec_version=spec_version,
            application=app,
            packages=bom_ref_to_package,
            unique_packages=unique_packages,
            raw_dependencies=dependency_edges,
            unresolved_references=sorted(unresolved_refs),
        )
