from dataclasses import dataclass
from typing import Optional
from packageurl import PackageURL


@dataclass(frozen=True)
class NormalizedPackage:
    ecosystem: str
    name: str
    version: str
    purl: Optional[str]
    bom_ref: Optional[str]
    package_type: Optional[str]
    canonical_id: str


class NormalizationService:
    """Service for deterministic and conservative package normalization."""

    @classmethod
    def normalize(
        cls,
        name: Optional[str] = None,
        version: Optional[str] = None,
        purl: Optional[str] = None,
        bom_ref: Optional[str] = None,
        package_type: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> NormalizedPackage:
        clean_purl: Optional[str] = None
        inferred_ecosystem: Optional[str] = ecosystem

        # 1. Attempt PURL parsing if available
        if purl:
            try:
                parsed_purl = PackageURL.from_string(purl.strip())
                clean_purl = parsed_purl.to_string()
                if not inferred_ecosystem and parsed_purl.type:
                    inferred_ecosystem = parsed_purl.type.lower().strip()
                if not name and parsed_purl.name:
                    if parsed_purl.namespace:
                        name = f"{parsed_purl.namespace}/{parsed_purl.name}"
                    else:
                        name = parsed_purl.name
                if not version and parsed_purl.version:
                    version = parsed_purl.version
            except Exception:
                # If PURL fails to parse, preserve as raw string if present but don't invent
                clean_purl = purl.strip()

        # 2. Strict identity verification: name and version cannot be invented
        if not name or not name.strip():
            raise ValueError("Missing required package identity: package name is required.")
        if not version or not version.strip():
            raise ValueError(f"Missing required package identity: package '{name}' is missing a version.")

        norm_name = name.strip()
        norm_version = version.strip()
        final_ecosystem = (inferred_ecosystem or "generic").lower().strip()

        # 3. Form deterministic canonical identity
        canonical_id = clean_purl if clean_purl else f"{final_ecosystem}:{norm_name}@{norm_version}"

        return NormalizedPackage(
            ecosystem=final_ecosystem,
            name=norm_name,
            version=norm_version,
            purl=clean_purl,
            bom_ref=bom_ref.strip() if bom_ref else None,
            package_type=package_type.strip() if package_type else None,
            canonical_id=canonical_id,
        )
