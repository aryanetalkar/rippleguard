import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import cvss
from cvss import CVSS2, CVSS3, CVSS4

logger = logging.getLogger(__name__)


class SeverityService:
    """Extracts, parses, and normalizes CVSS severity from OSV vulnerability records.

    Rules:
      1. Preferred source: CVSS Base Score.
      2. Normalization: severity_normalized = cvss_score / 10.0.
      3. Support CVSS v2, v3, and v4 vectors.
      4. If multiple valid CVSS entries exist, choose the highest Base Score.
      5. If no parseable CVSS score/vector exists, return None (unscored, never zero).
    """

    @classmethod
    def parse_vector_or_score(cls, entry: Any) -> Optional[Tuple[float, str]]:
        """Attempt to extract (base_score, cvss_version) from an entry.

        Entry can be a string, or a dict e.g. {"type": "CVSS_V3", "score": "CVSS:3.1/..."}.
        """
        raw_score: Optional[str] = None
        raw_type: Optional[str] = None

        if isinstance(entry, dict):
            raw_score = entry.get("score")
            raw_type = entry.get("type")
        elif isinstance(entry, str):
            raw_score = entry
        elif isinstance(entry, (int, float)):
            val = float(entry)
            if 0.0 <= val <= 10.0:
                return round(val, 2), "NUMERIC"
            return None

        if not raw_score or not isinstance(raw_score, str):
            return None

        score_str = raw_score.strip()

        # Check if score_str is a pure float like "7.5"
        try:
            val = float(score_str)
            if 0.0 <= val <= 10.0:
                ver_label = raw_type if raw_type else "CVSS"
                return round(val, 2), ver_label
        except ValueError:
            pass

        # Try CVSS v4
        if "CVSS:4" in score_str or (raw_type and "CVSS_V4" in raw_type.upper()):
            try:
                c4 = CVSS4(score_str)
                return round(float(c4.base_score), 2), "CVSS:4.0"
            except Exception as err:
                logger.debug("Failed parsing CVSS v4 vector '%s': %s", score_str, err)

        # Try CVSS v3
        if "CVSS:3" in score_str or (raw_type and "CVSS_V3" in raw_type.upper()):
            try:
                c3 = CVSS3(score_str)
                return round(float(c3.base_score), 2), f"CVSS:{c3.minor_version if hasattr(c3, 'minor_version') else '3.1'}"
            except Exception as err:
                logger.debug("Failed parsing CVSS v3 vector '%s': %s", score_str, err)

        # Try CVSS v2 (often starts with AV: or has type CVSS_V2)
        if "CVSS:2" in score_str or (raw_type and "CVSS_V2" in raw_type.upper()) or "AV:" in score_str:
            try:
                c2 = CVSS2(score_str)
                return round(float(c2.base_score), 2), "CVSS:2.0"
            except Exception as err:
                logger.debug("Failed parsing CVSS v2 vector '%s': %s", score_str, err)

        # Fallback: check any embedded vector via cvss.parser
        try:
            vectors = cvss.parser.parse_cvss_from_text(score_str)
            if vectors:
                v_obj = vectors[0]
                if hasattr(v_obj, "base_score"):
                    ver = "CVSS:3.1" if isinstance(v_obj, CVSS3) else "CVSS:4.0" if isinstance(v_obj, CVSS4) else "CVSS:2.0"
                    return round(float(v_obj.base_score), 2), ver
        except Exception:
            pass

        return None

    @classmethod
    def resolve_severity(
        cls, severity_data: Optional[List[Any]]
    ) -> Tuple[Optional[float], Optional[str], Optional[float]]:
        """Resolve highest valid CVSS score from severity_data.

        Returns:
          (cvss_score, cvss_version, severity_normalized)
          or (None, None, None) if unscored.
        """
        if not severity_data or not isinstance(severity_data, list):
            return None, None, None

        valid_candidates: List[Tuple[float, str]] = []

        for item in severity_data:
            parsed = cls.parse_vector_or_score(item)
            if parsed is not None:
                score, ver = parsed
                valid_candidates.append((score, ver))

        if not valid_candidates:
            return None, None, None

        # Select highest valid Base Score; if tie, preserve first
        best_score, best_ver = max(valid_candidates, key=lambda x: x[0])
        severity_normalized = round(best_score / 10.0, 4)

        return best_score, best_ver, severity_normalized
