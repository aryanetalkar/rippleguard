import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import httpx2
from packageurl import PackageURL

from app.core.config import settings

logger = logging.getLogger(__name__)


class OSVClientError(Exception):
    """Base exception for OSV client operations."""
    pass


class OSVTimeoutError(OSVClientError):
    """Raised when an OSV request times out."""
    pass


class OSVResponseError(OSVClientError):
    """Raised when OSV returns a non-2xx response or malformed payload."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class OSVBatchItemMatch:
    osv_id: str
    modified: Optional[str] = None


class OSVClient:
    """Independent typed client for the official OSV.dev REST API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
    ):
        self.base_url = (base_url or settings.OSV_API_URL).rstrip("/")
        self.timeout = httpx2.Timeout(timeout_seconds, connect=10.0)
        self.max_retries = max_retries

    @staticmethod
    def build_query(
        name: str,
        version: str,
        ecosystem: Optional[str] = None,
        purl: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Construct compliant OSV query following strict PURL vs Name/Ecosystem rules.

        Rule 1: If purl is present and versioned -> {"package": {"purl": purl}} (No top-level version)
        Rule 2: Otherwise -> {"package": {"name": name, "ecosystem": ecosystem}, "version": version} (No PURL)
        Never combine top-level version and versioned PURL.
        """
        has_versioned_purl = False
        if purl:
            try:
                parsed = PackageURL.from_string(purl.strip())
                if parsed.version:
                    has_versioned_purl = True
            except Exception:
                has_versioned_purl = False

        if has_versioned_purl and purl:
            return {
                "package": {
                    "purl": purl.strip(),
                }
            }
        else:
            final_ecosystem = ecosystem.strip() if ecosystem else "generic"
            return {
                "package": {
                    "name": name.strip(),
                    "ecosystem": final_ecosystem,
                },
                "version": version.strip(),
            }

    async def _send_request_with_retry(
        self,
        method: str,
        url: str,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute HTTP request with bounded retry for transient failures."""
        last_err: Optional[Exception] = None

        async with httpx2.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(self.max_retries + 1):
                try:
                    response = await client.request(method, url, json=json_data)
                    if response.status_code == 200:
                        try:
                            return response.json()
                        except Exception as json_err:
                            raise OSVResponseError(
                                f"Malformed JSON received from OSV: {str(json_err)}",
                                status_code=200,
                            ) from json_err

                    if 500 <= response.status_code < 600:
                        last_err = OSVResponseError(
                            f"OSV server error {response.status_code}: {response.text[:200]}",
                            status_code=response.status_code,
                        )
                        if attempt < self.max_retries:
                            await asyncio.sleep(0.5 * (2**attempt))
                            continue
                        raise last_err

                    # Non-retriable 4xx client errors
                    raise OSVResponseError(
                        f"OSV API returned HTTP {response.status_code}: {response.text[:200]}",
                        status_code=response.status_code,
                    )

                except (httpx2.TimeoutException, httpx2.ConnectTimeout) as t_err:
                    last_err = OSVTimeoutError(f"Request to OSV timed out: {str(t_err)}")
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    raise last_err from t_err
                except httpx2.RequestError as req_err:
                    last_err = OSVClientError(f"Connection to OSV failed: {str(req_err)}")
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    raise last_err from req_err

        if last_err:
            raise last_err
        raise OSVClientError("Unexpected error in OSV request execution.")

    async def query_batch(
        self, queries: List[Dict[str, Any]]
    ) -> List[List[OSVBatchItemMatch]]:
        """Query OSV in batches with multi-page token traversal.

        Returns a list of match lists matching 1:1 with input queries.
        """
        if not queries:
            return []

        url = f"{self.base_url}/querybatch"
        accumulated_results: Dict[int, List[OSVBatchItemMatch]] = {
            i: [] for i in range(len(queries))
        }

        # Active queries to process: (original_index, query_payload)
        current_batch: List[Tuple[int, Dict[str, Any]]] = [
            (i, q) for i, q in enumerate(queries)
        ]

        while current_batch:
            batch_payload = {"queries": [q for _, q in current_batch]}
            resp_data = await self._send_request_with_retry("POST", url, json_data=batch_payload)

            results = resp_data.get("results")
            if not isinstance(results, list):
                raise OSVResponseError("Malformed OSV querybatch response: 'results' array missing.")

            if len(results) != len(current_batch):
                raise OSVResponseError(
                    f"OSV querybatch mismatch: expected {len(current_batch)} results, got {len(results)}."
                )

            next_batch: List[Tuple[int, Dict[str, Any]]] = []

            for (orig_idx, orig_query), res in zip(current_batch, results):
                if not isinstance(res, dict):
                    continue

                vulns = res.get("vulns", [])
                if isinstance(vulns, list):
                    for v in vulns:
                        if isinstance(v, dict) and v.get("id"):
                            match = OSVBatchItemMatch(
                                osv_id=str(v["id"]).strip(),
                                modified=v.get("modified"),
                            )
                            # Deduplicate within same package match list
                            if not any(m.osv_id == match.osv_id for m in accumulated_results[orig_idx]):
                                accumulated_results[orig_idx].append(match)

                next_page = res.get("next_page_token")
                if next_page:
                    paged_query = dict(orig_query)
                    paged_query["page_token"] = str(next_page).strip()
                    next_batch.append((orig_idx, paged_query))

            current_batch = next_batch

        return [accumulated_results[i] for i in range(len(queries))]

    async def get_vulnerability(self, osv_id: str) -> Dict[str, Any]:
        """Retrieve complete OSV advisory record for a specific vulnerability ID."""
        url = f"{self.base_url}/vulns/{osv_id.strip()}"
        return await self._send_request_with_retry("GET", url)
