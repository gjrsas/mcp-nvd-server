from __future__ import annotations

from typing import Any

import httpx

from mcp_nvd_server.config import settings


class NVDClient:
    """Thin async wrapper around the NVD 2.0 APIs."""

    def __init__(self) -> None:
        headers: dict[str, str] = {"User-Agent": settings.server_name}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        self._client = httpx.AsyncClient(
            base_url=settings.nvd_api_base,
            headers=headers,
            timeout=settings.http_timeout_seconds,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = await self._client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    async def get_cve(self, cve_id: str) -> dict[str, Any]:
        return await self._get("/cves/2.0", params={"cveId": cve_id})

    async def search_cves(
        self,
        *,
        keyword: str | None = None,
        cpe_name: str | None = None,
        cve_id: str | None = None,
        cvss_v3_severity: str | None = None,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
        last_mod_start_date: str | None = None,
        last_mod_end_date: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "resultsPerPage": min(max(limit, 1), 50),
            "startIndex": 0,
        }
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        if cve_id:
            params["cveId"] = cve_id
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date
        if last_mod_start_date:
            params["lastModStartDate"] = last_mod_start_date
        if last_mod_end_date:
            params["lastModEndDate"] = last_mod_end_date
        return await self._get("/cves/2.0", params=params)
