import httpx

from mcp_nvd_server.config import settings


class NVDClient:
    def __init__(self) -> None:
        self.base_url = settings.nvd_api_base.rstrip("/")
        self.timeout = settings.http_timeout_seconds

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        return headers

    async def get_cve(self, cve_id: str) -> dict:
        url = f"{self.base_url}/cves/2.0"
        params = {"cveId": cve_id}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url, params=params, headers=self._headers())
            response.raise_for_status()
            return response.json()

    async def search_cves(
        self,
        keyword: str | None = None,
        cpe_name: str | None = None,
        cve_id: str | None = None,
        cvss_v3_severity: str | None = None,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
        last_mod_start_date: str | None = None,
        last_mod_end_date: str | None = None,
        limit: int = 10,
        start_index: int = 0,
    ) -> dict:
        url = f"{self.base_url}/cves/2.0"

        params: dict[str, str | int] = {
            "resultsPerPage": min(limit, 50),
            "startIndex": start_index,
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

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url, params=params, headers=self._headers())
            response.raise_for_status()
            return response.json()
