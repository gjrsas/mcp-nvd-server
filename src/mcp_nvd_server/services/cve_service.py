import httpx

from mcp_nvd_server.clients.nvd_client import NVDClient
from mcp_nvd_server.models import CVESearchResult, CVESummary


class CVEService:
    def __init__(self) -> None:
        self.client = NVDClient()

    def _extract_english_description(self, cve: dict) -> str | None:
        descriptions = cve.get("descriptions", [])
        return next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            None,
        )

    def _extract_cvss(self, cve: dict) -> tuple[str | None, float | None]:
        metrics = cve.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
                score = cvss_data.get("baseScore")
                return severity, score

        return None, None

    def _normalize_cve(self, cve: dict) -> CVESummary:
        severity, base_score = self._extract_cvss(cve)

        return CVESummary(
            cve_id=cve.get("id", ""),
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            description=self._extract_english_description(cve),
            severity=severity,
            base_score=base_score,
        )

    async def get_cve(self, cve_id: str) -> dict:
        try:
            data = await self.client.get_cve(cve_id)
        except httpx.HTTPStatusError as exc:
            return {
                "found": False,
                "cve_id": cve_id,
                "message": f"NVD HTTP error: {exc.response.status_code}",
            }
        except Exception as exc:
            return {
                "found": False,
                "cve_id": cve_id,
                "message": f"Unexpected error: {str(exc)}",
            }

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {
                "found": False,
                "cve_id": cve_id,
                "message": f"No CVE found for {cve_id}",
            }

        cve = vulnerabilities[0].get("cve", {})
        summary = self._normalize_cve(cve)


        return {
            "found": True,
            "cve": summary.model_dump(),
        }

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
    ) -> dict:
        try:
            data = await self.client.search_cves(
                keyword=keyword,
                cpe_name=cpe_name,
                cve_id=cve_id,
                cvss_v3_severity=cvss_v3_severity,
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
                last_mod_start_date=last_mod_start_date,
                last_mod_end_date=last_mod_end_date,
                limit=limit,
            )
        except httpx.HTTPStatusError as exc:
            return {
                "found": False,
                "message": f"NVD HTTP error: {exc.response.status_code}",
            }
        except Exception as exc:
            return {
                "found": False,
                "message": f"Unexpected error: {str(exc)}",
            }

        vulnerabilities = data.get("vulnerabilities", [])
        normalized = [
            self._normalize_cve(vuln.get("cve", {})).model_dump()
            for vuln in vulnerabilities
        ]

        result = CVESearchResult(
            total_results=data.get("totalResults", 0),
            start_index=data.get("startIndex", 0),
            results_per_page=data.get("resultsPerPage", len(normalized)),
            vulnerabilities=normalized,
        )

        return {
            "found": True,
            "result": result.model_dump(),
        }
