import httpx

from mcp_nvd_server.clients.nvd_client import NVDClient
from mcp_nvd_server.clients.kev_client import KEVClient
from mcp_nvd_server.models import CVESearchResult, CVESummary
from mcp_nvd_server.utils.cvss_helpers import build_normalized_cve

class CVEService:
    def __init__(self) -> None:
        self.client = NVDClient()
        self.kev_client = KEVClient()

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
        
        descriptions = cve.get("descriptions", [])
        english_description = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            None,
        )

        weaknesses = cve.get("weaknesses", [])
        cwe_list = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                value = desc.get("value")
                if value and value not in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                    cwe_list.append(value)

        configurations = cve.get("configurations", [])
        cpe_list = []

        def collect_cpes(nodes: list[dict]) -> None:
            for node in nodes:
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria")
                    if criteria:
                        cpe_list.append(criteria)
                for child in node.get("nodes", []):
                    collect_cpes([child])

        for config in configurations:
            collect_cpes(config.get("nodes", []))

        references = cve.get("references", [])
        references_list = [
            {
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", []),
            }
            for ref in references
            if ref.get("url")
        ]

        kev_record = await self.kev_client.get_by_cve(cve.get("id", ""))

        cisa_kev_metadata = {
            "exploit_add_date": cve.get("cisaExploitAdd"),
            "action_due_date": cve.get("cisaActionDue"),
            "required_action": cve.get("cisaRequiredAction"),
            "vulnerability_name": cve.get("cisaVulnerabilityName"),
            "known_ransomware_campaign_use": None,
            "notes": None,
            "kev_cwes": [],
            "in_kev_catalog": any(
                cve.get(field) is not None
                for field in (
                    "cisaExploitAdd",
                    "cisaActionDue",
                    "cisaRequiredAction",
                    "cisaVulnerabilityName",
                )
            ),
        }

        if kev_record:
            cisa_kev_metadata["known_ransomware_campaign_use"] = (kev_record.known_ransomware_campaign_use)
            cisa_kev_metadata["notes"] = kev_record.notes
            cisa_kev_metadata["kev_cwes"] = kev_record.kev_cwes
            cisa_kev_metadata["in_kev_catalog"] = True                    

        normalized = build_normalized_cve(
            cve_id=cve.get("id", ""),
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            description=english_description,
            cwe=cwe_list,
            cpes=cpe_list,
            references=references_list,
            raw_cve=cve,
            cisa_kev_metadata=cisa_kev_metadata,
        )

        return {
            "found": True,
            "cve": normalized.model_dump(),
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
            "results": result.model_dump(),
            "result": result.model_dump(),
        }
