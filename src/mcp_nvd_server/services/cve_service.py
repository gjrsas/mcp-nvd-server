from mcp_nvd_server.clients.nvd_client import NVDClient


class CVEService:
    def __init__(self) -> None:
        self.client = NVDClient()

    async def get_cve(self, cve_id: str) -> dict:
        data = await self.client.get_cve(cve_id)

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

        return {
            "found": True,
            "cve_id": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": english_description,
            "raw": cve,
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
        return {
            "message": "search_cves not fully implemented yet",
            "limit": limit,
        }
