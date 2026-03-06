import httpx

from mcp_nvd_server.clients.nvd_client import NVDClient


class CVEService:
    def __init__(self) -> None:
        self.client = NVDClient()

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

        return {
            "found": True,
            "cve_id": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": english_description,
        }
