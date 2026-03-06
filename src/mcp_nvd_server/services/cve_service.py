from __future__ import annotations

from typing import Any

from mcp_nvd_server.clients.nvd_client import NVDClient


class CVEService:
    """Service layer that normalizes NVD CVE responses for MCP tools."""
    def __init__(self) -> None:
        self.client = NVDClient()

    async def get_cve(self, cve_id: str) -> dict[str, Any]:
        data = await self.client.get_cve(cve_id)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {
                "found": False,
                "cve_id": cve_id,
                "message": f"No CVE found for {cve_id} in NVD.",
            }

        return {
            "found": True,
            "result": self._normalize_cve(vulns[0].get("cve", {})),
        }

    async def search_cves(self, **kwargs: Any) -> dict[str, Any]:
        raw = await self.client.search_cves(**kwargs)
        vulns = raw.get("vulnerabilities", [])
        return {
            "count": len(vulns),
            "results": [self._normalize_cve(item.get("cve", {})) for item in vulns],
        }

    def _normalize_cve(self, cve: dict[str, Any]) -> dict[str, Any]:
        descriptions = cve.get("descriptions", [])
        english_description = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            None,
        )

        metrics = cve.get("metrics", {})
        cvss = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            items = metrics.get(metric_key)
            if items:
                metric = items[0]
                cvss_data = metric.get("cvssData", {})
                cvss = {
                    "version": cvss_data.get("version"),
                    "base_score": cvss_data.get("baseScore"),
                    "severity": metric.get("baseSeverity") or cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                }
                break

        weaknesses = cve.get("weaknesses", [])
        cwes: list[str] = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                value = desc.get("value")
                if value:
                    cwes.append(value)

        references = [
            {"url": ref.get("url"), "source": ref.get("source"), "tags": ref.get("tags", [])}
            for ref in cve.get("references", [])
        ]

        cpes: list[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria")
                    if criteria:
                        cpes.append(criteria)

        return {
            "cve_id": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": english_description,
            "cwe": sorted(set(cwes)),
            "cvss": cvss,
            "cpes": sorted(set(cpes)),
            "references": references,
        }
