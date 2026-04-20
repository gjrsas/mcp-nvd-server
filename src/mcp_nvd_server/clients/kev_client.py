from __future__ import annotations

import httpx

from mcp_nvd_server.config import settings
from mcp_nvd_server.models.kev import KEVRecord


class KEVClient:
    def __init__(self) -> None:
        self.source_url = settings.kev_source_url
        self.timeout = settings.http_timeout_seconds
        self._by_cve: dict[str, KEVRecord] = {}
        self._loaded = False

    async def refresh(self) -> None:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(self.source_url)
            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        by_cve: dict[str, KEVRecord] = {}
        for item in vulnerabilities:
            cve_id = item.get("cveID")
            if not cve_id:
                continue

            raw_cwes = item.get("cwes", [])
            if isinstance(raw_cwes, list):
                kev_cwes = [str(cwe) for cwe in raw_cwes if cwe]
            elif isinstance(raw_cwes, str):
                kev_cwes = [raw_cwes] if raw_cwes else []
            else:
                kev_cwes = []

            by_cve[cve_id] = KEVRecord(
                cve_id=cve_id,
                known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse"),
                notes=item.get("notes"),
                kev_cwes=kev_cwes,
                vendor_product=item.get("vendorProject"),
                product=item.get("product"),
                vulnerability_name=item.get("vulnerabilityName"),
                date_added=item.get("dateAdded"),
                required_action=item.get("requiredAction"),
                due_date=item.get("dueDate"),
            )

        self._by_cve = by_cve
        self._loaded = True

    async def get_by_cve(self, cve_id: str) -> KEVRecord | None:
        if not self._loaded:
            await self.refresh()
        return self._by_cve.get(cve_id)

    async def search(
        self,
        vendor: str | None = None,
        product: str | None = None,
        ransomware_only: bool = False,
        limit: int = 10,
    ) -> list[KEVRecord]:
        if not self._loaded:
            await self.refresh()

        results = list(self._by_cve.values())

        if vendor:
            vendor_lower = vendor.lower()
            results = [
                record
                for record in results
                if record.vendor_product
                and vendor_lower in record.vendor_product.lower()
            ]

        if product:
            product_lower = product.lower()
            results = [
                record
                for record in results
                if record.product
                and product_lower in record.product.lower()
            ]

        if ransomware_only:
            results = [
                record
                for record in results
                if (record.known_ransomware_campaign_use or "").lower() == "known"
            ]

        return results[:limit]
