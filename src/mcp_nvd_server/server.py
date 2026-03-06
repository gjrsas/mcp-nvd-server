from mcp.server.fastmcp import FastMCP

from mcp_nvd_server.config import settings
from mcp_nvd_server.services.cpe_service import CPEPageService
from mcp_nvd_server.services.cve_service import CVEService
from mcp_nvd_server.services.history_service import HistoryService

mcp = FastMCP(
    settings.server_name,
    instructions=(
        "MCP server for the NIST National Vulnerability Database (NVD) "
        "with optional CISA KEV enrichment."
    ),
)

cve_service = CVEService()
cpe_service = CPEPageService()
history_service = HistoryService()


@mcp.tool()
async def nvd_get_cve(cve_id: str) -> dict:
    """Get normalized details for a single CVE ID."""
    return await cve_service.get_cve(cve_id)


@mcp.tool()
async def nvd_search_cves(
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
    """Search NVD CVEs using common filters."""
    return await cve_service.search_cves(
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


@mcp.tool()
async def nvd_get_cve_history(
    cve_id: str | None = None,
    change_start_date: str | None = None,
    change_end_date: str | None = None,
    event_name: str | None = None,
    limit: int = 20,
) -> dict:
    """Get CVE change history from NVD."""
    return await history_service.get_history(
        cve_id=cve_id,
        change_start_date=change_start_date,
        change_end_date=change_end_date,
        event_name=event_name,
        limit=limit,
    )


@mcp.tool()
async def nvd_search_cpes(
    keyword: str | None = None,
    cpe_match_string: str | None = None,
    cpe_name_id: str | None = None,
    limit: int = 10,
) -> dict:
    """Search CPE entries in the Official CPE Dictionary."""
    return await cpe_service.search_cpes(
        keyword=keyword,
        cpe_match_string=cpe_match_string,
        cpe_name_id=cpe_name_id,
        limit=limit,
    )


@mcp.resource("nvd://docs/query-cheatsheet")
def query_cheatsheet() -> str:
    return """
Use nvd_get_cve for one CVE.
Use nvd_search_cves for lists.
Use nvd_search_cpes to find official CPE names.
Use nvd_get_cve_history to inspect NVD record changes.
Date values should be ISO-8601.
""".strip()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
