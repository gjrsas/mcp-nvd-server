from mcp.server.fastmcp import FastMCP

from mcp_nvd_server.config import settings
from mcp_nvd_server.services.cve_service import CVEService

mcp = FastMCP(
    "mcp-nvd-server",
    instructions=(
        "MCP server for the NIST National Vulnerability Database (NVD) "
    ),
)

cve_service = CVEService()


@mcp.tool()
async def nvd_get_cve(cve_id: str) -> dict:
    """Get normalized details for a single CVE ID from the NVD."""
    return await cve_service.get_cve(cve_id)


@mcp.resource("nvd://docs/query-cheatsheet")
def query_cheatsheet() -> str:
    return "Use nvd_get_cve for a single CVE lookup."


def main() -> None:
    print("Starting MCP NVD server...")
    mcp.run()


if __name__ == "__main__":
    main()
