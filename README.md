# mcp-nvd-server
MCP server for NIST NVD


Starter MCP server for the NIST National Vulnerability Database (NVD) - the US government repository of standards based vulnerability management data.

### This project is not endorsed or supported by the US Government and is for personal development only.

## What this repo includes

- Python project layout with `src/` packaging
- MCP server using `FastMCP`
- `nvd_get_cve` tool
- `nvd_search_cves` tool
- starter NVD API client
- starter CVE normalization service
- GitHub Actions CI workflow with `lint` and `test`

## Current status

This is an MVP, not a finished production server. It currently focuses on:

- single CVE lookup from NVD
- basic CVE search from NVD
- a simple MCP resource with usage notes

Not yet included:

- CPE search
- CVE history search
- KEV client and enrichment
- retry/backoff logic
- caching
- full test coverage
- remote HTTP transport

## Quick start

### 1. Create a virtual environment and install dependencies

```bash
uv sync --all-groups
```

### 2. Optional: add a `.env` file

```bash
NVD_API_KEY=
NVD_API_BASE=https://services.nvd.nist.gov/rest/json
HTTP_TIMEOUT_SECONDS=30
CACHE_TTL_SECONDS=900
LOG_LEVEL=INFO
ENABLE_KEV=true
KEV_SOURCE_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### 3. Run the server locally

```bash
uv run python -m mcp_nvd_server.server
```

## Example tools

### `nvd_get_cve`
Returns a normalized CVE record for a single CVE ID.

### `nvd_search_cves`
Searches NVD CVEs using common filters such as keyword, CPE, severity, and date windows.

## Suggested next steps

1. Add `nvd_search_cpes`
2. Add `nvd_get_cve_history`
3. Add a KEV client and KEV lookup tools
4. Add tests with mocked NVD responses
5. Add remote HTTP transport
6. Add Docker support

## NVD attribution

This product uses the NIST NVD API but is not endorsed or supported by NIST or any other US Government agency.
