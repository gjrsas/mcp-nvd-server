# mcp-nvd-server
MCP server for NIST NVD

Starter MCP server for the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/) - the US government repository of standards based vulnerability management data.

The NVD includes databases of security checklist references, security-related software flaws, product names, and impact metrics.

Common Vulnerabilities and Exposures (CVE): NVD uses unique identifiers cve_id to identify vulnerabilities and to associate specific versions of code bases (e.g., software and shared libraries) with the Common Platform Enumeration (CPE) to those vulnerabilities. 

Known Exploited Vulnerabilities (KEV): Vulnerabilities that have been observed in the wild are listed in the CISA maintained [KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).  NVD flags CVEs listed in the KEV catalog, which provides more information about required actions and mitigation.

### This project is not endorsed or supported by the US Government and is for personal development only.

## Current status

This is an MVP, not a finished production server. It currently focuses on:

- single CVE lookup from NVD
- basic CVE search from NVD
- a simple MCP server with usage notes

## What this repo includes

- MCP server using `FastMCP`
- `nvd_get_cve` tool
- starter NVD API client
- starter CVE normalization service

Not yet included:

- `nvd_search_cves` tool
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
NVD_API_KEY= <your key here>
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

## Work in progress

1. Add `nvd_search_cves`
2. Add `nvd_search_cpes`
3. Add `nvd_get_cve_history`
4. Add a KEV client and KEV lookup tools for CISA KEV Catalog


## NVD attribution

This product uses the NIST NVD API but is not endorsed or supported by NIST or any other US Government agency.
