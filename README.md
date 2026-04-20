# mcp-nvd-server
MCP server for NIST NVD

### This project is not endorsed or supported by the US Government and is for personal development only.

Starter MCP server for the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/) - the US government repository of standards based vulnerability management data.

The NVD includes databases of security checklist references, security-related software flaws, product names, and impact metrics.

## Vulnerability Concepts
Common Vulnerabilities and Exposures (CVE): NVD uses unique identifiers cve_id to identify vulnerabilities and to associate specific versions of code bases (e.g., software and shared libraries) with the Common Platform Enumeration (CPE) to those vulnerabilities. 

Known Exploited Vulnerabilities (KEV): Subset of CVEs that have been observed in the wild and have a clear remediation action available.  NVD flags CVEs considered KEVs, while the KEV catalog provides more information about required actions and mitigation.

Common Vulnerability Scoring System (CVSS): Standardized evaluation method used to supply a measure of severity. Metrics result in a numerical score ranging from 0 to 10 (CriticaL). 

Common Platform Enumeration (CPE):  Structured naming scheme for information technology systems, software, and packages, which helps with asset management and allows mapping vulnerabilities (CVEs) to specific systems. 


## Vulnerability resources
[CVE Foundation](https://www.thecvefoundation.org/resources)  
[KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)  
[Common Vulnerability Scoring System](https://www.first.org/cvss/)  
[Common Platform Enumeration](https://nvd.nist.gov/products/cpe)  


## Current status

This is an MVP, not a finished production server. It currently focuses on:

- single CVE lookup from NVD
- basic CVE search from NVD
- a simple MCP server with usage notes

## NVD API coverage

This server targets the NIST NVD API v2.0 and primarily wraps these endpoints:  
`cves/2.0` for CVE lookup and search,  
`cvehistory/2.0` for CVE change history,  
`cpes/2.0` for official CPE dictionary records,  
`cpematch/2.0` for CPE match criteria, and  
`source/2.0` for source-organization metadata.  

Base URLs:
- `https://services.nvd.nist.gov/rest/json/cves/2.0`
- `https://services.nvd.nist.gov/rest/json/cvehistory/2.0`
- `https://services.nvd.nist.gov/rest/json/cpes/2.0`
- `https://services.nvd.nist.gov/rest/json/cpematch/2.0`
- `https://services.nvd.nist.gov/rest/json/source/2.0`

## What this repo includes

- MCP server using `FastMCP`
- `nvd_get_cve` tool
- `nvd_search_cves` tool
- NVD API client
- CVE normalization service
- CVE history search
- CPE search
- KEV client and enrichment

Not yet included:
- retry/backoff logic
- caching
- full test coverage
- remote HTTP transport
- OAuth authentication

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
### 4. (Optional) Test with MCP inspector

```bash
npx -y @modelcontextprotocol/inspector
```
Open browser link created to launch Inspector. Enter the bash command from step 3 above into the Command field and click Connect. Select the tools tab and enter a CVE Id (eg. CVE-2017-0144) to test and check the response.


## Example tools

### `nvd_get_cve`
Returns a normalized CVE record for a single CVE ID.

### `nvd_search_cves`
Searches NVD CVEs using common filters such as keyword, CPE, severity score (CVSS), and time frame windows.

## Work in progress

1. Add tools `nvd_search_cpes`, `nvd_get_cve_history`
2. Add a KEV client and KEV lookup tools for CISA KEV Catalog


## NVD attribution

This product uses the NIST NVD API but is not endorsed or supported by NIST or any other US Government agency.
