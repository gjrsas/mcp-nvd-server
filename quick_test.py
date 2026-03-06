import asyncio

from mcp_nvd_server.services.cve_service import CVEService


async def main():
    service = CVEService()
    result = await service.get_cve("CVE-2024-3400")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
