import pytest

from mcp_nvd_server.services.cve_service import CVEService


@pytest.mark.asyncio
async def test_get_cve_returns_dict():
    service = CVEService()
    result = await service.get_cve("CVE-2024-3400")
    assert isinstance(result, dict)
    assert "found" in result
