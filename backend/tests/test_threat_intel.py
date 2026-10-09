import pytest
from app.services.threat_intel_service import threat_intel_service

@pytest.mark.asyncio
async def test_threat_intel_not_configured():
    statuses = threat_intel_service.get_provider_status()
    assert "VirusTotal" in statuses

    # Without API keys, lookup returns NOT_CONFIGURED status safely
    res = await threat_intel_service.lookup_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res["VirusTotal"]["status"] == "NOT_CONFIGURED"
