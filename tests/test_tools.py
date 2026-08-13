from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from secops_agent_triage.schemas import IndicatorType, ThreatIntelProvider
from secops_agent_triage.tools import (
    AbuseIPDBTool,
    AlienVaultOTXTool,
    RateLimitError,
    ThreatIntelAPIError,
    VirusTotalTool,
    detect_indicator_type,
    generate_deterministic_mock,
)


def test_indicator_type_detection():
    assert detect_indicator_type("192.0.2.1") == IndicatorType.IP
    assert detect_indicator_type("44d88612fea8a8f36de82e1278abb02f") == IndicatorType.HASH
    assert detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == IndicatorType.HASH
    assert detect_indicator_type("malicious-domain.com") == IndicatorType.DOMAIN


def test_deterministic_mock_benign_and_malicious():
    res_benign = generate_deterministic_mock("1.1.1.1", ThreatIntelProvider.VIRUSTOTAL)
    assert res_benign.reputation_score == 0.0
    assert res_benign.malicious_votes == 0

    res_malicious = generate_deterministic_mock("192.0.2.1", ThreatIntelProvider.ABUSEIPDB)
    assert res_malicious.reputation_score > 70.0
    assert res_malicious.malicious_votes > 0

    res_hash = generate_deterministic_mock("some_unknown_string", ThreatIntelProvider.ALIENVAULT_OTX)
    assert res_hash.indicator == "some_unknown_string"
    assert 0.0 <= res_hash.reputation_score <= 100.0


@pytest.mark.asyncio
async def test_virustotal_mock_mode():
    tool = VirusTotalTool()
    res = await tool.query("8.8.8.8", mock=True)
    assert res.provider == ThreatIntelProvider.VIRUSTOTAL
    assert res.reputation_score == 0.0


@pytest.mark.asyncio
async def test_virustotal_live_mocked_http_success():
    tool = VirusTotalTool(api_key="fake_vt_key")
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "harmless": 20,
                    "undetected": 5
                }
            }
        }
    }
    
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        res = await tool.query("192.0.2.1", mock=False)
        assert res.malicious_votes == 45
        assert res.reputation_score > 60.0


@pytest.mark.asyncio
async def test_virustotal_rate_limit_and_error():
    tool = VirusTotalTool(api_key="fake_vt_key")
    
    mock_response = MagicMock()
    mock_response.status_code = 429
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        with pytest.raises(RateLimitError):
            await tool.query("192.0.2.1", mock=False)

    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        with pytest.raises(ThreatIntelAPIError):
            await tool.query("192.0.2.1", mock=False)


@pytest.mark.asyncio
async def test_abuseipdb_tool():
    tool = AbuseIPDBTool(api_key="fake_abuse_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 85.0,
            "totalReports": 120,
            "countryCode": "US"
        }
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        res = await tool.query("192.0.2.1", mock=False)
        assert res.reputation_score == 85.0
        assert res.provider == ThreatIntelProvider.ABUSEIPDB


@pytest.mark.asyncio
async def test_otx_tool():
    tool = AlienVaultOTXTool(api_key="fake_otx_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 5
        }
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        res = await tool.query("bad-domain.com", mock=False)
        assert res.reputation_score == 75.0
        assert res.provider == ThreatIntelProvider.ALIENVAULT_OTX
