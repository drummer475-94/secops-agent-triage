import json
from unittest.mock import patch
import pytest

from secops_agent_triage.mcp_server import (
    lookup_domain_reputation,
    lookup_hash_reputation,
    lookup_ip_reputation,
    main,
    triage_security_alert,
)


@pytest.mark.asyncio
async def test_mcp_triage_security_alert():
    raw_data = "<Event><System><EventID>4688</EventID></System><EventData><Data Name='CommandLine'>powershell.exe -enc aW52b2tlLW1pbWlrYXR6</Data></EventData></Event>"
    result_str = await triage_security_alert(raw_data, format_type="evtx", mock=True)
    data = json.loads(result_str)
    assert "assessment_id" in data
    assert "verdict" in data
    assert data["verdict"] == "TRUE_POSITIVE"
    assert "nist_mapping" in data
    assert "mitre_mapping" in data


@pytest.mark.asyncio
async def test_mcp_lookup_ip_reputation():
    res_str = await lookup_ip_reputation("192.0.2.1", mock=True)
    data = json.loads(res_str)
    assert isinstance(data, list)
    assert len(data) == 3
    providers = [d["provider"] for d in data]
    assert "VIRUSTOTAL" in providers
    assert "ABUSEIPDB" in providers
    assert "ALIENVAULT_OTX" in providers


@pytest.mark.asyncio
async def test_mcp_lookup_hash_reputation():
    res_str = await lookup_hash_reputation("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", mock=True)
    data = json.loads(res_str)
    assert isinstance(data, list)
    assert len(data) == 2


@pytest.mark.asyncio
async def test_mcp_lookup_domain_reputation():
    res_str = await lookup_domain_reputation("evil.com", mock=True)
    data = json.loads(res_str)
    assert isinstance(data, list)
    assert len(data) == 2


def test_mcp_main_entrypoint():
    with patch("mcp.server.MCPServer.run_stdio_async") as mock_run:
        main()
        mock_run.assert_called_once()
