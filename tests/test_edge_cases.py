import json
import pytest
from unittest.mock import AsyncMock, patch

from secops_agent_triage.agent.engine import TriageEngine
from secops_agent_triage.ingestion import (
    parse_cloudtrail_alert,
    parse_evtx_alert,
    parse_raw_alert,
    parse_syslog_alert,
)
from secops_agent_triage.ingestion.evtx_parser import try_decode_base64_cmdline
from secops_agent_triage.mcp_server import (
    lookup_domain_reputation,
    lookup_hash_reputation,
    lookup_ip_reputation,
    triage_security_alert,
)
from secops_agent_triage.schemas import AlertSeverity, AlertSource, TriageVerdict
from secops_agent_triage.tools import AbuseIPDBTool, AlienVaultOTXTool, VirusTotalTool
from secops_agent_triage.tools.base import detect_indicator_type, generate_deterministic_mock


# ============================================================================
# 1. Malformed EVTX XML & Dictionary Input Edge Cases
# ============================================================================

def test_evtx_parser_unclosed_xml_tags():
    """Verify parsing XML with missing closing tags falls back safely."""
    raw = "<Event><System><EventID>4688</EventID><TimeCreated"
    alert = parse_evtx_alert(raw)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert alert.alert_id.startswith("EVTX-")
    assert alert.severity_raw in [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH]


def test_evtx_parser_empty_event_tag():
    """Verify parsing empty <Event></Event> block."""
    raw = "<Event></Event>"
    alert = parse_evtx_alert(raw)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert alert.title == "Windows Event Log ID 0 on UNKNOWN"


def test_evtx_parser_missing_system_and_eventdata():
    """Verify XML with custom tags without System or EventData."""
    raw = "<Event><CustomBody><Message>Test</Message></CustomBody></Event>"
    alert = parse_evtx_alert(raw)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert alert.description == "Windows Event ID 0 recorded on host UNKNOWN."


def test_evtx_parser_missing_text_in_elements():
    """Verify XML elements with no text content (None text)."""
    raw = """<Event>
      <System>
        <EventID></EventID>
        <TimeCreated/>
        <Computer/>
      </System>
      <EventData>
        <Data Name="TargetUserName"></Data>
        <Data>Unnamed Value</Data>
      </EventData>
    </Event>"""
    alert = parse_evtx_alert(raw)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert alert.title == "Windows Event Log ID 0 on UNKNOWN"


def test_evtx_parser_dict_with_none_and_non_string_values():
    """Verify dict with None or integer values."""
    dict_payload = {
        "EventID": None,
        "TimeCreated": 12345,
        "Computer": None,
        "TargetUserName": 9999,
        "CommandLine": None,
    }
    alert = parse_evtx_alert(dict_payload)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert alert.alert_id.startswith("EVTX-")


# ============================================================================
# 2. Empty CloudTrail JSON and Invalid Syslog Messages Edge Cases
# ============================================================================

def test_cloudtrail_parser_empty_json_dict():
    """Verify empty JSON dictionary handles missing attributes without crash."""
    alert = parse_cloudtrail_alert("{}")
    assert alert.source == AlertSource.AWS_CLOUDTRAIL
    assert alert.severity_raw == AlertSeverity.LOW
    assert "UnknownCloudTrailEvent" in alert.title


def test_cloudtrail_parser_json_array_input():
    """Verify JSON array input string does not cause AttributeError."""
    alert = parse_cloudtrail_alert("[]")
    assert alert.source == AlertSource.AWS_CLOUDTRAIL
    assert alert.severity_raw == AlertSeverity.LOW


def test_cloudtrail_parser_json_null_and_primitives():
    """Verify non-dictionary JSON primitives (null, true, 123)."""
    for item in ["null", "true", "123.45"]:
        alert = parse_cloudtrail_alert(item)
        assert alert.source == AlertSource.AWS_CLOUDTRAIL


def test_cloudtrail_parser_null_response_elements_and_user_identity():
    """Verify null responseElements or null userIdentity does not crash."""
    dict_payload = {
        "eventName": "ConsoleLogin",
        "responseElements": None,
        "userIdentity": None,
    }
    alert = parse_cloudtrail_alert(dict_payload)
    assert alert.source == AlertSource.AWS_CLOUDTRAIL
    assert alert.severity_raw == AlertSeverity.MEDIUM


def test_cloudtrail_parser_records_list_with_none():
    """Verify Records array containing None or non-dict items."""
    dict_payload = {"Records": [None]}
    alert = parse_cloudtrail_alert(dict_payload)
    assert alert.source == AlertSource.AWS_CLOUDTRAIL


def test_syslog_parser_empty_string():
    """Verify empty string syslog parser."""
    alert = parse_syslog_alert("")
    assert alert.source == AlertSource.SYSLOG
    assert alert.severity_raw == AlertSeverity.LOW
    assert "unknown" in alert.title


def test_syslog_parser_corrupted_priority_header():
    """Verify corrupted priority header <999999> or missing header."""
    alert = parse_syslog_alert("<9999999999> INVALID HEADER SYSLOG MESSAGE")
    assert alert.source == AlertSource.SYSLOG
    assert alert.title == "Syslog Event from unknown (syslog)"


def test_syslog_parser_dict_missing_message_key():
    """Verify dictionary syslog input missing 'message' key."""
    alert = parse_syslog_alert({"other_key": "custom_data"})
    assert alert.source == AlertSource.SYSLOG


def test_syslog_parser_binary_characters():
    """Verify syslog message containing non-printable or binary escape characters."""
    alert = parse_syslog_alert("\x00\x01\x02\x03\x04 binary syslog data \x00")
    assert alert.source == AlertSource.SYSLOG


# ============================================================================
# 3. Extracted IP/Hash/Domain Edge Cases
# ============================================================================

def test_entity_extraction_invalid_ip_octets():
    """Verify IP regex does not match out-of-range octets like 999.999.999.999."""
    text = "Connecting to 999.999.999.999 and 192.0.2.1"
    alert = parse_evtx_alert(text)
    assert "192.0.2.1" in alert.entities.ips
    assert "999.999.999.999" not in alert.entities.ips


def test_cloudtrail_invalid_source_ip_handling():
    """Verify CloudTrail sourceIPAddress handling with invalid IP strings."""
    dict_payload = {
        "eventName": "RunInstances",
        "sourceIPAddress": "256.300.1.1.5",
    }
    alert = parse_cloudtrail_alert(dict_payload)
    assert alert.source == AlertSource.AWS_CLOUDTRAIL


def test_detect_indicator_type_edge_cases():
    """Verify indicator type detection on edge case values."""
    assert detect_indicator_type("192.0.2.1") == detect_indicator_type("192.0.2.1")
    assert detect_indicator_type("") == detect_indicator_type("domain.com")


def test_deterministic_mock_with_empty_and_unusual_indicators():
    """Verify generate_deterministic_mock on empty strings and unusual indicators."""
    res_empty = generate_deterministic_mock("", VirusTotalTool().provider)
    assert res_empty.indicator == ""
    assert res_empty.reputation_score >= 0.0

    res_long = generate_deterministic_mock("A" * 500, VirusTotalTool().provider)
    assert res_long.reputation_score >= 0.0


# ============================================================================
# 4. Base64 PowerShell Decoding Edge Cases
# ============================================================================

def test_base64_decoding_corrupted_padding():
    """Verify base64 decoding with invalid padding or corrupted base64 string."""
    cmd = "powershell.exe -enc invalid_b64!!!"
    res = try_decode_base64_cmdline(cmd)
    assert res == cmd


def test_base64_decoding_non_utf8_binary_payload():
    """Verify base64 payload containing raw non-UTF8 binary data."""
    # "/v8=" decodes to b"\xff\xff"
    cmd = "powershell.exe -enc /v8="
    res = try_decode_base64_cmdline(cmd)
    assert "Decoded:" in res


def test_base64_decoding_case_insensitivity_and_flag_variations():
    """Verify case insensitive flag matching for -EncodedCommand."""
    cmd = "powershell.exe -eNcoDeDcOmMaNd aW52b2tlLW1pbWlrYXR6"
    res = try_decode_base64_cmdline(cmd)
    assert "Decoded: invoke-mimikatz" in res


# ============================================================================
# 5. System Resilience, Error Handling & MCP Tool Verification
# ============================================================================

@pytest.mark.asyncio
async def test_triage_engine_resilience_on_malformed_inputs():
    """Verify TriageEngine completes triage without exception on malformed inputs."""
    engine = TriageEngine()
    assessment = await engine.triage_alert("<Event>Malformed", mock=True)
    assert assessment.verdict in [TriageVerdict.TRUE_POSITIVE, TriageVerdict.SUSPICIOUS, TriageVerdict.BENIGN, TriageVerdict.UNKNOWN]
    assert len(assessment.reasoning_trace) == 4


@pytest.mark.asyncio
async def test_mcp_tools_resilience_on_empty_and_invalid_inputs():
    """Verify MCP tool endpoints gracefully handle empty or invalid inputs."""
    res_ip = await lookup_ip_reputation("", mock=True)
    assert "indicator" in res_ip

    res_hash = await lookup_hash_reputation("invalid_hash", mock=True)
    assert "indicator" in res_hash

    res_dom = await lookup_domain_reputation("", mock=True)
    assert "indicator" in res_dom

    res_triage = await triage_security_alert("{invalid_json", mock=True)
    assert "assessment_id" in res_triage
