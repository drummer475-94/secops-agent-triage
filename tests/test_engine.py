import pytest

from secops_agent_triage.agent import TriageEngine
from secops_agent_triage.schemas import AlertSeverity, TriageVerdict


@pytest.mark.asyncio
async def test_triage_engine_malicious_powershell_evtx():
    engine = TriageEngine()
    evtx_data = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2026-08-13T12:00:00Z"/>
        <Computer>CORP-PC01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">victim_user</Data>
        <Data Name="CommandLine">powershell.exe -enc aW52b2tlLW1pbWlrYXR6IC1pcCAxOTIuMC4yLjE=</Data>
      </EventData>
    </Event>"""
    assessment = await engine.triage_alert(evtx_data, format_type="evtx", mock=True)

    assert assessment.verdict == TriageVerdict.TRUE_POSITIVE
    assert assessment.assessed_severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]
    assert assessment.confidence_score >= 0.90
    assert len(assessment.reasoning_trace) == 4
    assert assessment.mitre_mapping.technique_id == "T1059.001"
    assert "CAT 3 Malicious Code" in assessment.nist_mapping.category
    assert len(assessment.nist_mapping.containment_steps) > 0


@pytest.mark.asyncio
async def test_triage_engine_benign_alert():
    engine = TriageEngine()
    syslog_msg = "<13>Aug 13 11:15:00 webserver sshd: Accepted password for user1 from 1.1.1.1 port 22"
    assessment = await engine.triage_alert(syslog_msg, format_type="syslog", mock=True)

    assert assessment.verdict in [TriageVerdict.BENIGN, TriageVerdict.FALSE_POSITIVE, TriageVerdict.UNKNOWN]
    assert assessment.assessed_severity in [AlertSeverity.LOW, AlertSeverity.INFORMATIONAL]
    assert len(assessment.reasoning_trace) == 4


@pytest.mark.asyncio
async def test_triage_engine_cloudtrail_delete_trail():
    engine = TriageEngine()
    cloudtrail_data = {
        "eventName": "DeleteTrail",
        "eventSource": "cloudtrail.amazonaws.com",
        "sourceIPAddress": "198.51.100.14",
        "userIdentity": {"userName": "admin_attacker"}
    }
    assessment = await engine.triage_alert(cloudtrail_data, format_type="cloudtrail", mock=True)

    assert assessment.verdict == TriageVerdict.TRUE_POSITIVE
    assert assessment.assessed_severity == AlertSeverity.CRITICAL
    assert "CAT 3" in assessment.nist_mapping.category or "CAT 1" in assessment.nist_mapping.category


@pytest.mark.asyncio
async def test_triage_engine_brute_force_syslog():
    engine = TriageEngine()
    syslog_msg = "<165>1 2026-08-13T11:00:00Z edge-fw sshd 1234 - - Failed password for root from 1.1.1.1 port 22"
    assessment = await engine.triage_alert(syslog_msg, format_type="syslog", mock=True)
    assert assessment.mitre_mapping.technique_id == "T1110.001"
    assert "CAT 1 Unauthorized Access" in assessment.nist_mapping.category


@pytest.mark.asyncio
async def test_triage_engine_dos_syslog():
    engine = TriageEngine()
    syslog_msg = "<13>Aug 13 11:15:00 webserver iptables[5678]: iptables drop denial packet from 1.1.1.1"
    assessment = await engine.triage_alert(syslog_msg, format_type="syslog", mock=True)
    assert "CAT 2 Denial of Service" in assessment.nist_mapping.category


@pytest.mark.asyncio
async def test_triage_engine_service_installation():
    engine = TriageEngine()
    evtx_data = {"EventID": 7045, "Computer": "DC01", "ServiceName": "BackdoorService"}
    assessment = await engine.triage_alert(evtx_data, format_type="evtx", mock=True)
    assert assessment.mitre_mapping.technique_id == "T1543.003"


@pytest.mark.asyncio
async def test_triage_engine_c2_domain():
    engine = TriageEngine()
    syslog_msg = "Connection attempt to evil.com c2 domain from 1.1.1.1"
    assessment = await engine.triage_alert(syslog_msg, format_type="syslog", mock=True)
    assert assessment.mitre_mapping.technique_id == "T1071.001"
