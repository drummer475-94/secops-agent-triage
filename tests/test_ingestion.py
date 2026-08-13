import json
import pytest

from secops_agent_triage.ingestion import (
    parse_cloudtrail_alert,
    parse_evtx_alert,
    parse_raw_alert,
    parse_syslog_alert,
)
from secops_agent_triage.schemas import AlertSeverity, AlertSource


def test_evtx_parser_xml_4688():
    xml_data = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2026-08-13T12:00:00Z"/>
        <Computer>HOST01.CORP</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">admin</Data>
        <Data Name="CommandLine">powershell.exe -enc aW52b2tlLW1pbWlrYXR6</Data>
      </EventData>
    </Event>"""
    alert = parse_evtx_alert(xml_data)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert alert.severity_raw == AlertSeverity.HIGH
    assert "HOST01.CORP" in alert.title
    assert "admin" in alert.entities.accounts
    assert len(alert.entities.cmdlines) > 0
    assert "Decoded:" in alert.entities.cmdlines[0]


def test_evtx_parser_dict_4625():
    dict_data = {
        "EventID": 4625,
        "TimeCreated": "2026-08-13T12:30:00Z",
        "Computer": "DB-SERVER",
        "TargetUserName": "sqladmin",
        "IpAddress": "192.0.2.1",
    }
    alert = parse_evtx_alert(dict_data)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert alert.severity_raw == AlertSeverity.MEDIUM
    assert "192.0.2.1" in alert.entities.ips
    assert "sqladmin" in alert.entities.accounts


def test_evtx_parser_event7045():
    dict_data = {
        "EventID": 7045,
        "Computer": "DC01",
        "ServiceName": "MaliciousService",
        "ImagePath": "C:\\Windows\\Temp\\bad.exe",
    }
    alert = parse_evtx_alert(dict_data)
    assert alert.severity_raw == AlertSeverity.HIGH
    assert "Service Installed" in alert.title


def test_evtx_parser_plain_text():
    text = "EventID: 4624 Computer: FS01 TargetUserName: user1"
    alert = parse_evtx_alert(text)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert alert.severity_raw == AlertSeverity.INFORMATIONAL


def test_evtx_parser_invalid_xml():
    invalid_xml = "<Event>EventID: 4688 <invalid_xml>"
    alert = parse_evtx_alert(invalid_xml)
    assert alert.source == AlertSource.WINDOWS_EVTX
    assert "4688" in alert.title


def test_cloudtrail_parser_json_string():
    ct_data = json.dumps({
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "eventTime": "2026-08-13T10:00:00Z",
        "sourceIPAddress": "203.0.113.5",
        "userIdentity": {
            "userName": "attacker_user",
            "accountId": "123456789012"
        },
        "awsRegion": "us-west-2"
    })
    alert = parse_cloudtrail_alert(ct_data)
    assert alert.source == AlertSource.AWS_CLOUDTRAIL
    assert alert.severity_raw == AlertSeverity.HIGH
    assert "203.0.113.5" in alert.entities.ips
    assert "attacker_user" in alert.entities.accounts


def test_cloudtrail_parser_console_login_failure():
    ct_data = {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "sourceIPAddress": "198.51.100.14",
        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/baduser"},
        "responseElements": {"ConsoleLogin": "Failure"}
    }
    alert = parse_cloudtrail_alert(ct_data)
    assert alert.severity_raw == AlertSeverity.HIGH
    assert "198.51.100.14" in alert.entities.ips
    assert "arn:aws:iam::123456789012:user/baduser" in alert.entities.accounts


def test_cloudtrail_parser_records_wrapper():
    ct_data = {
        "Records": [{
            "eventName": "DeleteTrail",
            "eventSource": "cloudtrail.amazonaws.com",
            "sourceIPAddress": "198.51.100.14",
            "userIdentity": {"userName": "compromised_admin"}
        }]
    }
    alert = parse_cloudtrail_alert(ct_data)
    assert alert.severity_raw == AlertSeverity.CRITICAL
    assert "198.51.100.14" in alert.entities.ips


def test_cloudtrail_parser_invalid_json():
    alert = parse_cloudtrail_alert("{invalid_json_string")
    assert alert.source == AlertSource.AWS_CLOUDTRAIL
    assert alert.severity_raw == AlertSeverity.LOW


def test_syslog_parser_rfc5424():
    syslog_msg = "<165>1 2026-08-13T11:00:00Z edge-fw sshd 1234 - - Failed password for root from 192.0.2.1 port 22 ssh2"
    alert = parse_syslog_alert(syslog_msg)
    assert alert.source == AlertSource.SYSLOG
    assert alert.severity_raw == AlertSeverity.HIGH
    assert "192.0.2.1" in alert.entities.ips
    assert "root" in alert.entities.accounts


def test_syslog_parser_rfc3164():
    syslog_msg = "<13>Aug 13 11:15:00 webserver iptables[5678]: iptables drop packet from 198.51.100.14"
    alert = parse_syslog_alert(syslog_msg)
    assert alert.source == AlertSource.SYSLOG
    assert alert.severity_raw == AlertSeverity.MEDIUM
    assert "198.51.100.14" in alert.entities.ips


def test_syslog_parser_accepted_password():
    syslog_msg = "<13>Aug 13 11:20:00 webserver sshd[999]: Accepted password for admin from 1.1.1.1 port 22"
    alert = parse_syslog_alert(syslog_msg)
    assert alert.severity_raw == AlertSeverity.INFORMATIONAL
    assert "Session Opened" in alert.title


def test_unified_parser_auto_detection():
    # CloudTrail dict & string
    alert_ct = parse_raw_alert({"eventName": "ConsoleLogin", "sourceIPAddress": "1.1.1.1"})
    assert alert_ct.source == AlertSource.AWS_CLOUDTRAIL

    alert_ct_str = parse_raw_alert(json.dumps({"eventName": "CreateUser", "eventSource": "iam.amazonaws.com"}))
    assert alert_ct_str.source == AlertSource.AWS_CLOUDTRAIL

    # EVTX string & dict
    alert_evtx = parse_raw_alert("<Event><System><EventID>4688</EventID></System></Event>")
    assert alert_evtx.source == AlertSource.WINDOWS_EVTX

    alert_evtx_json = parse_raw_alert(json.dumps({"EventID": 4624, "Computer": "TEST"}))
    assert alert_evtx_json.source == AlertSource.WINDOWS_EVTX

    # Syslog string
    alert_sys = parse_raw_alert("<165>1 2026-08-13T11:00:00Z edge-fw sshd 1234 - - Failed password for user admin from 1.1.1.1")
    assert alert_sys.source == AlertSource.SYSLOG

    # Format overrides
    assert parse_raw_alert("data", format_type="evtx").source == AlertSource.WINDOWS_EVTX
    assert parse_raw_alert("data", format_type="cloudtrail").source == AlertSource.AWS_CLOUDTRAIL
    assert parse_raw_alert("data", format_type="syslog").source == AlertSource.SYSLOG

    # Unknown JSON fallback
    assert parse_raw_alert(json.dumps({"custom_field": "val"})).source == AlertSource.WINDOWS_EVTX
