import json
from typing import Any, Dict

from secops_agent_triage.ingestion.cloudtrail_parser import parse_cloudtrail_alert
from secops_agent_triage.ingestion.evtx_parser import parse_evtx_alert
from secops_agent_triage.ingestion.syslog_parser import parse_syslog_alert
from secops_agent_triage.schemas.alert import RawAlert


def parse_raw_alert(raw_data: str | Dict[str, Any], format_type: str = "auto") -> RawAlert:
    """Unified ingestion facade for security alerts.
    
    Supports format_type: 'auto', 'evtx', 'cloudtrail', 'syslog'.
    """
    fmt = format_type.lower()
    
    if fmt == "evtx":
        return parse_evtx_alert(raw_data)
    elif fmt in ["cloudtrail", "aws"]:
        return parse_cloudtrail_alert(raw_data)
    elif fmt == "syslog":
        return parse_syslog_alert(raw_data)
    
    # Auto-detection logic
    if isinstance(raw_data, dict):
        if "eventSource" in raw_data or "userIdentity" in raw_data or "eventName" in raw_data or "Records" in raw_data:
            return parse_cloudtrail_alert(raw_data)
        if "EventID" in raw_data or "event_id" in raw_data or "TargetUserName" in raw_data:
            return parse_evtx_alert(raw_data)
        return parse_evtx_alert(raw_data)

    if isinstance(raw_data, str):
        data_str = raw_data.strip()
        if data_str.startswith("<Event") or "<EventID>" in data_str or "EventID:" in data_str:
            return parse_evtx_alert(raw_data)
        if data_str.startswith("<") and (">1 " in data_str or " " in data_str) and not data_str.startswith("<Event"):
            return parse_syslog_alert(raw_data)
        
        # Try JSON parsing
        try:
            parsed_json = json.loads(data_str)
            if isinstance(parsed_json, dict):
                if "eventSource" in parsed_json or "userIdentity" in parsed_json or "eventName" in parsed_json or "Records" in parsed_json:
                    return parse_cloudtrail_alert(parsed_json)
                if "EventID" in parsed_json or "event_id" in parsed_json:
                    return parse_evtx_alert(parsed_json)
        except Exception:
            pass

        if "failed password" in data_str.lower() or "sshd" in data_str.lower() or "syslog" in data_str.lower():
            return parse_syslog_alert(raw_data)

    # Default fallback
    return parse_evtx_alert(raw_data)
