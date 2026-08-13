import base64
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple

from secops_agent_triage.schemas.alert import (
    AlertSeverity,
    AlertSource,
    ExtractedEntities,
    RawAlert,
)

IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
HASH_REGEX = re.compile(r'\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|ru|cn|xyz|online|top|site|gov|edu)\b', re.IGNORECASE)


def extract_entities_from_text(text: str) -> Tuple[List[str], List[str], List[str]]:
    ips = list(set(IP_REGEX.findall(text)))
    hashes = list(set(HASH_REGEX.findall(text)))
    domains = list(set(DOMAIN_REGEX.findall(text)))
    return ips, hashes, domains


def try_decode_base64_cmdline(cmdline: str) -> str:
    """Detects and decodes powershell base64 encoded commands if present."""
    match = re.search(r'-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]+)', cmdline, re.IGNORECASE)
    if match:
        b64_str = match.group(1)
        try:
            decoded_bytes = base64.b64decode(b64_str)
            # Powershell encoded commands are often UTF-16LE
            try:
                decoded_text = decoded_bytes.decode('utf-16le')
            except UnicodeDecodeError:
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
            return f"{cmdline} [Decoded: {decoded_text}]"
        except Exception:
            pass
    return cmdline


def parse_evtx_alert(raw_data: str | Dict[str, Any]) -> RawAlert:
    """Parses Windows Event Log data provided as XML string, JSON dict, or formatted log text."""
    alert_id = f"EVTX-{uuid.uuid4().hex[:8]}"
    timestamp = "1970-01-01T00:00:00Z"
    event_id = "0"
    channel = "Security"
    computer = "UNKNOWN"
    user_account = ""
    cmdline = ""
    target_filename = ""
    raw_payload: Dict[str, Any] = {}
    
    if isinstance(raw_data, dict):
        raw_payload = raw_data
        event_id = str(raw_data.get("EventID", raw_data.get("event_id", "0")))
        timestamp = str(raw_data.get("TimeCreated", raw_data.get("timestamp", "1970-01-01T00:00:00Z")))
        computer = str(raw_data.get("Computer", raw_data.get("computer", "UNKNOWN")))
        user_account = str(raw_data.get("TargetUserName", raw_data.get("SubjectUserName", raw_data.get("user", ""))))
        cmdline = str(raw_data.get("CommandLine", raw_data.get("cmdline", "")))
        target_filename = str(raw_data.get("TargetFilename", raw_data.get("Image", "")))
    elif isinstance(raw_data, str):
        raw_payload = {"raw_text": raw_data}
        if raw_data.strip().startswith("<Event"):
            try:
                # Remove XML namespaces for easier parsing
                xml_clean = re.sub(r'\sxmlns="[^"]+"', '', raw_data)
                root = ET.fromstring(xml_clean)
                
                system = root.find("System")
                if system is not None:
                    eid_elem = system.find("EventID")
                    if eid_elem is not None and eid_elem.text:
                        event_id = eid_elem.text
                    time_elem = system.find("TimeCreated")
                    if time_elem is not None and "SystemTime" in time_elem.attrib:
                        timestamp = time_elem.attrib["SystemTime"]
                    comp_elem = system.find("Computer")
                    if comp_elem is not None and comp_elem.text:
                        computer = comp_elem.text

                event_data = root.find("EventData")
                if event_data is not None:
                    data_dict = {}
                    for data in event_data.findall("Data"):
                        name = data.attrib.get("Name")
                        val = data.text or ""
                        if name:
                            data_dict[name] = val
                    raw_payload["EventData"] = data_dict
                    
                    cmdline = data_dict.get("CommandLine", data_dict.get("ProcessCommandLine", ""))
                    user_account = data_dict.get("TargetUserName", data_dict.get("SubjectUserName", ""))
                    target_filename = data_dict.get("TargetFilename", data_dict.get("NewProcessName", data_dict.get("Image", "")))
            except Exception:
                eid_match = re.search(r'EventID[:=]\s*(\d+)', raw_data, re.IGNORECASE)
                if eid_match:
                    event_id = eid_match.group(1)
                cmd_match = re.search(r'CommandLine[:=]\s*(.+)', raw_data, re.IGNORECASE)
                if cmd_match:
                    cmdline = cmd_match.group(1).strip()
                usr_match = re.search(r'(?:TargetUserName|User)[:=]\s*(\w+)', raw_data, re.IGNORECASE)
                if usr_match:
                    user_account = usr_match.group(1)
        else:
            # Plain text parsing attempt
            eid_match = re.search(r'EventID[:=]\s*(\d+)', raw_data, re.IGNORECASE)
            if eid_match:
                event_id = eid_match.group(1)
            cmd_match = re.search(r'CommandLine[:=]\s*(.+)', raw_data, re.IGNORECASE)
            if cmd_match:
                cmdline = cmd_match.group(1).strip()
            usr_match = re.search(r'(?:TargetUserName|User)[:=]\s*(\w+)', raw_data, re.IGNORECASE)
            if usr_match:
                user_account = usr_match.group(1)

    if cmdline:
        cmdline = try_decode_base64_cmdline(cmdline)

    payload_str = str(raw_payload) + " " + cmdline
    ips, hashes, domains = extract_entities_from_text(payload_str)
    
    accounts = []
    if user_account:
        accounts.append(user_account)
    cmdlines = []
    if cmdline:
        cmdlines.append(cmdline)

    # Determine severity and title based on EventID & content
    severity = AlertSeverity.LOW
    title = f"Windows Event Log ID {event_id} on {computer}"
    description = f"Windows Event ID {event_id} recorded on host {computer}."

    if event_id == "4688":
        title = f"Windows Process Creation (EventID 4688) on {computer}"
        description = f"Process created with command line: {cmdline or target_filename}"
        if "-enc" in cmdline.lower() or "powershell" in cmdline.lower() or "mimikatz" in cmdline.lower():
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM
    elif event_id == "4625":
        title = f"Windows Failed Logon (EventID 4625) for {user_account or 'unknown'}"
        description = f"Failed logon attempt detected on computer {computer}."
        severity = AlertSeverity.MEDIUM
    elif event_id == "4624":
        title = f"Windows Successful Logon (EventID 4624) for {user_account or 'unknown'}"
        description = f"Successful logon logged on host {computer}."
        severity = AlertSeverity.INFORMATIONAL
    elif event_id == "7045":
        title = f"Windows New Service Installed (EventID 7045) on {computer}"
        description = f"A new service was installed on host {computer}."
        severity = AlertSeverity.HIGH

    return RawAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        source=AlertSource.WINDOWS_EVTX,
        severity_raw=severity,
        title=title,
        description=description,
        raw_payload=raw_payload,
        entities=ExtractedEntities(
            ips=ips,
            hashes=hashes,
            domains=domains,
            accounts=accounts,
            cmdlines=cmdlines,
        ),
    )
