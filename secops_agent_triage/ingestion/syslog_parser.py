import re
import uuid
from typing import Any, Dict

from secops_agent_triage.ingestion.evtx_parser import extract_entities_from_text
from secops_agent_triage.schemas.alert import (
    AlertSeverity,
    AlertSource,
    ExtractedEntities,
    RawAlert,
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_PATTERN = re.compile(
    r'^<(?P<pri>\d+)>(?P<ver>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<appname>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<msg>.*)$'
)

# RFC 3164: <PRI>MMM DD HH:MM:SS HOSTNAME APP[PID]: MSG
RFC3164_PATTERN = re.compile(
    r'^<(?P<pri>\d+)>(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<appname>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$'
)


def parse_syslog_alert(raw_data: str | Dict[str, Any]) -> RawAlert:
    """Parses RFC 5424 and RFC 3164 Syslog messages."""
    alert_id = f"SYS-{uuid.uuid4().hex[:8]}"
    raw_str = raw_data if isinstance(raw_data, str) else str(raw_data.get("message", str(raw_data)))

    hostname = "unknown"
    appname = "syslog"
    msg = raw_str
    timestamp = "1970-01-01T00:00:00Z"
    pri = 13  # Default notice

    m5424 = RFC5424_PATTERN.match(raw_str)
    m3164 = RFC3164_PATTERN.match(raw_str)

    if m5424:
        gd = m5424.groupdict()
        pri = int(gd["pri"])
        timestamp = gd["timestamp"]
        hostname = gd["hostname"]
        appname = gd["appname"]
        msg = gd["msg"]
    elif m3164:
        gd = m3164.groupdict()
        pri = int(gd["pri"])
        timestamp = gd["timestamp"]
        hostname = gd["hostname"]
        appname = gd["appname"]
        msg = gd["msg"]

    ips, hashes, domains = extract_entities_from_text(raw_str)

    accounts = []
    # Extract SSH / sudo / auth user accounts from syslog message
    user_match = re.search(r'(?:user|for|account)\s+([a-zA-Z0-9_\-]+)', msg, re.IGNORECASE)
    if user_match:
        usr = user_match.group(1)
        if usr.lower() not in ["invalid", "from", "port", "via", "the", "a"]:
            accounts.append(usr)

    cmdlines = []
    if appname != "syslog":
        cmdlines.append(f"{appname}: {msg[:100]}")

    # Determine severity
    severity = AlertSeverity.LOW
    title = f"Syslog Event from {hostname} ({appname})"
    description = f"Syslog message received from host {hostname} by process {appname}: {msg}"

    msg_lower = msg.lower()
    if "failed password" in msg_lower or "brute force" in msg_lower or "authentication failure" in msg_lower:
        severity = AlertSeverity.HIGH if "root" in msg_lower or len(ips) > 0 else AlertSeverity.MEDIUM
        title = f"Authentication Failure / SSH Brute Force on {hostname}"
        description = f"Potential brute force attack detected on host {hostname}: {msg}"
    elif "iptables drop" in msg_lower or "ufw block" in msg_lower:
        severity = AlertSeverity.MEDIUM
        title = f"Firewall Drop / Block Event on {hostname}"
    elif "accepted password" in msg_lower or "session opened" in msg_lower:
        severity = AlertSeverity.INFORMATIONAL
        title = f"User Login Session Opened on {hostname}"

    return RawAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        source=AlertSource.SYSLOG,
        severity_raw=severity,
        title=title,
        description=description,
        raw_payload={"raw_message": raw_str, "hostname": hostname, "appname": appname, "priority": pri},
        entities=ExtractedEntities(
            ips=ips,
            hashes=hashes,
            domains=domains,
            accounts=accounts,
            cmdlines=cmdlines,
        ),
    )
