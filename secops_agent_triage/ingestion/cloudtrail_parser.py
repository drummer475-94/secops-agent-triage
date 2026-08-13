import json
import uuid
from typing import Any, Dict

from secops_agent_triage.ingestion.evtx_parser import extract_entities_from_text
from secops_agent_triage.schemas.alert import (
    AlertSeverity,
    AlertSource,
    ExtractedEntities,
    RawAlert,
)


def parse_cloudtrail_alert(raw_data: str | Dict[str, Any]) -> RawAlert:
    """Parses AWS CloudTrail JSON events or event records."""
    alert_id = f"CT-{uuid.uuid4().hex[:8]}"
    
    if isinstance(raw_data, str):
        try:
            event = json.loads(raw_data)
        except Exception:
            event = {"raw_text": raw_data}
    else:
        event = raw_data

    # Handle CloudTrail wrapped in {"Records": [...]}
    if isinstance(event, dict) and "Records" in event and isinstance(event["Records"], list) and len(event["Records"]) > 0:
        event = event["Records"][0]

    if not isinstance(event, dict):
        event = {"raw_text": str(event)}

    event_name = event.get("eventName", "UnknownCloudTrailEvent")
    event_source = event.get("eventSource", "aws.service")
    timestamp = event.get("eventTime", "1970-01-01T00:00:00Z")
    source_ip = event.get("sourceIPAddress", "")
    user_agent = event.get("userAgent", "")
    aws_region = event.get("awsRegion", "us-east-1")

    # Extract user identity
    user_identity = event.get("userIdentity", {})
    user_name = ""
    account_id = ""
    if isinstance(user_identity, dict):
        user_name = user_identity.get("userName") or user_identity.get("principalId", "")
        account_id = user_identity.get("accountId", "")
        if not user_name and "arn" in user_identity:
            user_name = user_identity["arn"]

    payload_str = json.dumps(event)
    ips, hashes, domains = extract_entities_from_text(payload_str)
    if source_ip and source_ip not in ips and not source_ip.startswith("AWS Internal"):
        # Check if source_ip is valid IP before adding
        if source_ip.count(".") == 3:
            ips.append(source_ip)

    accounts = []
    if user_name:
        accounts.append(user_name)
    if account_id and account_id not in accounts:
        accounts.append(account_id)

    cmdlines = []
    if event_name:
        cmdlines.append(f"aws {event_source.split('.')[0]} {event_name}")

    # Determine severity and title based on CloudTrail event name
    severity = AlertSeverity.LOW
    title = f"AWS CloudTrail Event: {event_name} by {user_name or 'unknown'}"
    description = f"CloudTrail event {event_name} from {event_source} in region {aws_region}."

    high_risk_events = ["AttachUserPolicy", "AttachGroupPolicy", "CreateAccessKey", "PutUserPolicy", "AuthorizeSecurityGroupIngress"]
    critical_risk_events = ["ConsoleLoginFailure", "DeleteTrail", "StopLogging", "DeactivateMFADevice"]

    resp_elems = event.get("responseElements")
    has_console_login_failure = isinstance(resp_elems, dict) and resp_elems.get("ConsoleLogin") == "Failure"

    if event_name in critical_risk_events or (event_name == "ConsoleLogin" and has_console_login_failure):
        severity = AlertSeverity.CRITICAL if "DeleteTrail" in event_name or "StopLogging" in event_name else AlertSeverity.HIGH
        title = f"CRITICAL AWS Event: {event_name} from {source_ip or 'unknown IP'}"
        description = f"Suspicious or administrative disruption event {event_name} performed by {user_name}."
    elif event_name in high_risk_events:
        severity = AlertSeverity.HIGH
        title = f"High Risk AWS Action: {event_name} by {user_name}"
        description = f"IAM or Security Group alteration event {event_name} requested from source IP {source_ip}."
    elif event_name in ["CreateUser", "RunInstances", "ConsoleLogin"]:
        severity = AlertSeverity.MEDIUM
        description = f"Identity or infrastructure activity {event_name} initiated by {user_name}."

    return RawAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        source=AlertSource.AWS_CLOUDTRAIL,
        severity_raw=severity,
        title=title,
        description=description,
        raw_payload=event if isinstance(event, dict) else {"raw": event},
        entities=ExtractedEntities(
            ips=ips,
            hashes=hashes,
            domains=domains,
            accounts=accounts,
            cmdlines=cmdlines,
        ),
    )
