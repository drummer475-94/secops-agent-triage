from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class AlertSource(str, Enum):
    WINDOWS_EVTX = "WINDOWS_EVTX"
    AWS_CLOUDTRAIL = "AWS_CLOUDTRAIL"
    SYSLOG = "SYSLOG"
    CUSTOM = "CUSTOM"


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ExtractedEntities(BaseModel):
    ips: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    accounts: List[str] = Field(default_factory=list)
    cmdlines: List[str] = Field(default_factory=list)


class RawAlert(BaseModel):
    alert_id: str
    timestamp: str
    source: AlertSource
    severity_raw: AlertSeverity
    title: str
    description: str
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    entities: ExtractedEntities = Field(default_factory=ExtractedEntities)
