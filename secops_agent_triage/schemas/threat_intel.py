from enum import Enum
from typing import Any, Dict
from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    IP = "IP"
    HASH = "HASH"
    DOMAIN = "DOMAIN"


class ThreatIntelProvider(str, Enum):
    VIRUSTOTAL = "VIRUSTOTAL"
    ABUSEIPDB = "ABUSEIPDB"
    ALIENVAULT_OTX = "ALIENVAULT_OTX"


class ThreatIntelResult(BaseModel):
    indicator: str
    indicator_type: IndicatorType
    provider: ThreatIntelProvider
    reputation_score: float = Field(ge=0.0, le=100.0)
    malicious_votes: int = 0
    total_votes: int = 0
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
