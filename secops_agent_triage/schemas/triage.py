from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from secops_agent_triage.schemas.alert import AlertSeverity
from secops_agent_triage.schemas.reasoning import ReasoningStep
from secops_agent_triage.schemas.threat_intel import ThreatIntelResult


class TriageVerdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class NISTMapping(BaseModel):
    category: str
    phase_guidance: str
    containment_steps: List[str] = Field(default_factory=list)
    eradication_steps: List[str] = Field(default_factory=list)
    recovery_steps: List[str] = Field(default_factory=list)


class MITREMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    subtechnique_id: Optional[str] = None


class TriageAssessment(BaseModel):
    assessment_id: str
    alert_id: str
    verdict: TriageVerdict
    assessed_severity: AlertSeverity
    confidence_score: float = Field(ge=0.0, le=1.0)
    nist_mapping: NISTMapping
    mitre_mapping: MITREMapping
    reasoning_trace: List[ReasoningStep] = Field(default_factory=list)
    threat_intel_summaries: List[ThreatIntelResult] = Field(default_factory=list)
