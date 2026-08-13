import asyncio
import uuid
from typing import Any, Dict, List, Optional

from secops_agent_triage.agent.mapper import NISTMITREMapper
from secops_agent_triage.ingestion.parser import parse_raw_alert
from secops_agent_triage.schemas.alert import AlertSeverity, RawAlert
from secops_agent_triage.schemas.reasoning import ReasoningStep
from secops_agent_triage.schemas.threat_intel import ThreatIntelResult
from secops_agent_triage.schemas.triage import (
    TriageAssessment,
    TriageVerdict,
)
from secops_agent_triage.tools.abuseipdb import AbuseIPDBTool
from secops_agent_triage.tools.otx import AlienVaultOTXTool
from secops_agent_triage.tools.virustotal import VirusTotalTool


class TriageEngine:
    def __init__(
        self,
        vt_tool: Optional[VirusTotalTool] = None,
        abuse_tool: Optional[AbuseIPDBTool] = None,
        otx_tool: Optional[AlienVaultOTXTool] = None,
    ):
        self.vt_tool = vt_tool or VirusTotalTool()
        self.abuse_tool = abuse_tool or AbuseIPDBTool()
        self.otx_tool = otx_tool or AlienVaultOTXTool()

    async def triage_alert(
        self, raw_data: str | Dict[str, Any], format_type: str = "auto", mock: bool = True
    ) -> TriageAssessment:
        assessment_id = f"TR-{uuid.uuid4().hex[:8]}"
        reasoning_trace: List[ReasoningStep] = []

        # Step 1: Ingestion & Entity Extraction
        alert: RawAlert = parse_raw_alert(raw_data, format_type=format_type)
        total_iocs = len(alert.entities.ips) + len(alert.entities.hashes) + len(alert.entities.domains)
        step1 = ReasoningStep(
            step_number=1,
            action="Ingest raw alert and extract IOC entities",
            observation=(
                f"Ingested alert {alert.alert_id} (Source: {alert.source.value}, Raw Severity: {alert.severity_raw.value}). "
                f"Extracted {len(alert.entities.ips)} IPs, {len(alert.entities.hashes)} hashes, "
                f"{len(alert.entities.domains)} domains, {len(alert.entities.accounts)} accounts, "
                f"and {len(alert.entities.cmdlines)} command lines."
            ),
            deduction=(
                f"Alert '{alert.title}' parsed successfully. Initial entity extraction yields {total_iocs} unique IOCs "
                f"requiring automated threat intelligence verification."
            ),
            confidence=0.95,
        )
        reasoning_trace.append(step1)

        # Step 2: Query Threat Intel Tools Asynchronously
        threat_intel_results: List[ThreatIntelResult] = []
        indicators_to_query = set(alert.entities.ips + alert.entities.hashes + alert.entities.domains)

        async def query_all_providers(ind: str):
            tasks = [
                self.vt_tool.query(ind, mock=mock),
                self.abuse_tool.query(ind, mock=mock),
                self.otx_tool.query(ind, mock=mock),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            valid_results = []
            for r in results:
                if isinstance(r, ThreatIntelResult):
                    valid_results.append(r)
            return valid_results

        if indicators_to_query:
            all_queries = await asyncio.gather(
                *[query_all_providers(ind) for ind in indicators_to_query]
            )
            for res_list in all_queries:
                threat_intel_results.extend(res_list)

        max_rep_score = max([r.reputation_score for r in threat_intel_results], default=0.0)
        malicious_count = sum(1 for r in threat_intel_results if r.reputation_score >= 70.0)

        step2 = ReasoningStep(
            step_number=2,
            action="Query Threat Intelligence APIs (VirusTotal, AbuseIPDB, AlienVault OTX)",
            observation=(
                f"Executed {len(threat_intel_results)} threat intel queries across {len(indicators_to_query)} indicators. "
                f"Max reputation score observed: {max_rep_score:.1f}/100. "
                f"Found {malicious_count} provider responses indicating high malicious confidence."
            ),
            deduction=(
                f"Threat intelligence lookup completed. "
                + (
                    f"Indicators exhibit high threat correlation with score {max_rep_score:.1f}."
                    if max_rep_score >= 70.0
                    else f"Indicators show low-to-moderate threat scores (max: {max_rep_score:.1f})."
                )
            ),
            confidence=0.90,
        )
        reasoning_trace.append(step2)

        # Step 3: Verdict Determination & Severity Assessment
        cmdline_text = " ".join(alert.entities.cmdlines).lower()
        has_encoded_powershell = "-enc" in cmdline_text or "encodedcommand" in cmdline_text
        has_mimikatz = "mimikatz" in cmdline_text or "sekurlsa" in cmdline_text

        if max_rep_score >= 70.0 or has_encoded_powershell or has_mimikatz or alert.severity_raw == AlertSeverity.CRITICAL:
            verdict = TriageVerdict.TRUE_POSITIVE
            assessed_severity = AlertSeverity.CRITICAL if (max_rep_score >= 85.0 or has_mimikatz) else AlertSeverity.HIGH
            confidence_score = 0.95
            deduction_msg = (
                "Alert verified as TRUE POSITIVE based on high-risk threat intel reputation score "
                f"({max_rep_score:.1f}/100) or detected malicious execution syntax."
            )
        elif max_rep_score >= 40.0 or alert.severity_raw == AlertSeverity.HIGH:
            verdict = TriageVerdict.SUSPICIOUS
            assessed_severity = AlertSeverity.MEDIUM
            confidence_score = 0.80
            deduction_msg = "Alert classified as SUSPICIOUS due to elevated indicator scores and context."
        elif max_rep_score < 20.0 and total_iocs > 0 and not has_encoded_powershell:
            verdict = TriageVerdict.BENIGN
            assessed_severity = AlertSeverity.LOW
            confidence_score = 0.90
            deduction_msg = "Alert classified as BENIGN as all queried IOCs returned low reputation risk scores."
        else:
            verdict = TriageVerdict.UNKNOWN
            assessed_severity = alert.severity_raw
            confidence_score = 0.60
            deduction_msg = "Alert triage inconclusive; manual SOC investigation recommended."

        step3 = ReasoningStep(
            step_number=3,
            action="Evaluate risk metrics and determine triage verdict",
            observation=f"Evaluated verdict: {verdict.value}, Assessed Severity: {assessed_severity.value}, Confidence: {confidence_score:.2f}.",
            deduction=deduction_msg,
            confidence=confidence_score,
        )
        reasoning_trace.append(step3)

        # Step 4: NIST SP 800-61 & MITRE ATT&CK Mapping
        nist_mapping, mitre_mapping = NISTMITREMapper.map_alert(
            alert, threat_intel_results, max_rep_score
        )
        step4 = ReasoningStep(
            step_number=4,
            action="Map alert to NIST SP 800-61 Rev 2 incident categories and MITRE ATT&CK techniques",
            observation=f"Mapped to NIST category '{nist_mapping.category}' and MITRE technique {mitre_mapping.technique_id} ({mitre_mapping.technique_name}).",
            deduction="Actionable remediation steps and compliance guidance appended to triage assessment.",
            confidence=0.95,
        )
        reasoning_trace.append(step4)

        return TriageAssessment(
            assessment_id=assessment_id,
            alert_id=alert.alert_id,
            verdict=verdict,
            assessed_severity=assessed_severity,
            confidence_score=confidence_score,
            nist_mapping=nist_mapping,
            mitre_mapping=mitre_mapping,
            reasoning_trace=reasoning_trace,
            threat_intel_summaries=threat_intel_results,
        )
