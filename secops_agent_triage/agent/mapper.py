from typing import List, Tuple

from secops_agent_triage.schemas.alert import AlertSource, RawAlert
from secops_agent_triage.schemas.threat_intel import ThreatIntelResult
from secops_agent_triage.schemas.triage import MITREMapping, NISTMapping


class NISTMITREMapper:
    @staticmethod
    def map_alert(
        alert: RawAlert, threat_intel_results: List[ThreatIntelResult], max_reputation_score: float
    ) -> Tuple[NISTMapping, MITREMapping]:
        
        cmdlines_str = " ".join(alert.entities.cmdlines).lower()
        title_desc_str = f"{alert.title} {alert.description}".lower()
        
        # 1. MITRE ATT&CK Mapping
        technique_id = "T1059"
        technique_name = "Command and Scripting Interpreter"
        tactic = "Execution"
        subtechnique_id = None

        if "powershell" in cmdlines_str or "-enc" in cmdlines_str or "encodedcommand" in cmdlines_str:
            technique_id = "T1059.001"
            technique_name = "Command and Scripting Interpreter: PowerShell"
            tactic = "Execution"
            subtechnique_id = "T1059.001"
        elif "failed password" in title_desc_str or "brute force" in title_desc_str or "consoleloginfailure" in title_desc_str or "4625" in title_desc_str:
            technique_id = "T1110.001"
            technique_name = "Brute Force: Password Guessing"
            tactic = "Credential Access"
            subtechnique_id = "T1110.001"
        elif "attachuserpolicy" in title_desc_str or "createuser" in title_desc_str or "createaccesskey" in title_desc_str:
            technique_id = "T1098"
            technique_name = "Account Manipulation"
            tactic = "Persistence / Privilege Escalation"
            subtechnique_id = None
        elif max_reputation_score > 60.0 or any("c2" in t.summary.lower() or "domain" in t.summary.lower() for t in threat_intel_results):
            technique_id = "T1071.001"
            technique_name = "Application Layer Protocol: Web Protocols"
            tactic = "Command and Control"
            subtechnique_id = "T1071.001"
        elif "service" in title_desc_str or "7045" in title_desc_str:
            technique_id = "T1543.003"
            technique_name = "Create or Modify System Process: Windows Service"
            tactic = "Persistence"
            subtechnique_id = "T1543.003"

        mitre_mapping = MITREMapping(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            subtechnique_id=subtechnique_id,
        )

        # 2. NIST SP 800-61 Rev 2 Category Mapping
        if max_reputation_score > 70.0 or "encodedcommand" in cmdlines_str or "mimikatz" in cmdlines_str:
            category = "CAT 3 Malicious Code"
            phase_guidance = "NIST SP 800-61 Rev 2 Section 3.3: Immediate containment of malicious code execution, host isolation, and malware eradication."
            containment_steps = [
                "Isolate affected host system from the network immediately.",
                "Block malicious IP addresses and domains at perimeter firewall / EDR.",
                "Revoke active session tokens and reset compromised account credentials."
            ]
            eradication_steps = [
                "Kill malicious processes and delete scheduled tasks / service entries.",
                "Perform full endpoint anti-malware scan and EDR telemetry audit.",
                "Remove persistence registry keys or unauthorized IAM policy attachments."
            ]
            recovery_steps = [
                "Restore affected system from verified clean backup if corrupted.",
                "Verify system integrity and re-enable network access under monitoring.",
                "Conduct post-incident review and update detection rules."
            ]
        elif "failed password" in title_desc_str or "brute force" in title_desc_str or "attachuserpolicy" in title_desc_str or alert.severity_raw.value in ["HIGH", "CRITICAL"]:
            category = "CAT 1 Unauthorized Access"
            phase_guidance = "NIST SP 800-61 Rev 2 Section 3.2: Containment of unauthorized access, account lockouts, and privilege revocation."
            containment_steps = [
                "Lockout target account temporarily and terminate all active MFA sessions.",
                "Enforce immediate source IP block on firewall for offending brute force address."
            ]
            eradication_steps = [
                "Audit IAM policy changes or newly created credentials for unauthorized escalation.",
                "Rotate all compromised API keys, passwords, and access credentials."
            ]
            recovery_steps = [
                "Re-enable account after identity verification and credential reset.",
                "Review authentication logs for 72 hours post-incident."
            ]
        elif "drop" in title_desc_str or "denial" in title_desc_str:
            category = "CAT 2 Denial of Service"
            phase_guidance = "NIST SP 800-61 Rev 2 Section 3.1: Traffic rate-limiting, upstream filtering, and service restoration."
            containment_steps = [
                "Apply rate limiting and drop rules for offending traffic at network edge.",
                "Enable cloud DDoS mitigation / WAF protective rules."
            ]
            eradication_steps = [
                "Filter attack vectors and identify originating botnet IPs."
            ]
            recovery_steps = [
                "Monitor bandwidth utilization and restore full service throughput."
            ]
        else:
            category = "CAT 0 Normal Ops / Suspicious Event"
            phase_guidance = "NIST SP 800-61 Rev 2 Section 3.0: Standard monitoring and contextual triage."
            containment_steps = ["Monitor target system for additional anomalous activity."]
            eradication_steps = ["No immediate eradication required; verify legitimacy of activity."]
            recovery_steps = ["Resume standard operational baseline monitoring."]

        nist_mapping = NISTMapping(
            category=category,
            phase_guidance=phase_guidance,
            containment_steps=containment_steps,
            eradication_steps=eradication_steps,
            recovery_steps=recovery_steps,
        )

        return nist_mapping, mitre_mapping
