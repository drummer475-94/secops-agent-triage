from typing import Optional
import httpx

from secops_agent_triage.schemas.threat_intel import (
    IndicatorType,
    ThreatIntelProvider,
    ThreatIntelResult,
)
from secops_agent_triage.tools.base import (
    BaseThreatIntelTool,
    MissingAPIKeyError,
    RateLimitError,
    ThreatIntelAPIError,
    detect_indicator_type,
    generate_deterministic_mock,
)


class VirusTotalTool(BaseThreatIntelTool):
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("VT_API_KEY", ThreatIntelProvider.VIRUSTOTAL)
        self.api_key = api_key

    async def query(self, indicator: str, mock: bool = False) -> ThreatIntelResult:
        key = self.get_api_key(self.api_key)
        if mock or not key:
            return generate_deterministic_mock(indicator, self.provider)

        ind_type = detect_indicator_type(indicator)
        headers = {"x-apikey": key}

        if ind_type == IndicatorType.IP:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        elif ind_type == IndicatorType.DOMAIN:
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        else:
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    raise RateLimitError("VirusTotal API rate limit exceeded")
                if resp.status_code != 200:
                    raise ThreatIntelAPIError(f"VirusTotal API error HTTP {resp.status_code}: {resp.text}")

                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + harmless + undetected

                score = (malicious / max(total, 1)) * 100.0
                summary = f"VirusTotal: {malicious}/{total} security vendors flagged this as malicious"

                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=ind_type,
                    provider=self.provider,
                    reputation_score=score,
                    malicious_votes=malicious,
                    total_votes=total,
                    summary=summary,
                    details=data,
                )
        except (RateLimitError, ThreatIntelAPIError):
            raise
        except Exception as e:
            raise ThreatIntelAPIError(f"VirusTotal request failed: {str(e)}") from e
