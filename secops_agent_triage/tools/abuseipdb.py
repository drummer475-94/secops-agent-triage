from typing import Optional
import httpx

from secops_agent_triage.schemas.threat_intel import (
    IndicatorType,
    ThreatIntelProvider,
    ThreatIntelResult,
)
from secops_agent_triage.tools.base import (
    BaseThreatIntelTool,
    RateLimitError,
    ThreatIntelAPIError,
    detect_indicator_type,
    generate_deterministic_mock,
)


class AbuseIPDBTool(BaseThreatIntelTool):
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("ABUSEIPDB_API_KEY", ThreatIntelProvider.ABUSEIPDB)
        self.api_key = api_key

    async def query(self, indicator: str, mock: bool = False) -> ThreatIntelResult:
        key = self.get_api_key(self.api_key)
        if mock or not key:
            return generate_deterministic_mock(indicator, self.provider)

        ind_type = detect_indicator_type(indicator)
        if ind_type != IndicatorType.IP:
            # AbuseIPDB is strictly for IPs
            return generate_deterministic_mock(indicator, self.provider)

        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": indicator, "maxAgeInDays": "90"}
        url = "https://api.abuseipdb.com/api/v2/check"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code == 429:
                    raise RateLimitError("AbuseIPDB API rate limit exceeded")
                if resp.status_code != 200:
                    raise ThreatIntelAPIError(f"AbuseIPDB API error HTTP {resp.status_code}: {resp.text}")

                data = resp.json().get("data", {})
                abuse_score = float(data.get("abuseConfidenceScore", 0))
                total_reports = int(data.get("totalReports", 0))
                country_code = data.get("countryCode", "Unknown")

                summary = f"AbuseIPDB: Confidence score {abuse_score:.0f}% with {total_reports} reports (Country: {country_code})"

                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=IndicatorType.IP,
                    provider=self.provider,
                    reputation_score=abuse_score,
                    malicious_votes=total_reports,
                    total_votes=max(total_reports, 100),
                    summary=summary,
                    details=data,
                )
        except (RateLimitError, ThreatIntelAPIError):
            raise
        except Exception as e:
            raise ThreatIntelAPIError(f"AbuseIPDB request failed: {str(e)}") from e
