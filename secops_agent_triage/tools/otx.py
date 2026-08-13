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


class AlienVaultOTXTool(BaseThreatIntelTool):
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("OTX_API_KEY", ThreatIntelProvider.ALIENVAULT_OTX)
        self.api_key = api_key

    async def query(self, indicator: str, mock: bool = False) -> ThreatIntelResult:
        key = self.get_api_key(self.api_key)
        if mock or not key:
            return generate_deterministic_mock(indicator, self.provider)

        ind_type = detect_indicator_type(indicator)
        headers = {"X-OTX-API-KEY": key}

        if ind_type == IndicatorType.IP:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
        elif ind_type == IndicatorType.DOMAIN:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
        else:
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    raise RateLimitError("AlienVault OTX API rate limit exceeded")
                if resp.status_code != 200:
                    raise ThreatIntelAPIError(f"AlienVault OTX API error HTTP {resp.status_code}: {resp.text}")

                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)

                # Score based on pulse count
                score = min(pulse_count * 15.0, 100.0)
                summary = f"AlienVault OTX: Found in {pulse_count} threat intel pulses"

                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=ind_type,
                    provider=self.provider,
                    reputation_score=score,
                    malicious_votes=pulse_count,
                    total_votes=max(pulse_count, 10),
                    summary=summary,
                    details=pulse_info,
                )
        except (RateLimitError, ThreatIntelAPIError):
            raise
        except Exception as e:
            raise ThreatIntelAPIError(f"AlienVault OTX request failed: {str(e)}") from e
