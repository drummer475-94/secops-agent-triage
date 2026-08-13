import hashlib
import os
import re
from typing import Optional

from secops_agent_triage.schemas.threat_intel import (
    IndicatorType,
    ThreatIntelProvider,
    ThreatIntelResult,
)


class ThreatIntelAPIError(Exception):
    """Base exception for threat intel tool errors."""
    pass


class RateLimitError(ThreatIntelAPIError):
    """Raised when API rate limits are exceeded."""
    pass


class MissingAPIKeyError(ThreatIntelAPIError):
    """Raised when an API key is missing and mock mode is not enabled."""
    pass


def detect_indicator_type(indicator: str) -> IndicatorType:
    ind = indicator.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ind):
        return IndicatorType.IP
    if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', ind):
        return IndicatorType.HASH
    return IndicatorType.DOMAIN


def generate_deterministic_mock(
    indicator: str, provider: ThreatIntelProvider
) -> ThreatIntelResult:
    ind_type = detect_indicator_type(indicator)
    ind_lower = indicator.strip().lower()

    benign_patterns = ["1.1.1.1", "8.8.8.8", "8.8.4.4", "127.0.0.1", "google.com", "example.com", "00000000000000000000000000000000"]
    malicious_patterns = ["192.0.2.1", "203.0.113.5", "198.51.100.14", "evil.com", "bad-domain.com", "malicious", "bad", "evil", "trojan", "c2", "ransomware", "phish"]

    if any(b in ind_lower for b in benign_patterns):
        score = 0.0
        malicious_votes = 0
        total_votes = 95
        summary = f"Mock {provider.value}: Clean/Benign indicator ({indicator})"
    elif any(m in ind_lower for m in malicious_patterns):
        score = 88.5
        malicious_votes = 52
        total_votes = 68
        summary = f"Mock {provider.value}: High-risk malicious indicator detected ({indicator})"
    else:
        # Deterministic seed based on string hash
        digest = int(hashlib.md5(indicator.encode()).hexdigest(), 16)
        score = float((digest % 70) + 10)  # Moderate score 10-80
        total_votes = 75
        malicious_votes = int(score * (total_votes / 100.0))
        summary = f"Mock {provider.value}: Evaluated reputation score {score:.1f}/100"

    return ThreatIntelResult(
        indicator=indicator,
        indicator_type=ind_type,
        provider=provider,
        reputation_score=score,
        malicious_votes=malicious_votes,
        total_votes=total_votes,
        summary=summary,
        details={
            "mock": True,
            "provider": provider.value,
            "indicator_type": ind_type.value,
            "raw_score": score,
        },
    )


class BaseThreatIntelTool:
    def __init__(self, api_key_env_var: str, provider: ThreatIntelProvider):
        self.api_key_env_var = api_key_env_var
        self.provider = provider

    def get_api_key(self, custom_key: Optional[str] = None) -> Optional[str]:
        return custom_key or os.environ.get(self.api_key_env_var)
