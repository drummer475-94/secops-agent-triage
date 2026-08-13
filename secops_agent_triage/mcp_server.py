import asyncio
import json
from typing import Any, Dict

from mcp.server import MCPServer

from secops_agent_triage.agent.engine import TriageEngine
from secops_agent_triage.tools.abuseipdb import AbuseIPDBTool
from secops_agent_triage.tools.otx import AlienVaultOTXTool
from secops_agent_triage.tools.virustotal import VirusTotalTool

# Initialize MCPServer instance
mcp = MCPServer("secops-agent-triage")
engine = TriageEngine()
vt_tool = VirusTotalTool()
abuse_tool = AbuseIPDBTool()
otx_tool = AlienVaultOTXTool()


@mcp.tool()
async def triage_security_alert(
    raw_data: str, format_type: str = "auto", mock: bool = True
) -> str:
    """Ingests a raw security alert (EVTX, CloudTrail, Syslog), queries threat intel tools,
    builds verifiable reasoning traces, and returns a structured TriageAssessment JSON string.
    """
    assessment = await engine.triage_alert(raw_data, format_type=format_type, mock=mock)
    return assessment.model_dump_json(indent=2)


@mcp.tool()
async def lookup_ip_reputation(ip: str, mock: bool = True) -> str:
    """Queries VirusTotal, AbuseIPDB, and AlienVault OTX for reputation score of an IP address."""
    results = await asyncio.gather(
        vt_tool.query(ip, mock=mock),
        abuse_tool.query(ip, mock=mock),
        otx_tool.query(ip, mock=mock),
        return_exceptions=True,
    )
    output = []
    for r in results:
        if hasattr(r, "model_dump"):
            output.append(r.model_dump())
    return json.dumps(output, indent=2)


@mcp.tool()
async def lookup_hash_reputation(hash_value: str, mock: bool = True) -> str:
    """Queries VirusTotal and AlienVault OTX for reputation score of a file hash (MD5/SHA1/SHA256)."""
    results = await asyncio.gather(
        vt_tool.query(hash_value, mock=mock),
        otx_tool.query(hash_value, mock=mock),
        return_exceptions=True,
    )
    output = []
    for r in results:
        if hasattr(r, "model_dump"):
            output.append(r.model_dump())
    return json.dumps(output, indent=2)


@mcp.tool()
async def lookup_domain_reputation(domain: str, mock: bool = True) -> str:
    """Queries VirusTotal and AlienVault OTX for reputation score of a domain name."""
    results = await asyncio.gather(
        vt_tool.query(domain, mock=mock),
        otx_tool.query(domain, mock=mock),
        return_exceptions=True,
    )
    output = []
    for r in results:
        if hasattr(r, "model_dump"):
            output.append(r.model_dump())
    return json.dumps(output, indent=2)


def main():
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
