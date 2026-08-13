import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

from secops_agent_triage.agent.engine import TriageEngine


SAMPLE_EVTX_PAYLOAD = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <Level>0</Level>
    <Task>13312</Task>
    <TimeCreated SystemTime="2026-08-13T14:30:00.000000Z" />
    <Computer>FINANCE-PC01.corp.internal</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jdoe</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -e aW52b2tlLW1pbWlrYXR6IC1pcCAxOTIuMC4yLjE=</Data>
    <Data Name="TargetFilename">powershell.exe</Data>
  </EventData>
</Event>"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="secops-agent-triage: Flagship AI Agentic Security Alert Triage CLI"
    )
    parser.add_argument(
        "--file",
        "-f",
        type=str,
        help="Path to file containing raw alert payload (XML, JSON, Syslog string)",
    )
    parser.add_argument(
        "--raw",
        "-r",
        type=str,
        help="Raw alert string input directly from CLI",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="auto",
        choices=["auto", "evtx", "cloudtrail", "syslog"],
        help="Format type of raw alert (default: auto)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        default=True,
        help="Use deterministic mock threat intel mode (default: True)",
    )
    parser.add_argument(
        "--no-mock",
        action="store_false",
        dest="mock",
        help="Use live threat intel API keys",
    )
    parser.add_argument(
        "--output-json",
        "-o",
        type=str,
        help="Path to save output TriageAssessment JSON",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose log output",
    )
    return parser


async def run_cli(args: Optional[list[str]] = None) -> int:
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    raw_data: str = ""
    if parsed_args.file:
        file_path = Path(parsed_args.file)
        if not file_path.exists():
            print(f"Error: Specified file does not exist: {parsed_args.file}", file=sys.stderr)
            return 1
        raw_data = file_path.read_text(encoding="utf-8")
    elif parsed_args.raw:
        raw_data = parsed_args.raw
    else:
        if parsed_args.verbose:
            print("No alert input specified via --file or --raw. Running with sample Windows Event Log 4688...", file=sys.stderr)
        raw_data = SAMPLE_EVTX_PAYLOAD

    engine = TriageEngine()
    assessment = await engine.triage_alert(
        raw_data, format_type=parsed_args.format, mock=parsed_args.mock
    )

    formatted_json = assessment.model_dump_json(indent=2)
    print(formatted_json)

    if parsed_args.output_json:
        out_path = Path(parsed_args.output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(formatted_json, encoding="utf-8")
        if parsed_args.verbose:
            print(f"Assessment JSON saved to {parsed_args.output_json}", file=sys.stderr)

    return 0


def main():
    sys.exit(asyncio.run(run_cli()))


if __name__ == "__main__":
    main()
