import json
from pathlib import Path
from unittest.mock import patch
import pytest

from secops_agent_triage.cli import main, run_cli


@pytest.mark.asyncio
async def test_cli_default_sample_run(capsys, tmp_path):
    out_json = tmp_path / "output.json"
    exit_code = await run_cli(["--mock", "--output-json", str(out_json), "--verbose"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "assessment_id" in captured.out
    
    assert out_json.exists()
    saved_data = json.loads(out_json.read_text(encoding="utf-8"))
    assert "verdict" in saved_data


@pytest.mark.asyncio
async def test_cli_raw_input(capsys):
    raw_str = "<Event><System><EventID>4624</EventID></System></Event>"
    exit_code = await run_cli(["--raw", raw_str, "--format", "evtx", "--mock"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "WINDOWS_EVTX" in captured.out


@pytest.mark.asyncio
async def test_cli_file_input(capsys, tmp_path):
    file_path = tmp_path / "alert.json"
    file_path.write_text(json.dumps({"eventName": "AttachUserPolicy", "sourceIPAddress": "192.0.2.1"}), encoding="utf-8")
    
    exit_code = await run_cli(["--file", str(file_path), "--format", "cloudtrail", "--mock"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "AWS_CLOUDTRAIL" in captured.out


@pytest.mark.asyncio
async def test_cli_invalid_file(capsys):
    exit_code = await run_cli(["--file", "non_existent_file_12345.xml"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error: Specified file does not exist" in captured.err


def test_cli_main_entrypoint(capsys):
    with patch("sys.argv", ["secops-triage", "--raw", "test alert", "--mock"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "assessment_id" in captured.out
