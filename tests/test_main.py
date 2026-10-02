from __future__ import annotations

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from vulnpilot.main import app

runner = CliRunner()


def test_cli_scan(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-1",
                "PkgName": "pkg",
                "InstalledVersion": "1.0",
                "Severity": "LOW"
            }]
        }]
    }))

    result = runner.invoke(app, ["scan", str(report_path), "--policy-file", "nonexistent.yaml"])
    assert result.exit_code == 0
    assert "Parsed 1 vulnerabilities" in result.stdout


def test_cli_scan_file_not_found() -> None:
    result = runner.invoke(app, ["scan", "doesnt_exist.json"])
    assert result.exit_code == 1
    assert "does not exist" in result.stdout


@patch("vulnpilot.main.TrivyParser.parse_file")
@patch("pathlib.Path.exists")
def test_main_cli_parse_error(mock_exists: MagicMock, mock_parse: MagicMock) -> None:
    mock_exists.return_value = True
    mock_parse.side_effect = ValueError("Bad JSON")
    result = runner.invoke(app, ["scan", "dummy.json"])
    assert result.exit_code == 1
    assert "Failed to parse file" in result.stdout


@patch("vulnpilot.main.update_kev", return_value=True)
@patch("vulnpilot.main.update_epss", return_value=True)
def test_main_update_intel_success(mock_epss: MagicMock, mock_kev: MagicMock) -> None:
    result = runner.invoke(app, ["update-intel"])
    assert result.exit_code == 0
    assert "refresh complete" in result.stdout


@patch("vulnpilot.main.update_kev", return_value=False)
@patch("vulnpilot.main.update_epss", return_value=True)
def test_main_update_intel_failure(mock_epss: MagicMock, mock_kev: MagicMock) -> None:
    result = runner.invoke(app, ["update-intel"])
    assert result.exit_code == 1

def test_main_cli_formats(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-1",
                "PkgName": "pkg",
                "InstalledVersion": "1.0",
                "Severity": "LOW"
            }]
        }]
    }))

    res_json = runner.invoke(app, ["scan", str(report_path), "--format", "json"])
    assert res_json.exit_code == 0
    assert "CVE-1" in res_json.stdout

    res_md = runner.invoke(app, ["scan", str(report_path), "--format", "markdown"])
    assert res_md.exit_code == 0
    assert "| CVE-1 |" in res_md.stdout

    res_sarif = runner.invoke(app, ["scan", str(report_path), "--format", "sarif"])
    assert res_sarif.exit_code == 0
    assert "sarif-2.1.0" in res_sarif.stdout


def test_cli_scan_with_policy_block(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-1",
                "PkgName": "pkg",
                "InstalledVersion": "1.0",
                "Severity": "CRITICAL"
            }]
        }]
    }))
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("""
deployment_policy:
  block:
    severity: [CRITICAL]
  fail_on_policy_violation: true
""")
    result = runner.invoke(app, ["scan", str(report_path), "--policy-file", str(policy_path)])
    assert result.exit_code == 1
    assert "Policy Decision: BLOCK" in result.stdout
