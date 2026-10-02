from typer.testing import CliRunner
from vulnpilot.main import app
import os
import json

runner = CliRunner()

def test_cli_scan(tmp_path):
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

def test_cli_scan_file_not_found():
    result = runner.invoke(app, ["scan", "doesnt_exist.json"])
    assert result.exit_code == 1
    assert "does not exist" in result.stdout
