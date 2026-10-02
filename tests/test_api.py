from __future__ import annotations

import json
from fastapi.testclient import TestClient
from vulnpilot.main import api_app

client = TestClient(api_app)


def test_health_check() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_endpoint_valid() -> None:
    request_data = {
        "image_name": "test-image:1.0",
        "trivy_json": {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-TEST-1",
                            "PkgName": "test-pkg",
                            "InstalledVersion": "1.0",
                            "Severity": "HIGH"
                        }
                    ]
                }
            ]
        }
    }
    response = client.post("/scan", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert data["vulnerabilities_found"] == 1
    assert data["details"][0]["id"] == "CVE-TEST-1"


def test_scan_endpoint_empty_results() -> None:
    request_data = {
        "image_name": "clean-image:1.0",
        "trivy_json": {"Results": []}
    }
    response = client.post("/scan", json=request_data)
    assert response.status_code == 200
    assert response.json()["vulnerabilities_found"] == 0


def test_scan_endpoint_missing_image_name_is_422() -> None:
    """FastAPI validates required fields and returns 422."""
    request_data = {"trivy_json": {"Results": []}}
    response = client.post("/scan", json=request_data)
    assert response.status_code == 422


def test_triage_endpoint_critical() -> None:
    request_data = {
        "cve": "CVE-TEST-1",
        "package": "test-pkg",
        "cvss": 9.0,
        "internet_exposed": True,
        "fixed_version": None,
        "runtime_context": "production",
    }
    response = client.post("/triage", json=request_data)
    assert response.status_code == 200
    assert response.json()["priority"] == "critical"


def test_triage_endpoint_low() -> None:
    request_data = {
        "cve": "CVE-TEST-2",
        "package": "test-pkg",
        "cvss": 2.0,
        "internet_exposed": False,
        "fixed_version": "2.0",
        "runtime_context": "development",
    }
    response = client.post("/triage", json=request_data)
    assert response.status_code == 200
    assert response.json()["priority"] == "low"


def test_triage_endpoint_missing_field_is_422() -> None:
    request_data = {"cve": "CVE-1", "cvss": 9.0}
    response = client.post("/triage", json=request_data)
    assert response.status_code == 422
