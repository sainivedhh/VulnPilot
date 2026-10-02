from fastapi.testclient import TestClient
from vulnpilot.main import api_app
from vulnpilot.api.schemas import ScanRequest, TriageRequest

client = TestClient(api_app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_scan_endpoint():
    request_data = {
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

def test_scan_endpoint_invalid():
    request_data = {
        "trivy_json": "invalid"
    }
    response = client.post("/scan", json=request_data)
    assert response.status_code == 400

def test_triage_endpoint():
    request_data = {
        "cve": "CVE-TEST-1",
        "package": "test-pkg",
        "cvss": 9.0,
        "internet_exposed": True
    }
    response = client.post("/triage", json=request_data)
    assert response.status_code == 200
    assert response.json()["priority"] == "critical"
