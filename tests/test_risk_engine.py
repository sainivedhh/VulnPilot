from vulnpilot.scanners.models import Vulnerability
from vulnpilot.triage.risk_engine import RiskEngine, WorkloadContext

def test_risk_engine_critical_internet_facing():
    # An 8.0 CVSS vulnerability in a production, internet-facing environment
    vuln = Vulnerability(
        id="CVE-TEST-1",
        package="test-pkg",
        installed_version="1.0",
        severity="HIGH",
        cvss=8.0
    )
    context = WorkloadContext(
        internet_exposed=True, 
        runtime_environment="production"
    )
    
    engine = RiskEngine()
    result = engine.evaluate(vuln, context)
    
    # Base = 80
    # Modifiers = 1.0 + 0.20 (internet) + 0.15 (prod) = 1.35
    # 80 * 1.35 = 108 -> capped at 100
    assert result.score == 100
    assert result.category == "CRITICAL"
    assert "+20% risk due to internet exposure" in result.factors

def test_risk_engine_low_internal():
    # A low severity vulnerability in a development, internal environment
    vuln = Vulnerability(
        id="CVE-TEST-2",
        package="test-pkg",
        installed_version="1.0",
        severity="LOW",
        cvss=3.0
    )
    context = WorkloadContext(
        internet_exposed=False, 
        runtime_environment="development"
    )
    
    engine = RiskEngine()
    result = engine.evaluate(vuln, context)
    
    # Base = 30
    # Modifiers = 1.0 -> 30
    assert result.score == 30
    assert result.category == "LOW"

def test_risk_engine_fallback_severity():
    # Testing when CVSS is missing, falls back to scanner severity
    vuln = Vulnerability(
        id="CVE-TEST-3",
        package="test-pkg",
        installed_version="1.0",
        severity="MEDIUM",
        cvss=None
    )
    context = WorkloadContext()
    
    engine = RiskEngine()
    result = engine.evaluate(vuln, context)
    
    # Base = 50 (from MEDIUM)
    assert result.score == 50
    assert result.category == "MEDIUM"
