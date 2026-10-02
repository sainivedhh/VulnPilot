from vulnpilot.triage.ai_analyzer import AIAnalyzer
from vulnpilot.api.schemas import TriageRequest

def test_ai_analyzer_fallback_critical():
    analyzer = AIAnalyzer()
    req = TriageRequest(cve="CVE-1", package="pkg", cvss=9.0, internet_exposed=True, fixed_version=None, runtime_context='production')
    res = analyzer.analyze(req)
    assert res.priority == "critical"
    assert res.confidence == 1.0

def test_ai_analyzer_fallback_low():
    analyzer = AIAnalyzer()
    req = TriageRequest(cve="CVE-2", package="pkg", cvss=3.0, internet_exposed=False, fixed_version=None, runtime_context='production')
    res = analyzer.analyze(req)
    assert res.priority == "low"
    assert res.confidence == 1.0

def test_ai_analyzer_fallback_high():
    analyzer = AIAnalyzer()
    req = TriageRequest(cve="CVE-3", package="pkg", cvss=6.0, internet_exposed=False, fixed_version=None, runtime_context='production')
    res = analyzer.analyze(req)
    assert res.priority == "high"
