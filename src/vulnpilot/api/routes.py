from fastapi import APIRouter, HTTPException
from .schemas import ScanRequest, TriageRequest, TriageResponse
from vulnpilot.scanners.trivy import TrivyParser
from vulnpilot.triage.risk_engine import RiskEngine, WorkloadContext
from vulnpilot.policy.evaluator import PolicyEvaluator
from vulnpilot.triage.ai_analyzer import AIAnalyzer

router = APIRouter()

@router.get("/health")
def health_check():
    return {"status": "ok"}

@router.post("/scan")
def scan_image(request: ScanRequest):
    parser = TrivyParser()
    try:
        vulns = parser.parse_dict(request.trivy_json)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"vulnerabilities_found": len(vulns), "details": vulns}

@router.post("/triage", response_model=TriageResponse)
def triage_vuln(request: TriageRequest):
    analyzer = AIAnalyzer()
    return analyzer.analyze(request)
