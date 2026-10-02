import os

from vulnpilot.api.schemas import TriageRequest, TriageResponse


class AIAnalyzer:
    """
    AI-Assisted Vulnerability Triage.
    Provides structured analysis of a vulnerability.
    Falls back to deterministic risk scoring if the API is unavailable.
    """
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")

    def analyze(self, request: TriageRequest) -> TriageResponse:
        # If no API key is configured or API is unreachable, use fallback logic
        if not self.api_key:
            return self._deterministic_fallback(request)
            
        # In a real implementation, this would call an LLM API (e.g. OpenAI)
        # and validate the response using Pydantic.
        return self._deterministic_fallback(request)

    def _deterministic_fallback(self, request: TriageRequest) -> TriageResponse:
        priority = "high"
        if request.cvss > 8.5 or (request.internet_exposed and request.cvss >= 7.0):
            priority = "critical"
        elif request.cvss < 4.0:
            priority = "low"
            
        reasoning = f"Deterministic fallback triggered. Vulnerability {request.cve} in package '{request.package}' has a CVSS of {request.cvss}."
        if request.internet_exposed:
            reasoning += " High risk due to internet exposure."
            
        action = f"Upgrade {request.package} to version {request.fixed_version} before deployment." if request.fixed_version else "Monitor and apply defense-in-depth."
        
        return TriageResponse(
            priority=priority,
            reasoning=reasoning,
            recommended_action=action,
            confidence=1.0  # Deterministic logic has 1.0 confidence
        )
