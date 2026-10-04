"""
AI Analyzer — thin wrapper that delegates to the configured TriageProvider.
Backward-compatible with the original API used by routes.py.
"""
from __future__ import annotations

from vulnpilot.api.schemas import TriageRequest, TriageResponse
from vulnpilot.triage.providers import OpenAIProvider, TriageProvider


class AIAnalyzer:
    """
    AI-Assisted Vulnerability Triage.
    Delegates to the configured provider.  Defaults to OpenAIProvider which
    falls back to FallbackProvider automatically when no API key is present.
    The final pipeline pass/fail decision ALWAYS comes from the deterministic
    RiskEngine and PolicyEvaluator — never from this layer.
    """

    def __init__(self, provider: TriageProvider | None = None) -> None:
        self._provider: TriageProvider = provider or OpenAIProvider()

    def analyze(self, request: TriageRequest) -> TriageResponse:
        result = self._provider.analyse(request)
        return TriageResponse(
            priority=result.priority,
            reasoning=result.rationale,
            recommended_action=result.suggested_fix,
            confidence=result.confidence,
        )
