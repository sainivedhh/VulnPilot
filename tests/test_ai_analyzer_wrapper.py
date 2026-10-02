from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from vulnpilot.api.schemas import TriageRequest
from vulnpilot.triage.ai_analyzer import AIAnalyzer
from vulnpilot.triage.providers import FallbackProvider, OpenAIProvider


def _req() -> TriageRequest:
    return TriageRequest(
        cve="CVE-TEST-1",
        package="test-pkg",
        cvss=7.0,
        internet_exposed=False,
        fixed_version="2.0",
        runtime_context="production",
    )


def test_ai_analyzer_uses_fallback_without_key() -> None:
    """If no API key is provided, the analyzer defaults to OpenAIProvider, which internally delegates to FallbackProvider."""
    with patch.dict("os.environ", {"OPENAI_API_KEY": ""}, clear=True):
        analyzer = AIAnalyzer()
        res = analyzer.analyze(_req())
        assert res.priority == "high"


def test_ai_analyzer_can_take_explicit_provider() -> None:
    analyzer = AIAnalyzer(provider=FallbackProvider())
    res = analyzer.analyze(_req())
    assert res.priority == "high"
