from __future__ import annotations

import httpx
import pytest
from unittest.mock import patch, MagicMock

from vulnpilot.api.schemas import TriageRequest
from vulnpilot.triage.providers import OpenAIProvider


def _req() -> TriageRequest:
    return TriageRequest(
        cve="CVE-TEST-1",
        package="test-pkg",
        cvss=7.0,
        internet_exposed=False,
        fixed_version="2.0",
        runtime_context="production",
    )


@patch.dict("os.environ", {"OPENAI_API_KEY": "fake-key"})
@patch("httpx.post")
def test_openai_provider_success(mock_post) -> None:
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "choices": [{
            "message": {
                "content": '{"priority": "high", "rationale": "test", "suggested_fix": "update", "confidence": 0.9}'
            }
        }]
    }
    mock_post.return_value = mock_resp

    provider = OpenAIProvider()
    res = provider.analyse(_req())
    assert res.priority == "high"


@patch.dict("os.environ", {"OPENAI_API_KEY": "fake-key"})
@patch("httpx.post")
def test_openai_provider_fallback_on_invalid_json(mock_post) -> None:
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "choices": [{
            "message": {
                "content": '{"invalid": "schema"}'
            }
        }]
    }
    mock_post.return_value = mock_resp

    provider = OpenAIProvider()
    res = provider.analyse(_req())
    # Should fall back to FallbackProvider due to Pydantic ValidationError
    assert res.source == "fallback"


@patch.dict("os.environ", {"OPENAI_API_KEY": "fake-key"})
@patch("httpx.post")
def test_openai_provider_fallback_on_network_error(mock_post) -> None:
    mock_post.side_effect = httpx.ConnectError("timeout")

    provider = OpenAIProvider()
    res = provider.analyse(_req())
    assert res.source == "fallback"
