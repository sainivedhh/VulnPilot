"""
Abstract provider interface and implementations for LLM-based triage.
The LLM is ADVISORY ONLY.  Final decisions always come from the deterministic engine.
"""
from __future__ import annotations

import abc
import logging
import os
import time

from pydantic import BaseModel, ValidationError

from vulnpilot.api.schemas import TriageRequest
from vulnpilot.triage.redaction import sanitise_for_llm

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_BASE = 1.0
_REQUEST_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Structured LLM response schema
# ---------------------------------------------------------------------------

class LLMTriageResponse(BaseModel):
    priority: str          # critical | high | medium | low
    rationale: str
    suggested_fix: str
    confidence: float      # 0.0 – 1.0
    source: str = "llm"    # "llm" or "fallback"


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------

class TriageProvider(abc.ABC):
    """Abstract base class for triage providers."""

    @abc.abstractmethod
    def analyse(self, request: TriageRequest) -> LLMTriageResponse:
        ...


# ---------------------------------------------------------------------------
# Deterministic fallback provider
# ---------------------------------------------------------------------------

class FallbackProvider(TriageProvider):
    """
    Deterministic triage provider used when:
    - No LLM API key is configured
    - The LLM is unavailable / times out / returns invalid output
    """

    def analyse(self, request: TriageRequest) -> LLMTriageResponse:
        cvss = request.cvss
        if cvss > 8.5 or (request.internet_exposed and cvss >= 7.0):
            priority = "critical"
        elif cvss >= 7.0:
            priority = "high"
        elif cvss < 4.0:
            priority = "low"
        else:
            priority = "high"

        rationale = (
            f"Deterministic fallback. CVE {request.cve} in '{request.package}' "
            f"has CVSS {cvss}."
        )
        if request.internet_exposed:
            rationale += " High risk due to internet exposure."

        suggested_fix = (
            f"Upgrade {request.package} to {request.fixed_version}."
            if request.fixed_version
            else "No fixed version available. Apply defence-in-depth controls."
        )

        return LLMTriageResponse(
            priority=priority,
            rationale=rationale,
            suggested_fix=suggested_fix,
            confidence=1.0,
            source="fallback",
        )


# ---------------------------------------------------------------------------
# Mock provider (for offline tests — fully deterministic)
# ---------------------------------------------------------------------------

class MockProvider(TriageProvider):
    """Configurable mock provider for unit and evaluation tests."""

    def __init__(self, response: LLMTriageResponse | None = None) -> None:
        self._response = response or LLMTriageResponse(
            priority="high",
            rationale="Mock LLM response",
            suggested_fix="Upgrade the package",
            confidence=0.9,
            source="llm",
        )

    def analyse(self, request: TriageRequest) -> LLMTriageResponse:
        return self._response


# ---------------------------------------------------------------------------
# Real OpenAI provider (with retries, backoff, timeout, circuit breaker)
# ---------------------------------------------------------------------------

class _CircuitBreaker:
    """Simple consecutive-failure circuit breaker."""

    def __init__(self, threshold: int = 3) -> None:
        self._threshold = threshold
        self._failures = 0
        self._open = False

    def record_success(self) -> None:
        self._failures = 0
        self._open = False

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._open = True
            logger.warning("Circuit breaker OPEN after %d failures", self._failures)

    @property
    def is_open(self) -> bool:
        return self._open


_circuit = _CircuitBreaker()


class OpenAIProvider(TriageProvider):
    """
    OpenAI-backed triage provider.
    Falls back to FallbackProvider on timeout, rate limit, invalid JSON,
    or when the circuit breaker is open.
    API key read exclusively from OPENAI_API_KEY env var — never from code.
    """

    def __init__(self) -> None:
        self._api_key = os.getenv("OPENAI_API_KEY", "")
        self._fallback = FallbackProvider()

    def _build_prompt(self, request: TriageRequest) -> str:
        safe = sanitise_for_llm(
            cve_id=request.cve,
            package=request.package,
            description="",
        )
        return (
            "You are a security analyst. Triage the following vulnerability.\n"
            "Return JSON only with keys: priority, rationale, suggested_fix, confidence.\n"
            "priority must be one of: critical, high, medium, low.\n"
            "confidence must be a float between 0 and 1.\n\n"
            "===BEGIN CVE DATA===\n"
            f"CVE ID: {safe['cve_id']}\n"
            f"Package: {safe['package']}\n"
            f"CVSS: {request.cvss}\n"
            f"Internet exposed: {request.internet_exposed}\n"
            f"Fixed version: {request.fixed_version or 'None'}\n"
            "===END CVE DATA==="
        )

    def _call_api(self, prompt: str) -> LLMTriageResponse:
        """Attempt the real OpenAI call.  Import lazily so tests don't need the package."""
        import json as _json  # local import

        try:
            import httpx  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError("httpx is required for OpenAIProvider") from None

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
        }
        resp = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        raw = _json.loads(content)
        return LLMTriageResponse(**raw)

    def analyse(self, request: TriageRequest) -> LLMTriageResponse:
        if not self._api_key:
            logger.info("No OPENAI_API_KEY set; using fallback provider.")
            return self._fallback.analyse(request)

        if _circuit.is_open:
            logger.warning("Circuit breaker is open; using fallback provider.")
            return self._fallback.analyse(request)

        prompt = self._build_prompt(request)
        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                result = self._call_api(prompt)
                _circuit.record_success()
                return result
            except ValidationError as exc:
                logger.error("LLM returned invalid schema on attempt %d: %s", attempt, exc)
                last_exc = exc
                _circuit.record_failure()
                break  # no point retrying schema errors
            except Exception as exc:  # noqa: BLE001
                logger.warning("LLM call failed on attempt %d: %s", attempt, exc)
                last_exc = exc
                _circuit.record_failure()
                if attempt < _MAX_RETRIES:
                    time.sleep(_BACKOFF_BASE * (2 ** (attempt - 1)))

        logger.error("All LLM attempts failed (%s); falling back.", last_exc)
        fb = self._fallback.analyse(request)
        fb.source = "fallback"
        return fb
