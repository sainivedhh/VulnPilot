"""
Redaction module: strips sensitive values before sending data to external LLMs.
"""
from __future__ import annotations

import re

# Patterns that should be redacted from text before external LLM calls
_PATTERNS: list[tuple[str, str]] = [
    # API keys / tokens
    (r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*\S+", "[REDACTED]"),
    # AWS keys
    (r"AKIA[0-9A-Z]{16}", "[REDACTED-AWS-KEY]"),
    # Internal hostnames (simplistic: host.internal, *.local, 10.x, 192.168.x)
    (r"\b(?:[\w-]+\.internal|[\w-]+\.local)\b", "[INTERNAL-HOST]"),
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[PRIVATE-IP]"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "[PRIVATE-IP]"),
    (r"\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", "[PRIVATE-IP]"),
    # Bearer / auth headers
    (r"(?i)bearer\s+[A-Za-z0-9+/=._-]{20,}", "Bearer [REDACTED]"),
    # Generic base64 that looks like a credential (long enough)
    (r"[A-Za-z0-9+/]{40,}={0,2}", "[REDACTED-BASE64]"),
]

_COMPILED = [(re.compile(pat), repl) for pat, repl in _PATTERNS]

# Maximum field lengths to send to LLM
MAX_CVE_DESCRIPTION = 512
MAX_PACKAGE_NAME = 128
MAX_CVE_ID = 32


def redact(text: str) -> str:
    """Apply all redaction patterns to the given text and return sanitised string."""
    for pattern, replacement in _COMPILED:
        text = pattern.sub(replacement, text)
    return text


def sanitise_for_llm(cve_id: str, package: str, description: str) -> dict[str, str]:
    """
    Return a dict of sanitised, length-truncated fields safe to include in an LLM prompt.
    All untrusted input is placed inside delimited data blocks in the prompt builder.
    """
    return {
        "cve_id": redact(cve_id[:MAX_CVE_ID]),
        "package": redact(package[:MAX_PACKAGE_NAME]),
        "description": redact(description[:MAX_CVE_DESCRIPTION]),
    }
