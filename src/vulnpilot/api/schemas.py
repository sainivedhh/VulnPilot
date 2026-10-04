from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ScanRequest(BaseModel):
    image_name: str
    trivy_json: dict[str, Any]


class TriageRequest(BaseModel):
    cve: str
    cvss: float
    package: str
    fixed_version: str | None
    internet_exposed: bool
    runtime_context: str


class TriageResponse(BaseModel):
    priority: str
    reasoning: str
    recommended_action: str
    confidence: float
