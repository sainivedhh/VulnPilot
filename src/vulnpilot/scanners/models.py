from __future__ import annotations

from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    id: str = Field(..., description="Vulnerability ID (e.g., CVE-XXXX-XXXX)")
    package: str = Field(..., description="Package name")
    installed_version: str = Field(..., description="Currently installed version")
    fixed_version: str | None = Field(None, description="Version containing the fix")
    severity: str = Field(..., description="Scanner severity (e.g., HIGH, CRITICAL)")
    cvss: float | None = Field(None, description="CVSS Score")
    title: str | None = Field(None, description="Vulnerability title or short description")
    description: str | None = Field(None, description="Detailed vulnerability description")
