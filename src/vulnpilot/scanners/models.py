from typing import Optional

from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    id: str = Field(..., description="Vulnerability ID (e.g., CVE-XXXX-XXXX)")
    package: str = Field(..., description="Package name")
    installed_version: str = Field(..., description="Currently installed version")
    fixed_version: Optional[str] = Field(None, description="Version containing the fix")
    severity: str = Field(..., description="Scanner severity (e.g., HIGH, CRITICAL)")
    cvss: Optional[float] = Field(None, description="CVSS Score")
    title: Optional[str] = Field(None, description="Vulnerability title or short description")
    description: Optional[str] = Field(None, description="Detailed vulnerability description")
