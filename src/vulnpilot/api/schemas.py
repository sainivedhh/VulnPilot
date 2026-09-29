from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class ScanRequest(BaseModel):
    image_name: str
    trivy_json: Dict[str, Any]

class TriageRequest(BaseModel):
    cve: str
    cvss: float
    package: str
    fixed_version: Optional[str]
    internet_exposed: bool
    runtime_context: str

class TriageResponse(BaseModel):
    priority: str
    reasoning: str
    recommended_action: str
    confidence: float
