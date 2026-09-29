from pydantic import BaseModel
from typing import List, Optional
from vulnpilot.scanners.models import Vulnerability

class WorkloadContext(BaseModel):
    """
    Context about where and how the container is running.
    """
    internet_exposed: bool = False
    runtime_environment: str = "development"  # e.g., development, staging, production
    contains_sensitive_data: bool = False

class RiskScore(BaseModel):
    """
    The output of the deterministic risk engine.
    """
    score: int
    category: str
    factors: List[str]

class RiskEngine:
    """
    Deterministic risk engine that calculates a normalized risk score (0-100) 
    based on the vulnerability and the workload context.
    """
    def evaluate(self, vuln: Vulnerability, context: WorkloadContext) -> RiskScore:
        factors = []
        
        # 1. Base Score Calculation
        base_score = 0
        if vuln.cvss is not None:
            base_score = vuln.cvss * 10
            factors.append(f"Base score {base_score} derived from CVSS ({vuln.cvss})")
        else:
            severity_map = {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
            base_score = severity_map.get(vuln.severity.upper(), 10)
            factors.append(f"Base score {base_score} derived from scanner severity ({vuln.severity})")
            
        # 2. Context Modifiers
        score_multiplier = 1.0
        
        if context.internet_exposed:
            score_multiplier += 0.20
            factors.append("+20% risk due to internet exposure")
            
        if context.runtime_environment == "production":
            score_multiplier += 0.15
            factors.append("+15% risk due to production environment")
            
        if context.contains_sensitive_data:
            score_multiplier += 0.15
            factors.append("+15% risk due to sensitive data exposure")
            
        if vuln.fixed_version:
            factors.append("A fix is available and should be prioritized")
            
        # 3. Calculate Final Score (Capped at 100)
        final_score = min(int(base_score * score_multiplier), 100)
        
        # 4. Map to Standardized Risk Category
        if final_score >= 85:
            category = "CRITICAL"
        elif final_score >= 70:
            category = "HIGH"
        elif final_score >= 40:
            category = "MEDIUM"
        else:
            category = "LOW"
            
        return RiskScore(
            score=final_score,
            category=category,
            factors=factors
        )
