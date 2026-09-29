import yaml
from pydantic import BaseModel
from typing import List, Tuple
from vulnpilot.scanners.models import Vulnerability
from vulnpilot.triage.risk_engine import RiskScore

class PolicyResult(BaseModel):
    decision: str  # PASS, WARN, BLOCK
    reason: str
    violations: List[str]

class PolicyEvaluator:
    def __init__(self, policy_path: str):
        with open(policy_path, 'r', encoding='utf-8') as f:
            self.policy_data = yaml.safe_load(f)
            
    def evaluate(self, findings: List[Tuple[Vulnerability, RiskScore]]) -> PolicyResult:
        deployment_policy = self.policy_data.get('deployment_policy', {})
        block_severities = deployment_policy.get('block', {}).get('severity', [])
        warn_severities = deployment_policy.get('warn', {}).get('severity', [])
        require_fix_for = deployment_policy.get('require_fix_for', [])
        
        violations = []
        warnings = []
        
        for vuln, risk in findings:
            # Check explicit block list by severity
            if risk.category in block_severities:
                violations.append(f"[{vuln.id}] Blocked: Risk category {risk.category} is explicitly blocked.")
                continue
                
            # Check if a fix is available and required for this severity
            if risk.category in require_fix_for and vuln.fixed_version:
                violations.append(f"[{vuln.id}] Blocked: Fix available ({vuln.fixed_version}) for {risk.category} risk.")
                continue
                
            # Check warn severities
            if risk.category in warn_severities:
                warnings.append(f"[{vuln.id}] Warning: Risk category {risk.category} triggers a warning.")
                
        # Check aggregate thresholds (e.g., max HIGH allowed)
        high_max = deployment_policy.get('high', {}).get('maximum_allowed')
        if high_max is not None:
            high_count = sum(1 for _, risk in findings if risk.category == "HIGH")
            if high_count > high_max:
                violations.append(f"Blocked: Found {high_count} HIGH risk vulnerabilities, maximum allowed is {high_max}.")

        # Determine final decision
        fail_on_violation = deployment_policy.get('fail_on_policy_violation', True)
        
        if violations:
            if fail_on_violation:
                return PolicyResult(
                    decision="BLOCK", 
                    reason="Pipeline blocked due to security policy violations.", 
                    violations=violations
                )
            else:
                return PolicyResult(
                    decision="WARN", 
                    reason="Violations detected, but 'fail_on_policy_violation' is false.", 
                    violations=violations + warnings
                )
                
        if warnings:
            return PolicyResult(
                decision="WARN", 
                reason="Pipeline passed with security warnings.", 
                violations=warnings
            )
            
        return PolicyResult(
            decision="PASS", 
            reason="All security policies passed.", 
            violations=[]
        )
