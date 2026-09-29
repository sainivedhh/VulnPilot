import os
import yaml
import pytest
from pathlib import Path
from vulnpilot.scanners.models import Vulnerability
from vulnpilot.triage.risk_engine import RiskScore
from vulnpilot.policy.evaluator import PolicyEvaluator

@pytest.fixture
def policy_file(tmp_path):
    policy_content = {
        "deployment_policy": {
            "block": {"severity": ["CRITICAL"]},
            "warn": {"severity": ["MEDIUM"]},
            "high": {"maximum_allowed": 1},
            "require_fix_for": ["HIGH"],
            "fail_on_policy_violation": True
        }
    }
    file_path = tmp_path / "test-policy.yaml"
    with open(file_path, "w") as f:
        yaml.dump(policy_content, f)
    return str(file_path)

def test_policy_pass(policy_file):
    evaluator = PolicyEvaluator(policy_file)
    vuln = Vulnerability(id="CVE-1", package="pkg", installed_version="1", severity="LOW")
    risk = RiskScore(score=20, category="LOW", factors=[])
    
    result = evaluator.evaluate([(vuln, risk)])
    assert result.decision == "PASS"
    assert len(result.violations) == 0

def test_policy_block_critical(policy_file):
    evaluator = PolicyEvaluator(policy_file)
    vuln = Vulnerability(id="CVE-2", package="pkg", installed_version="1", severity="CRITICAL")
    risk = RiskScore(score=95, category="CRITICAL", factors=[])
    
    result = evaluator.evaluate([(vuln, risk)])
    assert result.decision == "BLOCK"
    assert "CRITICAL" in result.violations[0]

def test_policy_require_fix_for_high(policy_file):
    evaluator = PolicyEvaluator(policy_file)
    
    # Has fix -> Should block
    vuln1 = Vulnerability(id="CVE-3", package="pkg", installed_version="1", fixed_version="2", severity="HIGH")
    risk1 = RiskScore(score=75, category="HIGH", factors=[])
    
    result1 = evaluator.evaluate([(vuln1, risk1)])
    assert result1.decision == "BLOCK"
    assert "Fix available" in result1.violations[0]

def test_policy_max_allowed(policy_file):
    evaluator = PolicyEvaluator(policy_file)
    
    # 2 HIGHs with no fixes. Max allowed is 1. -> Should block
    vuln1 = Vulnerability(id="CVE-4", package="pkg", installed_version="1", severity="HIGH")
    risk1 = RiskScore(score=80, category="HIGH", factors=[])
    
    vuln2 = Vulnerability(id="CVE-5", package="pkg", installed_version="1", severity="HIGH")
    risk2 = RiskScore(score=80, category="HIGH", factors=[])
    
    result = evaluator.evaluate([(vuln1, risk1), (vuln2, risk2)])
    assert result.decision == "BLOCK"
    assert any("Found 2 HIGH" in v for v in result.violations)
