from __future__ import annotations

import os
import yaml
import pytest
from pathlib import Path

from vulnpilot.scanners.models import Vulnerability
from vulnpilot.triage.risk_engine import RiskEngine, RiskScore, WorkloadContext
from vulnpilot.policy.evaluator import PolicyEvaluator

DATA_DIR = Path(__file__).parent.parent / "data"


def _make_risk_score(score: int, category: str) -> RiskScore:
    """Use the engine to produce a valid RiskScore (with explanation)."""
    engine = RiskEngine()
    # derive a plausible vuln and eval it, then override score/category
    from vulnpilot.triage.risk_engine import RiskExplanation
    return RiskScore(
        score=score,
        category=category,
        explanation=RiskExplanation(raw_score=score, final_score=score),
        factors=[],
    )


@pytest.fixture
def policy_file(tmp_path: Path) -> str:
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


def test_policy_pass(policy_file: str) -> None:
    evaluator = PolicyEvaluator(policy_file)
    vuln = Vulnerability(id="CVE-1", package="pkg", installed_version="1", severity="LOW")
    risk = _make_risk_score(20, "LOW")
    result = evaluator.evaluate([(vuln, risk)])
    assert result.decision == "PASS"
    assert len(result.violations) == 0


def test_policy_block_critical(policy_file: str) -> None:
    evaluator = PolicyEvaluator(policy_file)
    vuln = Vulnerability(id="CVE-2", package="pkg", installed_version="1", severity="CRITICAL")
    risk = _make_risk_score(95, "CRITICAL")
    result = evaluator.evaluate([(vuln, risk)])
    assert result.decision == "BLOCK"
    assert "CRITICAL" in result.violations[0]


def test_policy_require_fix_for_high(policy_file: str) -> None:
    evaluator = PolicyEvaluator(policy_file)
    vuln1 = Vulnerability(id="CVE-3", package="pkg", installed_version="1",
                          fixed_version="2", severity="HIGH")
    risk1 = _make_risk_score(75, "HIGH")
    result1 = evaluator.evaluate([(vuln1, risk1)])
    assert result1.decision == "BLOCK"
    assert "Fix available" in result1.violations[0]


def test_policy_max_allowed(policy_file: str) -> None:
    evaluator = PolicyEvaluator(policy_file)
    vuln1 = Vulnerability(id="CVE-4", package="pkg", installed_version="1", severity="HIGH")
    risk1 = _make_risk_score(80, "HIGH")
    vuln2 = Vulnerability(id="CVE-5", package="pkg", installed_version="1", severity="HIGH")
    risk2 = _make_risk_score(80, "HIGH")
    result = evaluator.evaluate([(vuln1, risk1), (vuln2, risk2)])
    assert result.decision == "BLOCK"
    assert any("Found 2 HIGH" in v for v in result.violations)


def test_policy_warn_only(tmp_path: Path) -> None:
    policy_content = {
        "deployment_policy": {
            "block": {"severity": []},
            "warn": {"severity": ["MEDIUM"]},
            "fail_on_policy_violation": False,
        }
    }
    pf = tmp_path / "warn.yaml"
    with open(pf, "w") as f:
        yaml.dump(policy_content, f)

    evaluator = PolicyEvaluator(str(pf))
    vuln = Vulnerability(id="CVE-6", package="pkg", installed_version="1", severity="MEDIUM")
    risk = _make_risk_score(50, "MEDIUM")
    result = evaluator.evaluate([(vuln, risk)])
    assert result.decision in ("WARN", "PASS")
