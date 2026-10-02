"""Tests for the upgraded risk engine (A2)."""
from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from vulnpilot.intel.loaders import EpssLoader, KevLoader
from vulnpilot.scanners.models import Vulnerability
from vulnpilot.triage.risk_engine import RiskEngine, RiskScore, ScoringWeights, WorkloadContext

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "data"


@pytest.fixture
def kev() -> KevLoader:
    return KevLoader(path=DATA_DIR / "kev.json")


@pytest.fixture
def epss() -> EpssLoader:
    return EpssLoader(path=DATA_DIR / "epss.json")


@pytest.fixture
def engine(kev: KevLoader, epss: EpssLoader) -> RiskEngine:
    return RiskEngine(kev=kev, epss=epss)


def _vuln(cve: str = "CVE-TEST", cvss: float | None = 8.0,
          severity: str = "HIGH", fixed: str | None = None) -> Vulnerability:
    return Vulnerability(id=cve, package="pkg", installed_version="1.0",
                         severity=severity, cvss=cvss, fixed_version=fixed)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_same_input_same_score(engine: RiskEngine) -> None:
    v = _vuln()
    ctx = WorkloadContext(internet_exposed=True, runtime_environment="production")
    r1 = engine.evaluate(v, ctx)
    r2 = engine.evaluate(v, ctx)
    assert r1.score == r2.score
    assert r1.category == r2.category


# ---------------------------------------------------------------------------
# KEV raises priority
# ---------------------------------------------------------------------------

def test_kev_raises_score(kev: KevLoader, epss: EpssLoader) -> None:
    engine = RiskEngine(kev=kev, epss=epss)
    kev_vuln = _vuln(cve="CVE-2021-44228", cvss=10.0)
    plain_vuln = _vuln(cve="CVE-UNKNOWN-9999", cvss=10.0)
    ctx = WorkloadContext()
    r_kev = engine.evaluate(kev_vuln, ctx)
    r_plain = engine.evaluate(plain_vuln, ctx)
    assert r_kev.score >= r_plain.score
    kev_factor_names = [f.name for f in r_kev.explanation.factors]
    assert "kev" in kev_factor_names


# ---------------------------------------------------------------------------
# Score cap at 100
# ---------------------------------------------------------------------------

def test_score_capped_at_100(engine: RiskEngine) -> None:
    v = _vuln(cve="CVE-2021-44228", cvss=10.0)
    ctx = WorkloadContext(internet_exposed=True, runtime_environment="production",
                         contains_sensitive_data=True)
    r = engine.evaluate(v, ctx)
    assert r.score == 100
    assert r.explanation.capped is True


# ---------------------------------------------------------------------------
# YAML weights take effect
# ---------------------------------------------------------------------------

def test_yaml_weights_applied() -> None:
    w = ScoringWeights(internet_facing_bonus=50)
    engine = RiskEngine(weights=w)
    # Supply a fixed version so no_fix_bonus is consistent in both cases
    v = _vuln(cvss=5.0, fixed="2.0.0")
    ctx_exposed = WorkloadContext(internet_exposed=True)
    ctx_internal = WorkloadContext(internet_exposed=False)
    delta = engine.evaluate(v, ctx_exposed).score - engine.evaluate(v, ctx_internal).score
    assert delta == 50


# ---------------------------------------------------------------------------
# No fix increases risk
# ---------------------------------------------------------------------------

def test_no_fix_adds_points(engine: RiskEngine) -> None:
    v_no_fix = _vuln(cvss=5.0, fixed=None)
    v_with_fix = _vuln(cvss=5.0, fixed="2.0.0")
    ctx = WorkloadContext()
    r_no = engine.evaluate(v_no_fix, ctx)
    r_fix = engine.evaluate(v_with_fix, ctx)
    assert r_no.score > r_fix.score


# ---------------------------------------------------------------------------
# Explanation object
# ---------------------------------------------------------------------------

def test_explanation_object(engine: RiskEngine) -> None:
    v = _vuln(cve="CVE-2021-44228", cvss=10.0)
    ctx = WorkloadContext(internet_exposed=True, runtime_environment="production")
    r = engine.evaluate(v, ctx)
    names = {f.name for f in r.explanation.factors}
    assert "cvss" in names
    assert "internet_facing" in names
    assert "production" in names
    assert "kev" in names
    # All factor points are non-negative
    for factor in r.explanation.factors:
        assert factor.points >= 0


# ---------------------------------------------------------------------------
# Legacy compatibility (factors list kept)
# ---------------------------------------------------------------------------

def test_legacy_factors_list(engine: RiskEngine) -> None:
    v = _vuln(cvss=7.0)
    ctx = WorkloadContext(internet_exposed=True)
    r = engine.evaluate(v, ctx)
    assert isinstance(r.factors, list)
    assert any("internet" in f.lower() for f in r.factors)


# ---------------------------------------------------------------------------
# Low internal dev vulnerability
# ---------------------------------------------------------------------------

def test_low_internal_dev(engine: RiskEngine) -> None:
    v = _vuln(cvss=3.0, severity="LOW")
    ctx = WorkloadContext()
    r = engine.evaluate(v, ctx)
    assert r.score <= 50
    assert r.category in ("LOW", "MEDIUM")


# ---------------------------------------------------------------------------
# Severity fallback (no CVSS)
# ---------------------------------------------------------------------------

def test_severity_fallback(engine: RiskEngine) -> None:
    v = _vuln(cvss=None, severity="MEDIUM")
    ctx = WorkloadContext()
    r = engine.evaluate(v, ctx)
    assert r.score >= 50
    factor_names = [f.name for f in r.explanation.factors]
    assert "severity_fallback" in factor_names


# ---------------------------------------------------------------------------
# Property-based: score always 0-100, monotonic with CVSS
# ---------------------------------------------------------------------------

@given(
    cvss=st.floats(min_value=0.0, max_value=10.0, allow_nan=False),
    internet=st.booleans(),
    prod=st.booleans(),
)
@settings(max_examples=200)
def test_score_bounds_property(cvss: float, internet: bool, prod: bool) -> None:
    engine = RiskEngine()
    v = Vulnerability(id="CVE-H", package="pkg", installed_version="1",
                      severity="LOW", cvss=cvss)
    ctx = WorkloadContext(internet_exposed=internet,
                         runtime_environment="production" if prod else "development")
    r = engine.evaluate(v, ctx)
    assert 0 <= r.score <= 100


@given(
    low_cvss=st.floats(min_value=0.0, max_value=4.9, allow_nan=False),
    high_cvss=st.floats(min_value=5.0, max_value=10.0, allow_nan=False),
)
@settings(max_examples=100)
def test_score_monotonic_cvss(low_cvss: float, high_cvss: float) -> None:
    """Higher CVSS should never produce a lower score (all else equal)."""
    engine = RiskEngine()
    ctx = WorkloadContext()
    v_low = Vulnerability(id="CVE-L", package="pkg", installed_version="1",
                          severity="LOW", cvss=low_cvss)
    v_high = Vulnerability(id="CVE-H", package="pkg", installed_version="1",
                           severity="HIGH", cvss=high_cvss)
    r_low = engine.evaluate(v_low, ctx)
    r_high = engine.evaluate(v_high, ctx)
    assert r_high.score >= r_low.score
