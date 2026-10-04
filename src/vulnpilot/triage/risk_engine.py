"""
Upgraded deterministic risk engine with KEV, EPSS, fix-availability signals
and a fully configurable scoring formula via YAML.

Every score comes with an ``explanation`` object listing each factor and
how many points it contributed, so humans can audit the result.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator

from vulnpilot.intel.loaders import EpssLoader, KevLoader
from vulnpilot.scanners.models import Vulnerability

# ---------------------------------------------------------------------------
# Configuration schema
# ---------------------------------------------------------------------------

class ScoringWeights(BaseModel):
    base_cvss_weight: float = 10.0
    internet_facing_bonus: int = 20
    production_bonus: int = 15
    kev_bonus: int = 20
    epss_per_tenth: int = 3
    no_fix_bonus: int = 5

    @model_validator(mode="after")
    def _positive_values(self) -> ScoringWeights:
        for field, val in self.__dict__.items():
            if isinstance(val, (int, float)) and val < 0:
                raise ValueError(f"Scoring weight '{field}' must be non-negative, got {val}")
        return self

    @classmethod
    def from_yaml(cls, path: Path) -> ScoringWeights:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(**data.get("scoring", {}))


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------

class ScoreFactor(BaseModel):
    name: str
    points: int
    detail: str


class RiskExplanation(BaseModel):
    factors: list[ScoreFactor] = Field(default_factory=list)
    raw_score: int = 0
    final_score: int = 0
    capped: bool = False


class WorkloadContext(BaseModel):
    internet_exposed: bool = False
    runtime_environment: str = "development"
    contains_sensitive_data: bool = False


class RiskScore(BaseModel):
    score: int
    category: str
    explanation: RiskExplanation
    # Keep backward-compat attribute used in tests / policy evaluator
    factors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RiskEngine:
    """
    Deterministic risk engine.  Scoring formula is fully configurable via YAML.
    Integrates CISA KEV and EPSS exploitability signals.
    """

    def __init__(
        self,
        weights: ScoringWeights | None = None,
        kev: KevLoader | None = None,
        epss: EpssLoader | None = None,
    ) -> None:
        self._weights = weights or ScoringWeights()
        self._kev = kev or KevLoader()
        self._epss = epss or EpssLoader()

    @classmethod
    def from_config(cls, config_path: Path) -> RiskEngine:
        return cls(weights=ScoringWeights.from_yaml(config_path))

    def evaluate(self, vuln: Vulnerability, context: WorkloadContext) -> RiskScore:
        w = self._weights
        raw: int = 0
        ex_factors: list[ScoreFactor] = []
        compat_factors: list[str] = []

        # 1. Base CVSS score
        if vuln.cvss is not None:
            pts = int(vuln.cvss * w.base_cvss_weight)
            ex_factors.append(ScoreFactor(name="cvss", points=pts,
                                          detail=f"CVSS {vuln.cvss} × {w.base_cvss_weight}"))
            compat_factors.append(f"Base score {pts} derived from CVSS ({vuln.cvss})")
        else:
            severity_map = {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
            pts = severity_map.get(vuln.severity.upper(), 10)
            ex_factors.append(ScoreFactor(name="severity_fallback", points=pts,
                                          detail=f"No CVSS; using severity {vuln.severity}"))
            compat_factors.append(f"Base score {pts} derived from scanner severity ({vuln.severity})")
        raw += pts

        # 2. Workload context
        if context.internet_exposed:
            raw += w.internet_facing_bonus
            ex_factors.append(ScoreFactor(name="internet_facing", points=w.internet_facing_bonus,
                                          detail="Workload is internet-facing"))
            compat_factors.append(f"+{w.internet_facing_bonus} risk due to internet exposure")

        if context.runtime_environment == "production":
            raw += w.production_bonus
            ex_factors.append(ScoreFactor(name="production", points=w.production_bonus,
                                          detail="Workload runs in production"))
            compat_factors.append(f"+{w.production_bonus} risk due to production environment")

        if context.contains_sensitive_data:
            raw += w.production_bonus  # reuse same weight for sensitive data
            ex_factors.append(ScoreFactor(name="sensitive_data", points=w.production_bonus,
                                          detail="Workload handles sensitive data"))
            compat_factors.append(f"+{w.production_bonus} risk due to sensitive data exposure")

        # 3. KEV membership
        if self._kev.is_kev(vuln.id):
            raw += w.kev_bonus
            ex_factors.append(ScoreFactor(name="kev", points=w.kev_bonus,
                                          detail="CVE is in CISA Known Exploited Vulnerabilities catalog"))
            compat_factors.append(f"+{w.kev_bonus} CISA KEV: actively exploited in the wild")

        # 4. EPSS score
        epss_val = self._epss.get_score(vuln.id)
        if epss_val > 0.0:
            epss_pts = int(epss_val * 10 * w.epss_per_tenth)
            raw += epss_pts
            ex_factors.append(ScoreFactor(name="epss", points=epss_pts,
                                          detail=f"EPSS {epss_val:.3f} probability of exploitation"))
            compat_factors.append(f"+{epss_pts} EPSS exploitation probability {epss_val:.3f}")

        # 5. No fix available
        if not vuln.fixed_version:
            raw += w.no_fix_bonus
            ex_factors.append(ScoreFactor(name="no_fix", points=w.no_fix_bonus,
                                          detail="No fixed version available yet"))
            compat_factors.append(f"+{w.no_fix_bonus} no fix available")
        else:
            compat_factors.append("A fix is available and should be prioritized")

        # 6. Cap at 100
        capped = raw > 100
        final = min(raw, 100)

        # 7. Category
        if final >= 85:
            category = "CRITICAL"
        elif final >= 70:
            category = "HIGH"
        elif final >= 40:
            category = "MEDIUM"
        else:
            category = "LOW"

        explanation = RiskExplanation(
            factors=ex_factors,
            raw_score=raw,
            final_score=final,
            capped=capped,
        )

        return RiskScore(
            score=final,
            category=category,
            explanation=explanation,
            factors=compat_factors,
        )
