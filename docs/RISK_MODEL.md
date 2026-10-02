"""
RISK_MODEL — Scoring Formula Documentation
==========================================

## Overview

VulnPilot uses a **fully deterministic, additive scoring formula** to produce a
risk score in the range **0–100** for every vulnerability.  The formula is
configurable via `policies/scoring.yaml`.  Every score includes an
`explanation` object that lists each contributing factor and its point value,
making the result fully auditable.

## Formula

```
raw_score = base_cvss_score
          + internet_facing_bonus       (if workload is internet-exposed)
          + production_bonus            (if runtime_environment == "production")
          + sensitive_data_bonus        (if workload contains sensitive data)
          + kev_bonus                   (if CVE is in CISA KEV catalog)
          + epss_bonus                  (epss_score × 10 × epss_per_tenth)
          + no_fix_bonus                (if no fixed version available)

final_score = min(raw_score, 100)
```

### Base CVSS Score
If a CVSS score is present: `base = cvss × base_cvss_weight` (default weight: 10).
If no CVSS is present, a severity map is used:
- CRITICAL → 90 pts
- HIGH → 75 pts
- MEDIUM → 50 pts
- LOW → 25 pts

### Default Weights (policies/scoring.yaml)

| Factor              | Default Points | Condition                                  |
|---------------------|----------------|--------------------------------------------|
| base_cvss_weight    | 10 (multiplier)| Applied to CVSS float (0–10)               |
| internet_facing     | +20            | WorkloadContext.internet_exposed = True     |
| production          | +15            | WorkloadContext.runtime_environment = prod  |
| kev                 | +20            | CVE in CISA KEV catalog                    |
| epss_per_tenth      | +3 per 0.1     | EPSS score × 10 × 3                        |
| no_fix              | +5             | vuln.fixed_version is None                 |

### Score → Category Mapping

| Score Range | Category |
|-------------|----------|
| 85 – 100    | CRITICAL |
| 70 – 84     | HIGH     |
| 40 – 69     | MEDIUM   |
| 0 – 39      | LOW      |

## Worked Example

**Vulnerability:** CVE-2021-44228 (Log4Shell)
- CVSS: 10.0
- In KEV: Yes
- EPSS: 0.975
- Fixed version: 2.17.0 (available)
- Context: internet-facing, production

| Factor          | Points |
|-----------------|--------|
| CVSS 10 × 10    | 100    |
| Internet-facing | +20    |
| Production      | +15    |
| KEV             | +20    |
| EPSS 0.975 → ≈29| +29   |
| Fix available   | +0     |
| **Raw total**   | **184**|
| **Capped**      | **100**|

**Result:** Score = 100 / CRITICAL, capped = True

## Offline Operation

KEV and EPSS data are loaded from `data/kev.json` and `data/epss.json`.
Run `vulnpilot update-intel` to refresh them (requires network).
Tests use the bundled sample files and never require network access.

## Configuring Weights

Create or modify `policies/scoring.yaml`:

```yaml
scoring:
  base_cvss_weight: 10.0
  internet_facing_bonus: 25    # Raise for high-exposure environments
  production_bonus: 10
  kev_bonus: 30                # Raise to treat KEV as near-critical
  epss_per_tenth: 2
  no_fix_bonus: 10
```

Pass it via CLI: `vulnpilot scan report.json --scoring-config policies/scoring.yaml`
"""
