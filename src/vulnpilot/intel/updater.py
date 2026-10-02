"""
update_intel: CLI command to refresh KEV and EPSS data from upstream.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?limit=100000"

DEFAULT_TIMEOUT = 30


def _data_dir() -> Path:
    d = Path("data")
    d.mkdir(exist_ok=True)
    return d


def update_kev(output: Optional[Path] = None, timeout: int = DEFAULT_TIMEOUT) -> bool:
    dest = output or _data_dir() / "kev.json"
    try:
        resp = httpx.get(KEV_URL, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(resp.json(), f, indent=2)
        logger.info("KEV data updated at %s (%d bytes)", dest, len(resp.content))
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to update KEV: %s", exc)
        return False


def update_epss(output: Optional[Path] = None, timeout: int = DEFAULT_TIMEOUT) -> bool:
    dest = output or _data_dir() / "epss.json"
    try:
        resp = httpx.get(EPSS_URL, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        # Normalize to a consistent local format
        payload = {"model_version": data.get("version", "unknown"),
                   "score_date": data.get("score_date", ""),
                   "scores": [{"cve": s["cve"], "epss": s["epss"], "percentile": s.get("percentile", 0)}
                               for s in data.get("data", [])]}
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        logger.info("EPSS data updated at %s (%d entries)", dest, len(payload["scores"]))
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to update EPSS: %s", exc)
        return False
