"""
Intel loader: reads locally cached KEV and EPSS JSON files.
Use `vulnpilot update-intel` to refresh them.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Default data directory (repository root / data)
_DATA_DIR = Path(__file__).parent.parent.parent.parent.parent / "data"


def _data_dir() -> Path:
    """Return the resolved data directory, falling back gracefully."""
    return _DATA_DIR if _DATA_DIR.is_dir() else Path("data")


class KevLoader:
    """Load the CISA Known Exploited Vulnerabilities catalog from a local JSON file."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _data_dir() / "kev.json"
        self._cves: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            logger.warning("KEV file not found at %s – KEV signals disabled.", self._path)
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            self._cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
            logger.debug("Loaded %d KEV entries from %s", len(self._cves), self._path)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load KEV data: %s", exc)

    def is_kev(self, cve_id: str) -> bool:
        """Return True if this CVE is in the CISA KEV catalog."""
        return cve_id.upper() in self._cves


class EpssLoader:
    """Load EPSS scores from a local JSON file."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _data_dir() / "epss.json"
        self._scores: dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            logger.warning("EPSS file not found at %s – EPSS signals disabled.", self._path)
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            self._scores = {
                entry["cve"].upper(): float(entry["epss"])
                for entry in data.get("scores", [])
            }
            logger.debug("Loaded %d EPSS scores from %s", len(self._scores), self._path)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load EPSS data: %s", exc)

    def get_score(self, cve_id: str) -> float:
        """Return the EPSS probability (0-1) for a CVE, or 0.0 if unknown."""
        return self._scores.get(cve_id.upper(), 0.0)
