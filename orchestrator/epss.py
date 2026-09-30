"""Local FIRST Exploit Prediction Scoring System (EPSS) Data Provider.

Provides fast, offline EPSS score and percentile lookups against locally stored snapshots.

Air-Gap Constraints:
- Zero runtime internet or external API access.
- Exposes snapshot date and model version on every enrichment result.
- Missing EPSS records explicitly return epss_status = "unavailable" and epss_score = None.
- Missing EPSS is NEVER treated as zero.
- Semantics: EPSS is an exploitation likelihood / prioritization signal,
  NOT proof of target-specific exploitability.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("AirGap.Epss")

DEFAULT_EPSS_PATHS = [
    Path(r"C:\airgap-security\data\epss\epss.json"),
    Path(__file__).resolve().parent.parent / "data" / "epss" / "epss.json",
    Path(__file__).resolve().parent / "data" / "epss.json",
]


class EpssDataStore:
    """Offline EPSS data store providing indexed score lookups and metadata tracking."""

    def __init__(
        self,
        data_path: Optional[str | Path] = None,
        max_age_days: int = 90,
        current_time: Optional[datetime] = None
    ):
        self.data_path = self._resolve_path(data_path)
        self.max_age_days = max_age_days
        self._current_time = current_time
        self.snapshot_date: str = "UNKNOWN"
        self.dataset_version: Optional[str] = None
        self.record_count: int = 0
        self._scores: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _resolve_path(self, path: Optional[str | Path]) -> Optional[Path]:
        if path:
            p = Path(path)
            if p.exists():
                return p
        for candidate in DEFAULT_EPSS_PATHS:
            if candidate.exists():
                return candidate
        return Path(path) if path else DEFAULT_EPSS_PATHS[0]

    def _load(self):
        """Load and index EPSS dataset from local JSON file."""
        if not self.data_path or not self.data_path.exists():
            logger.warning("EPSS local file not found at: %s", self.data_path)
            return

        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error("Failed to parse local EPSS file: %s", e)
            return

        meta = data.get("metadata", {})
        self.snapshot_date = meta.get("snapshot_date") or meta.get("date") or "UNKNOWN"
        self.dataset_version = meta.get("version") or meta.get("model_version")

        scores_map = data.get("scores", {})
        if isinstance(scores_map, dict):
            for k, v in scores_map.items():
                clean_id = str(k).strip().upper()
                if isinstance(v, dict):
                    self._scores[clean_id] = v
                elif isinstance(v, (int, float)):
                    self._scores[clean_id] = {"score": float(v), "percentile": None, "date": self.snapshot_date}

        self.record_count = len(self._scores)
        logger.info(
            "Loaded EPSS dataset: %d entries (snapshot: %s, version: %s)",
            self.record_count,
            self.snapshot_date,
            self.dataset_version
        )

    def is_stale(self, max_age_days: Optional[int] = None) -> bool:
        """Check if dataset snapshot exceeds freshness policy."""
        threshold = max_age_days if max_age_days is not None else self.max_age_days
        if not self.snapshot_date or self.snapshot_date == "UNKNOWN":
            return True

        try:
            snap_dt = datetime.strptime(self.snapshot_date, "%Y-%m-%d")
            now = self._current_time or datetime.now(timezone.utc).replace(tzinfo=None)
            age = (now - snap_dt).days
            return age > threshold
        except Exception:
            return False

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Exact lookup by normalized CVE ID."""
        clean_id = str(cve_id).strip().upper()
        return self._scores.get(clean_id)

    def get_enrichment(self, cve_id: str) -> Dict[str, Any]:
        """
        Enrich a CVE with EPSS score and percentile.
        Returns standardized EPSS fields adhering to AirGap platform contracts.
        """
        clean_id = str(cve_id).strip().upper()
        record = self._scores.get(clean_id)
        stale = self.is_stale()

        if record:
            score = record.get("score")
            percentile = record.get("percentile")
            return {
                "epss_score": float(score) if score is not None else None,
                "epss_percentile": float(percentile) if percentile is not None else None,
                "epss_data_date": record.get("date") or self.snapshot_date,
                "epss_dataset_snapshot_date": self.snapshot_date,
                "epss_dataset_version": self.dataset_version,
                "epss_status": "available",
                "epss_data_stale": stale
            }

        return {
            "epss_score": None,
            "epss_percentile": None,
            "epss_data_date": None,
            "epss_dataset_snapshot_date": self.snapshot_date,
            "epss_dataset_version": self.dataset_version,
            "epss_status": "unavailable",
            "epss_data_stale": stale
        }
