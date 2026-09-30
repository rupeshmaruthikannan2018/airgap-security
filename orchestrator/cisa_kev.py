"""Local CISA Known Exploited Vulnerabilities (KEV) Data Provider.

Provides fast, offline lookups against locally stored CISA KEV snapshots.

Air-Gap Constraints:
- Zero runtime internet or external API access.
- Exposes snapshot date and catalog version on every enrichment result.
- Provides configurable dataset staleness detection.
- Semantics: KEV presence indicates active in-the-wild exploitation signal,
  NOT target-specific proof of exploitability. Absence does NOT mean safe.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AirGap.CisaKev")

DEFAULT_KEV_PATHS = [
    Path(r"C:\airgap-security\data\cisa_kev\cisa_kev.json"),
    Path(__file__).resolve().parent.parent / "data" / "cisa_kev" / "cisa_kev.json",
    Path(__file__).resolve().parent / "data" / "cisa_kev.json",
]


class KevDataStore:
    """Offline CISA KEV data store providing indexed lookups and metadata tracking."""

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
        self._by_cve: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _resolve_path(self, path: Optional[str | Path]) -> Optional[Path]:
        if path:
            p = Path(path)
            if p.exists():
                return p
        for candidate in DEFAULT_KEV_PATHS:
            if candidate.exists():
                return candidate
        return Path(path) if path else DEFAULT_KEV_PATHS[0]

    def _load(self):
        """Load and index CISA KEV dataset from local storage."""
        if not self.data_path or not self.data_path.exists():
            logger.warning("CISA KEV local file not found at: %s", self.data_path)
            return

        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error("Failed to parse local CISA KEV file: %s", e)
            return

        meta = data.get("metadata", {})
        self.snapshot_date = (
            meta.get("snapshot_date")
            or str(data.get("dateReleased", ""))[:10]
            or "UNKNOWN"
        )
        self.dataset_version = meta.get("version") or data.get("catalogVersion")

        vulns = data.get("vulnerabilities", [])
        for item in vulns:
            if not isinstance(item, dict):
                continue
            cve_id = item.get("cveID") or item.get("cve_id")
            if cve_id:
                clean_id = str(cve_id).strip().upper()
                self._by_cve[clean_id] = item

        self.record_count = len(self._by_cve)
        logger.info(
            "Loaded CISA KEV dataset: %d entries (snapshot: %s, version: %s)",
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
        return self._by_cve.get(clean_id)

    def get_enrichment(self, cve_id: str) -> Dict[str, Any]:
        """
        Enrich a CVE with CISA KEV metadata.
        Returns standardized KEV fields adhering to AirGap platform contracts.
        """
        clean_id = str(cve_id).strip().upper()
        record = self._by_cve.get(clean_id)
        stale = self.is_stale()

        if record:
            return {
                "kev_listed": True,
                "kev_date_added": record.get("dateAdded"),
                "kev_due_date": record.get("dueDate"),
                "kev_vendor_project": record.get("vendorProject"),
                "kev_product": record.get("product"),
                "kev_vulnerability_name": record.get("vulnerabilityName"),
                "kev_required_action": record.get("requiredAction"),
                "kev_known_ransomware_use": record.get("knownRansomwareCampaignUse"),
                "kev_dataset_snapshot_date": self.snapshot_date,
                "kev_dataset_version": self.dataset_version,
                "kev_data_stale": stale
            }

        return {
            "kev_listed": False,
            "kev_date_added": None,
            "kev_due_date": None,
            "kev_vendor_project": None,
            "kev_product": None,
            "kev_vulnerability_name": None,
            "kev_required_action": None,
            "kev_known_ransomware_use": None,
            "kev_dataset_snapshot_date": self.snapshot_date,
            "kev_dataset_version": self.dataset_version,
            "kev_data_stale": stale
        }
