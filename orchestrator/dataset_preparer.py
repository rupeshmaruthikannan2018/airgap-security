"""Dataset Preparer for AirGap Security Platform.

Handles connected-environment acquisition, validation, checksumming,
and local storage of:
1. CISA Known Exploited Vulnerabilities (KEV) Catalog
2. FIRST Exploit Prediction Scoring System (EPSS) Dataset

Provides strict offline validation rules:
- Validates JSON / CSV structure
- Verifies record completeness and required fields
- Records snapshot date, dataset version, record count, and acquisition timestamp
- Saves atomically to prevent partial writes
- Never silently replaces known-good local datasets with invalid updates
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import shutil
import ssl
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import certifi
    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except Exception:
    SSL_CONTEXT = ssl.create_default_context()

logger = logging.getLogger("AirGap.DatasetPreparer")

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

DEFAULT_DATA_DIR = Path(r"C:\airgap-security\data")
DEFAULT_KEV_DIR = DEFAULT_DATA_DIR / "cisa_kev"
DEFAULT_EPSS_DIR = DEFAULT_DATA_DIR / "epss"


# ======================================================================
# 1. Validation Logic
# ======================================================================

def validate_kev_payload(payload: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate CISA KEV JSON payload structure and required fields.
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a JSON object"

    if "title" not in payload and "catalogVersion" not in payload:
        return False, "Missing KEV catalog title or version header"

    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        return False, "Payload missing 'vulnerabilities' array"

    if len(vulns) < 500:
        return False, f"KEV vulnerabilities count abnormally low ({len(vulns)} < 500)"

    # Verify sample records have required attributes
    sample_size = min(50, len(vulns))
    for i in range(sample_size):
        item = vulns[i]
        if not isinstance(item, dict):
            return False, f"Vulnerability item {i} is not a dictionary"
        cve_id = item.get("cveID") or item.get("cve_id")
        if not cve_id or not str(cve_id).upper().startswith("CVE-"):
            return False, f"Item {i} has invalid cveID: {cve_id}"

    return True, f"KEV payload valid: {len(vulns)} records"


def validate_epss_payload(scores_map: Dict[str, Dict[str, Any]], metadata: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate EPSS scores mapping and metadata.
    """
    if not isinstance(scores_map, dict):
        return False, "Scores map must be a dictionary"

    if len(scores_map) < 50000:
        return False, f"EPSS record count abnormally low ({len(scores_map)} < 50,000)"

    if not metadata.get("snapshot_date"):
        return False, "Missing snapshot_date in EPSS metadata"

    # Validate sample items
    for cve, entry in list(scores_map.items())[:50]:
        if not cve.upper().startswith("CVE-"):
            return False, f"Invalid CVE identifier in EPSS: {cve}"
        score = entry.get("score")
        percentile = entry.get("percentile")
        if score is None or not (0.0 <= float(score) <= 1.0):
            return False, f"Invalid EPSS score for {cve}: {score}"
        if percentile is not None and not (0.0 <= float(percentile) <= 1.0):
            return False, f"Invalid EPSS percentile for {cve}: {percentile}"

    return True, f"EPSS payload valid: {len(scores_map)} records"


# ======================================================================
# 2. Acquisition & Storage
# ======================================================================

def acquire_cisa_kev(
    target_dir: Optional[Path] = None,
    feed_url: str = CISA_KEV_FEED_URL,
    timeout: int = 30
) -> Path:
    """
    Acquire, validate, and store CISA KEV dataset into target directory.
    Uses atomic write to prevent corrupting existing datasets.
    """
    target_dir = Path(target_dir or DEFAULT_KEV_DIR)
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / "cisa_kev.json"

    logger.info("Connecting to CISA KEV feed: %s", feed_url)
    req = urllib.request.Request(feed_url, headers={"User-Agent": "AirGap-Security-Preparer/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as response:
        raw_bytes = response.read()

    payload = json.loads(raw_bytes.decode("utf-8"))
    valid, msg = validate_kev_payload(payload)
    if not valid:
        raise ValueError(f"CISA KEV validation failed: {msg}")

    # Build snapshot metadata
    released = payload.get("dateReleased", "")
    snapshot_date = released[:10] if released else datetime.now(timezone.utc).strftime("%Y-%m-%d")
    version = str(payload.get("catalogVersion") or snapshot_date)

    payload["metadata"] = {
        "snapshot_date": snapshot_date,
        "version": version,
        "catalog_version": version,
        "date_released": released,
        "record_count": len(payload.get("vulnerabilities", [])),
        "source_url": feed_url,
        "acquired_at": datetime.now(timezone.utc).isoformat()
    }

    # Atomic write via temporary file
    temp_file = target_dir / f"cisa_kev_temp_{os.getpid()}.json"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    shutil.move(str(temp_file), str(out_file))
    logger.info("CISA KEV saved to %s (%d records, snapshot %s)", out_file, payload["metadata"]["record_count"], snapshot_date)
    return out_file


def acquire_epss(
    target_dir: Optional[Path] = None,
    bulk_url: str = EPSS_BULK_URL,
    timeout: int = 60
) -> Path:
    """
    Acquire, validate, and store FIRST EPSS dataset into target directory.
    Downloads compressed bulk CSV and parses into local JSON dictionary.
    """
    target_dir = Path(target_dir or DEFAULT_EPSS_DIR)
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / "epss.json"

    logger.info("Connecting to EPSS bulk repository: %s", bulk_url)
    req = urllib.request.Request(bulk_url, headers={"User-Agent": "AirGap-Security-Preparer/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as response:
        compressed_bytes = response.read()

    # Save raw gzip file as backup
    raw_gz_path = target_dir / "epss_scores-current.csv.gz"
    with open(raw_gz_path, "wb") as f:
        f.write(compressed_bytes)

    # Decompress and parse
    model_version = "v2023.03.01"
    snapshot_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    with gzip.GzipFile(fileobj=io.BytesIO(compressed_bytes)) as gz:
        header_line = gz.readline().decode("utf-8").strip()
        _ = gz.readline()  # column names header (cve,epss,percentile)

        if header_line.startswith("#"):
            parts = header_line[1:].split(",")
            for p in parts:
                p_clean = p.strip()
                if p_clean.startswith("model_version:"):
                    model_version = p_clean.split(":", 1)[1]
                elif p_clean.startswith("date:"):
                    snapshot_date = p_clean.split(":", 1)[1][:10]

        scores_map: Dict[str, Dict[str, Any]] = {}
        for line_bytes in gz:
            line = line_bytes.decode("utf-8").strip()
            if not line:
                continue
            cols = line.split(",")
            if len(cols) >= 3:
                cve_id = cols[0].strip().upper()
                try:
                    score_val = float(cols[1].strip())
                    pct_val = float(cols[2].strip())
                    scores_map[cve_id] = {
                        "score": score_val,
                        "percentile": pct_val,
                        "date": snapshot_date
                    }
                except ValueError:
                    continue

    metadata = {
        "snapshot_date": snapshot_date,
        "version": model_version,
        "model_version": model_version,
        "record_count": len(scores_map),
        "source_url": bulk_url,
        "acquired_at": datetime.now(timezone.utc).isoformat()
    }

    valid, msg = validate_epss_payload(scores_map, metadata)
    if not valid:
        raise ValueError(f"EPSS validation failed: {msg}")

    payload = {
        "metadata": metadata,
        "scores": scores_map
    }

    temp_file = target_dir / f"epss_temp_{os.getpid()}.json"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    shutil.move(str(temp_file), str(out_file))
    logger.info("EPSS dataset saved to %s (%d records, snapshot %s)", out_file, len(scores_map), snapshot_date)
    return out_file


def main():
    """Command-line runner for preparation environment."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    print("=" * 70)
    print("AIRGAP SECURITY PLATFORM — KEV & EPSS DATASET PREPARER")
    print("=" * 70)

    try:
        kev_path = acquire_cisa_kev()
        print(f"[OK] CISA KEV acquired successfully: {kev_path}")
    except Exception as e:
        print(f"[ERROR] Failed to acquire CISA KEV: {e}")

    try:
        epss_path = acquire_epss()
        print(f"[OK] EPSS dataset acquired successfully: {epss_path}")
    except Exception as e:
        print(f"[ERROR] Failed to acquire EPSS: {e}")


if __name__ == "__main__":
    main()
