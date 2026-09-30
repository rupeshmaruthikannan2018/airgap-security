"""Offline CVE database lookup agent.

Supports high-performance local SQLite CVE databases (schema version 1)
as well as local JSON knowledge files, NVD 2.0 exports, and CVE JSON 5.0
records, making it suitable for air-gapped security operations.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, List, Optional

try:
    from orchestrator.cve_db import CVEDatabase
except ImportError:
    try:
        from cve_db import CVEDatabase
    except ImportError:
        CVEDatabase = None  # type: ignore

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class CVEDatabaseAgent:
    """Search a local CVE database without making network calls."""

    def __init__(self, database_path: str | Path | None = None):
        if database_path:
            self.database_path = Path(database_path)
        elif os.environ.get("CVE_DATABASE_PATH"):
            self.database_path = Path(os.environ["CVE_DATABASE_PATH"])
        else:
            # Check if SQLite database exists in workspace or orchestrator dir
            candidate_sqlite = Path(__file__).with_name("cve_database.db")
            if candidate_sqlite.exists():
                self.database_path = candidate_sqlite
            else:
                self.database_path = Path(__file__).with_name("cve_knowledge.json")

        self._db_instance: Optional[CVEDatabase] = None
        if self._is_sqlite() and CVEDatabase is not None:
            self._db_instance = CVEDatabase(self.database_path)

    def _is_sqlite(self) -> bool:
        """Check if database_path is a SQLite database file."""
        if self.database_path.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            return True
        if self.database_path.is_file() and not self.database_path.suffix.lower().endswith(".json"):
            # Check SQLite header
            try:
                with open(self.database_path, "rb") as f:
                    header = f.read(16)
                    return header.startswith(b"SQLite format 3")
            except OSError:
                return False
        return False

    def lookup(self, cve_id: str, include_rejected: bool = False) -> dict[str, Any] | None:
        """
        Lookup a CVE by ID.
        By default, rejected CVEs are NEVER returned as valid vulnerabilities.
        """
        normalized_id = self._normalize_id(cve_id)
        if not normalized_id:
            raise ValueError("CVE ID must look like CVE-YYYY-NNNN.")

        if self._is_sqlite() and self._db_instance is not None:
            rec = self._db_instance.lookup_cve(normalized_id, include_rejected=include_rejected)
            if not rec:
                return None
            return {
                "cve_id": rec["cve_id"],
                "status": rec.get("status"),
                "is_rejected": rec.get("is_rejected", False),
                "vendor": rec.get("primary_vendor"),
                "product": rec.get("primary_product"),
                "summary": rec.get("summary") or rec.get("description"),
                "description": rec.get("description"),
                "severity": rec.get("primary_severity"),
                "primary_cvss_score": rec.get("primary_cvss_score"),
                "cwe": rec["cwe_ids"][0] if rec.get("cwe_ids") else None,
                "cwes": rec.get("cwes", []),
                "cwe_ids": rec.get("cwe_ids", []),
                "published": rec.get("published_date"),
                "last_modified": rec.get("last_modified_date"),
                "cvss_metrics": rec.get("cvss_metrics", []),
                "cpe_matches": rec.get("cpe_matches", []),
                "configurations": rec.get("configurations", []),
                "affected_versions": rec.get("affected_versions", []),
                "references": rec.get("references", []),
                "sources": rec.get("sources", []),
                "provenance": rec.get("provenance", {}),
                "database_file": str(self.database_path),
            }

        return next((record for record in self._records() if record["cve_id"] == normalized_id), None)

    def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Search CVE records by keyword query."""
        if not query or not query.strip():
            raise ValueError("A CVE ID or search term is required.")

        if self._is_sqlite() and self._db_instance is not None:
            results = self._db_instance.search_cves(query.strip(), limit=limit)
            return [
                {
                    "cve_id": r["cve_id"],
                    "vendor": r.get("primary_vendor"),
                    "product": r.get("primary_product"),
                    "summary": r.get("summary") or r.get("description"),
                    "description": r.get("description"),
                    "severity": r.get("primary_severity"),
                    "cwe": r["cwe_ids"][0] if r.get("cwe_ids") else None,
                    "database_file": str(self.database_path),
                }
                for r in results
            ]

        terms = [term.lower() for term in query.split() if term.strip()]
        matches = []
        for record in self._records():
            indexed = " ".join(str(value) for value in (
                record["cve_id"], record.get("vendor"), record.get("product"),
                record.get("summary"), record.get("severity"), record.get("cwe"),
            ) if value).lower()
            if all(term in indexed for term in terms):
                matches.append(record)
        return matches[:max(1, min(limit, 100))]

    def _records(self) -> list[dict[str, Any]]:
        if not self.database_path.exists():
            raise FileNotFoundError(f"CVE database not found: {self.database_path}")
        files = [self.database_path] if self.database_path.is_file() else sorted(self.database_path.rglob("*.json"))
        records: dict[str, dict[str, Any]] = {}
        for file_path in files:
            try:
                with file_path.open(encoding="utf-8") as database_file:
                    data = json.load(database_file)
            except (OSError, json.JSONDecodeError):
                continue
            for raw in self._extract_raw_records(data):
                record = self._normalize_record(raw, file_path)
                if record:
                    records.setdefault(record["cve_id"], record)
        return list(records.values())

    @staticmethod
    def _extract_raw_records(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            return [item.get("cve", item) for item in data["vulnerabilities"] if isinstance(item, dict)]
        if isinstance(data, dict) and "cveMetadata" in data:
            return [data]
        if isinstance(data, dict):
            return [value for key, value in data.items() if _CVE_ID.match(str(key)) and isinstance(value, dict)]
        return []

    @staticmethod
    def _normalize_record(raw: dict[str, Any], source_file: Path) -> dict[str, Any] | None:
        metadata = raw.get("cveMetadata", {})
        cve_id = CVEDatabaseAgent._normalize_id(str(raw.get("id") or raw.get("cve_id") or metadata.get("cveId") or ""))
        if not cve_id:
            return None
        product_info = raw.get("product", {})
        vulnerability = raw.get("vulnerability", {})
        vendor = product_info.get("vendor") if isinstance(product_info, dict) else None
        product = product_info.get("name") if isinstance(product_info, dict) else None
        summary = vulnerability.get("title") if isinstance(vulnerability, dict) else None
        cwe = vulnerability.get("cwe") if isinstance(vulnerability, dict) else None
        severity = raw.get("severity")
        containers = raw.get("containers", {})
        cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
        if isinstance(cna, dict):
            descriptions, affected = cna.get("descriptions", []), cna.get("affected", [])
            summary = summary or next((item.get("value") for item in descriptions if isinstance(item, dict)), None)
            if affected and isinstance(affected[0], dict):
                vendor, product = vendor or affected[0].get("vendor"), product or affected[0].get("product")
        descriptions = raw.get("descriptions", [])
        if isinstance(descriptions, list):
            summary = summary or next((item.get("value") for item in descriptions if isinstance(item, dict)), None)
        metrics = raw.get("metrics", {})
        if isinstance(metrics, dict) and not severity:
            for metric in metrics.values():
                if isinstance(metric, list) and metric and isinstance(metric[0], dict):
                    severity = metric[0].get("cvssData", {}).get("baseSeverity")
                    if severity:
                        break
        description = raw.get("description") or summary
        return {"cve_id": cve_id, "vendor": vendor, "product": product, "summary": summary,
                "description": description, "severity": severity, "cwe": cwe,
                "affected_versions": raw.get("affected_versions"),
                "fixed_versions": raw.get("fixed_versions"),
                "remediation": raw.get("remediation"),
                "source": raw.get("source"),
                "database_file": str(source_file)}

    @staticmethod
    def _normalize_id(value: str) -> str | None:
        value = value.strip().upper()
        return value if _CVE_ID.match(value) else None
