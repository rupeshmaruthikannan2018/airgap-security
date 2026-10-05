"""Canonical SQLite Database Schema and Engine for Local/Air-Gapped CVE Foundation.

Schema Version: 1
Database Version: 2.0.0

Supports:
- Master canonical CVE metadata with field-level provenance
- Separate raw source records from NVD 2.0 and CVE List V5
- Preserved NVD configuration node trees (AND/OR, negate, nested hierarchy)
- Structured CPE 2.3 components (part, vendor, product, version, update, etc.)
- Multi-CVSS metric preservation (CVSS 2.0, 3.0, 3.1, 4.0, primary/secondary)
- Affected version ranges from CVE List V5
- Strict rejection enforcement (rejected records marked and excluded from normal lookups)
- Schema versioning and migration readiness
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCHEMA_VERSION = 1
DATABASE_VERSION = "2.0.0"


class CVEDatabase:
    """Manages the local SQLite CVE database, migrations, and structured queries."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self.init_schema()

    def connect(self) -> sqlite3.Connection:
        """Establish or reuse a connection with foreign keys and WAL mode."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("PRAGMA journal_mode = WAL;")
            self._conn.execute("PRAGMA synchronous = NORMAL;")
        return self._conn

    def close(self):
        """Close the database connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ------------------------------------------------------------------
    # Schema Definition & Migrations
    # ------------------------------------------------------------------

    def init_schema(self):
        """Initialize all canonical schema tables, constraints, and indexes."""
        conn = self.connect()
        with conn:
            # 1. Metadata Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS db_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 2. Master Canonical CVEs Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    is_rejected INTEGER NOT NULL DEFAULT 0,
                    description TEXT,
                    summary TEXT,
                    published_date TEXT,
                    last_modified_date TEXT,
                    primary_vendor TEXT,
                    primary_product TEXT,
                    primary_severity TEXT,
                    primary_cvss_score REAL,
                    cwe_ids TEXT, -- JSON array of CWE strings
                    has_cpe_config INTEGER NOT NULL DEFAULT 0,
                    sources TEXT NOT NULL, -- JSON array of sources (e.g. ["NVD", "CVE_LIST_V5"])
                    provenance TEXT NOT NULL, -- JSON object tracking source per field
                    raw_record_reference TEXT,
                    import_timestamp TEXT NOT NULL
                )
            """)

            # 3. Raw Source Records Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS source_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    source TEXT NOT NULL, -- 'NVD' or 'CVE_LIST_V5'
                    source_record_version TEXT,
                    vuln_status TEXT,
                    raw_json TEXT NOT NULL,
                    source_file TEXT,
                    import_timestamp TEXT NOT NULL,
                    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
                    UNIQUE(cve_id, source)
                )
            """)

            # 4. CVSS Metrics Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cvss_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    cvss_version TEXT NOT NULL, -- '2.0', '3.0', '3.1', '4.0'
                    vector_string TEXT,
                    base_score REAL,
                    base_severity TEXT,
                    metric_type TEXT, -- 'Primary' or 'Secondary'
                    exploitability_score REAL,
                    impact_score REAL,
                    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
                )
            """)

            # 5. Configuration Nodes Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_configurations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    config_index INTEGER NOT NULL,
                    operator TEXT NOT NULL, -- 'AND', 'OR'
                    negate INTEGER NOT NULL DEFAULT 0,
                    parent_node_id INTEGER,
                    node_type TEXT,
                    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
                    FOREIGN KEY(parent_node_id) REFERENCES cve_configurations(id) ON DELETE CASCADE
                )
            """)

            # 6. CPE Matches & Structured Ranges Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cpe_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    config_node_id INTEGER,
                    criteria TEXT NOT NULL,
                    match_criteria_id TEXT,
                    vulnerable INTEGER NOT NULL DEFAULT 1,
                    part TEXT,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    update_version TEXT,
                    edition TEXT,
                    language TEXT,
                    sw_edition TEXT,
                    target_sw TEXT,
                    target_hw TEXT,
                    other TEXT,
                    version_start_including TEXT,
                    version_start_excluding TEXT,
                    version_end_including TEXT,
                    version_end_excluding TEXT,
                    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
                    FOREIGN KEY(config_node_id) REFERENCES cve_configurations(id) ON DELETE CASCADE
                )
            """)

            # 7. Affected Versions Table (CNA statements)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_affected_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    vendor TEXT,
                    product TEXT,
                    package_url TEXT,
                    repo_url TEXT,
                    modules TEXT, -- JSON array
                    platforms TEXT, -- JSON array
                    version_value TEXT,
                    version_status TEXT, -- 'affected', 'unaffected'
                    version_type TEXT, -- 'semver', 'git', 'custom'
                    less_than TEXT,
                    less_than_or_equal TEXT,
                    default_status TEXT,
                    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
                )
            """)

            # 8. CWEs Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cwes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    source TEXT,
                    cwe_id TEXT NOT NULL,
                    description TEXT,
                    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
                )
            """)

            # 9. References Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_references (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    source TEXT,
                    url TEXT NOT NULL,
                    source_identifier TEXT,
                    tags TEXT, -- JSON array
                    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
                )
            """)

            # Indexes for optimal query performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_rejected ON cves(is_rejected)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_vendor_product ON cves(primary_vendor, primary_product)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(primary_severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source_records_cve ON source_records(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cvss_cve ON cve_cvss_metrics(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cve_cpe_matches(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cve_cpe_matches(vendor, product)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpe_vulnerable ON cve_cpe_matches(vulnerable)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_affected_cve ON cve_affected_versions(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_affected_vendor_prod ON cve_affected_versions(vendor, product)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cwes_cve ON cve_cwes(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cwes_cwe_id ON cve_cwes(cwe_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_refs_cve ON cve_references(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_config_cve ON cve_configurations(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_config_parent ON cve_configurations(parent_node_id)")

            # Initial metadata
            conn.execute("""
                INSERT OR IGNORE INTO db_metadata (key, value) VALUES ('schema_version', ?)
            """, (str(SCHEMA_VERSION),))
            conn.execute("""
                INSERT OR IGNORE INTO db_metadata (key, value) VALUES ('database_version', ?)
            """, (DATABASE_VERSION,))

    def migrate_schema(self):
        """Execute migrations if database schema version is behind target."""
        conn = self.connect()
        current = self.get_metadata("schema_version")
        current_v = int(current) if current and current.isdigit() else 0
        if current_v < SCHEMA_VERSION:
            self.set_metadata("schema_version", str(SCHEMA_VERSION))

    def get_metadata(self, key: Optional[str] = None) -> Any:
        conn = self.connect()
        if key:
            row = conn.execute("SELECT value FROM db_metadata WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None
        else:
            rows = conn.execute("SELECT key, value FROM db_metadata").fetchall()
            return {row["key"]: row["value"] for row in rows}

    def set_metadata(self, key: str, value: str):
        conn = self.connect()
        with conn:
            conn.execute("""
                INSERT INTO db_metadata (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
            """, (key, str(value)))

    def get_counts(self) -> Dict[str, int]:
        """Compute database record count statistics."""
        conn = self.connect()
        total_cves = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        rejected_cves = conn.execute("SELECT COUNT(*) FROM cves WHERE is_rejected = 1").fetchone()[0]
        active_cves = total_cves - rejected_cves
        no_cpe_count = conn.execute("SELECT COUNT(*) FROM cves WHERE has_cpe_config = 0 AND is_rejected = 0").fetchone()[0]
        nvd_record_count = conn.execute("SELECT COUNT(*) FROM source_records WHERE source = 'NVD'").fetchone()[0]
        cve_list_record_count = conn.execute("SELECT COUNT(*) FROM source_records WHERE source = 'CVE_LIST_V5'").fetchone()[0]
        linked_cve_count = conn.execute("""
            SELECT COUNT(DISTINCT cve_id) FROM (
                SELECT cve_id FROM source_records GROUP BY cve_id HAVING COUNT(DISTINCT source) > 1
            )
        """).fetchone()[0]
        return {
            "total_cves": total_cves,
            "active_cves": active_cves,
            "rejected_cves": rejected_cves,
            "no_cpe_count": no_cpe_count,
            "nvd_record_count": nvd_record_count,
            "cve_list_record_count": cve_list_record_count,
            "linked_cve_count": linked_cve_count,
        }

    def get_detailed_counts(self) -> Dict[str, int]:
        """Compute complete database statistics for production import verification."""
        conn = self.connect()
        counts = self.get_counts()
        counts["cves_with_cpe"] = conn.execute("SELECT COUNT(*) FROM cves WHERE has_cpe_config = 1").fetchone()[0]
        counts["cves_with_affected_versions"] = conn.execute(
            "SELECT COUNT(DISTINCT cve_id) FROM cve_affected_versions"
        ).fetchone()[0]
        counts["cves_with_cvss"] = conn.execute(
            "SELECT COUNT(DISTINCT cve_id) FROM cve_cvss_metrics"
        ).fetchone()[0]
        counts["cves_with_cwe"] = conn.execute(
            "SELECT COUNT(DISTINCT cve_id) FROM cve_cwes"
        ).fetchone()[0]
        counts["cves_with_references"] = conn.execute(
            "SELECT COUNT(DISTINCT cve_id) FROM cve_references"
        ).fetchone()[0]
        return counts

    # ------------------------------------------------------------------
    # Query & Lookup API (Air-Gapped, Offline)
    # ------------------------------------------------------------------

    def lookup_cve(self, cve_id: str, include_rejected: bool = False) -> Optional[Dict[str, Any]]:
        """
        Lookup a CVE by ID.
        By requirement A10: Rejected CVEs must never be returned by normal
        CVE lookups as valid vulnerabilities (unless explicitly requested).
        """
        conn = self.connect()
        normalized_id = cve_id.strip().upper()

        row = conn.execute("""
            SELECT * FROM cves WHERE cve_id = ?
        """, (normalized_id,)).fetchone()

        if not row:
            return None

        is_rejected = bool(row["is_rejected"])
        if is_rejected and not include_rejected:
            return None

        record = dict(row)
        record["is_rejected"] = is_rejected
        record["has_cpe_config"] = bool(row["has_cpe_config"])
        record["cwe_ids"] = json.loads(row["cwe_ids"]) if row["cwe_ids"] else []
        record["sources"] = json.loads(row["sources"]) if row["sources"] else []
        record["provenance"] = json.loads(row["provenance"]) if row["provenance"] else {}

        # Fetch CVSS metrics
        cvss_rows = conn.execute("""
            SELECT source, cvss_version, vector_string, base_score, base_severity,
                   metric_type, exploitability_score, impact_score
            FROM cve_cvss_metrics WHERE cve_id = ?
            ORDER BY cvss_version DESC, base_score DESC
        """, (normalized_id,)).fetchall()
        record["cvss_metrics"] = [dict(r) for r in cvss_rows]

        # Fetch CWEs
        cwe_rows = conn.execute("""
            SELECT source, cwe_id, description FROM cve_cwes WHERE cve_id = ?
        """, (normalized_id,)).fetchall()
        record["cwes"] = [dict(r) for r in cwe_rows]

        # Fetch References
        ref_rows = conn.execute("""
            SELECT source, url, source_identifier, tags FROM cve_references WHERE cve_id = ?
        """, (normalized_id,)).fetchall()
        record["references"] = [
            {
                "source": r["source"],
                "url": r["url"],
                "source_identifier": r["source_identifier"],
                "tags": json.loads(r["tags"]) if r["tags"] else []
            }
            for r in ref_rows
        ]

        # Fetch CPE Matches
        cpe_rows = conn.execute("""
            SELECT m.*, c.operator, c.negate, c.parent_node_id
            FROM cve_cpe_matches m
            LEFT JOIN cve_configurations c ON m.config_node_id = c.id
            WHERE m.cve_id = ?
        """, (normalized_id,)).fetchall()
        record["cpe_matches"] = [
            {
                "criteria": r["criteria"],
                "match_criteria_id": r["match_criteria_id"],
                "vulnerable": bool(r["vulnerable"]),
                "part": r["part"],
                "vendor": r["vendor"],
                "product": r["product"],
                "version": r["version"],
                "version_start_including": r["version_start_including"],
                "version_start_excluding": r["version_start_excluding"],
                "version_end_including": r["version_end_including"],
                "version_end_excluding": r["version_end_excluding"],
                "operator": r["operator"],
                "negate": bool(r["negate"]) if r["negate"] is not None else False
            }
            for r in cpe_rows
        ]

        # Fetch Configurations
        config_rows = conn.execute("""
            SELECT id, config_index, operator, negate, parent_node_id, node_type
            FROM cve_configurations WHERE cve_id = ?
            ORDER BY id ASC
        """, (normalized_id,)).fetchall()
        record["configurations"] = [
            {
                "id": r["id"],
                "config_index": r["config_index"],
                "operator": r["operator"],
                "negate": bool(r["negate"]),
                "parent_node_id": r["parent_node_id"],
                "node_type": r["node_type"]
            }
            for r in config_rows
        ]

        # Fetch Affected Versions (from CVE List V5)
        aff_rows = conn.execute("""
            SELECT vendor, product, package_url, repo_url, modules, platforms,
                   version_value, version_status, version_type, less_than,
                   less_than_or_equal, default_status
            FROM cve_affected_versions WHERE cve_id = ?
        """, (normalized_id,)).fetchall()
        record["affected_versions"] = [
            {
                "vendor": r["vendor"],
                "product": r["product"],
                "package_url": r["package_url"],
                "repo_url": r["repo_url"],
                "modules": json.loads(r["modules"]) if r["modules"] else [],
                "platforms": json.loads(r["platforms"]) if r["platforms"] else [],
                "version_value": r["version_value"],
                "version_status": r["version_status"],
                "version_type": r["version_type"],
                "less_than": r["less_than"],
                "less_than_or_equal": r["less_than_or_equal"],
                "default_status": r["default_status"]
            }
            for r in aff_rows
        ]

        return record

    def search_cves(
        self,
        query: str,
        limit: int = 20,
        include_rejected: bool = False
    ) -> List[Dict[str, Any]]:
        """Search CVE records by keyword matching against indexed fields."""
        terms = [t.lower() for t in query.split() if t.strip()]
        if not terms:
            return []

        conn = self.connect()
        rejected_clause = "" if include_rejected else "AND is_rejected = 0"

        # Build parameterized LIKE conditions
        like_clauses = []
        params: List[Any] = []
        for term in terms:
            like_clauses.append("""
                (cve_id LIKE ? OR primary_vendor LIKE ? OR primary_product LIKE ?
                 OR description LIKE ? OR summary LIKE ? OR primary_severity LIKE ? OR cwe_ids LIKE ?)
            """)
            wildcard = f"%{term}%"
            params.extend([wildcard] * 7)

        sql = f"""
            SELECT cve_id, status, is_rejected, description, summary, published_date,
                   last_modified_date, primary_vendor, primary_product, primary_severity,
                   primary_cvss_score, cwe_ids, has_cpe_config, sources
            FROM cves
            WHERE {" AND ".join(like_clauses)} {rejected_clause}
            ORDER BY primary_cvss_score DESC NULLS LAST
            LIMIT ?
        """
        params.append(max(1, min(limit, 100)))

        rows = conn.execute(sql, params).fetchall()
        results = []
        for r in rows:
            item = dict(r)
            item["is_rejected"] = bool(r["is_rejected"])
            item["has_cpe_config"] = bool(r["has_cpe_config"])
            item["cwe_ids"] = json.loads(r["cwe_ids"]) if r["cwe_ids"] else []
            item["sources"] = json.loads(r["sources"]) if r["sources"] else []
            results.append(item)
        return results
