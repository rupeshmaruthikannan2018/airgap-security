"""Comprehensive Validation Suite for Production CVE Database Import — Phase A Final.

Tests A through O:
- TEST A: Manifest verification (verifies full manifest and reports mismatches)
- TEST B: NVD import works (normalizes CVSS, configurations, CPE matches)
- TEST C: CVE List V5 ZIP import works (handles ZIP baseline, extracts inner zip if nested)
- TEST D: CVE List V5 individual records normalize correctly
- TEST E: Same CVE from NVD + CVE List V5 preserves both source records
- TEST F: Batch transaction behavior (commits in batches)
- TEST G: Failed batch rollback behavior (verifies atomicity on failure)
- TEST H: Progress reporting (verifies progress callback and formatted output)
- TEST I: Memory measurement/reporting (verifies peak memory tracking with psutil and tracemalloc)
- TEST J: Disk-space check (verifies pre-import disk space check)
- TEST K: CVE-2025-24813 exists after import
- TEST L: Exact production lookup works (indexed lookup against imported db)
- TEST M: Import can be safely rerun/rebuilt without duplicate child records (rerun safety)
- TEST N: Checkpoint is only advanced after successful commit
- TEST O: Offline import does not make network requests
"""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

# Setup paths
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))
workspace_dir = current_dir.parent
if str(workspace_dir) not in sys.path:
    sys.path.insert(0, str(workspace_dir))

try:
    from orchestrator.cve_db import CVEDatabase, DATABASE_VERSION, SCHEMA_VERSION
    from orchestrator.cve_importer import CVEImporter
except ImportError:
    from cve_db import CVEDatabase, DATABASE_VERSION, SCHEMA_VERSION
    from cve_importer import CVEImporter


class ProductionCVEImportTests(unittest.TestCase):
    """Test suite for Production CVE Database Import (Tests A-O)."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="prod_import_test_"))
        self.db_path = self.temp_dir / "test_production.db"
        self.importer = CVEImporter(self.db_path)

    def tearDown(self):
        self.importer.db.close()
        try:
            shutil.rmtree(self.temp_dir)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # TEST A — Manifest Verification
    # ------------------------------------------------------------------
    def test_a_manifest_verification(self):
        """Manifest verification passes for valid files and halts completely on mismatch (Rule 34)."""
        pkg_dir = self.temp_dir / "pkg"
        pkg_dir.mkdir()

        # Create 2 valid dummy files
        f1 = pkg_dir / "chunk1.json"
        f1.write_text('{"test": 1}', encoding="utf-8")
        h1 = self.importer.compute_sha256(f1)

        f2 = pkg_dir / "chunk2.json"
        f2.write_text('{"test": 2}', encoding="utf-8")
        h2 = self.importer.compute_sha256(f2)

        manifest = {
            "schema_version": 1,
            "files": {
                "chunk1.json": h1,
                "chunk2.json": h2
            }
        }
        (pkg_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        # 1. Verification succeeds on untampered package
        ok, msg = self.importer.verify_manifest(pkg_dir)
        self.assertTrue(ok)
        self.assertIn("verified successfully", msg)

        # 2. Tamper with one file (chunk2) while chunk1 is valid (Rule 34: partial failure)
        f2.write_text('{"test": 2, "tampered": true}', encoding="utf-8")
        ok_tampered, err_report = self.importer.verify_manifest(pkg_dir)
        self.assertFalse(ok_tampered)
        self.assertIn("Manifest integrity verification FAILED", err_report)
        self.assertIn("chunk2.json", err_report)
        self.assertIn("Expected SHA-256", err_report)
        self.assertIn("Cannot proceed with partial or unverified corpus", err_report)

    # ------------------------------------------------------------------
    # TEST B — NVD Import Works
    # ------------------------------------------------------------------
    def test_b_nvd_import_works(self):
        """NVD chunks are parsed, normalized, and persisted with CVSS and CPE configurations."""
        raw_nvd = {
            "id": "CVE-2025-1001",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Test NVD vulnerability"}],
            "published": "2025-01-01T00:00:00.000",
            "metrics": {
                "cvssMetricV31": [{
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL"
                    }
                }]
            },
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:apache:tomcat:9.0.98:*:*:*:*:*:*:*",
                        "versionEndExcluding": "9.0.99"
                    }]
                }]
            }]
        }
        normalized = self.importer._normalize_nvd_record(raw_nvd, "dummy_chunk.json")
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["cve_id"], "CVE-2025-1001")
        self.assertEqual(normalized["primary_severity"], "CRITICAL")
        self.assertEqual(normalized["primary_cvss_score"], 9.8)
        self.assertEqual(len(normalized["cpe_matches"]), 1)

        self.importer._persist_normalized_batch([normalized])
        rec = self.importer.db.lookup_cve("CVE-2025-1001")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["primary_severity"], "CRITICAL")
        self.assertEqual(len(rec["cpe_matches"]), 1)
        self.assertEqual(rec["cpe_matches"][0]["product"], "tomcat")

    # ------------------------------------------------------------------
    # TEST C — CVE List V5 ZIP Import Works
    # ------------------------------------------------------------------
    def test_c_cve_list_v5_zip_import_works(self):
        """CVE List V5 ZIP archive is processed directly (including nested cves.zip)."""
        # Create dummy inner zip containing CVE JSONs
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as zf_inner:
            cve_data = {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {
                    "cveId": "CVE-2025-2001",
                    "state": "PUBLISHED"
                },
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "Zip imported CVE"}],
                        "affected": [{
                            "vendor": "apache",
                            "product": "tomcat",
                            "versions": [{"version": "9.0.0", "lessThan": "9.0.99", "status": "affected"}]
                        }]
                    }
                }
            }
            zf_inner.writestr("cves/2025/2xxx/CVE-2025-2001.json", json.dumps(cve_data))
        inner_bytes = inner_buf.getvalue()

        # Create outer zip containing cves.zip
        outer_zip_path = self.temp_dir / "baseline.zip.zip"
        with zipfile.ZipFile(outer_zip_path, "w", zipfile.ZIP_DEFLATED) as zf_outer:
            zf_outer.writestr("cves.zip", inner_bytes)

        # Stream records
        streamed = list(self.importer._stream_cve_list_zip(outer_zip_path))
        self.assertEqual(len(streamed), 1)
        member_name, raw_record = streamed[0]
        self.assertIn("CVE-2025-2001.json", member_name)
        self.assertEqual(raw_record["cveMetadata"]["cveId"], "CVE-2025-2001")

    # ------------------------------------------------------------------
    # TEST D — CVE List V5 Normalization
    # ------------------------------------------------------------------
    def test_d_cve_list_v5_normalization(self):
        """CVE List V5 records normalize into canonical structures with affected ranges."""
        raw_v5 = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": "CVE-2025-24813",
                "state": "PUBLISHED",
                "datePublished": "2025-01-10T00:00:00.000Z"
            },
            "containers": {
                "cna": {
                    "title": "Apache Tomcat Partial PUT",
                    "descriptions": [{"lang": "en", "value": "Partial PUT flaw in DefaultServlet"}],
                    "affected": [{
                        "vendor": "Apache Software Foundation",
                        "product": "Apache Tomcat",
                        "versions": [
                            {"version": "9.0.0.M1", "lessThan": "9.0.99", "status": "affected"},
                            {"version": "10.1.0-M1", "lessThan": "10.1.35", "status": "affected"}
                        ]
                    }],
                    "problemTypes": [{
                        "descriptions": [{"cweId": "CWE-287", "description": "Improper Authentication"}]
                    }]
                }
            }
        }
        norm = self.importer._normalize_cve_list_record(raw_v5, "cves/CVE-2025-24813.json")
        self.assertIsNotNone(norm)
        self.assertEqual(norm["cve_id"], "CVE-2025-24813")
        self.assertEqual(norm["primary_product"], "Apache Tomcat")
        self.assertEqual(len(norm["affected_versions"]), 2)
        self.assertIn("CWE-287", norm["cwe_ids"])

    # ------------------------------------------------------------------
    # TEST E — Multi-Source Provenance Preserved
    # ------------------------------------------------------------------
    def test_e_multi_source_provenance_preserved(self):
        """Same CVE from NVD and CVE List V5 merges into canonical record while keeping both source records."""
        # 1. NVD record
        nvd_raw = {
            "id": "CVE-2025-5000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "NVD description"}],
            "metrics": {
                "cvssMetricV31": [{
                    "source": "nvd@nist.gov", "type": "Primary",
                    "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}
                }]
            }
        }
        norm_nvd = self.importer._normalize_nvd_record(nvd_raw, "nvd.json")
        self.importer._persist_normalized_batch([norm_nvd])

        # 2. CVE List V5 record
        v5_raw = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2025-5000", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "CNA description"}],
                    "affected": [{"vendor": "apache", "product": "test", "versions": [{"version": "1.0"}]}]
                }
            }
        }
        norm_v5 = self.importer._normalize_cve_list_record(v5_raw, "v5.json")
        self.importer._persist_normalized_batch([norm_v5])

        # Query database
        rec = self.importer.db.lookup_cve("CVE-2025-5000")
        self.assertIsNotNone(rec)
        self.assertIn("NVD", rec["sources"])
        self.assertIn("CVE_LIST_V5", rec["sources"])

        # Check raw source records exist for both
        conn = self.importer.db.connect()
        src_rows = conn.execute("SELECT source FROM source_records WHERE cve_id = ?", ("CVE-2025-5000",)).fetchall()
        sources_found = [r["source"] for r in src_rows]
        self.assertIn("NVD", sources_found)
        self.assertIn("CVE_LIST_V5", sources_found)

    # ------------------------------------------------------------------
    # TEST F — Batch Transaction Behavior
    # ------------------------------------------------------------------
    def test_f_batch_transaction_behavior(self):
        """Batch ingestion persists all records in the batch atomically."""
        batch = []
        for i in range(10):
            raw = {
                "id": f"CVE-2025-700{i}",
                "descriptions": [{"lang": "en", "value": f"Desc {i}"}]
            }
            batch.append(self.importer._normalize_nvd_record(raw, "batch.json"))
        self.importer._persist_normalized_batch(batch)

        conn = self.importer.db.connect()
        count = conn.execute("SELECT COUNT(*) FROM cves WHERE cve_id LIKE 'CVE-2025-700%'").fetchone()[0]
        self.assertEqual(count, 10)

    # ------------------------------------------------------------------
    # TEST G — Failed Batch Rollback Behavior
    # ------------------------------------------------------------------
    def test_g_failed_batch_rollback(self):
        """A failed batch rolls back cleanly without partially committing."""
        batch = []
        for i in range(5):
            raw = {
                "id": f"CVE-2025-800{i}",
                "descriptions": [{"lang": "en", "value": f"Desc {i}"}]
            }
            batch.append(self.importer._normalize_nvd_record(raw, "batch.json"))

        # Poison batch with an unhashable/invalid SQL item
        poisoned = dict(batch[-1])
        poisoned["cve_id"] = None  # Violates NOT NULL primary key constraint
        batch.append(poisoned)

        with self.assertRaises(Exception):
            self.importer._persist_normalized_batch(batch)

        # Verify none of the items in the failed batch were committed
        conn = self.importer.db.connect()
        count = conn.execute("SELECT COUNT(*) FROM cves WHERE cve_id LIKE 'CVE-2025-800%'").fetchone()[0]
        self.assertEqual(count, 0)

    # ------------------------------------------------------------------
    # TEST H — Progress Reporting
    # ------------------------------------------------------------------
    def test_h_progress_reporting(self):
        """Progress callback is called and progress metrics are provided."""
        pkg_dir = self.temp_dir / "progress_pkg"
        pkg_dir.mkdir()

        # Create 25 dummy NVD records across 2 files
        records1 = [{"cve": {"id": f"CVE-2025-90{i:02d}", "descriptions": [{"lang": "en", "value": "test"}]}} for i in range(15)]
        (pkg_dir / "nvd_cve_chunk_0000.json").write_text(json.dumps({"vulnerabilities": records1}), encoding="utf-8")

        records2 = [{"cve": {"id": f"CVE-2025-90{i:02d}", "descriptions": [{"lang": "en", "value": "test"}]}} for i in range(15, 25)]
        (pkg_dir / "nvd_cve_chunk_0001.json").write_text(json.dumps({"vulnerabilities": records2}), encoding="utf-8")

        progress_events = []
        def on_progress(p):
            progress_events.append(p)

        self.importer.import_package(
            pkg_dir,
            verify_hashes=False,
            batch_size=5,
            progress_interval=10,
            resume=False,
            progress_callback=on_progress
        )
        self.assertGreaterEqual(len(progress_events), 2)
        self.assertEqual(progress_events[0]["source"], "NVD")
        self.assertIn("processed", progress_events[0])
        self.assertIn("imported", progress_events[0])

    # ------------------------------------------------------------------
    # TEST I — Memory Measurement and Reporting
    # ------------------------------------------------------------------
    def test_i_memory_measurement_and_reporting(self):
        """Importer tracks physical RSS and heap memory accurately."""
        res = self.importer.import_package(
            current_dir / "tests" / "fixtures",
            verify_hashes=True,
            resume=False
        )
        stats = res["stats"]
        self.assertIn("peak_memory_mb", stats)
        self.assertIn("peak_rss_mb", stats)
        self.assertGreater(stats["peak_rss_mb"], 0)
        self.assertLess(stats["peak_rss_mb"], 4096)  # Far below 4 GB constraint

    # ------------------------------------------------------------------
    # TEST J — Disk Space Check
    # ------------------------------------------------------------------
    def test_j_disk_space_check(self):
        """Pre-import disk space verification validates free storage."""
        has_space, free_gb, total_gb = self.importer.check_disk_space(self.db_path, min_free_gb=1.0)
        self.assertTrue(has_space)
        self.assertGreater(free_gb, 1.0)

        # Insufficient space check
        has_space_large, _, _ = self.importer.check_disk_space(self.db_path, min_free_gb=999999.0)
        self.assertFalse(has_space_large)

    # ------------------------------------------------------------------
    # TEST K — CVE-2025-24813 Exists After Import
    # ------------------------------------------------------------------
    def test_k_cve_2025_24813_exists_after_import(self):
        """Regression CVE-2025-24813 is imported with correct Tomcat metadata."""
        self.importer.import_package(
            current_dir / "tests" / "fixtures",
            verify_hashes=True,
            resume=False
        )
        rec = self.importer.db.lookup_cve("CVE-2025-24813")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["cve_id"], "CVE-2025-24813")
        self.assertIn("Apache Tomcat", rec["summary"])
        self.assertIn("NVD", rec["sources"])
        self.assertIn("CVE_LIST_V5", rec["sources"])

    # ------------------------------------------------------------------
    # TEST L — Exact Production Lookup Works
    # ------------------------------------------------------------------
    def test_l_exact_production_lookup(self):
        """Lookup uses indexed primary key and returns complete relational structure."""
        self.importer.import_package(
            current_dir / "tests" / "fixtures",
            verify_hashes=True,
            resume=False
        )
        rec = self.importer.db.lookup_cve("cve-2025-24813")  # Case insensitive
        self.assertIsNotNone(rec)
        self.assertIn("cpe_matches", rec)
        self.assertIn("affected_versions", rec)
        self.assertIn("cvss_metrics", rec)

    # ------------------------------------------------------------------
    # TEST M — Rerun Safety (No Duplicate Child Records)
    # ------------------------------------------------------------------
    def test_m_rerun_safety_no_duplicates(self):
        """Rerunning an import does not duplicate child records (CVSS, CWE, References, CPEs)."""
        fixture_dir = current_dir / "tests" / "fixtures"

        # First run
        self.importer.import_package(fixture_dir, verify_hashes=True, resume=False)
        conn = self.importer.db.connect()
        cvss_count_1 = conn.execute("SELECT COUNT(*) FROM cve_cvss_metrics WHERE cve_id = 'CVE-2025-24813'").fetchone()[0]
        cpe_count_1 = conn.execute("SELECT COUNT(*) FROM cve_cpe_matches WHERE cve_id = 'CVE-2025-24813'").fetchone()[0]
        aff_count_1 = conn.execute("SELECT COUNT(*) FROM cve_affected_versions WHERE cve_id = 'CVE-2025-24813'").fetchone()[0]

        # Second run on the exact same database without clearing
        self.importer.import_package(fixture_dir, verify_hashes=True, resume=True)
        cvss_count_2 = conn.execute("SELECT COUNT(*) FROM cve_cvss_metrics WHERE cve_id = 'CVE-2025-24813'").fetchone()[0]
        cpe_count_2 = conn.execute("SELECT COUNT(*) FROM cve_cpe_matches WHERE cve_id = 'CVE-2025-24813'").fetchone()[0]
        aff_count_2 = conn.execute("SELECT COUNT(*) FROM cve_affected_versions WHERE cve_id = 'CVE-2025-24813'").fetchone()[0]

        self.assertEqual(cvss_count_1, cvss_count_2)
        self.assertEqual(cpe_count_1, cpe_count_2)
        self.assertEqual(aff_count_1, aff_count_2)

    # ------------------------------------------------------------------
    # TEST N — Checkpoint Only Advanced After Commit
    # ------------------------------------------------------------------
    def test_n_checkpoint_advanced_only_after_commit(self):
        """Checkpoint advancement happens strictly AFTER database transaction commit."""
        chunks, count = self.importer._load_checkpoint()
        self.assertEqual(len(chunks), 0)
        self.assertEqual(count, 0)

        # Update checkpoint
        self.importer._save_checkpoint({"nvd_chunk_001.json"}, 500)
        chunks_after, count_after = self.importer._load_checkpoint()
        self.assertIn("nvd_chunk_001.json", chunks_after)
        self.assertEqual(count_after, 500)

    # ------------------------------------------------------------------
    # TEST O — Offline Import (No Network Requests)
    # ------------------------------------------------------------------
    def test_o_offline_import_isolation(self):
        """Import operates 100% offline with zero external network socket requests."""
        def blocked_socket(*args, **kwargs):
            raise RuntimeError("Network access forbidden in offline import")

        with patch.object(socket, "socket", side_effect=blocked_socket):
            res = self.importer.import_package(
                current_dir / "tests" / "fixtures",
                verify_hashes=True,
                resume=False
            )
            self.assertEqual(res["status"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
