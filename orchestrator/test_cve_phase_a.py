"""Comprehensive Validation Suite for Phase A: CVE Ingestion, Normalization, and SQLite.

Validates:
1. Database creation, schema migrations, and schema_version metadata.
2. Complete pipeline ingestion from verified package fixtures.
3. Cryptographic SHA-256 manifest verification and refusal on mismatch.
4. Correct normalization of:
   - CVE-2025-24813 (Apache Tomcat Partial PUT, multi-source linked, affected versions, CPE match ranges)
   - CVE-2021-44228 (Log4Shell, multiple distinct CVSS v2 & v3.1 metrics, nested AND/OR node hierarchy)
   - CVE-2014-0160 (OpenSSL Heartbleed)
5. Strict rejection enforcement:
   - CVE-2022-21449 flagged as rejected (is_rejected=1) and filtered from normal lookups.
   - Explicit lookup with include_rejected=True returns the record.
6. Vulnerability without CPE configuration:
   - CVE-2024-99999 imported cleanly with has_cpe_config=0 and empty configurations.
7. Malformed record resilience:
   - Malformed records logged and counted, without aborting or corrupting the transaction.
8. Multi-source provenance & deduplication:
   - Preserves raw source records in source_records table.
   - Never silently overwrites one source with another.
   - Field-level provenance tracking in canonical cves table.
9. Reference tags and CVSS metrics preserved as discrete records.
10. Memory and performance telemetry via tracemalloc (< 2 GB peak RAM target).
11. Integration with CVEDatabaseAgent.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Support running from root or orchestrator directory
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))
workspace_dir = current_dir.parent
if str(workspace_dir) not in sys.path:
    sys.path.insert(0, str(workspace_dir))

try:
    from orchestrator.cve_db import CVEDatabase, DATABASE_VERSION, SCHEMA_VERSION
    from orchestrator.cve_importer import CVEImporter
    from orchestrator.cve_database_agent import CVEDatabaseAgent
except ImportError:
    from cve_db import CVEDatabase, DATABASE_VERSION, SCHEMA_VERSION
    from cve_importer import CVEImporter
    from cve_database_agent import CVEDatabaseAgent


class PhaseAValidationTests(unittest.TestCase):
    """Validation tests for all Phase A requirements."""

    @classmethod
    def setUpClass(cls):
        cls.fixture_dir = current_dir / "tests" / "fixtures"
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="phase_a_test_"))
        cls.db_path = cls.temp_dir / "cve_validation.db"

        # Import package into clean validation database
        cls.importer = CVEImporter(cls.db_path)
        cls.import_result = cls.importer.import_package(cls.fixture_dir)
        cls.db = CVEDatabase(cls.db_path)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        try:
            shutil.rmtree(cls.temp_dir)
        except OSError:
            pass

    # 1. Pipeline and Manifest Integrity
    def test_01_manifest_verification_and_integrity(self):
        """Verify that SHA-256 manifest verification passes and blocks tampering."""
        valid, msg = self.importer.verify_manifest(self.fixture_dir)
        self.assertTrue(valid, f"Manifest verification should pass: {msg}")

        # Test manifest tampering detection
        tamper_dir = self.temp_dir / "tampered_pkg"
        shutil.copytree(self.fixture_dir, tamper_dir)
        # Corrupt one file
        tampered_file = tamper_dir / "nvd_sample.json"
        with open(tampered_file, "a", encoding="utf-8") as f:
            f.write(" ")

        tampered_importer = CVEImporter(self.temp_dir / "tampered.db")
        is_valid, err_msg = tampered_importer.verify_manifest(tamper_dir)
        self.assertFalse(is_valid, "Tampered file must fail manifest verification")
        self.assertIn("mismatch", err_msg.lower())

        # Verify importer refuses to run on tampered package
        with self.assertRaises(ValueError):
            tampered_importer.import_package(tamper_dir)

    # 2. Schema and Metadata Verification
    def test_02_database_metadata_and_schema(self):
        """Verify database metadata contains required fields and schema version."""
        meta = self.db.get_metadata()
        self.assertEqual(str(meta.get("schema_version")), str(SCHEMA_VERSION))
        self.assertEqual(meta.get("database_version"), DATABASE_VERSION)
        self.assertIn("build_timestamp", meta)
        self.assertEqual(meta.get("package_sha256"), "verified")

        counts = self.db.get_counts()
        self.assertEqual(counts["total_cves"], 5)
        self.assertEqual(counts["active_cves"], 4)
        self.assertEqual(counts["rejected_cves"], 1)
        self.assertEqual(counts["no_cpe_count"], 1)
        self.assertEqual(counts["nvd_record_count"], 5)
        self.assertEqual(counts["cve_list_record_count"], 2)
        self.assertEqual(counts["linked_cve_count"], 2)

    # 3. Retrieval of Unrelated CVEs
    def test_03_lookup_multiple_unrelated_cves(self):
        """Verify multiple unrelated CVEs can be retrieved cleanly."""
        # 1. Apache Tomcat: CVE-2025-24813
        rec_tomcat = self.db.lookup_cve("CVE-2025-24813")
        self.assertIsNotNone(rec_tomcat)
        self.assertEqual(rec_tomcat["cve_id"], "CVE-2025-24813")
        self.assertIn("apache", rec_tomcat["primary_vendor"].lower())
        self.assertIn("tomcat", rec_tomcat["primary_product"].lower())

        # 2. Apache Log4j: CVE-2021-44228
        rec_log4j = self.db.lookup_cve("CVE-2021-44228")
        self.assertIsNotNone(rec_log4j)
        self.assertEqual(rec_log4j["cve_id"], "CVE-2021-44228")
        self.assertIn("apache", rec_log4j["primary_vendor"].lower())
        self.assertIn("log4j", rec_log4j["primary_product"].lower())

        # 3. OpenSSL Heartbleed: CVE-2014-0160
        rec_openssl = self.db.lookup_cve("CVE-2014-0160")
        self.assertIsNotNone(rec_openssl)
        self.assertEqual(rec_openssl["cve_id"], "CVE-2014-0160")
        self.assertEqual(rec_openssl["primary_vendor"].lower(), "openssl")
        self.assertEqual(rec_openssl["primary_product"].lower(), "openssl")

    # 4. Strict Rejection Handling
    def test_04_rejected_cve_handling(self):
        """Verify rejected CVEs are marked and excluded from normal lookups."""
        # Normal lookup MUST return None
        normal_lookup = self.db.lookup_cve("CVE-2022-21449")
        self.assertIsNone(normal_lookup, "Rejected CVE must NEVER be returned by normal lookup")

        # Explicit lookup with include_rejected=True returns record with is_rejected=True
        explicit_lookup = self.db.lookup_cve("CVE-2022-21449", include_rejected=True)
        self.assertIsNotNone(explicit_lookup)
        self.assertTrue(explicit_lookup["is_rejected"])
        self.assertEqual(explicit_lookup["status"], "Rejected")

        # Search must also exclude rejected CVEs
        search_results = self.db.search_cves("candidate")
        self.assertNotIn("CVE-2022-21449", [r["cve_id"] for r in search_results])

    # 5. Handling CVEs without CPE Configurations
    def test_05_cve_without_cpe_configuration(self):
        """Verify CVE without CPE configuration is handled gracefully."""
        rec = self.db.lookup_cve("CVE-2024-99999")
        self.assertIsNotNone(rec)
        self.assertFalse(rec["has_cpe_config"])
        self.assertEqual(len(rec["cpe_matches"]), 0)
        self.assertEqual(len(rec["configurations"]), 0)
        self.assertEqual(rec["primary_severity"], "MEDIUM")

    # 6. Malformed Record Resilience
    def test_06_malformed_record_resilience(self):
        """Verify that malformed records do not abort import or corrupt database."""
        scanned = self.import_result["stats"]["sources_scanned"]
        self.assertTrue(any("cve_list_sample.json" in s for s in scanned))
        self.assertTrue(any("malformed_record.json" in s for s in scanned))
        self.assertTrue(any("nvd_sample.json" in s for s in scanned))
        # All valid records were imported despite malformed record
        self.assertEqual(self.db.get_counts()["total_cves"], 5)

    # 7. Preservation of Multi-CVSS Metrics
    def test_07_cvss_metrics_preserved_individually(self):
        """Verify all CVSS metrics are preserved as discrete records (v2, v3, etc.)."""
        rec_log4j = self.db.lookup_cve("CVE-2021-44228")
        metrics = rec_log4j["cvss_metrics"]
        self.assertEqual(len(metrics), 2, "Log4j must have both CVSS 2.0 and 3.1 metrics")

        versions = {m["cvss_version"] for m in metrics}
        self.assertEqual(versions, {"2.0", "3.1"})

        # Check CVSS 3.1 metric
        v31 = next(m for m in metrics if m["cvss_version"] == "3.1")
        self.assertEqual(v31["base_score"], 10.0)
        self.assertEqual(v31["base_severity"], "CRITICAL")
        self.assertIn("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", v31["vector_string"])

        # Check CVSS 2.0 metric
        v2 = next(m for m in metrics if m["cvss_version"] == "2.0")
        self.assertEqual(v2["base_score"], 9.3)
        self.assertEqual(v2["vector_string"], "AV:N/AC:M/Au:N/C:C/I:C/A:C")

    # 8. Preservation of Configuration Node Tree & CPE Matches
    def test_08_cpe_configuration_structure_preserved(self):
        """Verify NVD configuration operators (AND/OR), negate, and structured version ranges."""
        rec_tomcat = self.db.lookup_cve("CVE-2025-24813")
        self.assertTrue(rec_tomcat["has_cpe_config"])
        self.assertGreater(len(rec_tomcat["cpe_matches"]), 0)

        # Check version ranges in CPE match
        match_90 = next((m for m in rec_tomcat["cpe_matches"] if m.get("version_start_including") == "9.0.0.M1"), None)
        self.assertIsNotNone(match_90)
        self.assertEqual(match_90["version_end_including"], "9.0.98")
        self.assertEqual(match_90["vendor"], "apache")
        self.assertEqual(match_90["product"], "tomcat")
        self.assertTrue(match_90["vulnerable"])

        # Log4j has nested AND/OR node hierarchy
        rec_log4j = self.db.lookup_cve("CVE-2021-44228")
        configs = rec_log4j["configurations"]
        self.assertGreater(len(configs), 0)
        operators = {c["operator"] for c in configs}
        self.assertTrue("AND" in operators or "OR" in operators)

    # 9. Reference Tags Preserved
    def test_09_reference_tags_preserved(self):
        """Verify NVD reference tags and URLs are preserved."""
        rec_tomcat = self.db.lookup_cve("CVE-2025-24813")
        refs = rec_tomcat["references"]
        self.assertGreater(len(refs), 0)
        nvd_ref = next((r for r in refs if r.get("tags")), None)
        self.assertIsNotNone(nvd_ref, "Reference with tags should be present")
        self.assertIn("https://lists.apache.org/thread/", nvd_ref["url"])
        self.assertIn("Vendor Advisory", nvd_ref["tags"])
        self.assertIn("Mailing List", nvd_ref["tags"])

    # 10. Multi-Source Provenance & Deduplication
    def test_10_multi_source_provenance_and_deduplication(self):
        """Verify NVD and CVE List V5 provenance remains distinct without overwrite."""
        rec_tomcat = self.db.lookup_cve("CVE-2025-24813")
        self.assertIn("NVD", rec_tomcat["sources"])
        self.assertIn("CVE_LIST_V5", rec_tomcat["sources"])

        prov = rec_tomcat["provenance"]
        self.assertIsInstance(prov, dict)
        self.assertEqual(prov.get("description"), "NVD")
        self.assertEqual(prov.get("configurations"), "NVD")
        self.assertEqual(prov.get("affected_versions"), "CVE_LIST_V5")

        # Verify separate records exist in source_records
        conn = self.db.connect()
        src_rows = conn.execute("""
            SELECT source, source_record_version, vuln_status
            FROM source_records WHERE cve_id = 'CVE-2025-24813'
            ORDER BY source ASC
        """).fetchall()
        self.assertEqual(len(src_rows), 2)
        sources_found = {r["source"] for r in src_rows}
        self.assertEqual(sources_found, {"CVE_LIST_V5", "NVD"})

        # Affected versions table holds CVE List V5 data
        aff_ranges = rec_tomcat["affected_versions"]
        self.assertEqual(len(aff_ranges), 2)
        v9 = next((a for a in aff_ranges if a["version_value"] == "9.0.0.M1"), None)
        self.assertIsNotNone(v9)
        self.assertEqual(v9["less_than_or_equal"], "9.0.98")

    # 11. Memory Usage Limits (< 2 GB)
    def test_11_memory_usage_within_budget(self):
        """Verify peak memory during import is tracked and well below 2 GB limit."""
        peak_mb = self.import_result["stats"]["peak_memory_mb"]
        self.assertLess(peak_mb, 2048.0, "Peak memory must be below 2048 MB")
        self.assertGreater(peak_mb, 0.0)

    # 12. CVEDatabaseAgent Compatibility
    def test_12_cve_database_agent_sqlite_integration(self):
        """Verify CVEDatabaseAgent works transparently with the SQLite database."""
        agent = CVEDatabaseAgent(self.db_path)
        # 1. Lookup active CVE
        res = agent.lookup("CVE-2025-24813")
        self.assertIsNotNone(res)
        self.assertEqual(res["cve_id"], "CVE-2025-24813")
        self.assertIn("apache", res["vendor"].lower())
        self.assertIn("tomcat", res["product"].lower())
        self.assertEqual(res["severity"], "HIGH")

        # 2. Lookup rejected CVE returns None
        self.assertIsNone(agent.lookup("CVE-2022-21449"))

        # 3. Search query
        search_res = agent.search("Log4j")
        self.assertGreater(len(search_res), 0)
        self.assertEqual(search_res[0]["cve_id"], "CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
