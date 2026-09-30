"""Comprehensive Test Suite for Phase B: Deterministic CVE Lookup and Version Evidence Bridge.

Covers all required specifications:
TEST A — Exact CVE lookup (indexed SQLite resolution)
TEST B — Identifier normalization (cve-2025-24813 -> CVE-2025-24813)
TEST C — Known CVE returns FOUND
TEST D — Unknown valid CVE returns DATABASE_MISS (never assumed safe)
TEST E — Unsupported identifier (GHSA / OSV returns UNSUPPORTED_IDENTIFIER_FORMAT)
TEST F — Multiple CVEs independently resolved
TEST G — Trivy evidence preservation (PkgName, InstalledVersion, FixedVersion, etc.)
TEST H — Affected version evaluation (installed inside range -> AFFECTED)
TEST I — Fixed / not-affected version evaluation (installed >= fixed -> NOT_AFFECTED)
TEST J — Unsupported / uncertain version scheme returns UNKNOWN (no lexicographic guessing)
TEST K — Multi-source provenance preserved (NVD and CVE List V5 remain distinct)
TEST L — Non-material range difference (both conclude AFFECTED -> NOT a conflict)
TEST M — Material contradiction (one source affected, other not affected -> VERSION_EVIDENCE_CONFLICT)
TEST N — Nuclei shared lookup service integration
TEST O — Nuclei insufficient version evidence returns FOUND with version_evidence=UNKNOWN
TEST P — Strict network isolation (raises if network/socket attempted)
TEST Q — Production lookup performance benchmark (< 100 ms target)
TEST R — Phase A test regression
TEST S — Database agent test regression
TEST T — CVE-2025-24813 regression
TEST U — Uncertain CPE-to-package mapping handled conservatively (NVD held as UNKNOWN)
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))
workspace_dir = current_dir.parent
if str(workspace_dir) not in sys.path:
    sys.path.insert(0, str(workspace_dir))

from cve_phase_b import (
    EcosystemVersionComparator,
    PhaseBEvidenceService,
    classify_identifier,
    extract_cve_identifiers,
    verify_cpe_package_mapping,
)
from cve_db import CVEDatabase


class PhaseBComprehensiveTests(unittest.TestCase):
    """Full automated test suite for Phase B requirements A through U."""

    @classmethod
    def setUpClass(cls):
        cls.db_path = current_dir / "cve_database.db"
        if not cls.db_path.exists():
            cls.db_path = workspace_dir / "cve_database.db"
        cls.service = PhaseBEvidenceService(cls.db_path)

    # ------------------------------------------------------------------
    # TEST A — Exact CVE lookup
    # ------------------------------------------------------------------
    def test_a_exact_cve_lookup(self):
        """Known CVE resolves through indexed SQLite lookup."""
        rec, elapsed_ms = self.service.lookup_cve_exact("CVE-2025-24813")
        self.assertIsNotNone(rec, "Expected to resolve CVE-2025-24813")
        self.assertEqual(rec["cve_id"], "CVE-2025-24813")
        self.assertLess(elapsed_ms, 100.0, f"Lookup took {elapsed_ms} ms, target is < 100 ms")

    # ------------------------------------------------------------------
    # TEST B — Identifier normalization
    # ------------------------------------------------------------------
    def test_b_identifier_normalization(self):
        """Lowercase / untrimmed CVE normalized to canonical uppercase format."""
        id_type, normalized = classify_identifier("  cve-2025-24813  ")
        self.assertEqual(id_type, "CVE")
        self.assertEqual(normalized, "CVE-2025-24813")

        id_type2, normalized2 = classify_identifier("CVE-2021-44228")
        self.assertEqual(id_type2, "CVE")
        self.assertEqual(normalized2, "CVE-2021-44228")

    # ------------------------------------------------------------------
    # TEST C — Known CVE
    # ------------------------------------------------------------------
    def test_c_known_cve_returns_found(self):
        """Known CVE present in local SQLite database returns database_status=FOUND."""
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "tomcat",
            "installed_version": "9.0.98",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["database_status"], "FOUND")
        self.assertEqual(res[0]["canonical_cve"], "CVE-2025-24813")

    # ------------------------------------------------------------------
    # TEST D — Unknown valid CVE
    # ------------------------------------------------------------------
    def test_d_unknown_valid_cve_returns_database_miss(self):
        """Valid CVE absent from local database returns DATABASE_MISS, never assumed safe."""
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2099-99999",
            "package": "some-package",
            "installed_version": "1.0.0",
            "ecosystem": "npm"
        }
        res = self.service.evaluate_finding(finding)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["database_status"], "DATABASE_MISS")
        self.assertEqual(res[0]["canonical_cve"], "CVE-2099-99999")
        self.assertEqual(res[0]["version_evidence"], "UNKNOWN")
        self.assertIn("not found in local database", res[0]["version_evidence_reason"])

    # ------------------------------------------------------------------
    # TEST E — Unsupported identifier
    # ------------------------------------------------------------------
    def test_e_unsupported_identifier(self):
        """GHSA or non-CVE identifier returns UNSUPPORTED_IDENTIFIER_FORMAT."""
        finding = {
            "scanner": "trivy",
            "cve": "GHSA-7rjr-3q55-vv33",
            "package": "org.apache.logging.log4j:log4j-core",
            "installed_version": "2.14.0",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["identifier_type"], "UNSUPPORTED_IDENTIFIER_FORMAT")
        self.assertEqual(res[0]["database_status"], "UNSUPPORTED_IDENTIFIER_FORMAT")
        self.assertEqual(res[0]["version_evidence"], "UNKNOWN")
        self.assertIsNone(res[0]["canonical_cve"])
        self.assertEqual(res[0]["scanner_evidence"]["vulnerability_id"], "GHSA-7rjr-3q55-vv33")

    # ------------------------------------------------------------------
    # TEST F — Multiple CVEs
    # ------------------------------------------------------------------
    def test_f_multiple_cves_independently_resolved(self):
        """Multi-CVE findings are independently resolved without losing missing ones."""
        finding = {
            "scanner": "trivy",
            "cve": ["CVE-2025-24813", "CVE-2099-0001"],
            "package": "tomcat",
            "installed_version": "9.0.98",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)
        self.assertEqual(len(res), 2)

        # First CVE should be FOUND
        r1 = next(r for r in res if r["identifier"] == "CVE-2025-24813")
        self.assertEqual(r1["database_status"], "FOUND")
        self.assertEqual(r1["version_evidence"], "AFFECTED")

        # Second CVE should be DATABASE_MISS
        r2 = next(r for r in res if r["identifier"] == "CVE-2099-0001")
        self.assertEqual(r2["database_status"], "DATABASE_MISS")
        self.assertEqual(r2["version_evidence"], "UNKNOWN")

    # ------------------------------------------------------------------
    # TEST G — Trivy evidence preservation
    # ------------------------------------------------------------------
    def test_g_trivy_evidence_preserved(self):
        """Trivy fields (PkgName, PkgID, InstalledVersion, FixedVersion, etc.) preserved."""
        finding = {
            "scanner": "trivy",
            "VulnerabilityID": "CVE-2025-24813",
            "PkgName": "org.apache.tomcat:tomcat-catalina",
            "PkgID": "tomcat-catalina@9.0.98",
            "InstalledVersion": "9.0.98",
            "FixedVersion": "9.0.99",
            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2025-24813",
            "Severity": "HIGH",
            "VendorSeverity": {"nvd": 3, "redhat": 2},
            "PkgPath": "/usr/local/tomcat/lib/catalina.jar",
            "Layer": "sha256:abc123456",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)[0]
        ev = res["scanner_evidence"]
        self.assertEqual(ev["package_name"], "org.apache.tomcat:tomcat-catalina")
        self.assertEqual(ev["pkg_id"], "tomcat-catalina@9.0.98")
        self.assertEqual(ev["installed_version"], "9.0.98")
        self.assertEqual(ev["fixed_version"], "9.0.99")
        self.assertEqual(ev["severity"], "HIGH")
        self.assertEqual(ev["pkg_path"], "/usr/local/tomcat/lib/catalina.jar")
        self.assertEqual(ev["layer"], "sha256:abc123456")

    # ------------------------------------------------------------------
    # TEST H — Affected version evaluation
    # ------------------------------------------------------------------
    def test_h_affected_version_evaluation(self):
        """Installed version inside a supported affected range returns AFFECTED."""
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "tomcat",
            "installed_version": "9.0.98",
            "fixed_version": "9.0.99",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)[0]
        self.assertEqual(res["version_evidence"], "AFFECTED")
        self.assertIn("AFFECTED", res["source_evidence"]["trivy"]["version_status"])
        self.assertIn("AFFECTED", res["source_evidence"]["nvd"]["version_status"])
        self.assertIn("AFFECTED", res["source_evidence"]["cve_list_v5"]["version_status"])

    # ------------------------------------------------------------------
    # TEST I — Fixed / not-affected version evaluation
    # ------------------------------------------------------------------
    def test_i_fixed_or_not_affected_version(self):
        """Installed version at or above fixed version returns NOT_AFFECTED."""
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "tomcat",
            "installed_version": "9.0.99",
            "fixed_version": "9.0.99",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)[0]
        self.assertEqual(res["version_evidence"], "NOT_AFFECTED")
        self.assertEqual(res["source_evidence"]["trivy"]["version_status"], "NOT_AFFECTED")
        self.assertEqual(res["source_evidence"]["nvd"]["version_status"], "NOT_AFFECTED")
        self.assertEqual(res["source_evidence"]["cve_list_v5"]["version_status"], "NOT_AFFECTED")

    # ------------------------------------------------------------------
    # TEST J — Unsupported version scheme
    # ------------------------------------------------------------------
    def test_j_unsupported_version_scheme_returns_unknown(self):
        """Unsupported/uncertain ecosystem semantics return UNKNOWN (no lexicographic guessing)."""
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "tomcat",
            "installed_version": "build_2025_release_beta_xyz",
            "fixed_version": "build_2025_release_beta_xyz_fixed",
            "ecosystem": "unsupported_custom_scheme"
        }
        res = self.service.evaluate_finding(finding)[0]
        self.assertEqual(res["version_evidence"], "UNKNOWN")
        self.assertIn("Unsupported", res["source_evidence"]["trivy"]["details"])

    # ------------------------------------------------------------------
    # TEST K — Multi-source provenance preserved
    # ------------------------------------------------------------------
    def test_k_provenance_preserved(self):
        """NVD, CVE List V5, and Trivy evidence remain separately identifiable."""
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "tomcat",
            "installed_version": "9.0.98",
            "fixed_version": "9.0.99",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)[0]
        src_ev = res["source_evidence"]
        self.assertIn("trivy", src_ev)
        self.assertIn("nvd", src_ev)
        self.assertIn("cve_list_v5", src_ev)

        prov = res["provenance"]
        self.assertIn("NVD", prov["database_sources"])
        self.assertIn("CVE_LIST_V5", prov["database_sources"])

    # ------------------------------------------------------------------
    # TEST L — Non-material range difference
    # ------------------------------------------------------------------
    def test_l_non_material_range_difference_not_conflict(self):
        """
        NVD: < 9.0.99. CVE List V5: >= 9.0.0.M1, <= 9.0.98.
        Installed: 9.0.98. Both conclude AFFECTED.
        Must NOT report VERSION_EVIDENCE_CONFLICT.
        """
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "tomcat",
            "installed_version": "9.0.98",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)[0]
        self.assertEqual(res["version_evidence"], "AFFECTED")
        self.assertNotEqual(res["version_evidence"], "VERSION_EVIDENCE_CONFLICT")

    # ------------------------------------------------------------------
    # TEST M — Material contradiction
    # ------------------------------------------------------------------
    def test_m_material_contradiction_detects_conflict(self):
        """One source says affected, another says not affected -> VERSION_EVIDENCE_CONFLICT."""
        mock_record = {
            "cve_id": "CVE-2025-9999",
            "sources": ["NVD", "CVE_LIST_V5"],
            "provenance": {},
            "cpe_matches": [
                {
                    "vendor": "apache", "product": "testpkg", "vulnerable": 1,
                    "version_start_including": "1.0.0", "version_end_including": "1.5.0"
                }
            ],
            "affected_versions": [
                {
                    "vendor": "apache", "product": "testpkg", "version_status": "unaffected",
                    "version_value": "1.2.0"
                }
            ]
        }

        with patch.object(self.service.db, "lookup_cve", return_value=mock_record):
            finding = {
                "scanner": "custom",
                "cve": "CVE-2025-9999",
                "package": "testpkg",
                "installed_version": "1.2.0",
                "ecosystem": "semver"
            }
            res = self.service.evaluate_finding(finding)[0]
            self.assertEqual(res["version_evidence"], "VERSION_EVIDENCE_CONFLICT")
            self.assertIn("Material version evidence conflict", res["version_evidence_reason"])

    # ------------------------------------------------------------------
    # TEST N — Nuclei shared lookup service
    # ------------------------------------------------------------------
    def test_n_nuclei_shared_lookup(self):
        """Nuclei finding uses the exact same Phase B lookup service as Trivy."""
        nuclei_finding = {
            "scanner": "nuclei",
            "template_id": "cve-2025-24813",
            "template_name": "Apache Tomcat Partial PUT",
            "severity": "HIGH",
            "cve": "CVE-2025-24813",
            "target": "http://127.0.0.1:8081",
            "package": "Apache Tomcat",
            "extracted_results": ["Apache Tomcat/9.0.98"]
        }
        res = self.service.evaluate_finding(nuclei_finding)[0]
        self.assertEqual(res["database_status"], "FOUND")
        self.assertEqual(res["canonical_cve"], "CVE-2025-24813")
        self.assertEqual(res["scanner"], "NUCLEI")
        self.assertEqual(res["version_evidence"], "AFFECTED")

    # ------------------------------------------------------------------
    # TEST O — Nuclei insufficient version
    # ------------------------------------------------------------------
    def test_o_nuclei_insufficient_version_evidence(self):
        """Nuclei finding with CVE but no version evidence returns FOUND with version_evidence=UNKNOWN."""
        nuclei_finding = {
            "scanner": "nuclei",
            "template_id": "cve-2025-24813",
            "template_name": "Apache Tomcat Partial PUT",
            "severity": "HIGH",
            "cve": "CVE-2025-24813",
            "target": "http://127.0.0.1:8081",
            "package": "Apache Tomcat",
            "extracted_results": []  # No version string extracted
        }
        res = self.service.evaluate_finding(nuclei_finding)[0]
        self.assertEqual(res["database_status"], "FOUND")
        self.assertEqual(res["version_evidence"], "UNKNOWN")
        self.assertIn("insufficient version", res["version_evidence_reason"].lower())

    # ------------------------------------------------------------------
    # TEST P — Strict network isolation
    # ------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    @patch("socket.socket")
    def test_p_network_isolation(self, mock_socket, mock_urlopen):
        """Phase B lookup/evaluation path executes with zero network calls permitted."""
        mock_urlopen.side_effect = AssertionError("Network access attempted in Phase B!")
        mock_socket.side_effect = AssertionError("Socket creation attempted in Phase B!")

        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "tomcat",
            "installed_version": "9.0.98",
            "fixed_version": "9.0.99",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["database_status"], "FOUND")
        self.assertEqual(mock_urlopen.call_count, 0)
        self.assertEqual(mock_socket.call_count, 0)

    # ------------------------------------------------------------------
    # TEST Q — Production lookup performance (< 100 ms target)
    # ------------------------------------------------------------------
    def test_q_production_lookup_performance(self):
        """Benchmark exact CVE lookup against SQLite database. Strictly verify < 100 ms."""
        bench = self.service.benchmark_exact_lookup(cve_id="CVE-2025-24813", repetitions=100)
        print("\n[PHASE B PERFORMANCE BENCHMARK RESULT]")
        print(f"Database Record Count : {bench['database_record_count']}")
        print(f"Repetitions           : {bench['repetitions']}")
        print(f"Mean Latency          : {bench['mean_latency_ms']} ms")
        print(f"P95 Latency           : {bench['p95_latency_ms']} ms")
        print(f"Target (< 100 ms)     : {'MET' if bench['target_met'] else 'NOT MET'}")

        self.assertTrue(bench["target_met"], f"P95 latency {bench['p95_latency_ms']} ms exceeded 100 ms target")
        self.assertLess(bench["mean_latency_ms"], 100.0)

    # ------------------------------------------------------------------
    # TEST R — Phase A test regression
    # ------------------------------------------------------------------
    def test_r_phase_a_regression(self):
        """Ensure all Phase A validation tests continue passing."""
        import subprocess
        res = subprocess.run(
            [sys.executable, str(current_dir / "test_cve_phase_a.py")],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"Phase A tests failed:\n{res.stderr}\n{res.stdout}")

    # ------------------------------------------------------------------
    # TEST S — Database-agent regression
    # ------------------------------------------------------------------
    def test_s_database_agent_regression(self):
        """Ensure CVEDatabaseAgent unit tests continue passing."""
        from cve_database_agent import CVEDatabaseAgent
        agent = CVEDatabaseAgent(self.db_path)
        rec = agent.lookup("CVE-2025-24813")
        self.assertIsNotNone(rec)
        self.assertIn("apache", rec["vendor"].lower())
        self.assertIn("tomcat", rec["product"].lower())

    # ------------------------------------------------------------------
    # TEST T — CVE-2025-24813 regression
    # ------------------------------------------------------------------
    def test_t_cve_2025_24813_regression(self):
        """Verify CVE-2025-24813 resolves correctly through Phase B without triggering Phase C logic."""
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "tomcat",
            "installed_version": "9.0.98",
            "fixed_version": "9.0.99",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)[0]
        self.assertEqual(res["canonical_cve"], "CVE-2025-24813")
        self.assertEqual(res["database_status"], "FOUND")
        self.assertEqual(res["version_evidence"], "AFFECTED")
        # Ensure Phase C keys are NOT present
        self.assertNotIn("applicable", res)
        self.assertNotIn("prerequisite_satisfied", res)
        self.assertNotIn("confirmed_exploitable", res)

    # ------------------------------------------------------------------
    # TEST U — Uncertain CPE-to-package mapping
    # ------------------------------------------------------------------
    def test_u_uncertain_cpe_to_package_mapping(self):
        """
        Trivy package name cannot be reliably mapped to NVD CPE product.
        NVD-derived version evidence must be held as UNKNOWN.
        System does NOT assume affected or unaffected solely from uncertain mapping.
        Original Trivy package/version evidence remains preserved.
        """
        # Construct finding with an unrelated package name that cannot map to 'tomcat' CPE
        finding = {
            "scanner": "trivy",
            "cve": "CVE-2025-24813",
            "package": "completely-unrelated-library-xyz",
            "installed_version": "9.0.98",
            "fixed_version": "9.0.99",
            "ecosystem": "maven"
        }
        res = self.service.evaluate_finding(finding)[0]

        # 1. Mapping status must be UNCERTAIN
        self.assertEqual(res["mapping_status"], "UNCERTAIN")
        self.assertIn("Uncertain or unverified CPE product", res["mapping_reason"])

        # 2. NVD-derived version evidence must be UNKNOWN
        nvd_ev = res["source_evidence"]["nvd"]
        self.assertEqual(nvd_ev["version_status"], "UNKNOWN")
        self.assertEqual(nvd_ev["mapping_status"], "UNCERTAIN")

        # 3. System does not assume AFFECTED or NOT_AFFECTED solely from NVD
        # (NVD did NOT contribute an AFFECTED determination)
        self.assertNotIn("NVD", res["version_evidence_reason"])

        # 4. Original Trivy package and version evidence remain preserved
        self.assertEqual(res["scanner_evidence"]["package_name"], "completely-unrelated-library-xyz")
        self.assertEqual(res["scanner_evidence"]["installed_version"], "9.0.98")
        self.assertEqual(res["scanner_evidence"]["fixed_version"], "9.0.99")

        # 5. Trivy's independent determination is preserved separately
        self.assertIn("trivy", res["source_evidence"])
        self.assertEqual(res["source_evidence"]["trivy"]["version_status"], "AFFECTED")


if __name__ == "__main__":
    unittest.main()
