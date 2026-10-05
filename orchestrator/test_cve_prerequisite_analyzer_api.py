"""
Test suite for the CVE Prerequisite Analyzer API endpoint.

Tests:
1. Input validation (missing CVE, invalid CVE ID format).
2. TEST 1: CVE-2025-24813 retrieval from local database (Case A: FOUND, 4 prerequisites, 1 unknown, Authoritative trust, GHSA/vendor provenance).
3. TEST 2: CVE-2020-1938 retrieval from local database (Case A: FOUND, 1 prerequisite: AJP connector active, Authoritative trust).
4. TEST 3: CVE-2026-29145 handling when no prerequisite data exists (Case C: NOT AVAILABLE, 0 prerequisites, does not invent prerequisites, clear explanation).
5. Exploitability invariant: no "EXPLOITABLE" claims are made.
"""

import unittest
import sys
from pathlib import Path

# Add backend and orchestrator to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "backend"))
sys.path.insert(0, str(project_root / "orchestrator"))

from app import app


class TestCVEPrerequisiteAnalyzerAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_01_invalid_cve_formats(self):
        """Test validation of empty or malformed CVE IDs."""
        # Empty
        res = self.client.post("/api/cve/prerequisites", json={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("CVE ID is required", data.get("error", ""))

        # Malformed
        res2 = self.client.post("/api/cve/prerequisites", json={"cve_id": "INVALID-ID"})
        self.assertEqual(res2.status_code, 400)
        data2 = res2.get_json()
        self.assertIn("Invalid CVE ID format", data2.get("error", ""))

    def test_02_cve_2025_24813_found_case_a(self):
        """TEST 1: CVE-2025-24813 returns 4 authoritative prerequisites and 1 unknown condition."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-2025-24813"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-2025-24813")
        self.assertEqual(data["case"], "CASE_A")
        self.assertEqual(data["data_status"], "FOUND")
        self.assertEqual(data["source_origin"], "LOCAL STORED DATA")
        self.assertEqual(data["extraction_status"], "SUCCESS")
        self.assertFalse(data["extraction_attempted"])

        # Check prerequisite count
        self.assertEqual(data["prerequisites_count"], 4)
        prereqs = data["prerequisites"]
        names = [p["name"] for p in prereqs]
        raw_names = [p["raw_name"] for p in prereqs]

        self.assertIn("Default Servlet writes enabled", names)
        self.assertIn("Partial PUT enabled", names)
        self.assertIn("File-based session persistence", names)
        self.assertIn("Deserialization gadget library present", names)

        self.assertIn("default_servlet_writes_enabled", raw_names)
        self.assertIn("partial_put_enabled", raw_names)
        self.assertIn("file_based_session_persistence", raw_names)
        self.assertIn("deserialization_gadget_library_present", raw_names)

        # Check trust level and required fields
        for p in prereqs:
            self.assertEqual(p["trust_level"], "Authoritative")
            self.assertTrue(p["required"])
            self.assertIn("verification_method", p)
            self.assertIn("evidence", p)
            self.assertIn("source_type", p)

        # Check unknown conditions
        self.assertEqual(data["unknown_conditions_count"], 1)
        unknowns = data["unknown_conditions"]
        self.assertEqual(unknowns[0]["name"], "Attacker knows sensitive uploaded filename")
        self.assertTrue(
            "cannot be verified" in unknowns[0]["reason"].lower() or 
            "cannot be established" in unknowns[0]["reason"].lower()
        )

        # Raw record
        self.assertIn("raw_record", data)

    def test_03_cve_2020_1938_ghostcat_case_a(self):
        """TEST 2: CVE-2020-1938 returns AJP connector active prerequisite."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-2020-1938"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-2020-1938")
        self.assertEqual(data["case"], "CASE_A")
        self.assertEqual(data["data_status"], "FOUND")
        self.assertEqual(data["source_origin"], "LOCAL STORED DATA")
        self.assertGreaterEqual(data["prerequisites_count"], 1)

        raw_names = [p["raw_name"] for p in data["prerequisites"]]
        self.assertIn("ajp_connector_active", raw_names)
        p0 = next(p for p in data["prerequisites"] if p["raw_name"] == "ajp_connector_active")
        self.assertEqual(p0["name"], "AJP connector active")
        self.assertEqual(p0["raw_name"], "ajp_connector_active")
        self.assertEqual(p0["verification_method"], "Config Collector")
        self.assertEqual(p0["trust_level"], "Authoritative")
        self.assertEqual(p0["expected_state"], "active")

    def test_04_unknown_cve_not_available_case_c(self):
        """CASE C: CVE with no stored data and no online sources reports NOT AVAILABLE."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-9999-99999"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-9999-99999")
        self.assertEqual(data["case"], "CASE_C")
        self.assertEqual(data["data_status"], "NOT AVAILABLE")
        self.assertEqual(data["source_origin"], "N/A")
        self.assertEqual(data["prerequisites_count"], 0)
        self.assertEqual(data["prerequisites"], [])
        self.assertEqual(data["unknown_conditions_count"], 0)
        self.assertTrue(data["extraction_attempted"])

        # Check reason explanation
        self.assertIn("No stored prerequisite data found", data["reason"])
        self.assertIn("No prerequisites were invented", data["reason"])

    def test_04b_cve_2026_29145_case_b(self):
        """CASE B: CVE-2026-29145 has no stored data, extracts authoritative version prerequisite via fallback."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-2026-29145"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-2026-29145")
        self.assertEqual(data["case"], "CASE_B")
        self.assertEqual(data["data_status"], "EXTRACTED")
        self.assertEqual(data["prerequisites_count"], 1)
        self.assertEqual(data["prerequisites"][0]["name"], "Software version vulnerable")
        self.assertEqual(data["authoritative_prerequisites_count"], 1)

    def test_05_exploitability_guardrail(self):
        """Invariant: Endpoint does not claim the target is EXPLOITABLE."""
        for cve in ["CVE-2025-24813", "CVE-2020-1938", "CVE-2026-29145"]:
            res = self.client.post("/api/cve/prerequisites", json={"cve_id": cve})
            text = res.get_data(as_text=True)
            self.assertNotIn('"EXPLOITABLE"', text)
            self.assertNotIn('"exploitable"', text.lower().replace("remote code execution", ""))

    def test_06_online_extraction_cve_2024_50379(self):
        """Online extraction for CVE-2024-50379 fetches GHSA/vendor and extracts authoritative preconditions."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-2024-50379", "mode": "online"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-2024-50379")
        self.assertEqual(data["case"], "ONLINE_EXTRACTION")
        self.assertEqual(data["data_status"], "EXTRACTED")
        self.assertEqual(data["extraction_status"], "EXTRACTED FROM ONLINE SOURCES")
        self.assertGreaterEqual(data["sources_retrieved"], 1)
        self.assertGreaterEqual(data["authoritative_sources"], 1)
        self.assertEqual(data["prerequisites_count"], 2)

        names = [p["name"] for p in data["prerequisites"]]
        self.assertIn("Default Servlet writes enabled", names)
        self.assertIn("Case-insensitive file system", names)

        # Check comparison with local data
        self.assertIn("comparison", data)
        comp = data["comparison"]
        self.assertTrue(comp["has_local_data"])
        self.assertIn("Default Servlet writes enabled", comp["only_online"])

    def test_07_online_extraction_cve_2026_29145_no_hallucinations(self):
        """Online extraction for CVE-2026-29145 extracts the version prerequisite without hallucinations."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-2026-29145", "mode": "online"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-2026-29145")
        self.assertEqual(data["case"], "ONLINE_EXTRACTION")
        self.assertEqual(data["data_status"], "EXTRACTED")
        self.assertEqual(data["extraction_status"], "EXTRACTED FROM ONLINE SOURCES")
        self.assertEqual(data["prerequisites_count"], 1)
        self.assertEqual(data["prerequisites"][0]["name"], "Software version vulnerable")
        self.assertEqual(data["authoritative_prerequisites_count"], 1)
        self.assertEqual(data["attack_conditions_count"], 0)

    def test_10_online_extraction_cve_2014_0224(self):
        """Online extraction for CVE-2014-0224 extracts Software version vulnerable, client/server relationship, communication, and attack conditions."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-2014-0224", "mode": "online"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-2014-0224")
        self.assertEqual(data["case"], "ONLINE_EXTRACTION")
        self.assertEqual(data["data_status"], "EXTRACTED")
        self.assertEqual(data["extraction_status"], "EXTRACTED FROM ONLINE SOURCES")
        self.assertGreaterEqual(data["prerequisites_count"], 3)
        
        names = [p["name"] for p in data["prerequisites"]]
        self.assertIn("Software version vulnerable", names)
        self.assertIn("OpenSSL-to-OpenSSL communication", names)
        self.assertIn("Vulnerable client and server relationship", names)

        self.assertGreaterEqual(data["authoritative_prerequisites_count"], 1)
        self.assertGreaterEqual(data["attack_conditions_count"], 2)

        attack_names = [a["name"] for a in data["attack_conditions"]]
        self.assertTrue(any("MITM" in a for a in attack_names))
        self.assertTrue(any("handshake" in a.lower() for a in attack_names))

        # Check applicability & dynamic validation status fields are present
        self.assertIn("applicability_status", data)
        self.assertIn("dynamic_validation_status", data)
        self.assertIn("environmental_evaluation", data)

    def test_08_online_extraction_cve_2026_24733(self):
        """Online extraction for CVE-2026-24733 extracts HEAD-allowed, GET-denied, and HTTP/0.9 attack condition."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-2026-24733", "mode": "online"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-2026-24733")
        self.assertEqual(data["case"], "ONLINE_EXTRACTION")
        self.assertEqual(data["data_status"], "EXTRACTED")
        self.assertEqual(data["extraction_status"], "EXTRACTED FROM ONLINE SOURCES")
        self.assertEqual(data["prerequisites_count"], 2)

        names = [p["name"] for p in data["prerequisites"]]
        self.assertIn("Security constraint allows HEAD", names)
        self.assertIn("Security constraint denies GET", names)

        # Attack conditions
        self.assertIn("attack_conditions", data)
        self.assertGreaterEqual(data["attack_conditions_count"], 1)
        ac_titles = [a["condition"] for a in data["attack_conditions"]]
        self.assertTrue(any("HTTP/0.9" in t and "HEAD" in t for t in ac_titles))

        ac = data["attack_conditions"][0]
        self.assertEqual(ac.get("name"), "Specification-invalid HTTP/0.9 HEAD request")
        self.assertEqual(ac.get("category"), "Request Condition")
        self.assertTrue(ac.get("required"))
        self.assertEqual(ac.get("verification_method"), "dynamic_validation")
        self.assertEqual(ac.get("trust_level"), "Authoritative")
        self.assertEqual(ac.get("confidence"), "HIGH")
        self.assertTrue(len(ac.get("evidence", "")) > 0)
        self.assertIn("HTTP/0.9", ac.get("evidence", ""))

    def test_09_online_extraction_cve_2021_3449(self):
        """Online extraction for CVE-2021-3449 extracts TLS 1.2 enabled, TLS renegotiation enabled, and ClientHello attack condition."""
        res = self.client.post("/api/cve/prerequisites", json={"cve_id": "CVE-2021-3449", "mode": "online"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["cve_id"], "CVE-2021-3449")
        self.assertEqual(data["case"], "ONLINE_EXTRACTION")
        self.assertEqual(data["data_status"], "EXTRACTED")
        self.assertEqual(data["extraction_status"], "EXTRACTED FROM ONLINE SOURCES")
        self.assertGreaterEqual(data["prerequisites_count"], 2)

        names = [p["name"] for p in data["prerequisites"]]
        self.assertIn("TLS 1.2 enabled", names)
        self.assertIn("TLS renegotiation enabled", names)

        # Check expected states
        p_tls = [p for p in data["prerequisites"] if p["name"] == "TLS 1.2 enabled"][0]
        self.assertEqual(p_tls["verification_method"], "Config Collector")
        self.assertEqual(p_tls["expected_state"], "enabled")
        self.assertEqual(p_tls["trust_level"], "Authoritative")

        # Attack conditions
        self.assertIn("attack_conditions", data)
        self.assertGreaterEqual(data["attack_conditions_count"], 1)
        ac = data["attack_conditions"][0]
        self.assertIn("ClientHello", ac["name"])
        self.assertEqual(ac["category"], "Request Condition")
        self.assertEqual(ac["verification_method"], "dynamic_validation")
        self.assertEqual(ac["trust_level"], "Authoritative")
        self.assertEqual(ac["confidence"], "HIGH")


if __name__ == "__main__":
    unittest.main()



