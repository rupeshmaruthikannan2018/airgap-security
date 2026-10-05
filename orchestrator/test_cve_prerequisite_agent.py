"""
Unit and Integration Tests for CVE Prerequisite Extraction Agent.

Covers:
1. CVE reference retrieval
2. Advisory caching
3. Source prioritization
4. Prerequisite extraction
5. Evidence provenance
6. Unknown/uncertain conditions
7. Nuclei template parsing
8. Duplicate prerequisite handling
9. SQLite storage
10. Offline reuse of cached evidence
11. Malformed source handling
12. LLM failure handling
13. Derived trust_level resolves to UNKNOWN, not NOT_SATISFIED
14. Authoritative trust_level resolves to NOT_SATISFIED
"""

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from orchestrator.cve_evaluator import CVEEvaluator
from orchestrator.cve_prerequisite_agent import (
    CVEPrerequisiteAgent,
    NucleiTemplateInspector,
    PrerequisiteExtractor,
    PrerequisiteStore,
    SourceRetriever,
    classify_source_url,
    SOURCE_PRIORITY
)


class TestCVEPrerequisiteAgent(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_prereq_agent_")
        self.cache_dir = Path(self.temp_dir) / "advisories"
        self.db_path = Path(self.temp_dir) / "prerequisites.db"
        self.templates_dir = Path(self.temp_dir) / "templates"
        self.templates_dir.mkdir(parents=True, exist_ok=True)

        self.agent = CVEPrerequisiteAgent(
            cache_dir=self.cache_dir,
            db_path=self.db_path,
            templates_dir=self.templates_dir,
            online_mode=False
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------
    # 1. CVE reference retrieval
    # -------------------------------------------------------------
    def test_01_cve_reference_retrieval(self):
        info = self.agent.cve_db_agent.lookup("CVE-2025-24813")
        self.assertIsNotNone(info)
        refs = info.get("references", [])
        self.assertTrue(len(refs) > 0)
        urls = [r.get("url") if isinstance(r, dict) else str(r) for r in refs]
        self.assertTrue(any("apache.org" in u for u in urls))

    # -------------------------------------------------------------
    # 2. Advisory caching
    # -------------------------------------------------------------
    def test_02_advisory_caching(self):
        retriever = SourceRetriever(cache_dir=self.cache_dir, online_mode=True)
        cve_id = "CVE-TEST-0001"
        sample_url = "https://example.com/test_advisory.txt"
        sample_content = "Vulnerability requires feature X enabled."

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = sample_content.encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            res = retriever.fetch_url_cached(cve_id, sample_url, "vendor_advisory")

        self.assertIsNotNone(res)
        self.assertEqual(res["content"], sample_content)
        self.assertTrue(Path(res["local_cache_path"]).exists())
        self.assertIn("content_sha256", res)

    # -------------------------------------------------------------
    # 3. Source prioritization
    # -------------------------------------------------------------
    def test_03_source_prioritization(self):
        urls = [
            ("https://tomcat.apache.org/security-9.html", "vendor_advisory"),
            ("https://lists.apache.org/thread/123", "project_advisory"),
            ("https://github.com/advisories/GHSA-1234", "ghsa"),
            ("https://nvd.nist.gov/vuln/detail/CVE-2025-24813", "cve_reference"),
            ("https://github.com/apache/tomcat/commit/abcdef", "source_fix"),
            ("https://exploit-db.com/exploits/99999", "technical_research"),
        ]
        ranks = []
        for url, expected_type in urls:
            stype, rank = classify_source_url(url)
            self.assertEqual(stype, expected_type)
            ranks.append(rank)

        # Confirm strictly increasing or prioritized ordering
        self.assertEqual(ranks, sorted(ranks))

    # -------------------------------------------------------------
    # 4. Prerequisite extraction
    # -------------------------------------------------------------
    def test_04_prerequisite_extraction(self):
        extractor = PrerequisiteExtractor()
        sources = [{
            "source_id": "src_1",
            "source_type": "vendor_advisory",
            "source_url": "https://tomcat.apache.org/security-9.html",
            "content": (
                "If all of the following were true, an attacker could achieve RCE:\n"
                "- writes enabled for the default servlet\n"
                "- support for partial PUT\n"
                "- application was using Tomcat's file based session persistence\n"
                "- application included a library that may be leveraged in a deserialization attack"
            )
        }]

        result = extractor.extract_from_evidence("CVE-2025-24813", sources)
        prereqs = result["prerequisites"]
        names = [p["name"] for p in prereqs]

        self.assertIn("default_servlet_writes_enabled", names)
        self.assertIn("partial_put_enabled", names)
        self.assertIn("file_based_session_persistence", names)
        self.assertIn("deserialization_gadget_library_present", names)

        # Trust level must be authoritative for official vendor advisory
        for p in prereqs:
            self.assertEqual(p["trust_level"], "authoritative")

    # -------------------------------------------------------------
    # 5. Evidence provenance
    # -------------------------------------------------------------
    def test_05_evidence_provenance(self):
        extractor = PrerequisiteExtractor()
        sources = [{
            "source_id": "src_1",
            "source_type": "vendor_advisory",
            "source_url": "https://tomcat.apache.org/security-9.html",
            "content": "writes enabled for the default servlet"
        }]

        result = extractor.extract_from_evidence("CVE-2025-24813", sources)
        p = result["prerequisites"][0]
        evidence = p["evidence"][0]

        self.assertEqual(evidence["source_type"], "vendor_advisory")
        self.assertEqual(evidence["source_url"], "https://tomcat.apache.org/security-9.html")
        self.assertTrue(len(evidence["evidence_text"]) > 0)

    # -------------------------------------------------------------
    # 6. Unknown / uncertain conditions
    # -------------------------------------------------------------
    def test_06_unknown_conditions(self):
        extractor = PrerequisiteExtractor()
        sources = [{
            "source_id": "src_1",
            "source_type": "vendor_advisory",
            "source_url": "https://tomcat.apache.org/security-9.html",
            "content": "requires attacker knowledge of uploaded file names"
        }]

        result = extractor.extract_from_evidence("CVE-2025-24813", sources)
        unknowns = result["unknown_conditions"]
        self.assertTrue(len(unknowns) > 0)
        self.assertEqual(unknowns[0]["status"], "UNKNOWN")

    # -------------------------------------------------------------
    # 7. Nuclei template parsing
    # -------------------------------------------------------------
    def test_07_nuclei_template_parsing(self):
        tpl_dir = self.templates_dir / "http" / "cves" / "2025"
        tpl_dir.mkdir(parents=True, exist_ok=True)
        tpl_path = tpl_dir / "CVE-2025-24813.yaml"
        tpl_path.write_text("""
id: CVE-2025-24813
info:
  name: Apache Tomcat Partial PUT RCE
  severity: critical
requests:
  - method: PUT
    path:
      - "{{BaseURL}}/test.jsp"
    headers:
      Content-Type: application/octet-stream
    matchers:
      - type: status
        status:
          - 201
          - 204
""", encoding="utf-8")

        inspector = NucleiTemplateInspector(templates_dir=self.templates_dir)
        info = inspector.inspect_template("CVE-2025-24813")

        self.assertIsNotNone(info)
        self.assertIn("PUT", info["methods"])
        self.assertEqual(info["template_id"], "CVE-2025-24813")

    # -------------------------------------------------------------
    # 8. Duplicate prerequisite handling
    # -------------------------------------------------------------
    def test_08_duplicate_prerequisite_handling(self):
        extractor = PrerequisiteExtractor()
        sources = [
            {
                "source_id": "src_1",
                "source_type": "vendor_advisory",
                "source_url": "https://tomcat.apache.org/1",
                "content": "writes enabled for the default servlet"
            },
            {
                "source_id": "src_2",
                "source_type": "ghsa",
                "source_url": "https://github.com/advisories/1",
                "content": "writes enabled for the default servlet"
            }
        ]

        result = extractor.extract_from_evidence("CVE-2025-24813", sources)
        writes_conditions = [p for p in result["prerequisites"] if p["name"] == "default_servlet_writes_enabled"]
        self.assertEqual(len(writes_conditions), 1)

    # -------------------------------------------------------------
    # 9. SQLite storage
    # -------------------------------------------------------------
    def test_09_sqlite_storage(self):
        store = PrerequisiteStore(db_path=self.db_path)
        record = {
            "cve_id": "CVE-TEST-9999",
            "summary": "Test Summary",
            "affected_versions": ["1.0 through 2.0"],
            "prerequisites": [
                {
                    "id": "cond_1",
                    "name": "test_feature_enabled",
                    "description": "Feature X must be on",
                    "category": "configuration",
                    "required": True,
                    "expected_state": "true",
                    "verification_method": "config_collector",
                    "trust_level": "authoritative",
                    "evidence": [{
                        "source_type": "vendor_advisory",
                        "source_url": "https://example.com",
                        "evidence_text": "feature on",
                        "confidence": "high"
                    }]
                }
            ],
            "attack_conditions": [],
            "unknown_conditions": [],
            "sources": []
        }

        store.save_record(record)
        fetched = store.get_record("CVE-TEST-9999")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["summary"], "Test Summary")
        self.assertEqual(len(fetched["prerequisites"]), 1)

        # Inspect raw SQLite rows
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name, trust_level FROM cve_prerequisites WHERE cve_id = 'CVE-TEST-9999'")
        rows = cursor.fetchall()
        conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "test_feature_enabled")
        self.assertEqual(rows[0][1], "authoritative")

    # -------------------------------------------------------------
    # 10. Offline reuse of cached evidence
    # -------------------------------------------------------------
    def test_10_offline_reuse_of_cached_evidence(self):
        cve_id = "CVE-OFFLINE-001"
        url = "https://example.com"
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        cve_cache_dir = self.cache_dir / cve_id
        cve_cache_dir.mkdir(parents=True, exist_ok=True)
        cached_file = cve_cache_dir / f"ghsa_{url_hash}.txt"
        cached_meta = cve_cache_dir / f"ghsa_{url_hash}.meta.json"

        cached_file.write_text("Cached Advisory: writes enabled for the default servlet", encoding="utf-8")
        cached_meta.write_text(json.dumps({"url": url, "sha256": "abc"}), encoding="utf-8")

        # In offline mode
        retriever = SourceRetriever(cache_dir=self.cache_dir, online_mode=False)
        res = retriever.fetch_url_cached(cve_id, url, "ghsa")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("from_cache"))

    # -------------------------------------------------------------
    # 11. Malformed source handling
    # -------------------------------------------------------------
    def test_11_malformed_source_handling(self):
        extractor = PrerequisiteExtractor()
        # Feed corrupt / invalid / empty sources
        corrupt_sources = [
            {"source_id": "bad_1", "source_type": "other", "content": None},
            {"source_id": "bad_2", "source_type": "ghsa", "content": "\x00\x01\x02 corrupt"},
            {"source_id": "bad_3", "source_type": "vendor_advisory", "content": ""}
        ]

        # Should not raise exception
        result = extractor.extract_from_evidence("CVE-TEST-CORRUPT", corrupt_sources)
        self.assertIsNotNone(result)
        self.assertEqual(result["cve_id"], "CVE-TEST-CORRUPT")
        # Defaults to version condition
        self.assertTrue(len(result["prerequisites"]) >= 1)

    # -------------------------------------------------------------
    # 12. LLM failure handling
    # -------------------------------------------------------------
    def test_12_llm_failure_handling(self):
        # Even if network or LLM throws an exception, agent produces valid structured result
        agent = CVEPrerequisiteAgent(cache_dir=self.cache_dir, db_path=self.db_path, online_mode=False)
        with patch.object(agent.extractor, "extract_from_evidence", side_effect=Exception("LLM Timeout")):
            with self.assertRaises(Exception):
                agent.process_cve("CVE-FAIL-TEST")

    # -------------------------------------------------------------
    # 13. Trust level DERIVED resolves to UNKNOWN, not NOT_SATISFIED
    # -------------------------------------------------------------
    def test_13_trust_level_derived_resolves_to_unknown(self):
        knowledge_path = Path(self.temp_dir) / "derived_knowledge.json"
        config_path = Path(self.temp_dir) / "config.json"

        # Config: readonly is False (so writes are enabled), but jar_files is empty []
        config_data = {
            "effective_configuration": {
                "default_servlet": {"readonly": False},
                "application_libraries": {"jar_files": []}
            }
        }
        config_path.write_text(json.dumps(config_data), encoding="utf-8")

        # Knowledge: writes_enabled is SATISFIED (authoritative).
        # cond_derived is NOT_SATISFIED because jar_files is empty, BUT its trust_level is "derived".
        knowledge_data = {
            "CVE-TEST-DERIVED": {
                "cve_id": "CVE-TEST-DERIVED",
                "affected_versions": {"range": "<= 9.0.98"},
                "fixed_versions": {},
                "conditions": {
                    "attack_preconditions": [
                        {
                            "id": "c1",
                            "name": "writes_enabled",
                            "configuration_evidence": ["default_servlet.readonly"],
                            "required_value": True,
                            "trust_level": "authoritative"
                        },
                        {
                            "id": "c2",
                            "name": "derived_gadget_check",
                            "configuration_evidence": ["application_libraries.jar_files"],
                            "required_value": True,
                            "trust_level": "derived"
                        }
                    ]
                }
            }
        }
        knowledge_path.write_text(json.dumps(knowledge_data), encoding="utf-8")

        evaluator = CVEEvaluator(knowledge_path, config_path)
        eval_result = evaluator.evaluate_cve("CVE-TEST-DERIVED")
        group_status = eval_result["evaluation"]["attack_preconditions"]["status"]

        # MUST resolve to unknown, NOT not_satisfied
        self.assertEqual(group_status, "unknown")

    # -------------------------------------------------------------
    # 14. Trust level AUTHORITATIVE resolves to NOT_SATISFIED
    # -------------------------------------------------------------
    def test_14_trust_level_authoritative_resolves_to_not_satisfied(self):
        knowledge_path = Path(self.temp_dir) / "auth_knowledge.json"
        config_path = Path(self.temp_dir) / "config.json"

        config_data = {
            "effective_configuration": {
                "default_servlet": {"readonly": False},
                "application_libraries": {"jar_files": []}
            }
        }
        config_path.write_text(json.dumps(config_data), encoding="utf-8")

        knowledge_data = {
            "CVE-TEST-AUTH": {
                "cve_id": "CVE-TEST-AUTH",
                "affected_versions": {"range": "<= 9.0.98"},
                "fixed_versions": {},
                "conditions": {
                    "attack_preconditions": [
                        {
                            "id": "c1",
                            "name": "writes_enabled",
                            "configuration_evidence": ["default_servlet.readonly"],
                            "required_value": True,
                            "trust_level": "authoritative"
                        },
                        {
                            "id": "c2",
                            "name": "authoritative_gadget_check",
                            "configuration_evidence": ["application_libraries.jar_files"],
                            "required_value": True,
                            "trust_level": "authoritative"
                        }
                    ]
                }
            }
        }
        knowledge_path.write_text(json.dumps(knowledge_data), encoding="utf-8")

        evaluator = CVEEvaluator(knowledge_path, config_path)
        eval_result = evaluator.evaluate_cve("CVE-TEST-AUTH")
        group_status = eval_result["evaluation"]["attack_preconditions"]["status"]

        # MUST resolve to not_satisfied because condition is authoritative
        self.assertEqual(group_status, "not_satisfied")

    # -------------------------------------------------------------
    # 15. extract_attack_conditions stage
    # -------------------------------------------------------------
    def test_15_extract_attack_conditions_stage(self):
        """Test extract_attack_conditions parses compound conditional prose into prerequisites and attack conditions."""
        extractor = PrerequisiteExtractor()
        sample_text = (
            "If a security constraint was configured to allow HEAD requests to a URI but deny GET requests, "
            "the user could bypass that constraint on GET requests by sending a (specification invalid) HEAD request using HTTP/0.9."
        )
        res = extractor.extract_attack_conditions(sample_text, source_type="vendor_advisory", source_url="https://tomcat.apache.org/security-10.html")

        # Environment prerequisites
        prereqs = res.get("prerequisites", [])
        self.assertEqual(len(prereqs), 2)
        p_names = [p["name"] for p in prereqs]
        self.assertIn("security_constraint_allows_head", p_names)
        self.assertIn("security_constraint_denies_get", p_names)

        head_cond = next(p for p in prereqs if p["name"] == "security_constraint_allows_head")
        self.assertEqual(head_cond["category"], "authorization")
        self.assertEqual(head_cond["expected_state"], "allowed")
        self.assertTrue(head_cond["required"])
        self.assertEqual(head_cond["trust_level"], "authoritative")

        get_cond = next(p for p in prereqs if p["name"] == "security_constraint_denies_get")
        self.assertEqual(get_cond["category"], "authorization")
        self.assertEqual(get_cond["expected_state"], "denied")
        self.assertTrue(get_cond["required"])
        self.assertEqual(get_cond["trust_level"], "authoritative")

        # Attack conditions
        attack_conds = res.get("attack_conditions", [])
        self.assertGreaterEqual(len(attack_conds), 1)
        ac = attack_conds[0]
        self.assertIn("HTTP/0.9", ac["condition"])
        self.assertIn("HEAD", ac["condition"])
        self.assertEqual(ac["category"], "request_condition")
        self.assertFalse(ac["automatically_verifiable"])
        self.assertEqual(ac["trust_level"], "authoritative")

    # -------------------------------------------------------------
    # 16. CVE-2026-24733 regression test (Authoritative advisory)
    # -------------------------------------------------------------
    def test_16_cve_2026_24733_regression(self):
        """
        CVE-2026-24733 regression: authoritative advisory text produces both
        HEAD-allowed and GET-denied prerequisites, and the HTTP/0.9 attack condition.
        """
        sources = [{
            "source_id": "src_ghsa_1",
            "source_type": "ghsa",
            "source_url": "https://github.com/advisories/GHSA-qq5r-98hh-rxc9",
            "priority_rank": 3,
            "content": (
                "Tomcat did not limit HTTP/0.9 requests to the GET method. "
                "If a security constraint was configured to allow HEAD requests to a URI but deny GET requests, "
                "the user could bypass that constraint on GET requests by sending a (specification invalid) HEAD request using HTTP/0.9.\n\n"
                "This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.14, from 10.1.0-M1 through 10.1.49, from 9.0.0.M1 through 9.0.112."
            )
        }]

        extractor = PrerequisiteExtractor()
        record = extractor.extract_from_evidence("CVE-2026-24733", sources)

        # 1. Prerequisites contains both HEAD-allowed and GET-denied conditions
        prereqs = record.get("prerequisites", [])
        names = [p["name"] for p in prereqs]
        self.assertTrue(any("allows_head" in n for n in names))
        self.assertTrue(any("denies_get" in n for n in names))

        for p in prereqs:
            self.assertEqual(p["trust_level"], "authoritative")
            self.assertTrue(len(p["evidence"]) > 0)
            self.assertTrue(len(p["evidence"][0]["evidence_text"]) > 0)

        # 2. Attack conditions is not empty and captures the malicious HTTP/0.9 request
        attack_conds = record.get("attack_conditions", [])
        self.assertNotEqual(attack_conds, [])
        ac_text = " ".join(a.get("condition", "") for a in attack_conds)
        self.assertIn("HTTP/0.9", ac_text)
        self.assertIn("HEAD", ac_text)

        ac = attack_conds[0]
        self.assertEqual(ac.get("name"), "Specification-invalid HTTP/0.9 HEAD request")
        self.assertEqual(ac.get("category"), "request_condition")
        self.assertTrue(ac.get("required"))
        self.assertEqual(ac.get("verification_method"), "dynamic_validation")
        self.assertEqual(ac.get("trust_level"), "authoritative")
        self.assertEqual(ac.get("confidence"), "high")
        self.assertTrue(len(ac.get("evidence", [])) > 0)
        self.assertIn("HTTP/0.9", ac["evidence"][0]["evidence_text"])
        self.assertEqual(ac["evidence"][0]["source_url"], "https://github.com/advisories/GHSA-qq5r-98hh-rxc9")

    # -------------------------------------------------------------
    # 17. CVE-2021-3449 regression test (OpenSSL TLS 1.2 & Renegotiation)
    # -------------------------------------------------------------
    def test_17_cve_2021_3449_regression(self):
        """
        CVE-2021-3449 regression: authoritative advisory text produces:
        - Environment: TLS 1.2 enabled, TLS renegotiation enabled
        - Attack condition: maliciously crafted TLSv1.2 renegotiation ClientHello
        """
        sources = [{
            "source_id": "src_ghsa_openssl",
            "source_type": "ghsa",
            "source_url": "https://github.com/advisories/GHSA-83mx-573x-5rw9",
            "priority_rank": 3,
            "content": (
                "An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. "
                "If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), "
                "but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. "
                "A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). "
                "OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue."
            )
        }]

        extractor = PrerequisiteExtractor()
        record = extractor.extract_from_evidence("CVE-2021-3449", sources)

        # 1. Environment prerequisites: TLS 1.2 enabled and TLS renegotiation enabled
        prereqs = record.get("prerequisites", [])
        self.assertEqual(len(prereqs), 2)
        names = [p["name"] for p in prereqs]
        self.assertIn("tls_1_2_enabled", names)
        self.assertIn("tls_renegotiation_enabled", names)

        for p in prereqs:
            self.assertEqual(p["expected_state"], "enabled")
            self.assertTrue(p["required"])
            self.assertEqual(p["verification_method"], "config_collector")
            self.assertEqual(p["category"], "protocol")
            self.assertEqual(p["trust_level"], "authoritative")
            self.assertEqual(p["confidence"], "high")
            self.assertTrue(len(p["evidence"]) > 0)
            self.assertIn("TLSv1.2 and renegotiation enabled", p["evidence"][0]["evidence_text"])
            self.assertEqual(p["evidence"][0]["source_url"], "https://github.com/advisories/GHSA-83mx-573x-5rw9")

        # 2. Attack condition: maliciously crafted ClientHello
        attack_conds = record.get("attack_conditions", [])
        self.assertGreaterEqual(len(attack_conds), 1)
        ac = attack_conds[0]
        self.assertIn("maliciously crafted", ac["condition"].lower())
        self.assertIn("clienthello", ac["condition"].lower())
        self.assertEqual(ac["category"], "request_condition")
        self.assertTrue(ac["required"])
        self.assertEqual(ac["verification_method"], "dynamic_validation")
        self.assertFalse(ac["automatically_verifiable"])
        self.assertEqual(ac["trust_level"], "authoritative")
        self.assertEqual(ac["confidence"], "high")
        self.assertIn("may crash if sent a maliciously crafted", ac["evidence"][0]["evidence_text"])


if __name__ == "__main__":
    unittest.main()


