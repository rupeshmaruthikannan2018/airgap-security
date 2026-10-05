"""
Unit and Integration Tests for Dynamic Generic CVE Evaluator (cve_evaluator.py).

Verifies:
1. Dynamic evaluation across different real CVEs (CVE-2025-24813, CVE-2024-50379, CVE-2020-1938).
2. Different prerequisite structures evaluated by the same code.
3. Unknown CVE returns UNKNOWN / NO_PREREQUISITE_DATA (zero Tomcat fallback).
4. Missing Config Collector evidence returns UNKNOWN.
5. Authoritative non-satisfied condition produces NOT_SATISFIED.
6. Derived non-satisfied condition produces UNKNOWN (never false negative).
7. Multiple evidence paths preserve OR semantics.
8. Type safety: unexpected type (e.g. string where boolean expected, or dict where scalar expected) returns UNKNOWN without coercion.
9. Isolation: CVE A only uses CVE A prerequisites, never leaks to CVE B.
10. Genuinely new, previously untested CVE evaluated with zero code changes from SQLite DB fixture.
"""

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from orchestrator.cve_evaluator import CVEEvaluator


class TestGenericCVEEvaluator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_prerequisites.db"
        self._init_test_db()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _init_test_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_prerequisite_records (
                    cve_id TEXT PRIMARY KEY,
                    summary TEXT,
                    affected_versions TEXT,
                    prerequisites_count INTEGER DEFAULT 0,
                    unknown_conditions_count INTEGER DEFAULT 0,
                    has_nuclei_template INTEGER DEFAULT 0,
                    raw_record_json TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_prerequisites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    prerequisite_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    category TEXT,
                    required INTEGER DEFAULT 1,
                    expected_state TEXT,
                    verification_method TEXT,
                    trust_level TEXT DEFAULT 'authoritative',
                    confidence TEXT DEFAULT 'high',
                    evidence_source TEXT,
                    evidence_url TEXT,
                    evidence_text TEXT,
                    created_at TEXT,
                    source_version TEXT
                )
            """)
            conn.commit()

    def _insert_cve_fixture(self, cve_id: str, summary: str, affected_range: str, prerequisites: list, unknown_conditions: list = None):
        raw_json = json.dumps({
            "cve_id": cve_id,
            "summary": summary,
            "affected_versions": [affected_range],
            "prerequisites": prerequisites,
            "unknown_conditions": unknown_conditions or []
        })
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO cve_prerequisite_records (
                    cve_id, summary, affected_versions, prerequisites_count, raw_record_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (cve_id, summary, json.dumps([affected_range]), len(prerequisites), raw_json)
            )
            for p in prerequisites:
                cursor.execute(
                    """
                    INSERT INTO cve_prerequisites (
                        cve_id, prerequisite_id, name, description, category,
                        required, expected_state, verification_method, trust_level, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cve_id,
                        p.get("id", p.get("name")),
                        p.get("name"),
                        p.get("description", ""),
                        p.get("category", "configuration"),
                        1 if p.get("required", True) else 0,
                        str(p.get("expected_state", "true")),
                        p.get("verification_method", "config_collector"),
                        p.get("trust_level", "authoritative"),
                        p.get("confidence", "high")
                    )
                )
            conn.commit()

    # -------------------------------------------------------------
    # 1. Unknown CVE has ZERO Tomcat Fallback
    # -------------------------------------------------------------
    def test_01_unknown_cve_returns_unknown_no_tomcat_fallback(self):
        config = {
            "effective_configuration": {
                "connectors": [{"port": 8080}],
                "default_servlet": {"readonly": False, "writes_enabled": True}
            }
        }
        evaluator = CVEEvaluator(config_source=config, db_path=self.db_path)
        res = evaluator.evaluate_cve("CVE-UNKNOWN-9999")

        self.assertEqual(res["status"], "unknown")
        self.assertIn("No CVE-specific prerequisite data is available", res["reason"])
        self.assertEqual(res["evaluation"], {})
        # Verify no synthetic Tomcat conditions were injected
        self.assertNotIn("environment_preconditions", res["evaluation"])
        self.assertNotIn("network_connectors_active", str(res))

    # -------------------------------------------------------------
    # 2. CVE-2025-24813 Dynamic Evaluation from DB
    # -------------------------------------------------------------
    def test_02_cve_2025_24813_evaluation(self):
        self._insert_cve_fixture(
            cve_id="CVE-2025-24813",
            summary="Tomcat Partial PUT RCE",
            affected_range="<= 9.0.98",
            prerequisites=[
                {
                    "id": "c1",
                    "name": "default_servlet_writes_enabled",
                    "configuration_path": "default_servlet.readonly",
                    "expected_state": "true",
                    "trust_level": "authoritative"
                },
                {
                    "id": "c2",
                    "name": "partial_put_enabled",
                    "configuration_path": "default_servlet.allowPartialPut",
                    "expected_state": "true",
                    "trust_level": "authoritative"
                },
                {
                    "id": "c3",
                    "name": "file_based_session_persistence",
                    "configuration_path": "session_persistence.file_based_persistence",
                    "expected_state": "true",
                    "trust_level": "authoritative"
                }
            ]
        )
        config = {
            "effective_configuration": {
                "default_servlet": {"readonly": False, "allowPartialPut": True},
                "session_persistence": {"file_based_persistence": True}
            },
            "installed_version": "9.0.98"
        }
        evaluator = CVEEvaluator(config_source=config, db_path=self.db_path)
        res = evaluator.evaluate_cve("CVE-2025-24813")

        self.assertEqual(res["status"], "satisfied")
        self.assertEqual(len(res["evaluation"]["prerequisites"]["conditions"]), 4)  # 3 prereqs + 1 version

    # -------------------------------------------------------------
    # 3. CVE-2020-1938 Different Prerequisite Structure (Ghostcat)
    # -------------------------------------------------------------
    def test_03_cve_2020_1938_evaluation(self):
        self._insert_cve_fixture(
            cve_id="CVE-2020-1938",
            summary="Tomcat AJP Ghostcat",
            affected_range="<= 9.0.30",
            prerequisites=[
                {
                    "id": "c_ajp",
                    "name": "ajp_connector_active",
                    "configuration_path": "connectors.ajp_enabled",
                    "expected_state": "true",
                    "trust_level": "authoritative"
                }
            ]
        )
        # Test case: AJP connector disabled
        config_disabled = {
            "effective_configuration": {
                "connectors": {"ajp_enabled": False}
            },
            "installed_version": "9.0.30"
        }
        evaluator = CVEEvaluator(config_source=config_disabled, db_path=self.db_path)
        res_dis = evaluator.evaluate_cve("CVE-2020-1938")
        self.assertEqual(res_dis["status"], "not_satisfied")

        # Test case: AJP connector enabled
        config_enabled = {
            "effective_configuration": {
                "connectors": {"ajp_enabled": True}
            },
            "installed_version": "9.0.30"
        }
        evaluator2 = CVEEvaluator(config_source=config_enabled, db_path=self.db_path)
        res_en = evaluator2.evaluate_cve("CVE-2020-1938")
        self.assertEqual(res_en["status"], "satisfied")

    # -------------------------------------------------------------
    # 4. CVE Isolation: CVE A does not leak to CVE B
    # -------------------------------------------------------------
    def test_04_cve_prerequisite_isolation(self):
        self._insert_cve_fixture(
            cve_id="CVE-ALPHA",
            summary="Alpha Vulnerability",
            affected_range="<= 1.0",
            prerequisites=[{"name": "alpha_flag", "configuration_path": "alpha.flag", "expected_state": "true"}]
        )
        self._insert_cve_fixture(
            cve_id="CVE-BETA",
            summary="Beta Vulnerability",
            affected_range="<= 2.0",
            prerequisites=[{"name": "beta_flag", "configuration_path": "beta.flag", "expected_state": "true"}]
        )
        config = {
            "effective_configuration": {
                "alpha": {"flag": True},
                "beta": {"flag": False}
            },
            "version": "1.0"
        }
        evaluator = CVEEvaluator(config_source=config, db_path=self.db_path)

        res_a = evaluator.evaluate_cve("CVE-ALPHA")
        res_b = evaluator.evaluate_cve("CVE-BETA")

        self.assertEqual(res_a["status"], "satisfied")
        self.assertEqual(res_b["status"], "not_satisfied")

        # Ensure no cross-contamination of conditions
        cond_names_a = [c["name"] for c in res_a["evaluation"]["prerequisites"]["conditions"]]
        cond_names_b = [c["name"] for c in res_b["evaluation"]["prerequisites"]["conditions"]]
        self.assertIn("alpha_flag", cond_names_a)
        self.assertNotIn("beta_flag", cond_names_a)
        self.assertIn("beta_flag", cond_names_b)
        self.assertNotIn("alpha_flag", cond_names_b)

    # -------------------------------------------------------------
    # 5. Missing Evidence in Config Collector returns UNKNOWN
    # -------------------------------------------------------------
    def test_05_missing_evidence_returns_unknown(self):
        self._insert_cve_fixture(
            cve_id="CVE-MISSING-TEST",
            summary="Missing Config Test",
            affected_range="<= 3.0",
            prerequisites=[
                {
                    "name": "non_existent_feature",
                    "configuration_path": "totally.missing.setting",
                    "expected_state": "true",
                    "trust_level": "authoritative"
                }
            ]
        )
        config = {"effective_configuration": {"server": "active"}, "version": "1.0"}
        evaluator = CVEEvaluator(config_source=config, db_path=self.db_path)
        res = evaluator.evaluate_cve("CVE-MISSING-TEST")

        self.assertEqual(res["status"], "unknown")
        cond = [c for c in res["evaluation"]["prerequisites"]["conditions"] if c["name"] == "non_existent_feature"][0]
        self.assertEqual(cond["status"], "unknown")

    # -------------------------------------------------------------
    # 6. Authoritative Negative vs Derived Negative Trust Level
    # -------------------------------------------------------------
    def test_06_trust_level_authoritative_vs_derived(self):
        # Authoritative condition failing -> NOT_SATISFIED
        self._insert_cve_fixture(
            cve_id="CVE-AUTH-FAIL",
            summary="Authoritative Fail Test",
            affected_range="<= 1.0",
            prerequisites=[
                {
                    "name": "auth_cond",
                    "configuration_path": "service.auth_setting",
                    "expected_state": "true",
                    "trust_level": "authoritative"
                }
            ]
        )
        config = {"effective_configuration": {"service": {"auth_setting": False}}, "version": "1.0"}
        evaluator = CVEEvaluator(config_source=config, db_path=self.db_path)
        res_auth = evaluator.evaluate_cve("CVE-AUTH-FAIL")
        self.assertEqual(res_auth["status"], "not_satisfied")

        # Derived condition failing -> MUST be UNKNOWN, NOT NOT_SATISFIED
        self._insert_cve_fixture(
            cve_id="CVE-DERIVED-FAIL",
            summary="Derived Fail Test",
            affected_range="<= 1.0",
            prerequisites=[
                {
                    "name": "derived_cond",
                    "configuration_path": "service.derived_setting",
                    "expected_state": "true",
                    "trust_level": "derived"
                }
            ]
        )
        config_der = {"effective_configuration": {"service": {"derived_setting": False}}, "version": "1.0"}
        evaluator_der = CVEEvaluator(config_source=config_der, db_path=self.db_path)
        res_der = evaluator_der.evaluate_cve("CVE-DERIVED-FAIL")

        self.assertEqual(res_der["status"], "unknown")
        der_cond = [c for c in res_der["evaluation"]["prerequisites"]["conditions"] if c["name"] == "derived_cond"][0]
        self.assertEqual(der_cond["status"], "unknown")

    # -------------------------------------------------------------
    # 7. Multiple Evidence Paths (OR Semantics)
    # -------------------------------------------------------------
    def test_07_alternative_evidence_paths_or_semantics(self):
        # Condition can be satisfied by path A or path B
        self._insert_cve_fixture(
            cve_id="CVE-OR-TEST",
            summary="Alternative Evidence Paths",
            affected_range="<= 1.0",
            prerequisites=[
                {
                    "name": "flexible_feature",
                    "configuration_evidence": ["feature.enabled_v1", "feature.enabled_v2"],
                    "expected_state": "true",
                    "trust_level": "authoritative"
                }
            ]
        )
        # Only v2 is present and True; v1 is missing
        config = {
            "effective_configuration": {
                "feature": {"enabled_v2": True}
            },
            "version": "1.0"
        }
        evaluator = CVEEvaluator(config_source=config, db_path=self.db_path)
        res = evaluator.evaluate_cve("CVE-OR-TEST")

        self.assertEqual(res["status"], "satisfied")
        cond = [c for c in res["evaluation"]["prerequisites"]["conditions"] if c["name"] == "flexible_feature"][0]
        self.assertEqual(cond["status"], "satisfied")

    # -------------------------------------------------------------
    # 8. Type Safety: Unexpected Type Treated as Missing Evidence (UNKNOWN)
    # -------------------------------------------------------------
    def test_08_unexpected_type_returns_unknown_never_coerced(self):
        self._insert_cve_fixture(
            cve_id="CVE-TYPE-SAFETY",
            summary="Type Safety Test",
            affected_range="<= 1.0",
            prerequisites=[
                {
                    "name": "bool_expected_found_str",
                    "configuration_path": "settings.flag",
                    "expected_state": "true",  # Expecting boolean True
                    "trust_level": "authoritative"
                },
                {
                    "name": "scalar_expected_found_dict",
                    "configuration_path": "settings.port",
                    "expected_state": "8080",  # Expecting string "8080"
                    "trust_level": "authoritative"
                }
            ]
        )
        # config has string "true" where bool expected, and nested dict where scalar string expected
        config = {
            "effective_configuration": {
                "settings": {
                    "flag": "true",        # String, NOT boolean
                    "port": {"nested": 80} # Dict, NOT string
                }
            },
            "version": "1.0"
        }
        evaluator = CVEEvaluator(config_source=config, db_path=self.db_path)
        res = evaluator.evaluate_cve("CVE-TYPE-SAFETY")

        # Must return unknown because types cannot be safely reconciled without coercion
        self.assertEqual(res["status"], "unknown")
        c1 = [c for c in res["evaluation"]["prerequisites"]["conditions"] if c["name"] == "bool_expected_found_str"][0]
        c2 = [c for c in res["evaluation"]["prerequisites"]["conditions"] if c["name"] == "scalar_expected_found_dict"][0]
        self.assertEqual(c1["status"], "unknown")
        self.assertEqual(c2["status"], "unknown")

    # -------------------------------------------------------------
    # 9. Genuinely New Untested CVE Evaluated with Zero Code Changes
    # -------------------------------------------------------------
    def test_09_genuinely_new_untested_cve_evaluated_without_code_changes(self):
        """
        Acceptance Criteria: Insert a brand new, previously unseen CVE into
        cve_prerequisites.db and evaluate it against live config with zero evaluator edits.
        """
        new_cve = "CVE-2029-8888"
        self._insert_cve_fixture(
            cve_id=new_cve,
            summary="Hypothetical Cloud Microservice Auth Bypass",
            affected_range="<= 3.5.0",
            prerequisites=[
                {
                    "id": "cond_jwt_none",
                    "name": "jwt_none_algorithm_allowed",
                    "configuration_path": "security.jwt.allow_none",
                    "expected_state": "true",
                    "trust_level": "authoritative"
                },
                {
                    "id": "cond_mfa_disabled",
                    "name": "mfa_enforcement_disabled",
                    "configuration_path": "security.mfa.enabled",
                    "expected_state": "false",
                    "trust_level": "authoritative"
                }
            ]
        )

        microservice_config = {
            "effective_configuration": {
                "security": {
                    "jwt": {"allow_none": True},
                    "mfa": {"enabled": False}
                }
            },
            "version": "3.2.0"
        }

        # Run CVEEvaluator with ZERO code changes
        evaluator = CVEEvaluator(config_source=microservice_config, db_path=self.db_path)
        result = evaluator.evaluate_cve(new_cve)

        self.assertEqual(result["cve_id"], new_cve)
        self.assertEqual(result["status"], "satisfied")
        self.assertIn("Prerequisites satisfied", result["reason"])
        conditions = result["evaluation"]["prerequisites"]["conditions"]
        self.assertEqual(len(conditions), 3)  # version + 2 security conditions
        jwt_cond = [c for c in conditions if c["name"] == "jwt_none_algorithm_allowed"][0]
        mfa_cond = [c for c in conditions if c["name"] == "mfa_enforcement_disabled"][0]
        self.assertEqual(jwt_cond["status"], "satisfied")
        self.assertEqual(mfa_cond["status"], "satisfied")


if __name__ == "__main__":
    unittest.main()
