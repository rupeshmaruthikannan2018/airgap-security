"""
Regression Test Suite for Generic CVE Prerequisite Extraction & Deterministic Evaluation Pipeline.

Covers:
1. CVE with only a version prerequisite (Satisfied / Not Satisfied / Missing).
2. CVE with configuration prerequisites.
3. CVE with multiple AND prerequisites.
4. CVE with alternative OR conditions / vectors.
5. CVE with environmental + attack conditions (Attack conditions preserved separately).
6. CVE with contextual / network conditions (endpoint_inventory, network_context).
7. CVE where prerequisite evidence is missing (Missing evidence = UNKNOWN).
8. CVE with no prerequisite data.
9. Unsupported verification method (e.g. manual_review without evidence -> UNKNOWN).
10. Malformed / unexpected evidence types (strict type safety -> UNKNOWN).
11. End-to-end pipeline test for CVE-2014-0224 without hardcoded logic.
"""

import unittest
from orchestrator.cve_evaluator import CVEEvaluator, is_version_affected
from orchestrator.cve_prerequisite_agent import CVEPrerequisiteAgent, PrerequisiteExtractor


class TestGenericConditionEvaluation(unittest.TestCase):

    # 1. CVE with only a version prerequisite
    def test_version_only_cve(self):
        cve_record = {
            "cve_id": "CVE-TEST-VER",
            "product": "OpenSSL",
            "affected_versions": {"range": "< 1.0.1h"},
            "prerequisites": [
                {
                    "id": "cond_ver",
                    "name": "software_version_vulnerable",
                    "category": "version",
                    "required": True,
                    "expected_state": "< 1.0.1h",
                    "verification_method": "version_check"
                }
            ]
        }

        # Case A: Installed version 1.0.1g -> SATISFIED -> APPLICABLE
        evaluator_sat = CVEEvaluator(config_source={"openssl": {"version": "1.0.1g"}})
        res_sat = evaluator_sat.evaluate_cve(cve_record)
        self.assertEqual(res_sat["applicability_status"], "APPLICABLE")
        self.assertEqual(res_sat["version_evaluation"]["status"], "satisfied")

        # Case B: Installed version 1.0.1h -> NOT_SATISFIED -> NOT_APPLICABLE
        evaluator_not = CVEEvaluator(config_source={"openssl": {"version": "1.0.1h"}})
        res_not = evaluator_not.evaluate_cve(cve_record)
        self.assertEqual(res_not["applicability_status"], "NOT_APPLICABLE")
        self.assertEqual(res_not["version_evaluation"]["status"], "not_satisfied")

        # Case C: Installed version unavailable -> UNKNOWN -> UNKNOWN
        evaluator_unk = CVEEvaluator(config_source={})
        res_unk = evaluator_unk.evaluate_cve(cve_record)
        self.assertEqual(res_unk["applicability_status"], "UNKNOWN")
        self.assertEqual(res_unk["version_evaluation"]["status"], "unknown")

    # 2. CVE with configuration prerequisites
    def test_configuration_prerequisites(self):
        cve_record = {
            "cve_id": "CVE-TEST-CFG",
            "affected_versions": {"range": "all"},
            "prerequisites": [
                {
                    "id": "cond_readonly",
                    "name": "readonly_mode_disabled",
                    "category": "configuration",
                    "configuration_evidence": ["server.readonly"],
                    "required_value": False,
                    "required": True,
                    "verification_method": "config_collector"
                }
            ]
        }

        # Configuration matches requirement: readonly = False
        eval_match = CVEEvaluator(config_source={"server": {"readonly": False}, "version": "1.0.0"})
        res_match = eval_match.evaluate_cve(cve_record)
        self.assertEqual(res_match["applicability_status"], "APPLICABLE")

        # Configuration does not match: readonly = True
        eval_mismatch = CVEEvaluator(config_source={"server": {"readonly": True}, "version": "1.0.0"})
        res_mismatch = eval_mismatch.evaluate_cve(cve_record)
        self.assertEqual(res_mismatch["applicability_status"], "NOT_APPLICABLE")

    # 3. CVE with multiple AND prerequisites
    def test_multiple_and_prerequisites(self):
        cve_record = {
            "cve_id": "CVE-TEST-AND",
            "affected_versions": {"range": "< 2.0.0"},
            "prerequisites": [
                {
                    "id": "c1",
                    "name": "tls_1_2_enabled",
                    "configuration_evidence": ["tls.v1_2"],
                    "required_value": True,
                    "required": True,
                    "verification_method": "config_collector"
                },
                {
                    "id": "c2",
                    "name": "renegotiation_enabled",
                    "configuration_evidence": ["tls.renegotiation"],
                    "required_value": True,
                    "required": True,
                    "verification_method": "config_collector"
                }
            ]
        }

        # All satisfied -> APPLICABLE
        eval_all = CVEEvaluator(config_source={
            "version": "1.9.0",
            "tls": {"v1_2": True, "renegotiation": True}
        })
        self.assertEqual(eval_all.evaluate_cve(cve_record)["applicability_status"], "APPLICABLE")

        # One NOT_SATISFIED -> NOT_APPLICABLE
        eval_fail = CVEEvaluator(config_source={
            "version": "1.9.0",
            "tls": {"v1_2": True, "renegotiation": False}
        })
        self.assertEqual(eval_fail.evaluate_cve(cve_record)["applicability_status"], "NOT_APPLICABLE")

        # One UNKNOWN, none NOT_SATISFIED -> UNKNOWN
        eval_unk = CVEEvaluator(config_source={
            "version": "1.9.0",
            "tls": {"v1_2": True}  # renegotiation missing
        })
        self.assertEqual(eval_unk.evaluate_cve(cve_record)["applicability_status"], "UNKNOWN")

    # 4. CVE with alternative OR conditions
    def test_alternative_or_conditions(self):
        cve_record = {
            "cve_id": "CVE-TEST-OR",
            "affected_versions": {"range": "< 3.0.0"},
            "conditions": {
                "vector_a": [
                    {
                        "id": "va_1",
                        "name": "port_8080_exposed",
                        "configuration_evidence": ["ports.http_8080"],
                        "required_value": True,
                        "required": True
                    }
                ],
                "vector_b": [
                    {
                        "id": "vb_1",
                        "name": "ajp_connector_active",
                        "configuration_evidence": ["connectors.ajp"],
                        "required_value": True,
                        "required": True
                    }
                ]
            }
        }

        # Vector A satisfied, Vector B not satisfied -> overall APPLICABLE (alternative vector available)
        eval_one = CVEEvaluator(config_source={
            "version": "2.5.0",
            "ports": {"http_8080": True},
            "connectors": {"ajp": False}
        })
        self.assertEqual(eval_one.evaluate_cve(cve_record)["applicability_status"], "APPLICABLE")

        # Both vectors not satisfied -> NOT_APPLICABLE
        eval_none = CVEEvaluator(config_source={
            "version": "2.5.0",
            "ports": {"http_8080": False},
            "connectors": {"ajp": False}
        })
        self.assertEqual(eval_none.evaluate_cve(cve_record)["applicability_status"], "NOT_APPLICABLE")

        # Vector A not satisfied, Vector B missing evidence -> UNKNOWN
        eval_part = CVEEvaluator(config_source={
            "version": "2.5.0",
            "ports": {"http_8080": False}
        })
        self.assertEqual(eval_part.evaluate_cve(cve_record)["applicability_status"], "UNKNOWN")

    # 5. CVE with environmental + attack conditions
    def test_environmental_and_attack_conditions(self):
        cve_record = {
            "cve_id": "CVE-TEST-ENV-ATTACK",
            "affected_versions": {"range": "< 5.0.0"},
            "prerequisites": [
                {
                    "id": "c_env",
                    "name": "debug_mode_enabled",
                    "configuration_evidence": ["app.debug"],
                    "required_value": True,
                    "required": True,
                    "category": "configuration",
                    "verification_method": "config_collector"
                }
            ],
            "attack_conditions": [
                {
                    "name": "Attacker must have network access",
                    "category": "attacker_capability",
                    "verification_method": "dynamic_validation",
                    "required": True
                },
                {
                    "name": "Attacker sends crafted serialized payload",
                    "category": "request_condition",
                    "verification_method": "dynamic_validation",
                    "required": True
                }
            ]
        }

        evaluator = CVEEvaluator(config_source={
            "version": "4.1.0",
            "app": {"debug": True}
        })
        res = evaluator.evaluate_cve(cve_record)

        # Environmental conditions decide applicability
        self.assertEqual(res["applicability_status"], "APPLICABLE")
        # Attack conditions are preserved in their own separate layer
        self.assertEqual(len(res["attack_conditions"]), 2)
        # Attack conditions do NOT turn applicability into NOT_APPLICABLE
        self.assertNotEqual(res["applicability_status"], "NOT_APPLICABLE")

    # 6. CVE with contextual / network conditions
    def test_contextual_network_conditions(self):
        cve_record = {
            "cve_id": "CVE-TEST-CONTEXT",
            "affected_versions": {"range": "all"},
            "prerequisites": [
                {
                    "id": "c_ctx",
                    "name": "peer_to_peer_tls_communication",
                    "category": "network_context",
                    "expected_state": "active",
                    "verification_method": "endpoint_inventory",
                    "required": True
                }
            ]
        }

        # Evidence provided via endpoint_inventory
        eval_ctx = CVEEvaluator(config_source={
            "version": "1.0.0",
            "endpoint_inventory": {
                "peer_to_peer_tls_communication": True
            }
        })
        res = eval_ctx.evaluate_cve(cve_record)
        self.assertEqual(res["applicability_status"], "APPLICABLE")
        cond = [c for c in res["environmental_conditions"] if c["name"] == "peer_to_peer_tls_communication"][0]
        self.assertEqual(cond["status"], "satisfied")

    # 7. CVE where prerequisite evidence is missing
    def test_prerequisite_evidence_missing(self):
        cve_record = {
            "cve_id": "CVE-TEST-MISSING",
            "affected_versions": {"range": "< 2.0.0"},
            "prerequisites": [
                {
                    "id": "c_missing",
                    "name": "uncommon_feature_enabled",
                    "configuration_evidence": ["features.uncommon_module"],
                    "required_value": True,
                    "required": True,
                    "verification_method": "config_collector"
                }
            ]
        }

        evaluator = CVEEvaluator(config_source={"version": "1.0.0"})
        res = evaluator.evaluate_cve(cve_record)

        # Missing evidence MUST yield UNKNOWN (never inferred as satisfied or not satisfied)
        self.assertEqual(res["applicability_status"], "UNKNOWN")
        cond = [c for c in res["environmental_conditions"] if c["name"] == "uncommon_feature_enabled"][0]
        self.assertEqual(cond["status"], "unknown")

    # 8. CVE with no prerequisite data
    def test_no_prerequisite_data(self):
        evaluator = CVEEvaluator(config_source={"version": "1.0.0"})
        res = evaluator.evaluate_cve("CVE-9999-99999")

        self.assertEqual(res["applicability_status"], "UNKNOWN")
        self.assertEqual(res["dynamic_validation_status"], "NO_DYNAMIC_TEST_AVAILABLE")
        self.assertEqual(len(res["environmental_conditions"]), 0)

    # 9. Unsupported verification method
    def test_unsupported_verification_method(self):
        cve_record = {
            "cve_id": "CVE-TEST-UNSUPPORTED",
            "affected_versions": {"range": "all"},
            "prerequisites": [
                {
                    "id": "c_manual",
                    "name": "requires_source_code_inspection",
                    "category": "manual_review",
                    "verification_method": "manual_review",
                    "required": True,
                    "expected_state": "true"
                }
            ]
        }

        evaluator = CVEEvaluator(config_source={})
        res = evaluator.evaluate_cve(cve_record)

        # Unsupported verification method with missing evidence yields UNKNOWN
        self.assertEqual(res["applicability_status"], "UNKNOWN")
        cond = [c for c in res["environmental_conditions"] if c["name"] == "requires_source_code_inspection"][0]
        self.assertEqual(cond["status"], "unknown")

    # 10. Malformed / unexpected evidence types (strict type safety)
    def test_malformed_evidence_type_safety(self):
        cve_record = {
            "cve_id": "CVE-TEST-MALFORMED",
            "affected_versions": {"range": "all"},
            "prerequisites": [
                {
                    "id": "c_bool",
                    "name": "boolean_expected_condition",
                    "configuration_evidence": ["app.flag"],
                    "required_value": True,
                    "required": True
                }
            ]
        }

        # Value in config is a nested dict or string instead of expected boolean
        evaluator = CVEEvaluator(config_source={"app": {"flag": {"unexpected": "object"}}})
        res = evaluator.evaluate_cve(cve_record)

        # Strict type safety: no coercion, treat as UNKNOWN
        self.assertEqual(res["applicability_status"], "UNKNOWN")
        cond = [c for c in res["environmental_conditions"] if c["name"] == "boolean_expected_condition"][0]
        self.assertEqual(cond["status"], "unknown")

    # 11. CVE-2014-0224 regression verification
    def test_cve_2014_0224_generic_pipeline(self):
        agent = CVEPrerequisiteAgent(online_mode=False)
        extracted = agent.process_cve("CVE-2014-0224", save_to_db=False)

        prereq_names = [p["name"] for p in extracted.get("prerequisites", [])]
        self.assertIn("software_version_vulnerable", prereq_names)
        self.assertIn("openssl_to_openssl_communication", prereq_names)
        # Assert that vulnerable_client_and_server_relationship is marked strictly required=True
        rel_cond = [p for p in extracted.get("prerequisites", []) if p["name"] == "vulnerable_client_and_server_relationship"][0]
        self.assertTrue(rel_cond.get("required", False))
        self.assertEqual(rel_cond.get("category"), "client_server_relationship")
        self.assertEqual(rel_cond.get("trust_level"), "authoritative")

        # Attack conditions separation check
        attack_names = [a["name"] for a in extracted.get("attack_conditions", [])]
        self.assertTrue(any("mitm" in a.lower() for a in attack_names))
        self.assertTrue(any("handshake" in a.lower() for a in attack_names))

        # Scenario A: OpenSSL 1.0.1g is vulnerable, communication present, but relationship evidence MISSING
        # "Required but unverifiable" MUST produce UNKNOWN, never APPLICABLE or required=false
        config_missing_rel = {
            "openssl": {"version": "1.0.1g"},
            "endpoint_inventory": {
                "openssl_to_openssl_communication": True
                # vulnerable_client_and_server_relationship is absent/missing
            }
        }
        eval_missing = CVEEvaluator(config_source=config_missing_rel)
        res_missing = eval_missing.evaluate_cve(extracted)
        cond_missing = [c for c in res_missing["environmental_conditions"] if c["name"] == "vulnerable_client_and_server_relationship"][0]
        self.assertTrue(cond_missing["required"])
        self.assertEqual(cond_missing["status"], "unknown")
        self.assertEqual(res_missing["applicability_status"], "UNKNOWN")

        # Scenario B: Target evidence confirms both endpoints are vulnerable -> APPLICABLE
        config_satisfied = {
            "openssl": {"version": "1.0.1g"},
            "endpoint_inventory": {
                "openssl_to_openssl_communication": True,
                "vulnerable_client_and_server_relationship": True
            }
        }
        eval_sat = CVEEvaluator(config_source=config_satisfied)
        res_sat = eval_sat.evaluate_cve(extracted)
        cond_sat = [c for c in res_sat["environmental_conditions"] if c["name"] == "vulnerable_client_and_server_relationship"][0]
        self.assertTrue(cond_sat["required"])
        self.assertEqual(cond_sat["status"], "satisfied")
        self.assertEqual(res_sat["applicability_status"], "APPLICABLE")

        # Scenario C: Target evidence confirms client is NOT vulnerable -> NOT_SATISFIED -> NOT_APPLICABLE
        config_not_satisfied_rel = {
            "openssl": {"version": "1.0.1g"},
            "endpoint_inventory": {
                "openssl_to_openssl_communication": True,
                "vulnerable_client_and_server_relationship": False
            }
        }
        eval_not_sat = CVEEvaluator(config_source=config_not_satisfied_rel)
        res_not_sat = eval_not_sat.evaluate_cve(extracted)
        cond_not_sat = [c for c in res_not_sat["environmental_conditions"] if c["name"] == "vulnerable_client_and_server_relationship"][0]
        self.assertTrue(cond_not_sat["required"])
        self.assertEqual(cond_not_sat["status"], "not_satisfied")
        self.assertEqual(res_not_sat["applicability_status"], "NOT_APPLICABLE")

        # Scenario D: Patched server OpenSSL 1.0.1h -> version NOT_SATISFIED -> NOT_APPLICABLE
        config_patched = {
            "openssl": {"version": "1.0.1h"},
            "endpoint_inventory": {
                "openssl_to_openssl_communication": True,
                "vulnerable_client_and_server_relationship": True
            }
        }
        eval_patched = CVEEvaluator(config_source=config_patched)
        res_patched = eval_patched.evaluate_cve(extracted)
        self.assertEqual(res_patched["applicability_status"], "NOT_APPLICABLE")

    # 12. Diverse Scenario 3: Version + Feature Enabled (e.g. protocol extension / compression / heartbeat)
    def test_scenario_03_version_plus_feature_enabled(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-FEATURE",
            "product": "WebEngine",
            "affected_versions": {"range": "< 4.5.0"},
            "prerequisites": [
                {
                    "id": "f_1",
                    "name": "tls_heartbeat_extension_enabled",
                    "category": "feature",
                    "required": True,
                    "expected_state": "enabled",
                    "configuration_evidence": ["tls.heartbeat_extension"],
                    "required_value": True,
                    "verification_method": "config_collector"
                }
            ]
        }

        # Case 1: Version vulnerable + Feature enabled -> SATISFIED + SATISFIED -> APPLICABLE
        eval_app = CVEEvaluator(config_source={"version": "4.4.1", "tls": {"heartbeat_extension": True}})
        res_app = eval_app.evaluate_cve(cve_record)
        self.assertEqual(res_app["applicability_status"], "APPLICABLE")

        # Case 2: Version vulnerable + Feature disabled -> SATISFIED + NOT_SATISFIED -> NOT_APPLICABLE
        eval_not = CVEEvaluator(config_source={"version": "4.4.1", "tls": {"heartbeat_extension": False}})
        res_not = eval_not.evaluate_cve(cve_record)
        self.assertEqual(res_not["applicability_status"], "NOT_APPLICABLE")

        # Case 3: Version vulnerable + Feature UNKNOWN (no config evidence) -> SATISFIED + UNKNOWN -> UNKNOWN
        eval_unk = CVEEvaluator(config_source={"version": "4.4.1"})
        res_unk = eval_unk.evaluate_cve(cve_record)
        self.assertEqual(res_unk["applicability_status"], "UNKNOWN")

    # 13. Diverse Scenario 6: Client/Server & Peer Relationship Condition
    def test_scenario_06_client_server_relationship(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-RELATIONSHIP",
            "affected_versions": {"range": "all"},
            "prerequisites": [
                {
                    "id": "rel_1",
                    "name": "vulnerable_client_and_server_relationship",
                    "category": "client_server_relationship",
                    "required": True,
                    "expected_state": "vulnerable_endpoints",
                    "configuration_evidence": ["endpoint_inventory.vulnerable_client_and_server_relationship"],
                    "required_value": True,
                    "verification_method": "endpoint_inventory"
                }
            ]
        }

        # Confirmed communicating endpoints are both vulnerable -> APPLICABLE
        eval_rel_ok = CVEEvaluator(config_source={
            "version": "1.0",
            "endpoint_inventory": {"vulnerable_client_and_server_relationship": True}
        })
        self.assertEqual(eval_rel_ok.evaluate_cve(cve_record)["applicability_status"], "APPLICABLE")

        # Confirmed client endpoint is patched / not vulnerable -> NOT_APPLICABLE
        eval_rel_no = CVEEvaluator(config_source={
            "version": "1.0",
            "endpoint_inventory": {"vulnerable_client_and_server_relationship": False}
        })
        self.assertEqual(eval_rel_no.evaluate_cve(cve_record)["applicability_status"], "NOT_APPLICABLE")

        # Endpoint relationship evidence missing -> UNKNOWN (Never false/not applicable)
        eval_rel_unk = CVEEvaluator(config_source={"version": "1.0"})
        self.assertEqual(eval_rel_unk.evaluate_cve(cve_record)["applicability_status"], "UNKNOWN")

    # 14. Diverse Scenario 7: Network Exposure / Context Condition
    def test_scenario_07_network_exposure_context(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-EXPOSURE",
            "affected_versions": {"range": "< 2.0"},
            "prerequisites": [
                {
                    "id": "net_exp",
                    "name": "management_interface_exposed_to_untrusted_network",
                    "category": "network_exposure",
                    "required": True,
                    "expected_state": "exposed",
                    "configuration_evidence": ["network_exposure.management_interface_exposed_to_untrusted_network"],
                    "required_value": True,
                    "verification_method": "network_exposure"
                }
            ]
        }

        # Evidence: Interface exposed to untrusted network -> APPLICABLE
        eval_exp = CVEEvaluator(config_source={
            "version": "1.8",
            "network_exposure": {"management_interface_exposed_to_untrusted_network": True}
        })
        self.assertEqual(eval_exp.evaluate_cve(cve_record)["applicability_status"], "APPLICABLE")

        # Evidence: Interface strictly bound to localhost / internal only -> NOT_APPLICABLE
        eval_no_exp = CVEEvaluator(config_source={
            "version": "1.8",
            "network_exposure": {"management_interface_exposed_to_untrusted_network": False}
        })
        self.assertEqual(eval_no_exp.evaluate_cve(cve_record)["applicability_status"], "NOT_APPLICABLE")

    # 15. Diverse Scenario 8: Dependency / Library Condition
    def test_scenario_08_dependency_library_condition(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-DEPENDENCY",
            "affected_versions": {"range": "< 3.0"},
            "prerequisites": [
                {
                    "id": "dep_1",
                    "name": "vulnerable_codec_library_present",
                    "category": "dependency",
                    "required": True,
                    "expected_state": "present",
                    "configuration_evidence": ["dependencies.vulnerable_codec_library_present"],
                    "required_value": True,
                    "verification_method": "dependency_check"
                }
            ]
        }

        # Library present in classpath / lib dir -> APPLICABLE
        eval_dep = CVEEvaluator(config_source={
            "version": "2.5",
            "dependencies": {"vulnerable_codec_library_present": True}
        })
        self.assertEqual(eval_dep.evaluate_cve(cve_record)["applicability_status"], "APPLICABLE")

        # Library verified absent from runtime classpath -> NOT_APPLICABLE
        eval_no_dep = CVEEvaluator(config_source={
            "version": "2.5",
            "dependencies": {"vulnerable_codec_library_present": False}
        })
        self.assertEqual(eval_no_dep.evaluate_cve(cve_record)["applicability_status"], "NOT_APPLICABLE")

    # 16. Diverse Scenario 9: Filesystem / OS Condition
    def test_scenario_09_filesystem_os_condition(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-FS",
            "affected_versions": {"range": "< 10.0"},
            "prerequisites": [
                {
                    "id": "fs_1",
                    "name": "case_insensitive_file_system",
                    "category": "filesystem",
                    "required": True,
                    "expected_state": "true",
                    "configuration_evidence": ["environment.filesystem_case_insensitive"],
                    "required_value": True,
                    "verification_method": "config_collector"
                }
            ]
        }

        # OS is Windows / macOS with case-insensitive filesystem -> APPLICABLE
        eval_fs = CVEEvaluator(config_source={
            "version": "9.0",
            "environment": {"filesystem_case_insensitive": True}
        })
        self.assertEqual(eval_fs.evaluate_cve(cve_record)["applicability_status"], "APPLICABLE")

        # OS is Linux ext4 case-sensitive filesystem -> NOT_APPLICABLE
        eval_fs_linux = CVEEvaluator(config_source={
            "version": "9.0",
            "environment": {"filesystem_case_insensitive": False}
        })
        self.assertEqual(eval_fs_linux.evaluate_cve(cve_record)["applicability_status"], "NOT_APPLICABLE")

    # 17. Diverse Scenario 10: Service / Connector Condition
    def test_scenario_10_service_connector_condition(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-CONNECTOR",
            "affected_versions": {"range": "all"},
            "prerequisites": [
                {
                    "id": "conn_1",
                    "name": "ajp_connector_active",
                    "category": "service",
                    "required": True,
                    "expected_state": "active",
                    "configuration_evidence": ["connectors.ajp_active"],
                    "required_value": True,
                    "verification_method": "service_inventory"
                }
            ]
        }

        # AJP connector listener active on port 8009 -> APPLICABLE
        eval_conn = CVEEvaluator(config_source={
            "version": "1.0",
            "connectors": {"ajp_active": True}
        })
        self.assertEqual(eval_conn.evaluate_cve(cve_record)["applicability_status"], "APPLICABLE")

        # AJP connector disabled in server config -> NOT_APPLICABLE
        eval_no_conn = CVEEvaluator(config_source={
            "version": "1.0",
            "connectors": {"ajp_active": False}
        })
        self.assertEqual(eval_no_conn.evaluate_cve(cve_record)["applicability_status"], "NOT_APPLICABLE")

    # 18. Diverse Scenario 11: Runtime / Application State Condition
    def test_scenario_11_runtime_application_state(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-RUNTIME",
            "affected_versions": {"range": "< 6.0"},
            "prerequisites": [
                {
                    "id": "rt_1",
                    "name": "file_based_session_persistence",
                    "category": "application_state",
                    "required": True,
                    "expected_state": "active",
                    "configuration_evidence": ["session_persistence.file_based_persistence"],
                    "required_value": True,
                    "verification_method": "config_collector"
                }
            ]
        }

        # Target uses StandardManager file-based persistence -> APPLICABLE
        eval_rt = CVEEvaluator(config_source={
            "version": "5.5",
            "session_persistence": {"file_based_persistence": True}
        })
        self.assertEqual(eval_rt.evaluate_cve(cve_record)["applicability_status"], "APPLICABLE")

        # Target uses Redis / JDBC cluster persistence -> NOT_APPLICABLE
        eval_no_rt = CVEEvaluator(config_source={
            "version": "5.5",
            "session_persistence": {"file_based_persistence": False}
        })
        self.assertEqual(eval_no_rt.evaluate_cve(cve_record)["applicability_status"], "NOT_APPLICABLE")

    # 19. Diverse Scenario 12: Attack Conditions Separate From Environment
    def test_scenario_12_attack_condition_separation(self):
        agent = CVEPrerequisiteAgent(online_mode=False)
        sample_advisory = (
            "A vulnerability exists in SuperService when HTTP/2 multiplexing is enabled. "
            "To exploit this vulnerability, a man-in-the-middle attacker must transmit a crafted "
            "SETTINGS frame followed by a malformed DATA payload during the initial handshake."
        )
        extracted = agent.extractor.extract_attack_conditions(sample_advisory)

        # Environmental prerequisite: HTTP/2 multiplexing enabled
        prereq_names = [p["name"] for p in extracted["prerequisites"]]
        self.assertTrue(any("http_2" in p or "multiplexing" in p for p in prereq_names))
        for p in extracted["prerequisites"]:
            # Environmental conditions are evaluated against target config
            self.assertIn(p["category"], ("feature", "protocol", "configuration"))
            self.assertEqual(p["verification_method"], "config_collector")

        # Attack conditions: MITM positioning, crafted SETTINGS frame
        attack_conds = extracted["attack_conditions"]
        self.assertGreaterEqual(len(attack_conds), 1)
        for a in attack_conds:
            self.assertIn(a["category"], ("request_condition", "attacker_capability", "attacker_condition"))
            self.assertEqual(a["verification_method"], "dynamic_validation")
            self.assertFalse(a.get("automatically_verifiable", True))

    # 20. Diverse Scenario 13: CVE With No Additional Environmental Prerequisite
    def test_scenario_13_no_additional_environmental_prerequisite(self):
        agent = CVEPrerequisiteAgent(online_mode=False)
        simple_cve = "CVE-2026-99999"
        sources = [{
            "source_id": "src_nvd",
            "source_type": "cve_reference",
            "source_url": "https://nvd.nist.gov/detail",
            "content": "SuperApp before 3.2.1 allows buffer overflow via long command arguments."
        }]
        res = agent.extractor.extract_from_evidence(simple_cve, sources, cve_summary="SuperApp before 3.2.1 buffer overflow")
        prereqs = res["prerequisites"]
        # Version condition should be the only prerequisite extracted
        self.assertEqual(len(prereqs), 1)
        self.assertEqual(prereqs[0]["name"], "software_version_vulnerable")
        self.assertEqual(prereqs[0]["category"], "version")

    # 21. Diverse Scenario 14: CVE With Insufficient Evidence -> UNKNOWN
    def test_scenario_14_insufficient_evidence_yields_unknown(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-UNVERIFIED",
            "affected_versions": {"range": "< 2.0.0"},
            "prerequisites": [
                {
                    "id": "p_req",
                    "name": "custom_internal_audit_module_loaded",
                    "category": "module",
                    "required": True,
                    "expected_state": "loaded",
                    "configuration_evidence": ["modules.custom_audit_loaded"],
                    "required_value": True,
                    "verification_method": "dependency_check"
                }
            ]
        }

        # Target evidence does not contain modules.custom_audit_loaded
        evaluator = CVEEvaluator(config_source={"version": "1.5.0"})
        res = evaluator.evaluate_cve(cve_record)

        # Missing evidence MUST yield UNKNOWN (never NOT_SATISFIED, never SATISFIED)
        self.assertEqual(res["applicability_status"], "UNKNOWN")
        cond = [c for c in res["environmental_conditions"] if c["name"] == "custom_internal_audit_module_loaded"][0]
        self.assertTrue(cond["required"])
        self.assertEqual(cond["status"], "unknown")

    # 22. Diverse Scenario 15: CVE Dynamic Nuclei Validation Separation
    def test_scenario_15_dynamic_nuclei_validation_separation(self):
        # Case A1: No dynamic test available for this CVE
        cve_no_dyn = {
            "cve_id": "CVE-GENERIC-NO-DYN",
            "affected_versions": {"range": "< 5.0"},
            "prerequisites": [
                {
                    "id": "p1",
                    "name": "debug_console_active",
                    "category": "service",
                    "required": True,
                    "configuration_evidence": ["app.debug_console"],
                    "required_value": True
                }
            ]
        }
        eval_no_dyn = CVEEvaluator(config_source={"version": "4.0", "app": {"debug_console": True}})
        res_no_dyn = eval_no_dyn.evaluate_cve(cve_no_dyn)
        self.assertEqual(res_no_dyn["applicability_status"], "APPLICABLE")
        self.assertEqual(res_no_dyn["dynamic_validation_status"], "NO_DYNAMIC_TEST_AVAILABLE")

        # Case A2: Dynamic probe defined, but no dynamic test was run -> APPLICABLE + UNDETERMINED
        cve_record = {
            "cve_id": "CVE-GENERIC-DYNAMIC",
            "affected_versions": {"range": "< 5.0"},
            "prerequisites": [
                {
                    "id": "p1",
                    "name": "debug_console_active",
                    "category": "service",
                    "required": True,
                    "configuration_evidence": ["app.debug_console"],
                    "required_value": True
                }
            ],
            "attack_conditions": [
                {
                    "name": "Dynamic exploit probe",
                    "category": "request_condition",
                    "verification_method": "dynamic_validation"
                }
            ]
        }
        eval_static = CVEEvaluator(config_source={"version": "4.0", "app": {"debug_console": True}})
        res_static = eval_static.evaluate_cve(cve_record)
        self.assertEqual(res_static["applicability_status"], "APPLICABLE")
        self.assertEqual(res_static["dynamic_validation_status"], "UNDETERMINED")

        # Case B: Applicable + Dynamic test CONFIRMED
        eval_dyn = CVEEvaluator(
            config_source={
                "version": "4.0",
                "app": {"debug_console": True},
                "dynamic_validation": {"CVE-GENERIC-DYNAMIC": {"confirmed": True}}
            }
        )
        res_dyn = eval_dyn.evaluate_cve(cve_record)
        self.assertEqual(res_dyn["applicability_status"], "APPLICABLE")
        self.assertEqual(res_dyn["dynamic_validation_status"], "CONFIRMED")

        # Case C: Not Applicable (patched version) + Dynamic finding present -> NOT_APPLICABLE
        # Environmental determinism takes precedence over dynamic false-positive
        eval_patched = CVEEvaluator(
            config_source={
                "version": "5.1",
                "app": {"debug_console": True},
                "dynamic_validation": {"CVE-GENERIC-DYNAMIC": {"confirmed": True}}
            }
        )
        res_patched = eval_patched.evaluate_cve(cve_record)
        self.assertEqual(res_patched["applicability_status"], "NOT_APPLICABLE")

    # 23. Linguistic Condition Extraction Across Diverse Grammars
    def test_generic_linguistic_diversity(self):
        agent = CVEPrerequisiteAgent(online_mode=False)

        # Clause A: "permits an RCE on case insensitive file systems when the default servlet is enabled for write"
        adv_1 = "Vulnerability permits an RCE on case insensitive file systems when the default servlet is enabled for write."
        res_1 = agent.extractor.extract_attack_conditions(adv_1)
        names_1 = [p["name"] for p in res_1["prerequisites"]]
        self.assertIn("case_insensitive_file_system", names_1)
        self.assertIn("default_servlet_writes_enabled", names_1)

        # Clause B: "only vulnerable if the server has HTTP/2 and zlib compression enabled"
        adv_2 = "A server is only vulnerable if the server has HTTP/2 and zlib compression enabled."
        res_2 = agent.extractor.extract_attack_conditions(adv_2)
        names_2 = [p["name"] for p in res_2["prerequisites"]]
        self.assertTrue(any("compression" in n for n in names_2))

        # Clause C: "requires that both client and server communicate using TLSv1.3"
        adv_3 = "Exploitation can only be performed between a vulnerable client and a vulnerable server."
        res_3 = agent.extractor.extract_attack_conditions(adv_3)
        names_3 = [p["name"] for p in res_3["prerequisites"]]
        self.assertIn("vulnerable_client_and_server_relationship", names_3)

        # Clause D: Alternative OR clauses
        adv_4 = "Only exploitable if either port 8080 is exposed or AJP connector is active."
        res_4 = agent.extractor.extract_attack_conditions(adv_4)
        for p in res_4["prerequisites"]:
            self.assertEqual(p.get("logical_operator"), "OR")
            self.assertIsNotNone(p.get("alternative_group"))

    # 24. CVE-2014-0160 End-to-End Generic Pipeline Regression (Items A through I)
    def test_cve_2014_0160_generic_pipeline(self):
        """
        Regression test for CVE-2014-0160 verifying:
        A. Version prerequisite remains (category=version, required=true, trust_level=authoritative)
        B. Authoritative source evidence referring to TLS/DTLS Heartbeat Extension is detected
        C. Extractor determines applicability condition from evidence (flaw in extension handling / workaround)
        D. Normalized as environment prerequisite with generic category (protocol/feature) without hardcoding
        E. Crafted packet buffer-over-read remains an ATTACK CONDITION, not environment prereq
        F. Nuclei template remains DYNAMIC VALIDATION, not attack condition or environment prereq
        G. Source provenance preserved (irrelevant sources marked is_relevant=False)
        H. Missing target evidence yields UNKNOWN, not NOT_SATISFIED
        I. Missing config key does not make authoritative prerequisite disappear
        """
        agent = CVEPrerequisiteAgent(online_mode=False)
        rec = agent.process_cve("CVE-2014-0160", save_to_db=False)

        prereqs = rec.get("prerequisites", [])
        prereq_names = [p["name"] for p in prereqs]

        # Item A: Version prerequisite remains authoritative
        self.assertIn("software_version_vulnerable", prereq_names)
        ver_prereq = next(p for p in prereqs if p["name"] == "software_version_vulnerable")
        self.assertEqual(ver_prereq["category"], "version")
        self.assertTrue(ver_prereq["required"])
        self.assertEqual(ver_prereq["trust_level"], "authoritative")

        # Items B, C, D: TLS Heartbeat extension normalized as environment prerequisite
        self.assertIn("tls_heartbeat_extension_enabled", prereq_names)
        hb_prereq = next(p for p in prereqs if p["name"] == "tls_heartbeat_extension_enabled")
        self.assertIn(hb_prereq["category"], ("protocol", "feature", "component"))
        self.assertTrue(hb_prereq["required"])
        self.assertEqual(hb_prereq["trust_level"], "authoritative")
        self.assertTrue(len(hb_prereq.get("evidence", [])) > 0)

        # Item E: Crafted heartbeat packet buffer over-read remains an ATTACK CONDITION
        attack_conds = rec.get("attack_conditions", [])
        self.assertTrue(any("buffer over-read" in a.get("name", "").lower() or "crafted" in a.get("name", "").lower() for a in attack_conds))
        for ac in attack_conds:
            self.assertNotEqual(ac.get("name"), "tls_heartbeat_extension_enabled")
            self.assertEqual(ac.get("category"), "request_condition")

        # Item F: Nuclei template is represented under dynamic_validation, NOT in attack_conditions
        self.assertFalse(any("nuclei" in a.get("name", "").lower() for a in attack_conds))
        dyn_vals = rec.get("dynamic_validation", [])
        self.assertTrue(len(dyn_vals) > 0)
        self.assertEqual(dyn_vals[0]["source"], "nuclei")
        self.assertEqual(dyn_vals[0]["type"], "nuclei_dynamic_probe")
        self.assertEqual(dyn_vals[0]["template_id"], "CVE-2014-0160")
        self.assertEqual(dyn_vals[0]["verification_method"], "dynamic_test")

        # Item G: Source provenance preserved, irrelevant sources tagged
        sources = rec.get("sources", [])
        self.assertTrue(len(sources) >= 5)
        # Irrelevant Pony Mail SPA sources marked is_relevant=False
        irrelevant_sources = [s for s in sources if not s.get("is_relevant", True)]
        self.assertTrue(len(irrelevant_sources) >= 1)
        for s in irrelevant_sources:
            self.assertFalse(s["is_relevant"])
            self.assertIn("SPA", s.get("relevance_reason", ""))

        # Version normalization: no unrelated "2.0" license versions
        self.assertNotIn("2.0", rec.get("affected_versions", []))
        self.assertTrue(any("before" in str(v).lower() or "1.0.1" in str(v) for v in rec.get("affected_versions", [])))

        # Item H & I: Deterministic Evaluation
        # Case 1: Missing environmental evidence -> UNKNOWN
        eval_missing = CVEEvaluator(config_source={"openssl": {"version": "1.0.1f"}})
        res_missing = eval_missing.evaluate_cve(rec)
        self.assertEqual(res_missing["applicability_status"], "UNKNOWN")
        cond_hb_missing = next(c for c in res_missing["environmental_conditions"] if c["name"] == "tls_heartbeat_extension_enabled")
        self.assertEqual(cond_hb_missing["status"], "unknown")
        self.assertTrue(cond_hb_missing["required"])

        # Case 2: Heartbeat enabled -> APPLICABLE
        eval_sat = CVEEvaluator(config_source={"openssl": {"version": "1.0.1f"}, "tls": {"heartbeat_extension": True}})
        res_sat = eval_sat.evaluate_cve(rec)
        self.assertEqual(res_sat["applicability_status"], "APPLICABLE")

        # Case 3: Heartbeat disabled (workaround) -> NOT_APPLICABLE
        eval_dis = CVEEvaluator(config_source={"openssl": {"version": "1.0.1f"}, "tls": {"heartbeat_extension": False}})
        res_dis = eval_dis.evaluate_cve(rec)
        self.assertEqual(res_dis["applicability_status"], "NOT_APPLICABLE")

        # Case 4: Patched version (1.0.1g) -> NOT_APPLICABLE
        eval_patch = CVEEvaluator(config_source={"openssl": {"version": "1.0.1g"}, "tls": {"heartbeat_extension": True}})
        res_patch = eval_patch.evaluate_cve(rec)
        self.assertEqual(res_patch["applicability_status"], "NOT_APPLICABLE")

    # 25. Version-Only CVE Regression
    def test_version_only_cve_regression(self):
        extractor = PrerequisiteExtractor()
        adv_text = "Apache HTTP Server 2.4.50 before 2.4.51 allows a denial of service."
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://httpd.apache.org", "content": adv_text}]
        rec = extractor.extract_from_evidence("CVE-2021-42013", sources, cve_summary=adv_text)
        prereqs = rec.get("prerequisites", [])
        self.assertEqual(len(prereqs), 1)
        self.assertEqual(prereqs[0]["name"], "software_version_vulnerable")
        self.assertEqual(prereqs[0]["category"], "version")
        self.assertTrue(prereqs[0]["required"])

    # 26. Version + Feature Prerequisite Regression
    def test_version_plus_feature_regression(self):
        extractor = PrerequisiteExtractor()
        adv_text = (
            "A flaw in the handling of the custom_compression extension in Server 2.0 before 2.4 allows memory leakage. "
            "Users can mitigate this vulnerability by compiling with -DSERVER_NO_CUSTOM_COMPRESSION."
        )
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com/secadv", "content": adv_text}]
        rec = extractor.extract_from_evidence("CVE-GENERIC-FEAT", sources, cve_summary=adv_text)
        prereq_names = [p["name"] for p in rec.get("prerequisites", [])]
        self.assertIn("software_version_vulnerable", prereq_names)
        self.assertIn("custom_compression_extension_enabled", prereq_names)
        comp_p = next(p for p in rec["prerequisites"] if p["name"] == "custom_compression_extension_enabled")
        self.assertIn(comp_p["category"], ("feature", "protocol"))
        self.assertTrue(comp_p["required"])
        self.assertEqual(comp_p["trust_level"], "authoritative")

    # 27. Version + Configuration Prerequisite Regression
    def test_version_plus_configuration_regression(self):
        extractor = PrerequisiteExtractor()
        adv_text = "App 3.0 before 3.5 is only vulnerable when debug_logging is enabled."
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com/secadv", "content": adv_text}]
        rec = extractor.extract_from_evidence("CVE-GENERIC-CFG", sources, cve_summary=adv_text)
        prereq_names = [p["name"] for p in rec.get("prerequisites", [])]
        self.assertIn("software_version_vulnerable", prereq_names)
        self.assertIn("debug_logging_enabled", prereq_names)

    # 28. Protocol / Extension Prerequisite Regression
    def test_protocol_extension_prerequisite_regression(self):
        extractor = PrerequisiteExtractor()
        adv_text = "Proxy 1.0 before 1.8 does not properly handle websocket_subprotocol extension packets, resulting in heap corruption."
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com/secadv", "content": adv_text}]
        rec = extractor.extract_from_evidence("CVE-GENERIC-PROTO", sources, cve_summary=adv_text)
        prereq_names = [p["name"] for p in rec.get("prerequisites", [])]
        self.assertIn("software_version_vulnerable", prereq_names)
        self.assertIn("websocket_subprotocol_extension_enabled", prereq_names)

    # 29. Attack-Condition-Only Evidence Regression
    def test_attack_condition_only_evidence_regression(self):
        extractor = PrerequisiteExtractor()
        adv_text = "Software 1.0 is vulnerable when remote attackers crash the server by sending a crafted HTTP/2 CONTINUATION frame with invalid flags."
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com/secadv", "content": adv_text}]
        rec = extractor.extract_from_evidence("CVE-GENERIC-ATTACK", sources, cve_summary=adv_text)
        prereqs = rec.get("prerequisites", [])
        attack_conds = rec.get("attack_conditions", [])
        # Environment prerequisites only contains the version, NOT the attack frame
        self.assertEqual(len(prereqs), 1)
        self.assertEqual(prereqs[0]["name"], "software_version_vulnerable")
        # Attack frame is in attack_conditions
        self.assertTrue(len(attack_conds) >= 1)
        self.assertTrue(any("crafted" in a.get("name", "").lower() or "continuation" in a.get("name", "").lower() for a in attack_conds))

    # 30. Dynamic-Validation-Only Evidence Regression
    def test_dynamic_validation_only_evidence_regression(self):
        extractor = PrerequisiteExtractor()
        nuclei_info = {
            "template_path": "/rules/CVE-GENERIC-DYN.yaml",
            "template_id": "CVE-GENERIC-DYN",
            "methods": ["GET"],
            "endpoints": ["/api/v1/test"]
        }
        rec = extractor.extract_from_evidence("CVE-GENERIC-DYN", [], nuclei_info=nuclei_info, cve_summary="Test summary")
        # Dynamic validation is stored in dynamic_validation
        dyn = rec.get("dynamic_validation", [])
        self.assertEqual(len(dyn), 1)
        self.assertEqual(dyn[0]["source"], "nuclei")
        self.assertEqual(dyn[0]["type"], "nuclei_dynamic_probe")
        # NOT in attack conditions or prerequisites
        self.assertFalse(any("nuclei" in a.get("name", "").lower() for a in rec.get("attack_conditions", [])))
        self.assertFalse(any("nuclei" in p.get("name", "").lower() for p in rec.get("prerequisites", [])))

    # 31. Irrelevant Source Contamination Filtered Regression
    def test_irrelevant_source_contamination_filtered_regression(self):
        extractor = PrerequisiteExtractor()
        spa_html = """<!doctype html>
        <!-- Licensed to the Apache Software Foundation (ASF) under Apache License, Version 2.0 -->
        <html><head><title>Pony Mail</title></head><body><div id="app"></div></body></html>"""
        sources = [
            {"source_id": "s_valid", "source_type": "vendor_advisory", "source_url": "https://example.com/valid", "content": "Vulnerability in Software 1.0 before 1.5.", "is_relevant": True},
            {"source_id": "s_spa", "source_type": "project_advisory", "source_url": "https://lists.apache.org/thread", "content": spa_html, "is_relevant": False}
        ]
        rec = extractor.extract_from_evidence("CVE-GENERIC-SPA", sources, cve_summary="Software before 1.5")
        # Version 2.0 from license header is NOT extracted
        self.assertNotIn("2.0", rec.get("affected_versions", []))

    # 32. Multiple Version Numbers in Source Text Regression
    def test_multiple_version_numbers_in_source_text_regression(self):
        extractor = PrerequisiteExtractor()
        text = (
            "Distributed under Apache License, Version 2.0. HTTP/1.1 and HTTP/2.0 protocols supported. "
            "The vulnerability affects Product 3.1 before 3.1.9."
        )
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com", "content": text, "is_relevant": True}]
        rec = extractor.extract_from_evidence("CVE-GENERIC-VERS", sources, cve_summary=text)
        self.assertNotIn("2.0", rec.get("affected_versions", []))
        self.assertTrue(any("3.1" in v for v in rec.get("affected_versions", [])))

    # 33. Missing Environment Evidence Yields UNKNOWN Regression
    def test_missing_environment_evidence_yields_unknown_regression(self):
        cve_record = {
            "cve_id": "CVE-GENERIC-UNVERIFIED-2",
            "affected_versions": {"range": "< 2.0.0"},
            "prerequisites": [
                {
                    "id": "p_req",
                    "name": "custom_extension_enabled",
                    "category": "feature",
                    "required": True,
                    "expected_state": "enabled",
                    "configuration_evidence": ["extensions.custom_enabled"],
                    "required_value": True,
                    "verification_method": "config_collector"
                }
            ]
        }
        evaluator = CVEEvaluator(config_source={"version": "1.0.0"})
        res = evaluator.evaluate_cve(cve_record)
        self.assertEqual(res["applicability_status"], "UNKNOWN")

    # =========================================================
    # PHASE 7 VERIFICATION SUITE (Tests 1 through 5)
    # =========================================================

    def test_phase7_test1_generic_feature_handling_creates_prerequisite(self):
        """TEST 1: Generic feature/extension handling statement creates an environmental prerequisite."""
        extractor = PrerequisiteExtractor()
        adv_text = (
            "A security flaw in the handling of the telemetry_streaming extension in Agent 4.0 before 4.2 "
            "allows out-of-bounds reads. The telemetry_streaming extension is required to trigger this vulnerability."
        )
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com/secadv", "content": adv_text, "is_relevant": True}]
        rec = extractor.extract_from_evidence("CVE-TEST-T1", sources, cve_summary=adv_text)
        prereq_names = [p["name"] for p in rec.get("prerequisites", [])]
        self.assertIn("telemetry_streaming_extension_enabled", prereq_names)
        p = next(p for p in rec["prerequisites"] if p["name"] == "telemetry_streaming_extension_enabled")
        self.assertTrue(p["required"])
        self.assertIn(p["category"], ("feature", "protocol"))
        self.assertEqual(p["trust_level"], "authoritative")

    def test_phase7_test2_crafted_packet_remains_attack_condition(self):
        """TEST 2: Attacker-crafted packet remains an attack condition and is NOT promoted to an environment prerequisite."""
        extractor = PrerequisiteExtractor()
        adv_text = "Server 1.0 before 1.5 crashes when an attacker sends a crafted heartbeat packet buffer over-read."
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com/secadv", "content": adv_text, "is_relevant": True}]
        rec = extractor.extract_from_evidence("CVE-TEST-T2", sources, cve_summary=adv_text)
        prereqs = rec.get("prerequisites", [])
        attack_conds = rec.get("attack_conditions", [])
        self.assertFalse(any("crafted" in p.get("name", "").lower() or "packet" in p.get("name", "").lower() for p in prereqs))
        self.assertTrue(any("crafted" in a.get("name", "").lower() or "packet" in a.get("name", "").lower() or "buffer" in a.get("name", "").lower() for a in attack_conds))
        ac = attack_conds[0]
        self.assertEqual(ac.get("category"), "request_condition")
        self.assertEqual(ac.get("verification_method"), "dynamic_validation")

    def test_phase7_test3_compile_time_workaround_provides_feature_evidence(self):
        """TEST 3: Generic compile-time disablement workaround provides evidence of feature requirement without becoming the prerequisite itself."""
        extractor = PrerequisiteExtractor()
        adv_text = (
            "Improper handling of packet compression in Gateway 2.0 before 2.8. "
            "Users can disable the compression feature by compiling with -DGATEWAY_NO_PACKET_COMPRESSION."
        )
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com/secadv", "content": adv_text, "is_relevant": True}]
        rec = extractor.extract_from_evidence("CVE-TEST-T3", sources, cve_summary=adv_text)
        prereq_names = [p["name"] for p in rec.get("prerequisites", [])]
        self.assertIn("packet_compression_enabled", prereq_names)
        self.assertNotIn("gateway_no_packet_compression", prereq_names)
        p = next(p for p in rec["prerequisites"] if p["name"] == "packet_compression_enabled")
        self.assertTrue(p["required"])
        self.assertIn(p["category"], ("feature", "protocol"))

    def test_phase7_test4_unrelated_numerics_not_affected_versions(self):
        """TEST 4: Unrelated numeric values (Apache License 2.0, TLS/1.2, CVSS 9.8, dates) do not become affected versions."""
        extractor = PrerequisiteExtractor()
        text = (
            "<!-- Licensed under the Apache License, Version 2.0 (the License); -->\n"
            "Supported protocols: TLS/1.2, TLS/1.3, HTTP/2.0. Published on 2024-04-07. CVSS score: 9.8.\n"
            "The vulnerability affects Engine 5.0 before 5.0.8."
        )
        sources = [{"source_id": "s1", "source_type": "vendor_advisory", "source_url": "https://example.com", "content": text, "is_relevant": True}]
        rec = extractor.extract_from_evidence("CVE-TEST-T4", sources, cve_summary="Engine 5.0 before 5.0.8")
        aff = rec.get("affected_versions", [])
        self.assertNotIn("2.0", aff)
        self.assertNotIn("1.2", aff)
        self.assertNotIn("1.3", aff)
        self.assertNotIn("9.8", aff)
        self.assertTrue(any("5.0 before 5.0.8" in v or "5.0" in v for v in aff))

    def test_phase7_test5_real_cve_2014_0160_production_extraction(self):
        """TEST 5: Real CVE-2014-0160 production extraction produces the correct structured result."""
        agent = CVEPrerequisiteAgent(online_mode=True)
        rec = agent.process_cve("CVE-2014-0160", save_to_db=False)

        prereq_names = [p["name"] for p in rec.get("prerequisites", [])]
        self.assertIn("tls_heartbeat_extension_enabled", prereq_names)
        self.assertIn("software_version_vulnerable", prereq_names)

        hb_p = next(p for p in rec["prerequisites"] if p["name"] == "tls_heartbeat_extension_enabled")
        self.assertTrue(hb_p["required"])
        self.assertEqual(hb_p["trust_level"], "authoritative")
        self.assertIn(hb_p["category"], ("protocol", "feature"))

        ver_p = next(p for p in rec["prerequisites"] if p["name"] == "software_version_vulnerable")
        self.assertTrue(ver_p["required"])
        self.assertEqual(ver_p["trust_level"], "authoritative")
        self.assertEqual(ver_p["category"], "version")

        attacks = rec.get("attack_conditions", [])
        self.assertTrue(any("buffer over-read" in a.get("name", "").lower() or "crafted" in a.get("name", "").lower() for a in attacks))
        for a in attacks:
            self.assertEqual(a.get("category"), "request_condition")
            self.assertEqual(a.get("verification_method"), "dynamic_validation")

        dyns = rec.get("dynamic_validation", [])
        self.assertTrue(len(dyns) >= 1)
        self.assertEqual(dyns[0]["source"], "nuclei")
        self.assertEqual(dyns[0]["type"], "nuclei_dynamic_probe")
        self.assertEqual(dyns[0]["template_id"], "CVE-2014-0160")

        aff = rec.get("affected_versions", [])
        self.assertNotIn("2.0", aff)
        self.assertTrue(any("1.0.1" in v for v in aff))

    def test_real_cve_2020_1938_production_extraction(self):
        """Regression test for real CVE-2020-1938 production extraction."""
        agent = CVEPrerequisiteAgent(online_mode=False)
        rec = agent.process_cve("CVE-2020-1938", save_to_db=False)

        prereqs = rec.get("prerequisites", [])
        prereq_names = [p["name"] for p in prereqs]

        # 1. Software version vulnerable
        self.assertIn("software_version_vulnerable", prereq_names)
        ver_p = next(p for p in prereqs if p["name"] == "software_version_vulnerable")
        self.assertTrue(ver_p["required"])
        self.assertEqual(ver_p["trust_level"], "authoritative")
        self.assertEqual(ver_p["category"], "version")

        # 2. Service/configuration prerequisite representing AJP connector enabled/active
        self.assertIn("ajp_connector_active", prereq_names)
        svc_p = next(p for p in prereqs if p["name"] == "ajp_connector_active")
        self.assertTrue(svc_p["required"])
        self.assertEqual(svc_p["trust_level"], "authoritative")
        self.assertIn(svc_p["category"], ("service", "configuration"))
        self.assertEqual(svc_p["verification_method"], "config_collector")
        self.assertEqual(svc_p["expected_state"], "active")

        # 3. Network exposure prerequisite representing AJP accessibility to untrusted users
        self.assertIn("ajp_port_accessible_to_untrusted_users", prereq_names)
        net_p = next(p for p in prereqs if p["name"] == "ajp_port_accessible_to_untrusted_users")
        self.assertTrue(net_p["required"])
        self.assertEqual(net_p["trust_level"], "authoritative")
        self.assertEqual(net_p["category"], "network_exposure")
        self.assertEqual(net_p["verification_method"], "config_collector")

        # 4. File upload is NOT treated as a prerequisite for basic CVE applicability
        self.assertFalse(any("upload" in p.get("name", "").lower() for p in prereqs))

        # 5. File upload condition is captured under attack_conditions as an impact condition for RCE
        attacks = rec.get("attack_conditions", [])
        self.assertTrue(any("upload" in a.get("name", "").lower() for a in attacks))
        upload_a = next(a for a in attacks if "upload" in a.get("name", "").lower())
        self.assertEqual(upload_a.get("category"), "impact_condition")
        self.assertFalse(upload_a.get("required"))
        self.assertEqual(upload_a.get("verification_method"), "dynamic_validation")

    def test_real_cve_2017_12615_production_extraction(self):
        """Regression test for real CVE-2017-12615 production extraction."""
        agent = CVEPrerequisiteAgent(online_mode=False)
        rec = agent.process_cve("CVE-2017-12615", save_to_db=False)

        prereqs = rec.get("prerequisites", [])
        prereq_names = [p["name"] for p in prereqs]

        # 1. Software version vulnerable
        self.assertIn("software_version_vulnerable", prereq_names)
        ver_p = next(p for p in prereqs if p["name"] == "software_version_vulnerable")
        self.assertTrue(ver_p["required"])
        self.assertEqual(ver_p["trust_level"], "authoritative")
        self.assertEqual(ver_p["category"], "version")

        # 2. Platform / OS prerequisite representing Windows
        self.assertIn("target_platform_windows", prereq_names)
        plat_p = next(p for p in prereqs if p["name"] == "target_platform_windows")
        self.assertTrue(plat_p["required"])
        self.assertEqual(plat_p["trust_level"], "authoritative")
        self.assertEqual(plat_p["category"], "operating_system")
        self.assertEqual(plat_p["verification_method"], "platform_inspector")
        self.assertEqual(plat_p["expected_state"], "windows")

        # 3. HTTP PUT / write-enabled prerequisite
        self.assertIn("http_put_enabled", prereq_names)
        put_p = next(p for p in prereqs if p["name"] == "http_put_enabled")
        self.assertTrue(put_p["required"])
        self.assertEqual(put_p["trust_level"], "authoritative")
        self.assertEqual(put_p["category"], "configuration")
        self.assertEqual(put_p["verification_method"], "config_collector")
        self.assertEqual(put_p["expected_state"], "enabled")
        self.assertEqual(put_p.get("config_explanation"), "readonly=false")
        self.assertIn("default_servlet.readonly", put_p.get("configuration_evidence", []))

        # 4. Attacker action 'specially crafted request' remains strictly in attack_conditions
        self.assertFalse(any("crafted" in p.get("name", "").lower() for p in prereqs))
        attacks = rec.get("attack_conditions", [])
        self.assertTrue(any("crafted" in a.get("name", "").lower() for a in attacks))
        crafted_a = next(a for a in attacks if "crafted" in a.get("name", "").lower())
        self.assertEqual(crafted_a.get("category"), "request_condition")
        self.assertTrue(crafted_a.get("required"))
        self.assertEqual(crafted_a.get("trust_level"), "authoritative")

        # 5. JSP execution is NOT an environment prerequisite for base CVE
        self.assertFalse(any("jsp" in p.get("name", "").lower() for p in prereqs))

        # 6. Evaluation against different environmental configurations
        eval_dict = agent.export_for_cve_evaluator("CVE-2017-12615")

        # A. Windows + HTTP PUTs enabled (readonly=False) + vulnerable version (7.0.50) -> satisfied
        cfg_valid = {
            "effective_configuration": {
                "environment": {"os": "Windows"},
                "default_servlet": {"readonly": False}
            },
            "installed_version": "7.0.50"
        }
        res_valid = CVEEvaluator(knowledge_source=eval_dict, config_source=cfg_valid).evaluate_cve("CVE-2017-12615")
        self.assertEqual(res_valid["status"], "satisfied")

        # B. Linux (wrong OS) -> not_satisfied due to platform mismatch
        cfg_linux = {
            "effective_configuration": {
                "environment": {"os": "Linux"},
                "default_servlet": {"readonly": False}
            },
            "installed_version": "7.0.50"
        }
        res_linux = CVEEvaluator(knowledge_source=eval_dict, config_source=cfg_linux).evaluate_cve("CVE-2017-12615")
        self.assertEqual(res_linux["status"], "not_satisfied")
        self.assertIn("target_platform_windows", res_linux["reason"])

        # C. Windows + readonly=True (PUTs disabled) -> not_satisfied due to HTTP PUT disabled
        cfg_no_put = {
            "effective_configuration": {
                "environment": {"os": "Windows"},
                "default_servlet": {"readonly": True}
            },
            "installed_version": "7.0.50"
        }
        res_no_put = CVEEvaluator(knowledge_source=eval_dict, config_source=cfg_no_put).evaluate_cve("CVE-2017-12615")
        self.assertEqual(res_no_put["status"], "not_satisfied")
        self.assertIn("http_put_enabled", res_no_put["reason"])

        # D. Patched version (7.0.80) -> not_satisfied due to software version
        cfg_patched = {
            "effective_configuration": {
                "environment": {"os": "Windows"},
                "default_servlet": {"readonly": False}
            },
            "installed_version": "7.0.80"
        }
        res_patched = CVEEvaluator(knowledge_source=eval_dict, config_source=cfg_patched).evaluate_cve("CVE-2017-12615")
        self.assertEqual(res_patched["status"], "not_satisfied")
        self.assertIn("software_version_vulnerable", res_patched["reason"])


if __name__ == "__main__":
    unittest.main()
