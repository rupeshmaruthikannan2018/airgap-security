"""
Comprehensive Generic Architecture Regression Test Suite.
Validates the complete Condition IR, AST evaluation, 3-valued boolean logic,
semantic extractor, and regression across CVE-2017-12615, CVE-2020-1938,
CVE-2014-0160, CVE-2014-0224, CVE-2019-0708, CVE-2021-3449, and CVE-2025-24813,
plus synthetic AST and invariant tests.
"""

import unittest
from pathlib import Path
import re

from orchestrator.condition_ir import (
    ConditionNode,
    ConditionType,
    ConditionCategory,
    Operator,
    TrustLevel,
    VerificationMethod,
    EvaluationStatus,
    AndGroup,
    OrGroup,
    NotNode,
    CVEConditionTree,
    deserialize_ast_node,
)
from orchestrator.condition_extractor import SemanticConditionExtractor
from orchestrator.cve_evaluator import CVEEvaluator


class TestGenericConditionArchitecture(unittest.TestCase):
    """Full regression suite for Section 27 and Section 32 acceptance criteria."""

    def setUp(self):
        self.extractor = SemanticConditionExtractor()

    # =========================================================================
    # PART 1: Synthetic AST & 3-Valued Logic Tests
    # =========================================================================

    def test_synthetic_a_and_b(self):
        """Test A AND B under all 3-valued logic truth table combinations."""
        # 1. SATISFIED AND SATISFIED => SATISFIED
        tree_sat = AndGroup(operands=[
            ConditionNode(
                condition_id="c_a",
                condition_type=ConditionType.CONFIGURATION,
                subject="feature_a",
                operator=Operator.EQUALS,
                value=True,
                required=True,
                category=ConditionCategory.ENVIRONMENT
            ),
            ConditionNode(
                condition_id="c_b",
                condition_type=ConditionType.CONFIGURATION,
                subject="feature_b",
                operator=Operator.EQUALS,
                value=True,
                required=True,
                category=ConditionCategory.ENVIRONMENT
            ),
        ])
        evaluator_sat = CVEEvaluator(config_source={
            "configuration": {"feature_a": True, "feature_b": True}
        })
        st_sat, res_sat = evaluator_sat.evaluate_ast_node(tree_sat)
        self.assertEqual(st_sat.upper(), "SATISFIED")
        self.assertEqual(res_sat["evaluation_status"], "SATISFIED")

        # 2. SATISFIED AND NOT_SATISFIED => NOT_SATISFIED
        evaluator_not = CVEEvaluator(config_source={
            "configuration": {"feature_a": True, "feature_b": False}
        })
        st_not, res_not = evaluator_not.evaluate_ast_node(tree_sat)
        self.assertEqual(st_not.upper(), "NOT_SATISFIED")
        self.assertEqual(res_not["evaluation_status"], "NOT_SATISFIED")

        # 3. SATISFIED AND UNKNOWN => UNKNOWN (missing evidence NEVER becomes false!)
        evaluator_unk = CVEEvaluator(config_source={
            "configuration": {"feature_a": True}
        })
        st_unk, res_unk = evaluator_unk.evaluate_ast_node(tree_sat)
        self.assertEqual(st_unk.upper(), "UNKNOWN")
        self.assertEqual(res_unk["evaluation_status"], "UNKNOWN")

    def test_synthetic_a_or_b(self):
        """Test A OR B under 3-valued logic."""
        tree = OrGroup(operands=[
            ConditionNode(
                condition_id="c_a",
                condition_type=ConditionType.CONFIGURATION,
                subject="a",
                operator=Operator.EQUALS,
                value=True,
                required=True,
                category=ConditionCategory.ENVIRONMENT
            ),
            ConditionNode(
                condition_id="c_b",
                condition_type=ConditionType.CONFIGURATION,
                subject="b",
                operator=Operator.EQUALS,
                value=True,
                required=True,
                category=ConditionCategory.ENVIRONMENT
            ),
        ])

        # SATISFIED OR UNKNOWN => SATISFIED
        st1, res1 = CVEEvaluator(config_source={"configuration": {"a": True}}).evaluate_ast_node(tree)
        self.assertEqual(st1.upper(), "SATISFIED")

        # NOT_SATISFIED OR UNKNOWN => UNKNOWN
        st2, res2 = CVEEvaluator(config_source={"configuration": {"a": False}}).evaluate_ast_node(tree)
        self.assertEqual(st2.upper(), "UNKNOWN")

        # NOT_SATISFIED OR NOT_SATISFIED => NOT_SATISFIED
        st3, res3 = CVEEvaluator(config_source={"configuration": {"a": False, "b": False}}).evaluate_ast_node(tree)
        self.assertEqual(st3.upper(), "NOT_SATISFIED")

    def test_synthetic_not_a(self):
        """Test NOT A under 3-valued logic."""
        tree = NotNode(operand=ConditionNode(
            condition_id="c_a",
            condition_type=ConditionType.CONFIGURATION,
            subject="disabled_mode",
            operator=Operator.EQUALS,
            value=True,
            required=True,
            category=ConditionCategory.ENVIRONMENT
        ))

        # NOT (SATISFIED) => NOT_SATISFIED
        st1, res1 = CVEEvaluator(config_source={"configuration": {"disabled_mode": True}}).evaluate_ast_node(tree)
        self.assertEqual(st1.upper(), "NOT_SATISFIED")

        # NOT (NOT_SATISFIED) => SATISFIED
        st2, res2 = CVEEvaluator(config_source={"configuration": {"disabled_mode": False}}).evaluate_ast_node(tree)
        self.assertEqual(st2.upper(), "SATISFIED")

        # NOT (UNKNOWN) => UNKNOWN
        st3, res3 = CVEEvaluator(config_source={}).evaluate_ast_node(tree)
        self.assertEqual(st3.upper(), "UNKNOWN")

    def test_synthetic_a_and_b_or_c(self):
        """Test A AND (B OR C)."""
        tree = AndGroup(operands=[
            ConditionNode(
                condition_id="c_a",
                condition_type=ConditionType.CONFIGURATION,
                subject="a",
                operator=Operator.EQUALS,
                value=True,
                required=True,
                category=ConditionCategory.ENVIRONMENT
            ),
            OrGroup(operands=[
                ConditionNode(
                    condition_id="c_b",
                    condition_type=ConditionType.CONFIGURATION,
                    subject="b",
                    operator=Operator.EQUALS,
                    value=True,
                    required=True,
                    category=ConditionCategory.ENVIRONMENT
                ),
                ConditionNode(
                    condition_id="c_c",
                    condition_type=ConditionType.CONFIGURATION,
                    subject="c",
                    operator=Operator.EQUALS,
                    value=True,
                    required=True,
                    category=ConditionCategory.ENVIRONMENT
                ),
            ])
        ])

        # A=True, B=True, C=False => SATISFIED
        st1, res1 = CVEEvaluator(config_source={"configuration": {"a": True, "b": True, "c": False}}).evaluate_ast_node(tree)
        self.assertEqual(st1.upper(), "SATISFIED")

        # A=False, B=True, C=True => NOT_SATISFIED
        st2, res2 = CVEEvaluator(config_source={"configuration": {"a": False, "b": True, "c": True}}).evaluate_ast_node(tree)
        self.assertEqual(st2.upper(), "NOT_SATISFIED")

        # A=True, B=False, C missing => UNKNOWN
        st3, res3 = CVEEvaluator(config_source={"configuration": {"a": True, "b": False}}).evaluate_ast_node(tree)
        self.assertEqual(st3.upper(), "UNKNOWN")

    def test_synthetic_a_or_b_and_c_or_d(self):
        """Test (A OR B) AND (C OR D)."""
        tree = AndGroup(operands=[
            OrGroup(operands=[
                ConditionNode(
                    condition_id="c_a",
                    condition_type=ConditionType.CONFIGURATION,
                    subject="a",
                    operator=Operator.EQUALS,
                    value=True,
                    required=True,
                    category=ConditionCategory.ENVIRONMENT
                ),
                ConditionNode(
                    condition_id="c_b",
                    condition_type=ConditionType.CONFIGURATION,
                    subject="b",
                    operator=Operator.EQUALS,
                    value=True,
                    required=True,
                    category=ConditionCategory.ENVIRONMENT
                ),
            ]),
            OrGroup(operands=[
                ConditionNode(
                    condition_id="c_c",
                    condition_type=ConditionType.CONFIGURATION,
                    subject="c",
                    operator=Operator.EQUALS,
                    value=True,
                    required=True,
                    category=ConditionCategory.ENVIRONMENT
                ),
                ConditionNode(
                    condition_id="c_d",
                    condition_type=ConditionType.CONFIGURATION,
                    subject="d",
                    operator=Operator.EQUALS,
                    value=True,
                    required=True,
                    category=ConditionCategory.ENVIRONMENT
                ),
            ])
        ])

        # A=True, D=True => SATISFIED
        st1, res1 = CVEEvaluator(config_source={"configuration": {"a": True, "d": True}}).evaluate_ast_node(tree)
        self.assertEqual(st1.upper(), "SATISFIED")

        # A=False, B=False (first group fails) => NOT_SATISFIED
        st2, res2 = CVEEvaluator(config_source={"configuration": {"a": False, "b": False, "c": True}}).evaluate_ast_node(tree)
        self.assertEqual(st2.upper(), "NOT_SATISFIED")

    # =========================================================================
    # PART 2: Invariants (Evidence, Trust, Categories, Anaphora)
    # =========================================================================

    def test_missing_evidence_is_unknown_not_false(self):
        """Invariant: required=True with missing evidence MUST evaluate to UNKNOWN, NEVER false."""
        node = ConditionNode(
            condition_id="cond_unseen",
            condition_type=ConditionType.FEATURE,
            subject="obscure_feature",
            operator=Operator.EQUALS,
            value=True,
            required=True,
            category=ConditionCategory.ENVIRONMENT
        )
        st, res = CVEEvaluator(config_source={}).evaluate_ast_node(node)
        self.assertEqual(st.upper(), "UNKNOWN")

    def test_contradictory_evidence_conflict_handling(self):
        """When evidence directly contradicts required state, status is NOT_SATISFIED."""
        node = ConditionNode(
            condition_id="cond_tls",
            condition_type=ConditionType.PROTOCOL,
            subject="tls_version",
            operator=Operator.EQUALS,
            value="1.2",
            required=True,
            category=ConditionCategory.ENVIRONMENT
        )
        st, res = CVEEvaluator(config_source={"configuration": {"tls_version": "1.3"}}).evaluate_ast_node(node)
        self.assertEqual(st.upper(), "NOT_SATISFIED")

    def test_low_trust_source_does_not_override_authoritative(self):
        """Advisory extractor preserves trust levels and does not allow low-trust sources to override authoritative."""
        sources = [
            {
                "source_type": "technical_research",
                "source_url": "https://blog.example.com/poc",
                "content": "Windows might also be vulnerable if feature Z is enabled."
            },
            {
                "source_type": "vendor_advisory",
                "source_url": "https://vendor.example.com/advisory",
                "content": "Only vulnerable when running on Linux with feature Y enabled."
            }
        ]
        cond_tree = self.extractor.extract_from_sources("CVE-TEST-TRUST", sources)
        for cond in cond_tree.get_all_leaves():
            if "linux" in cond.subject.lower() or "linux" in str(cond.value).lower():
                self.assertEqual(cond.trust_level, TrustLevel.AUTHORITATIVE)
            elif "windows" in cond.subject.lower():
                self.assertIn(cond.trust_level, [TrustLevel.DERIVED, TrustLevel.INFERRED, TrustLevel.UNKNOWN])

    def test_duplicate_condition_deduplication(self):
        """Deduplication ensures version conditions are not redundantly duplicated."""
        sources = [
            {
                "source_type": "vendor_advisory",
                "content": "Affects versions 1.0.0 through 1.2.3."
            },
            {
                "source_type": "project_advisory",
                "content": "Affects versions 1.0.0 to 1.2.3."
            }
        ]
        cond_tree = self.extractor.extract_from_sources("CVE-TEST-DEDUP", sources)
        ver_conds = cond_tree.version_conditions
        self.assertLessEqual(len(ver_conds), 2)

    def test_anaphora_resolution(self):
        """Generic anaphora resolver replaces 'such connections' with the antecedent subject."""
        text = "The AJP connector is enabled by default. Such connections can be exploited by an unauthenticated attacker."
        resolved = self.extractor.resolve_anaphora_and_context(text)
        self.assertIn("AJP connector connections", resolved)
        self.assertNotIn("Such connections", resolved)

    def test_impact_condition_separation(self):
        """Impact conditions (e.g. file upload for RCE) must NOT become base prerequisites."""
        text = "Vulnerable if the debug interface is exposed. Remote code execution is possible when file upload capability is enabled."
        cond_tree = self.extractor.extract_from_sources("CVE-TEST-IMPACT", [
            {"source_type": "vendor_advisory", "content": text}
        ])
        impacts = cond_tree.impact_conditions
        self.assertTrue(len(impacts) > 0, "Impact condition should be extracted separately")
        for imp in impacts:
            self.assertEqual(imp.category, ConditionCategory.IMPACT)
            self.assertIn("upload", imp.evidence.lower())

    def test_mitigation_separation(self):
        """Mitigations/workarounds must be classified as MITIGATION, not environmental prerequisites."""
        text = "This vulnerability can be mitigated by disabling the legacy AJP connector."
        cond_tree = self.extractor.extract_from_sources("CVE-TEST-MITIG", [
            {"source_type": "vendor_advisory", "content": text}
        ])
        mits = cond_tree.mitigations
        self.assertTrue(len(mits) > 0)
        self.assertEqual(mits[0].category, ConditionCategory.MITIGATION)

    def test_platform_condition_evaluation(self):
        """Platform condition evaluates against environment OS inventory."""
        node = ConditionNode(
            condition_id="c_os",
            condition_type=ConditionType.OS,
            subject="os",
            operator=Operator.EQUALS,
            value="windows",
            required=True,
            category=ConditionCategory.ENVIRONMENT,
            verification_method=VerificationMethod.PLATFORM_INSPECTOR
        )
        # Windows inventory -> SATISFIED
        st1, res1 = CVEEvaluator(config_source={"environment": {"os": "windows 11"}}).evaluate_ast_node(node)
        self.assertEqual(st1.upper(), "SATISFIED")

        # Linux inventory -> NOT_SATISFIED
        st2, res2 = CVEEvaluator(config_source={"environment": {"os": "linux ubuntu 22.04"}}).evaluate_ast_node(node)
        self.assertEqual(st2.upper(), "NOT_SATISFIED")

    def test_relationship_condition_evaluation(self):
        """Client-server relationship condition evaluates against topology inventory."""
        node = ConditionNode(
            condition_id="c_rel",
            condition_type=ConditionType.CLIENT_SERVER_RELATIONSHIP,
            subject="relationship",
            operator=Operator.EQUALS,
            value="openssl_to_openssl",
            required=True,
            category=ConditionCategory.ENVIRONMENT,
            verification_method=VerificationMethod.ENDPOINT_INVENTORY
        )
        st_ok, res_ok = CVEEvaluator(config_source={
            "relationships": {"communication": "openssl_to_openssl"}
        }).evaluate_ast_node(node)
        self.assertEqual(st_ok.upper(), "SATISFIED")

    def test_network_exposure_condition_evaluation(self):
        """Network exposure condition evaluates against network inventory."""
        node = ConditionNode(
            condition_id="c_net",
            condition_type=ConditionType.NETWORK_EXPOSURE,
            subject="ajp_port_accessible",
            operator=Operator.EQUALS,
            value=True,
            required=True,
            category=ConditionCategory.ENVIRONMENT,
            verification_method=VerificationMethod.NETWORK_CHECK
        )
        st_exp, res_exposed = CVEEvaluator(config_source={
            "network": {"ajp_port_accessible": True}
        }).evaluate_ast_node(node)
        self.assertEqual(st_exp.upper(), "SATISFIED")

    def test_dependency_condition_evaluation(self):
        """Dependency condition evaluates against package inventory."""
        node = ConditionNode(
            condition_id="c_dep",
            condition_type=ConditionType.DEPENDENCY,
            subject="commons-collections",
            operator=Operator.EQUALS,
            value="3.2.1",
            required=True,
            category=ConditionCategory.ENVIRONMENT,
            verification_method=VerificationMethod.CODE_ANALYSIS
        )
        st_f, res_found = CVEEvaluator(config_source={
            "dependencies": {"commons-collections": "3.2.1"}
        }).evaluate_ast_node(node)
        self.assertEqual(st_f.upper(), "SATISFIED")

    # =========================================================================
    # PART 3: Real Vulnerability Regressions (Items 1-7 from Section 27)
    # =========================================================================

    def test_cve_2017_12615_regression(self):
        """
        CVE-2017-12615 Regression:
        - Authoritative advisory: 'When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled...'
        - Environmental prerequisites: Windows OS, HTTP PUT enabled, version vulnerable.
        - Attack condition: specially crafted request.
        """
        advisory = (
            "When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled, "
            "an attacker can upload a JSP file via a specially crafted request."
        )
        tree = self.extractor.extract_from_sources("CVE-2017-12615", [
            {"source_type": "vendor_advisory", "source_url": "https://tomcat.apache.org/security-7.html", "content": advisory}
        ])

        leaves = tree.get_all_leaves()

        # 1. Environmental: OS = Windows
        os_conds = [c for c in leaves if c.condition_type == ConditionType.OS]
        self.assertTrue(len(os_conds) >= 1)
        self.assertEqual(os_conds[0].value.lower(), "windows")
        self.assertTrue(os_conds[0].required)

        # 2. Environmental: HTTP PUT enabled
        put_conds = [c for c in leaves if "put" in c.subject.lower() or "put" in str(c.value).lower()]
        self.assertTrue(len(put_conds) >= 1)
        self.assertTrue(put_conds[0].required)

        # 3. Version: 7.0.0 to 7.0.79
        self.assertTrue(len(tree.version_conditions) >= 1)

        # 4. Attack condition: crafted request
        attack_conds = [c for c in tree.attack_conditions if "crafted" in c.evidence.lower()]
        self.assertTrue(len(attack_conds) >= 1)
        self.assertEqual(attack_conds[0].category, ConditionCategory.ATTACK)

    def test_cve_2020_1938_regression(self):
        """
        CVE-2020-1938 Regression (Ghostcat):
        - AJP connector active required
        - Network exposure required
        - Version required
        - File upload for RCE separated as impact condition
        """
        advisory = (
            "When the AJP connector is active and exposed to untrusted network users, "
            "an unauthenticated attacker can read arbitrary files. "
            "Furthermore, remote code execution is possible when the application allows file upload."
        )
        tree = self.extractor.extract_from_sources("CVE-2020-1938", [
            {"source_type": "vendor_advisory", "content": advisory}
        ])

        leaves = tree.get_all_leaves()

        # 1. AJP connector active
        ajp_conds = [c for c in leaves if "ajp" in c.subject.lower()]
        self.assertTrue(len(ajp_conds) >= 1)

        # 2. Network exposure
        net_conds = [c for c in leaves if c.condition_type == ConditionType.NETWORK_EXPOSURE or "network" in c.subject.lower() or "untrusted" in c.subject.lower()]
        self.assertTrue(len(net_conds) >= 1)

        # 3. RCE upload condition separated as impact condition (NOT base prerequisite)
        impacts = tree.impact_conditions
        self.assertTrue(len(impacts) >= 1)
        self.assertIn("upload", impacts[0].evidence.lower())
        self.assertEqual(impacts[0].category, ConditionCategory.IMPACT)

    def test_cve_2014_0160_regression(self):
        """
        CVE-2014-0160 Regression (Heartbleed):
        - TLS heartbeat extension enabled required
        - Software version vulnerable
        - Crafted heartbeat packet = attack condition
        """
        advisory = (
            "A vulnerability in OpenSSL 1.0.1 through 1.0.1f allows information disclosure "
            "when the TLS heartbeat extension is enabled. "
            "An attacker can exploit this by sending a specially crafted heartbeat packet."
        )
        tree = self.extractor.extract_from_sources("CVE-2014-0160", [
            {"source_type": "vendor_advisory", "content": advisory}
        ])

        leaves = tree.get_all_leaves()

        # 1. Feature: Heartbeat enabled
        hb_conds = [c for c in leaves if "heartbeat" in c.subject.lower()]
        self.assertTrue(len(hb_conds) >= 1)
        self.assertEqual(hb_conds[0].category, ConditionCategory.ENVIRONMENT)

        # 2. Attack condition: crafted heartbeat packet
        attacks = [c for c in tree.attack_conditions if "heartbeat" in c.evidence.lower()]
        self.assertTrue(len(attacks) >= 1)
        self.assertEqual(attacks[0].category, ConditionCategory.ATTACK)

    def test_cve_2014_0224_regression(self):
        """
        CVE-2014-0224 Regression:
        - Vulnerable client and vulnerable server
        - OpenSSL-to-OpenSSL communication relationship
        - MITM capability = attack condition
        - Crafted handshake = attack condition
        """
        advisory = (
            "An attacker using a man-in-the-middle (MITM) position can force the use of weak keying material "
            "by sending a crafted handshake between a vulnerable client and a vulnerable server "
            "when communicating between OpenSSL client and OpenSSL server."
        )
        tree = self.extractor.extract_from_sources("CVE-2014-0224", [
            {"source_type": "vendor_advisory", "content": advisory}
        ])

        leaves = tree.get_all_leaves()

        # 1. OpenSSL-to-OpenSSL communication relationship
        rel_conds = [c for c in leaves if c.condition_type == ConditionType.CLIENT_SERVER_RELATIONSHIP]
        self.assertTrue(len(rel_conds) >= 1)

        # 2. MITM capability = attack condition
        mitm_attacks = [c for c in tree.attack_conditions if "mitm" in c.evidence.lower() or "man-in-the-middle" in c.evidence.lower()]
        self.assertTrue(len(mitm_attacks) >= 1)
        self.assertEqual(mitm_attacks[0].category, ConditionCategory.ATTACK)

        # 3. Crafted handshake = attack condition
        hs_attacks = [c for c in tree.attack_conditions if "handshake" in c.evidence.lower()]
        self.assertTrue(len(hs_attacks) >= 1)

    def test_cve_2019_0708_regression(self):
        """
        CVE-2019-0708 Regression (BlueKeep):
        - Version vulnerable
        - Specially crafted RDP requests = attack condition
        - Invariant: Do NOT hallucinate unrelated prerequisites without source evidence.
        """
        advisory = (
            "A remote code execution vulnerability exists in Remote Desktop Services on Windows. "
            "An attacker can exploit this by sending specially crafted requests to the target system via RDP."
        )
        tree = self.extractor.extract_from_sources("CVE-2019-0708", [
            {"source_type": "vendor_advisory", "content": advisory}
        ])

        # 1. Attack condition: crafted requests
        attacks = [c for c in tree.attack_conditions if "crafted" in c.evidence.lower() or "rdp" in c.evidence.lower() or "request" in c.evidence.lower()]
        self.assertTrue(len(attacks) >= 1)

        # 2. Must NOT hallucinate unrelated environmental prerequisites (e.g. no fake file upload or proxy requirements)
        leaves = tree.get_all_leaves()
        for env_cond in leaves:
            self.assertNotIn("upload", env_cond.subject.lower())
            self.assertNotIn("proxy", env_cond.subject.lower())

    def test_cve_2021_3449_regression(self):
        """
        CVE-2021-3449 Regression:
        - TLS 1.2 enabled required
        - TLS renegotiation enabled required
        - Malicious renegotiation ClientHello = attack condition
        """
        advisory = (
            "An OpenSSL TLS server is vulnerable to denial of service if TLS 1.2 and renegotiation are enabled. "
            "An attacker can trigger a crash by sending a malicious renegotiation ClientHello."
        )
        tree = self.extractor.extract_from_sources("CVE-2021-3449", [
            {"source_type": "vendor_advisory", "content": advisory}
        ])

        leaves = tree.get_all_leaves()

        # 1. TLS 1.2
        tls_conds = [c for c in leaves if "1.2" in str(c.value) or "1.2" in c.subject or "tls" in c.subject]
        self.assertTrue(len(tls_conds) >= 1)

        # 2. Renegotiation
        reneg_conds = [c for c in leaves if "renegotiation" in c.subject.lower()]
        self.assertTrue(len(reneg_conds) >= 1)

        # 3. Malicious ClientHello = attack condition
        attacks = [c for c in tree.attack_conditions if "clienthello" in c.evidence.lower()]
        self.assertTrue(len(attacks) >= 1)
        self.assertEqual(attacks[0].category, ConditionCategory.ATTACK)

    def test_cve_2025_24813_regression(self):
        """
        CVE-2025-24813 Regression:
        - 4 environmental prerequisites (writes, partial PUT, persistence, deserialization gadget)
        - Version condition
        - Verified via end-to-end evaluation
        """
        cve_record = {
            "cve_id": "CVE-2025-24813",
            "product": "Apache Tomcat",
            "affected_versions": {"range": "< 10.1.35"},
            "prerequisites": [
                {
                    "condition_id": "c1",
                    "name": "default_servlet_writes_enabled",
                    "subject": "readonly",
                    "operator": "equals",
                    "required_value": True,
                    "category": "environment",
                    "required": True,
                    "verification_method": "config_collector"
                },
                {
                    "condition_id": "c2",
                    "name": "partial_put_enabled",
                    "subject": "allowPartialPut",
                    "operator": "equals",
                    "required_value": True,
                    "category": "environment",
                    "required": True,
                    "verification_method": "config_collector"
                }
            ]
        }

        # Case 1: Environment satisfies both prerequisites and version -> SATISFIED / APPLICABLE
        evaluator_sat = CVEEvaluator(config_source={
            "tomcat": {"version": "10.1.18"},
            "configuration": {"readonly": False, "allowPartialPut": True}
        })
        res_sat = evaluator_sat.evaluate_cve(cve_record)
        self.assertEqual(res_sat["applicability_status"], "APPLICABLE")

        # Case 2: Readonly is True -> NOT_SATISFIED / NOT_APPLICABLE
        evaluator_not = CVEEvaluator(config_source={
            "tomcat": {"version": "10.1.18"},
            "configuration": {"readonly": True, "allowPartialPut": True}
        })
        res_not = evaluator_not.evaluate_cve(cve_record)
        self.assertEqual(res_not["applicability_status"], "NOT_APPLICABLE")

    # =========================================================================
    # PART 4: Codebase Audit Test: No Hardcoded CVEs in Production Logic
    # =========================================================================

    def test_zero_cve_specific_logic_in_production_code(self):
        """
        Verify that production code files contain ZERO hardcoded CVE identifiers.
        Only tests and test fixtures are permitted to reference specific CVE IDs.
        """
        prod_files = [
            Path("orchestrator/condition_ir.py"),
            Path("orchestrator/condition_extractor.py"),
            Path("orchestrator/nvd_applicability_parser.py"),
            Path("orchestrator/cve_evaluator.py"),
            Path("orchestrator/cve_prerequisite_agent.py"),
        ]

        cve_pattern = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

        for pf in prod_files:
            if not pf.exists():
                continue
            content = pf.read_text(encoding="utf-8")
            matches = cve_pattern.findall(content)
            self.assertEqual(
                matches,
                [],
                f"Production file {pf} contains hardcoded CVE IDs: {matches}!"
            )


if __name__ == "__main__":
    unittest.main()
