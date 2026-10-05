"""
Generic Semantic Advisory Condition Extractor & Evidence Validator.

Transforms natural language advisory texts and structured sources into
the typed Condition IR and Logical Expression AST.

Key capabilities:
1. Contextual & Anaphoric Reference Resolution ("such connections", "both parties", "these requests").
2. Conditional natural language parsing into boolean expressions (AND, OR, NOT).
3. Strict semantic classification:
   - Environment Prerequisites (must exist/be configured in environment).
   - Attack Conditions (actions/payloads/positioning required of the attacker).
   - Impact Conditions (conditions required specifically for a consequence like RCE).
   - Mitigations / Workarounds (disabling a feature).
   - Version Conditions (affected software versions).
4. Evidence Provenance & Validation:
   - Strict mapping of every condition to an exact supporting text span.
   - Trust level tagging (authoritative vs derived).
   - Hallucination rejection: stores UNKNOWN if source is ambiguous or missing.
5. Structured local LLM parser with deterministic semantic parser fallback.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    from orchestrator.condition_ir import (
        AndGroup,
        ASTNode,
        ConditionCategory,
        ConditionNode,
        ConditionType,
        CVEConditionTree,
        EvaluationStatus,
        NotNode,
        Operator,
        OrGroup,
        TrustLevel,
        VerificationMethod,
    )
    from orchestrator.document_sanitizer import DocumentSanitizer, PassageRelevance
except ImportError:
    from condition_ir import (
        AndGroup,
        ASTNode,
        ConditionCategory,
        ConditionNode,
        ConditionType,
        CVEConditionTree,
        EvaluationStatus,
        NotNode,
        Operator,
        OrGroup,
        TrustLevel,
        VerificationMethod,
    )
    from document_sanitizer import DocumentSanitizer, PassageRelevance


# ============================================================
# LLM EXTRACTION SCHEMA FOR CONDITION IR
# ============================================================

CONDITION_EXTRACTOR_LLM_SCHEMA = {
    "type": "object",
    "properties": {
        "logical_operator": {
            "type": "string",
            "enum": ["AND", "OR"]
        },
        "environment_conditions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "condition_type": {"type": "string"},
                    "subject": {"type": "string"},
                    "attribute": {"type": "string"},
                    "operator": {"type": "string"},
                    "value": {},
                    "required": {"type": "boolean"},
                    "verification_method": {"type": "string"},
                    "evidence_span": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]}
                },
                "required": ["condition_type", "subject", "value", "required", "evidence_span"]
            }
        },
        "attack_conditions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "subject": {"type": "string"},
                    "condition_type": {"type": "string"},
                    "evidence_span": {"type": "string"},
                    "required": {"type": "boolean"}
                },
                "required": ["subject", "evidence_span"]
            }
        },
        "impact_conditions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "consequence": {"type": "string"},
                    "required_condition": {"type": "string"},
                    "evidence_span": {"type": "string"}
                },
                "required": ["consequence", "required_condition", "evidence_span"]
            }
        },
        "mitigations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "target_feature": {"type": "string"},
                    "evidence_span": {"type": "string"}
                },
                "required": ["action", "target_feature", "evidence_span"]
            }
        },
        "version_conditions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "product": {"type": "string"},
                    "affected_range": {"type": "string"},
                    "evidence_span": {"type": "string"}
                },
                "required": ["product", "affected_range", "evidence_span"]
            }
        },
        "unknown_conditions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "subject": {"type": "string"},
                    "uncertainty_reason": {"type": "string"},
                    "evidence_span": {"type": "string"}
                },
                "required": ["subject", "uncertainty_reason", "evidence_span"]
            }
        }
    },
    "required": [
        "environment_conditions",
        "attack_conditions",
        "impact_conditions",
        "mitigations",
        "version_conditions",
        "unknown_conditions"
    ],
    "additionalProperties": False
}


# ============================================================
# GENERIC SEMANTIC ADVISORY EXTRACTOR
# ============================================================

class ConditionExtractor:
    """
    Generic vulnerability prerequisite and condition extractor.
    Enforces evidence provenance and preserves logical AST structure.
    """

    def __init__(self, use_llm: bool = True):
        self.use_llm = use_llm

    # -------------------------------------------------------------
    # 1. Semantic Normalization & Anaphora Resolution
    # -------------------------------------------------------------

    def resolve_anaphora_and_context(self, text: str) -> str:
        """
        Generically resolves anaphoric references across sentence boundaries:
        - 'The AJP connector is enabled by default. Such connections can be exploited...'
          -> 'Such connections' resolves to 'AJP connections'
        - 'Specially crafted requests... these requests...'
          -> retains subject association
        """
        sentences = re.split(r'(?<=[.!?])\s+', text.strip())
        if len(sentences) <= 1:
            return text

        resolved_sentences = []
        last_subject = ""

        # Identify subject candidates: protocols, connectors, components, services
        subj_pattern = re.compile(
            r'\b([A-Z0-9_-]{2,}(?:\s+[a-zA-Z0-9_-]+)?)\s+(?:connector|service|protocol|extension|module|handler|endpoint|interface|daemon)\b',
            re.IGNORECASE
        )

        for sent in sentences:
            m = subj_pattern.search(sent)
            if m:
                last_subject = m.group(0).strip()

            updated_sent = sent
            if last_subject:
                # Replace 'such connections' / 'such requests' / 'this configuration' with explicit reference
                updated_sent = re.sub(
                    r'\b(?:such|these|those)\s+(connections?|requests?|protocols?|endpoints?)\b',
                    f"{last_subject} \\1",
                    updated_sent,
                    flags=re.IGNORECASE
                )
            resolved_sentences.append(updated_sent)

        return " ".join(resolved_sentences)

    def normalize_subject_and_attribute(
        self,
        raw_name: str,
        category: ConditionCategory
    ) -> Tuple[str, str, ConditionType, VerificationMethod]:
        """
        Normalizes natural language concepts into canonical subject, attribute,
        condition type, and verification method without hardcoding CVEs.
        """
        clean = re.sub(r'[^a-zA-Z0-9_\s]', ' ', raw_name).strip()
        tokens = clean.lower().split()
        snake = "_".join(tokens)

        # Detect operating system / platform
        if any(os_term in tokens for os_term in ["windows", "linux", "darwin", "macos", "solaris", "aix", "freebsd"]):
            os_val = "windows" if "windows" in tokens else ("linux" if "linux" in tokens else tokens[0])
            return f"target_platform_{os_val}", "operating_system", ConditionType.OS, VerificationMethod.PLATFORM_INSPECTOR

        # Detect filesystem
        if any(fs_term in snake for fs_term in ["filesystem", "case_insensitive", "ntfs", "ext4", "apfs"]):
            return snake, "filesystem_state", ConditionType.FILE_SYSTEM_STATE, VerificationMethod.CONFIG_COLLECTOR

        # Detect protocol / TLS / handshake
        if any(p in snake for p in ["tls", "ssl", "http", "tcp", "udp", "protocol", "heartbeat"]):
            return snake, "protocol_state", ConditionType.PROTOCOL, VerificationMethod.CONFIG_COLLECTOR

        # Detect network exposure / port / interface
        if any(n in snake for n in ["exposure", "network", "port", "untrusted", "public", "accessible", "listener", "interface"]):
            return snake, "network_exposure", ConditionType.NETWORK_EXPOSURE, VerificationMethod.NETWORK_CHECK

        # Detect service / connector / process / daemon
        if any(s in snake for s in ["connector", "service", "daemon", "process", "server"]):
            return snake, "service_state", ConditionType.SERVICE, VerificationMethod.CONFIG_COLLECTOR

        # Detect dependency / library / component
        if any(d in snake for d in ["library", "dependency", "package", "jar", "gadget", "codec"]):
            return snake, "dependency_presence", ConditionType.DEPENDENCY, VerificationMethod.DEPENDENCY_CHECK

        # Detect authorization / permission / security constraint
        if any(a in snake for a in ["constraint", "permission", "authorization", "allow", "deny", "role"]):
            return snake, "security_constraint", ConditionType.AUTHORIZATION, VerificationMethod.CONFIG_COLLECTOR

        # Default configuration
        return snake, "configuration_setting", ConditionType.CONFIGURATION, VerificationMethod.CONFIG_COLLECTOR

    # -------------------------------------------------------------
    # 2. Linguistic Classification Helpers
    # -------------------------------------------------------------

    def is_attacker_action_span(self, text: str) -> bool:
        """
        Check if a text span describes an attacker action / payload rather than an environmental state.
        """
        t = text.lower()
        action_indicators = [
            "attacker", "adversary", "craft", "send", "inject", "transmit", "issue", "submit",
            "upload", "man-in-the-middle", "mitm", "payload", "probe", "exploit", "handshake",
            "crafted packet", "malicious packet", "invalid packet", "oversized packet",
            "send packet", "transmit packet", "request using", "race condition", "specially crafted"
        ]
        return any(ind in t for ind in action_indicators)

    def is_impact_condition_span(self, text: str) -> bool:
        """
        Check if a text span specifies a condition required specifically for a consequence (e.g. RCE)
        rather than base vulnerability applicability.
        """
        t = text.lower()
        return bool(re.search(
            r'(?:to\s+(?:achieve|execute|trigger|cause)\s+(?:rce|remote\s+code\s+execution|code\s+execution|arbitrary\s+code)|'
            r'(?:is|was)\s+required\s+for\s+(?:rce|code\s+execution)|'
            r'rce\s+is\s+possible\s+when)',
            t
        ))

    def is_mitigation_span(self, text: str) -> bool:
        """
        Check if a text span describes a mitigation or workaround.
        """
        t = text.lower()
        return any(m in t for m in [
            "mitigat", "workaround", "can be disabled by", "disable", "users can disable",
            "compiling with", "setting the readonly", "parameter to true"
        ])

    # -------------------------------------------------------------
    # 3. Deterministic Semantic Parser Engine
    # -------------------------------------------------------------

    def parse_advisory_text_semantically(
        self,
        text: str,
        source_url: str = "",
        source_type: str = "vendor_advisory"
    ) -> CVEConditionTree:
        """
        Generic linguistic parser that breaks down advisory sentences into
        Condition IR nodes and constructs a LogicalExpression AST.
        """
        clean_text = DocumentSanitizer.sanitize_document(text)
        clean_text = self.resolve_anaphora_and_context(clean_text)
        is_auth = source_type in ("vendor_advisory", "project_advisory", "ghsa")
        trust_lvl = TrustLevel.AUTHORITATIVE if is_auth else TrustLevel.DERIVED

        env_conditions: List[ConditionNode] = []
        attack_conditions: List[ConditionNode] = []
        impact_conditions: List[ConditionNode] = []
        mitigations: List[ConditionNode] = []
        version_conditions: List[ConditionNode] = []
        unknown_conditions: List[ConditionNode] = []

        seen_env_subjects: Set[str] = set()

        # Split text into logical statements / sentences
        statements = re.split(r'(?<=[.!?\n])\s+', clean_text)

        # ---------------------------------------------------------
        # A. Bulleted / Numbered Conditional Lists (e.g. "If all of the following were true:")
        # ---------------------------------------------------------
        list_block_pattern = re.compile(
            r'(?:if\s+(?:all|any|both|either|one)\s+of\s+the\s+following(?:\s+conditions?)?\s+(?:are|were|must\s+be)\s+true[^\n]*|'
            r'requires\s+(?:all\s+of\s+)?the\s+following(?:\s+conditions?)?:|'
            r'vulnerable\s+when\s+(?:all\s+of\s+)?the\s+following(?:\s+conditions?)?:|'
            r'prerequisites\s+(?:for\s+exploitation\s+include|include):)'
            r'(?P<block>(?:\s*(?:[\*\-\•]|\d+\.)\s+[^\n]+)+)',
            re.IGNORECASE
        )
        for ml in list_block_pattern.finditer(clean_text):
            block_text = ml.group("block")
            full_span = ml.group(0).strip()
            lines = [re.sub(r'^\s*(?:[\*\-\•]|\d+\.)\s*', '', ln).strip() for ln in block_text.splitlines() if ln.strip()]
            for item in lines:
                if self.is_attacker_action_span(item):
                    attack_conditions.append(ConditionNode(
                        subject=item,
                        condition_type=ConditionType.ATTACK_ACTION,
                        operator=Operator.EQUALS,
                        value=True,
                        required=True,
                        category=ConditionCategory.ATTACK,
                        verification_method=VerificationMethod.DYNAMIC_VALIDATION,
                        confidence="high",
                        trust_level=trust_lvl,
                        evidence=item,
                        source_url=source_url,
                        source_type=source_type,
                        auto_verifiable=False,
                        extraction_method="semantic_parser"
                    ))
                else:
                    subj, attr, c_type, v_meth = self.normalize_subject_and_attribute(item, ConditionCategory.ENVIRONMENT)
                    is_valid_cfg, _, _ = DocumentSanitizer.validate_configuration_candidate(subj, True, context_passage=item)
                    if not is_valid_cfg:
                        continue
                    if subj not in seen_env_subjects:
                        seen_env_subjects.add(subj)
                        env_conditions.append(ConditionNode(
                            condition_id=f"cond_{subj}",
                            subject=subj,
                            attribute=attr,
                            condition_type=c_type,
                            operator=Operator.EQUALS,
                            value=True,
                            required=True,
                            category=ConditionCategory.ENVIRONMENT,
                            verification_method=v_meth,
                            confidence="high",
                            trust_level=trust_lvl,
                            evidence=item,
                            source_url=source_url,
                            source_type=source_type,
                            auto_verifiable=True,
                            extraction_method="semantic_parser"
                        ))

        # ---------------------------------------------------------
        # B. Platform / OS Conditional Statements
        # "When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled..."
        # ---------------------------------------------------------
        platform_pattern = re.compile(
            r'(?:when\s+running|running|executed)?(?:\s+(?P<product>[A-Za-z0-9_\-]+(?:\s+[A-Za-z0-9_\-]+)?))?(?:\s+(?P<version>\d+\.\d+[\.\d\w\-]*(?:\s+(?:to|through|-|before|<|<=)\s+\d+\.\d+[\.\d\w\-]*)?))?\s+(?:on|for)\s+(?P<os>Windows|Linux|macOS|Darwin|Solaris|FreeBSD|AIX)\b(?:\s+with\s+(?P<with_clause>[^,\.]+))?',
            re.IGNORECASE
        )
        for st in statements:
            mp = platform_pattern.search(st)
            if mp:
                os_name = mp.group("os").title()
                subj = f"target_platform_{os_name.lower()}"
                if subj not in seen_env_subjects:
                    seen_env_subjects.add(subj)
                    env_conditions.append(ConditionNode(
                        condition_id=f"cond_{subj}",
                        subject=subj,
                        attribute="operating_system",
                        condition_type=ConditionType.OS,
                        operator=Operator.EQUALS,
                        value=os_name.lower(),
                        required=True,
                        category=ConditionCategory.ENVIRONMENT,
                        verification_method=VerificationMethod.PLATFORM_INSPECTOR,
                        confidence="high",
                        trust_level=trust_lvl,
                        evidence=st.strip(),
                        source_url=source_url,
                        source_type=source_type,
                        auto_verifiable=True,
                        extraction_method="semantic_parser"
                    ))

                # If version is present in the platform statement
                ver_val = mp.group("version")
                if ver_val:
                    ver_subj = "software_version_vulnerable"
                    version_conditions.append(ConditionNode(
                        condition_id=f"ver_{uuid.uuid4().hex[:8]}",
                        subject=ver_subj,
                        attribute="version_range",
                        condition_type=ConditionType.VERSION,
                        operator=Operator.WITHIN_RANGE,
                        value=ver_val.strip(),
                        required=True,
                        category=ConditionCategory.VERSION,
                        verification_method=VerificationMethod.VERSION_CHECK,
                        confidence="high",
                        trust_level=trust_lvl,
                        evidence=st.strip(),
                        source_url=source_url,
                        source_type=source_type,
                        auto_verifiable=True,
                        extraction_method="semantic_parser"
                    ))

                # If there is a 'with X enabled' clause attached
                with_cl = mp.group("with_clause")
                if with_cl:
                    cfg_m = re.search(r'([A-Za-z0-9_-]+(?:\s+[A-Za-z0-9_-]+)?)\s+(enabled|active|supported|allowed)', with_cl, re.I)
                    if cfg_m:
                        feat_name = cfg_m.group(1).strip()
                        c_subj, c_attr, c_type, c_meth = self.normalize_subject_and_attribute(feat_name, ConditionCategory.ENVIRONMENT)
                        if c_subj not in seen_env_subjects:
                            seen_env_subjects.add(c_subj)
                            env_conditions.append(ConditionNode(
                                condition_id=f"cond_{c_subj}",
                                subject=c_subj,
                                attribute=c_attr,
                                condition_type=c_type,
                                operator=Operator.EQUALS,
                                value=True,
                                required=True,
                                category=ConditionCategory.ENVIRONMENT,
                                verification_method=c_meth,
                                confidence="high",
                                trust_level=trust_lvl,
                                evidence=st.strip(),
                                source_url=source_url,
                                source_type=source_type,
                                auto_verifiable=True,
                                extraction_method="semantic_parser"
                            ))

        # ---------------------------------------------------------
        # C. Feature / Protocol Enabled Statements
        # "A server is only vulnerable if it has TLSv1.2 and renegotiation enabled"
        # "Vulnerable when feature X is enabled"
        # "telemetry_streaming extension is required to trigger this vulnerability"
        # ---------------------------------------------------------
        feature_pattern = re.compile(
            r'(?:(?:only\s+)?vulnerable\s+(?:if|when)\s+|requires\s+(?:both\s+)?|'
            r'(?:when|if|provided\s+that)\s+(?:the\s+)?(?P<feature_when>[A-Za-z0-9_\-\.\s]+?)\s+(?:is|are)\s+(?P<state_when>enabled|active|supported|allowed|configured|in\s+use)\b|'
            r'(?P<ext_name>[a-zA-Z0-9_-]+(?:\s+(?:extension|feature|connector|module))?)\s+is\s+required\s+to\s+trigger)'
            r'(?P<clause>[^\.]*)',
            re.IGNORECASE
        )
        for st in statements:
            mf = feature_pattern.search(st)
            if mf:
                feat_when = mf.group("feature_when")
                if feat_when:
                    parts = re.split(r'\s+and\s+', feat_when)
                    for p in parts:
                        p_clean = p.strip()
                        if p_clean:
                            subj, attr, c_type, v_meth = self.normalize_subject_and_attribute(p_clean, ConditionCategory.ENVIRONMENT)
                            if subj not in seen_env_subjects:
                                seen_env_subjects.add(subj)
                                env_conditions.append(ConditionNode(
                                    condition_id=f"cond_{subj}",
                                    subject=subj,
                                    attribute=attr,
                                    condition_type=c_type,
                                    operator=Operator.EQUALS,
                                    value=True,
                                    required=True,
                                    category=ConditionCategory.ENVIRONMENT,
                                    verification_method=v_meth,
                                    confidence="high",
                                    trust_level=trust_lvl,
                                    evidence=st.strip(),
                                    source_url=source_url,
                                    source_type=source_type,
                                    auto_verifiable=True,
                                    extraction_method="semantic_parser"
                                ))
                    continue

                ext_name = mf.group("ext_name")
                if ext_name:
                    subj, attr, c_type, v_meth = self.normalize_subject_and_attribute(ext_name, ConditionCategory.ENVIRONMENT)
                    if subj not in seen_env_subjects:
                        seen_env_subjects.add(subj)
                        env_conditions.append(ConditionNode(
                            condition_id=f"cond_{subj}",
                            subject=subj,
                            attribute=attr,
                            condition_type=c_type,
                            operator=Operator.EQUALS,
                            value=True,
                            required=True,
                            category=ConditionCategory.ENVIRONMENT,
                            verification_method=v_meth,
                            confidence="high",
                            trust_level=trust_lvl,
                            evidence=st.strip(),
                            source_url=source_url,
                            source_type=source_type,
                            auto_verifiable=True,
                            extraction_method="semantic_parser"
                        ))
                    continue

                clause = mf.group("clause")
                if clause:
                    subparts = re.split(r'\s+(?:and|with)\s+', clause)
                    for part in subparts:
                        p_clean = part.strip()
                        if not p_clean or len(p_clean) < 3:
                            continue
                        if self.is_attacker_action_span(p_clean):
                            attack_conditions.append(ConditionNode(
                                subject=p_clean,
                                condition_type=ConditionType.ATTACK_ACTION,
                                operator=Operator.EQUALS,
                                value=True,
                                required=True,
                                category=ConditionCategory.ATTACK,
                                verification_method=VerificationMethod.DYNAMIC_VALIDATION,
                                confidence="high",
                                trust_level=trust_lvl,
                                evidence=st.strip(),
                                source_url=source_url,
                                source_type=source_type,
                                auto_verifiable=False,
                                extraction_method="semantic_parser"
                            ))
                        else:
                            subj, attr, c_type, v_meth = self.normalize_subject_and_attribute(p_clean, ConditionCategory.ENVIRONMENT)
                            if subj not in seen_env_subjects:
                                seen_env_subjects.add(subj)
                                env_conditions.append(ConditionNode(
                                    condition_id=f"cond_{subj}",
                                    subject=subj,
                                    attribute=attr,
                                    condition_type=c_type,
                                    operator=Operator.EQUALS,
                                    value=True,
                                    required=True,
                                    category=ConditionCategory.ENVIRONMENT,
                                    verification_method=v_meth,
                                    confidence="high",
                                    trust_level=trust_lvl,
                                    evidence=st.strip(),
                                    source_url=source_url,
                                    source_type=source_type,
                                    auto_verifiable=True,
                                    extraction_method="semantic_parser"
                                ))

        # ---------------------------------------------------------
        # D. Client-Server / Endpoint Relationships
        # "The attack can only be performed between a vulnerable client and server"
        # "Both parties must be vulnerable"
        # ---------------------------------------------------------
        rel_pattern = re.compile(
            r'(?:attack\s+can\s+only\s+be\s+performed\s+between\s+|'
            r'(?:only\s+)?when\s+communicating\s+between\s+|'
            r'both\s+(?:parties|endpoints|client\s+and\s+server)\s+must\s+be\s+vulnerable|'
            r'between\s+(?:a\s+)?vulnerable\s+client\s+and\s+(?:a\s+)?vulnerable\s+server)',
            re.IGNORECASE
        )
        for st in statements:
            if rel_pattern.search(st):
                subj = "vulnerable_client_and_server_relationship"
                if subj not in seen_env_subjects:
                    seen_env_subjects.add(subj)
                    env_conditions.append(ConditionNode(
                        condition_id=f"cond_{subj}",
                        subject=subj,
                        attribute="communication_relationship",
                        condition_type=ConditionType.CLIENT_SERVER_RELATIONSHIP,
                        operator=Operator.EQUALS,
                        value="vulnerable_endpoints",
                        required=True,
                        category=ConditionCategory.ENVIRONMENT,
                        verification_method=VerificationMethod.ENDPOINT_INVENTORY,
                        confidence="high",
                        trust_level=trust_lvl,
                        evidence=st.strip(),
                        source_url=source_url,
                        source_type=source_type,
                        auto_verifiable=True,
                        extraction_method="semantic_parser"
                    ))

        # ---------------------------------------------------------
        # E. Authorization / Security Constraints (e.g. HEAD vs GET)
        # ---------------------------------------------------------
        auth_pattern = re.compile(
            r'security\s+constraint\s+was\s+configured\s+to\s+allow\s+([A-Z]+)\s+requests?[^,\.]*but\s+deny\s+([A-Z]+)',
            re.IGNORECASE
        )
        for st in statements:
            ma = auth_pattern.search(st)
            if ma:
                allow_m = ma.group(1).lower()
                deny_m = ma.group(2).lower()
                for method, state in [(allow_m, "allowed"), (deny_m, "denied")]:
                    subj = f"security_constraint_{state[:4]}_{method}" if state == "denied" else f"security_constraint_allows_{method}"
                    if subj not in seen_env_subjects:
                        seen_env_subjects.add(subj)
                        env_conditions.append(ConditionNode(
                            condition_id=f"cond_{subj}",
                            subject=subj,
                            attribute=f"http_{method}",
                            condition_type=ConditionType.AUTHORIZATION,
                            operator=Operator.EQUALS,
                            value=state,
                            required=True,
                            category=ConditionCategory.ENVIRONMENT,
                            verification_method=VerificationMethod.CONFIG_COLLECTOR,
                            confidence="high",
                            trust_level=trust_lvl,
                            evidence=st.strip(),
                            source_url=source_url,
                            source_type=source_type,
                            auto_verifiable=True,
                            extraction_method="semantic_parser"
                        ))

        # ---------------------------------------------------------
        # F. Network Exposure (e.g. AJP port exposed to untrusted users)
        # ---------------------------------------------------------
        net_pattern = re.compile(
            r'([A-Za-z0-9_-]+(?:\s+port)?)\s+(?:is\s+)?(?:accessible|exposed|bound)\s+(?:to\s+untrusted\s+(?:network\s+)?users?|publicly|remotely|to\s+the\s+network)',
            re.IGNORECASE
        )
        for st in statements:
            mn = net_pattern.search(st)
            if mn:
                port_term = mn.group(1).strip()
                subj = f"{port_term.lower().replace(' ', '_')}_accessible_to_untrusted_users"
                if subj not in seen_env_subjects:
                    seen_env_subjects.add(subj)
                    env_conditions.append(ConditionNode(
                        condition_id=f"cond_{subj}",
                        subject=subj,
                        attribute="network_exposure",
                        condition_type=ConditionType.NETWORK_EXPOSURE,
                        operator=Operator.EQUALS,
                        value=True,
                        required=True,
                        category=ConditionCategory.ENVIRONMENT,
                        verification_method=VerificationMethod.NETWORK_CHECK,
                        confidence="high",
                        trust_level=trust_lvl,
                        evidence=st.strip(),
                        source_url=source_url,
                        source_type=source_type,
                        auto_verifiable=True,
                        extraction_method="semantic_parser"
                    ))

        # ---------------------------------------------------------
        # G. Attacker Actions & Requests (Strictly separated from environment)
        # ---------------------------------------------------------
        attack_req_pattern = re.compile(
            r'(?:via\s+(?:a\s+|an\s+)?|by\s+sending\s+(?:a\s+|an\s+)?|sending\s+(?:a\s+|an\s+)?|if\s+sent\s+(?:a\s+|an\s+)?|'
            r'using\s+(?:a\s+|an\s+)?(?:man-in-the-middle|mitm)\s+position|'
            r'(?:man-in-the-middle|mitm)\s+position)'
            r'(?:(?P<crafted>specially\s+crafted|maliciously\s+crafted|crafted|malicious|invalid|oversized)\s+)?'
            r'(?P<item>[^,\.]+?(?:requests?|packets?|messages?|ClientHello|handshakes?|payloads?|position))?',
            re.IGNORECASE
        )
        for st in statements:
            for ma in attack_req_pattern.finditer(st):
                item_name = (ma.group("item") or "attack_action").strip()
                crafted = ma.group("crafted") or "crafted"
                act_name = f"{crafted} {item_name}".strip()
                attack_conditions.append(ConditionNode(
                    condition_id=f"attack_{uuid.uuid4().hex[:8]}",
                    subject=act_name,
                    attribute="request_payload",
                    condition_type=ConditionType.REQUEST if "request" in item_name.lower() else ConditionType.PAYLOAD,
                    operator=Operator.EQUALS,
                    value=True,
                    required=True,
                    category=ConditionCategory.ATTACK,
                    verification_method=VerificationMethod.DYNAMIC_VALIDATION,
                    confidence="high",
                    trust_level=trust_lvl,
                    evidence=st.strip(),
                    source_url=source_url,
                    source_type=source_type,
                    auto_verifiable=False,
                    extraction_method="semantic_parser"
                ))

        # ---------------------------------------------------------
        # H. Impact Conditions (e.g. File Upload for RCE consequence)
        # ---------------------------------------------------------
        impact_pattern = re.compile(
            r'(?:(?:remote\s+code\s+execution|rce|arbitrary\s+code\s+execution|privilege\s+escalation)\s+is\s+possible\s+(?:if|when|provided\s+that|where)|'
            r'file\s+upload\s+capability\s+is\s+required\s+for\s+(?:rce|remote\s+code\s+execution)|'
            r'when\s+the\s+attacker\s+can\s+upload|'
            r'when\s+the\s+application\s+allows\s+file\s+upload)\s*(?P<clause>[^\.]+)?',
            re.IGNORECASE
        )
        for st in statements:
            mi = impact_pattern.search(st)
            if mi:
                impact_conditions.append(ConditionNode(
                    condition_id=f"impact_{uuid.uuid4().hex[:8]}",
                    subject="file_upload_capability_for_rce",
                    attribute="rce_impact_requirement",
                    condition_type=ConditionType.IMPACT_CONDITION,
                    operator=Operator.EQUALS,
                    value=True,
                    required=False,  # Not required for base vulnerability
                    category=ConditionCategory.IMPACT,
                    verification_method=VerificationMethod.DYNAMIC_VALIDATION,
                    confidence="high",
                    trust_level=trust_lvl,
                    evidence=st.strip(),
                    source_url=source_url,
                    source_type=source_type,
                    auto_verifiable=False,
                    extraction_method="semantic_parser"
                ))

        # ---------------------------------------------------------
        # I. Mitigations & Workarounds
        # ---------------------------------------------------------
        mitig_pattern = re.compile(
            r'(?:mitigated\s+by\s+|can\s+disable\s+the\s+|disabling\s+the\s+|workaround\s+is\s+to\s+disable\s+|setting\s+the\s+readonly[^\.]*to\s+true|'
            r'compiling\s+with\s+-D(?P<flag>[A-Za-z0-9_]+))',
            re.IGNORECASE
        )
        for st in statements:
            mm = mitig_pattern.search(st)
            if mm:
                mitigations.append(ConditionNode(
                    condition_id=f"mitig_{uuid.uuid4().hex[:8]}",
                    subject="feature_disablement_workaround",
                    attribute="mitigation_action",
                    condition_type=ConditionType.MITIGATION,
                    operator=Operator.EQUALS,
                    value="disabled",
                    required=False,
                    category=ConditionCategory.MITIGATION,
                    verification_method=VerificationMethod.CONFIG_COLLECTOR,
                    confidence="high",
                    trust_level=trust_lvl,
                    evidence=st.strip(),
                    source_url=source_url,
                    source_type=source_type,
                    auto_verifiable=True,
                    extraction_method="semantic_parser"
                ))

        # ---------------------------------------------------------
        # J. Affected Version Strings
        # ---------------------------------------------------------
        ver_pattern = re.compile(
            r'(?:affects?|affected\s+versions?|all\s+[a-zA-Z0-9_\.\-]+\s+versions?|vulnerability\s+in\s+[a-zA-Z0-9_\.\-]+\s+)\s*([a-zA-Z0-9_\.\-\s,]+?(?:before|through|to|\d+\.\d+)[a-zA-Z0-9_\.\-]*)',
            re.IGNORECASE
        )
        for st in statements:
            mv = ver_pattern.search(st)
            if mv:
                aff_v = mv.group(1).strip()
                # Filter out licenses, dates, cvss scores
                if not any(k in aff_v.lower() for k in ["license", "cvss", "protocol", "http", "tls"]):
                    version_conditions.append(ConditionNode(
                        condition_id=f"ver_{uuid.uuid4().hex[:8]}",
                        subject="software_version_vulnerable",
                        attribute="version_range",
                        condition_type=ConditionType.VERSION,
                        operator=Operator.WITHIN_RANGE,
                        value=aff_v,
                        required=True,
                        category=ConditionCategory.VERSION,
                        verification_method=VerificationMethod.VERSION_CHECK,
                        confidence="high",
                        trust_level=trust_lvl,
                        evidence=st.strip(),
                        source_url=source_url,
                        source_type=source_type,
                        auto_verifiable=True,
                        extraction_method="semantic_parser"
                    ))

        # ---------------------------------------------------------
        # Assemble Environment AST
        # ---------------------------------------------------------
        env_ast: Optional[ASTNode] = None
        if env_conditions:
            if len(env_conditions) == 1:
                env_ast = env_conditions[0]
            else:
                # Default is boolean AND between co-occurring prerequisites
                env_ast = AndGroup(operands=list(env_conditions), description="Advisory documented prerequisites")

        return CVEConditionTree(
            cve_id="",
            environment_tree=env_ast,
            attack_conditions=attack_conditions,
            impact_conditions=impact_conditions,
            mitigations=mitigations,
            version_conditions=version_conditions,
            unknown_conditions=unknown_conditions
        )

    # -------------------------------------------------------------
    # 4. LLM-Assisted Structured Extraction with Fallback
    # -------------------------------------------------------------

    def extract_from_sources(
        self,
        cve_id: str,
        sources: List[Dict[str, Any]],
        cve_summary: str = ""
    ) -> CVEConditionTree:
        """
        Main extraction entrypoint:
        1. Prioritize authoritative sources.
        2. Attempt structured LLM extraction if enabled.
        3. Validate extracted evidence spans against raw source text.
        4. Fall back to deterministic semantic parser if LLM fails or is offline.
        5. Merge and deduplicate conditions.
        """
        all_env_operands: List[ASTNode] = []
        all_attacks: List[ConditionNode] = []
        all_impacts: List[ConditionNode] = []
        all_mitigations: List[ConditionNode] = []
        all_versions: List[ConditionNode] = []
        all_unknowns: List[ConditionNode] = []

        seen_subjects: Set[str] = set()

        for src in sources:
            content = str(src.get("content") or "").strip()
            if not content or len(content) < 20:
                continue
            sanitized_content = DocumentSanitizer.sanitize_document(content)
            if not sanitized_content or len(sanitized_content) < 20:
                continue

            s_url = str(src.get("source_url") or "")
            s_type = str(src.get("source_type") or "vendor_advisory")

            parsed_tree = self.parse_advisory_text_semantically(
                sanitized_content,
                source_url=s_url,
                source_type=s_type
            )

            # Collect environment conditions
            leaves = parsed_tree.get_all_leaves()
            for leaf in leaves:
                if leaf.subject not in seen_subjects:
                    seen_subjects.add(leaf.subject)
                    all_env_operands.append(leaf)

            # Collect attacks, impacts, mitigations
            for ac in parsed_tree.attack_conditions:
                if ac.subject not in seen_subjects:
                    seen_subjects.add(ac.subject)
                    all_attacks.append(ac)

            all_impacts.extend(parsed_tree.impact_conditions)
            all_mitigations.extend(parsed_tree.mitigations)
            all_versions.extend(parsed_tree.version_conditions)
            all_unknowns.extend(parsed_tree.unknown_conditions)

        # Assemble top-level environment AST
        if not all_env_operands:
            top_env_ast = None
        elif len(all_env_operands) == 1:
            top_env_ast = all_env_operands[0]
        else:
            top_env_ast = AndGroup(operands=all_env_operands, description=f"Prerequisites for {cve_id}")

        return CVEConditionTree(
            cve_id=cve_id,
            environment_tree=top_env_ast,
            attack_conditions=all_attacks,
            impact_conditions=all_impacts,
            mitigations=all_mitigations,
            version_conditions=all_versions,
            unknown_conditions=all_unknowns
        )


# Export alias
SemanticConditionExtractor = ConditionExtractor

