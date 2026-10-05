"""
Generic Condition Intermediate Representation (IR) and Abstract Syntax Tree (AST)
for Vulnerability Prerequisite Extraction and Deterministic Evaluation.

Provides:
1. Strongly typed enums for condition types, categories, operators, and trust levels.
2. ConditionNode dataclass representing individual documented vulnerability conditions.
3. LogicalExpression AST (AndGroup, OrGroup, NotNode, ConditionNode) supporting
   arbitrary nested boolean expressions (AND, OR, NOT).
4. Full JSON serialization/deserialization with schema validation.
5. Backward-compatibility adapters for legacy prerequisite dictionaries.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union


# ============================================================
# ENUMS
# ============================================================

class ConditionCategory(str, Enum):
    """
    High-level functional category separating environment prerequisites
    from attacker prerequisites, consequences, mitigations, and versioning.
    """
    ENVIRONMENT = "environment"
    ATTACK = "attack"
    IMPACT = "impact"
    MITIGATION = "mitigation"
    VERSION = "version"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: str) -> ConditionCategory:
        v = (val or "").strip().lower()
        if v in ("environment", "env", "configuration", "service", "network", "platform", "operating_system", "filesystem", "dependency", "protocol", "authorization", "authentication"):
            return cls.ENVIRONMENT
        elif v in ("attack", "attack_action", "attacker_condition", "request_condition", "request", "payload", "interaction"):
            return cls.ATTACK
        elif v in ("impact", "impact_condition", "consequence"):
            return cls.IMPACT
        elif v in ("mitigation", "workaround"):
            return cls.MITIGATION
        elif v in ("version", "software_version"):
            return cls.VERSION
        return cls.UNKNOWN


class ConditionType(str, Enum):
    """
    Typed, generic Condition IR types covering software, platform,
    network, application state, attacker positioning, and mitigations.
    """
    # Version & Identity
    VERSION = "VERSION"
    PRODUCT = "PRODUCT"
    VENDOR = "VENDOR"
    PLATFORM = "PLATFORM"
    OS = "OS"
    ARCHITECTURE = "ARCHITECTURE"

    # Components & Services
    SERVICE = "SERVICE"
    PROCESS = "PROCESS"
    COMPONENT = "COMPONENT"
    MODULE = "MODULE"
    LIBRARY = "LIBRARY"
    DEPENDENCY = "DEPENDENCY"

    # Network & Listeners
    LISTENER = "LISTENER"
    PORT = "PORT"
    PROTOCOL = "PROTOCOL"
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    NETWORK_INTERFACE = "NETWORK_INTERFACE"
    ENDPOINT = "ENDPOINT"

    # Configuration & Security State
    CONFIGURATION = "CONFIGURATION"
    FEATURE = "FEATURE"
    PERMISSION = "PERMISSION"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"

    # Environmental & Deployment State
    FILE_SYSTEM_STATE = "FILE_SYSTEM_STATE"
    APPLICATION_STATE = "APPLICATION_STATE"
    DEPLOYMENT_STATE = "DEPLOYMENT_STATE"
    RUNTIME_STATE = "RUNTIME_STATE"

    # Topology & Relationships
    CLIENT_SERVER_RELATIONSHIP = "CLIENT_SERVER_RELATIONSHIP"
    ENDPOINT_RELATIONSHIP = "ENDPOINT_RELATIONSHIP"
    TOPOLOGY = "TOPOLOGY"
    COMMUNICATION_RELATIONSHIP = "COMMUNICATION_RELATIONSHIP"

    # Attacker Positioning & Capability
    ATTACKER_CAPABILITY = "ATTACKER_CAPABILITY"
    ATTACKER_POSITION = "ATTACKER_POSITION"
    ATTACKER_ACCESS = "ATTACKER_ACCESS"
    ATTACKER_AUTHENTICATION = "ATTACKER_AUTHENTICATION"

    # Attack Actions & Payloads
    REQUEST = "REQUEST"
    PAYLOAD = "PAYLOAD"
    INTERACTION = "INTERACTION"
    ATTACK_ACTION = "ATTACK_ACTION"

    # Consequence & Workaround
    IMPACT_CONDITION = "IMPACT_CONDITION"
    MITIGATION = "MITIGATION"
    WORKAROUND = "WORKAROUND"

    # Generic Fallback
    GENERIC = "GENERIC"

    @classmethod
    def from_str(cls, val: str) -> ConditionType:
        v = (val or "").strip().upper()
        if hasattr(cls, v):
            return cls[v]
        # Mapping helpers
        mapping = {
            "OPERATING_SYSTEM": cls.OS,
            "FILESYSTEM": cls.FILE_SYSTEM_STATE,
            "CONFIG": cls.CONFIGURATION,
            "NETWORK": cls.NETWORK_EXPOSURE,
            "REQUEST_CONDITION": cls.REQUEST,
            "ATTACK_CONDITION": cls.ATTACK_ACTION,
        }
        return mapping.get(v, cls.GENERIC)


class Operator(str, Enum):
    """
    Comparison / evaluation operators for leaf conditions.
    """
    EQUALS = "=="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    GREATER_THAN_OR_EQUAL = ">="
    LESS_THAN = "<"
    LESS_THAN_OR_EQUAL = "<="
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"
    MATCHES_REGEX = "regex"
    IS_ENABLED = "is_enabled"
    IS_DISABLED = "is_disabled"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    WITHIN_RANGE = "within_range"
    OUTSIDE_RANGE = "outside_range"


class TrustLevel(str, Enum):
    """
    Source trust level for conditions.
    """
    AUTHORITATIVE = "authoritative"
    DERIVED = "derived"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class VerificationMethod(str, Enum):
    """
    Evidence provider backend assigned to verify this condition.
    """
    CONFIG_COLLECTOR = "config_collector"
    VERSION_CHECK = "version_check"
    PLATFORM_INSPECTOR = "platform_inspector"
    ENDPOINT_INVENTORY = "endpoint_inventory"
    NETWORK_CHECK = "network_check"
    DEPENDENCY_CHECK = "dependency_check"
    CODE_ANALYSIS = "code_analysis"
    DYNAMIC_VALIDATION = "dynamic_validation"
    MANUAL_VERIFICATION = "manual_verification"
    UNKNOWN = "unknown"


class EvaluationStatus(str, Enum):
    """
    Three-valued deterministic evaluation status.
    """
    SATISFIED = "SATISFIED"
    NOT_SATISFIED = "NOT_SATISFIED"
    UNKNOWN = "UNKNOWN"


# ============================================================
# CONDITION NODE (LEAF OF AST)
# ============================================================

@dataclass
class ConditionNode:
    """
    Typed, generic Condition IR leaf node adhering to the specification in Section 4.
    """
    condition_id: str = field(default_factory=lambda: f"cond_{uuid.uuid4().hex[:10]}")
    condition_type: ConditionType = ConditionType.GENERIC
    subject: str = ""
    attribute: str = ""
    operator: Operator = Operator.EQUALS
    value: Any = True

    logical_group: Optional[str] = None
    parent_condition_id: Optional[str] = None

    # Required means logically documented as required for the vulnerability.
    # It does NOT mean evidence is currently available.
    required: bool = True

    category: ConditionCategory = ConditionCategory.ENVIRONMENT

    verification_method: VerificationMethod = VerificationMethod.CONFIG_COLLECTOR

    confidence: str = "high"  # high | medium | low
    trust_level: TrustLevel = TrustLevel.AUTHORITATIVE

    # Exact evidence span from the authoritative advisory / source
    evidence: str = ""
    source_url: str = ""
    source_type: str = "vendor_advisory"
    source_reference: str = ""

    auto_verifiable: bool = True
    extraction_method: str = "semantic_parser"  # structured_data | semantic_parser | llm | rule
    normalization_notes: str = ""

    # Dynamic evaluation result tracking
    evaluation_status: EvaluationStatus = EvaluationStatus.UNKNOWN
    evaluation_reason: str = ""
    target_evidence_found: Any = None
    configuration_evidence: List[Union[str, Dict[str, Any]]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert condition node to JSON-serializable dictionary."""
        return {
            "condition_id": self.condition_id,
            "condition_type": self.condition_type.value if isinstance(self.condition_type, ConditionType) else str(self.condition_type),
            "subject": self.subject,
            "attribute": self.attribute,
            "operator": self.operator.value if isinstance(self.operator, Operator) else str(self.operator),
            "value": self.value,
            "logical_group": self.logical_group,
            "parent_condition_id": self.parent_condition_id,
            "required": self.required,
            "category": self.category.value if isinstance(self.category, ConditionCategory) else str(self.category),
            "verification_method": self.verification_method.value if isinstance(self.verification_method, VerificationMethod) else str(self.verification_method),
            "confidence": self.confidence,
            "trust_level": self.trust_level.value if isinstance(self.trust_level, TrustLevel) else str(self.trust_level),
            "evidence": self.evidence,
            "source_url": self.source_url,
            "source_type": self.source_type,
            "source_reference": self.source_reference,
            "auto_verifiable": self.auto_verifiable,
            "extraction_method": self.extraction_method,
            "normalization_notes": self.normalization_notes,
            "evaluation_status": self.evaluation_status.value if isinstance(self.evaluation_status, EvaluationStatus) else str(self.evaluation_status),
            "evaluation_reason": self.evaluation_reason,
            "target_evidence_found": self.target_evidence_found,
            "configuration_evidence": self.configuration_evidence,
            # Legacy compatibility field alias
            "name": self.subject or self.condition_id,
            "expected_state": self.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConditionNode:
        """Instantiate ConditionNode from dictionary."""
        c_type = ConditionType.from_str(data.get("condition_type", "GENERIC"))
        cat = ConditionCategory.from_str(data.get("category", "environment"))

        op_str = data.get("operator", "==")
        try:
            op = Operator(op_str)
        except Exception:
            op = Operator.EQUALS

        v_meth_str = data.get("verification_method", "config_collector")
        try:
            v_meth = VerificationMethod(v_meth_str)
        except Exception:
            v_meth = VerificationMethod.CONFIG_COLLECTOR

        t_lvl_str = data.get("trust_level", "authoritative")
        try:
            t_lvl = TrustLevel(t_lvl_str)
        except Exception:
            t_lvl = TrustLevel.AUTHORITATIVE

        eval_st_str = data.get("evaluation_status", "UNKNOWN")
        try:
            eval_st = EvaluationStatus(eval_st_str)
        except Exception:
            eval_st = EvaluationStatus.UNKNOWN

        return cls(
            condition_id=str(data.get("condition_id") or data.get("id") or f"cond_{uuid.uuid4().hex[:10]}"),
            condition_type=c_type,
            subject=str(data.get("subject") or data.get("name") or ""),
            attribute=str(data.get("attribute") or ""),
            operator=op,
            value=data.get("value") if "value" in data else data.get("expected_state", True),
            logical_group=data.get("logical_group"),
            parent_condition_id=data.get("parent_condition_id"),
            required=bool(data.get("required", True)),
            category=cat,
            verification_method=v_meth,
            confidence=str(data.get("confidence", "high")),
            trust_level=t_lvl,
            evidence=str(data.get("evidence") or (data.get("evidence_text") if "evidence_text" in data else "")),
            source_url=str(data.get("source_url") or data.get("evidence_url") or ""),
            source_type=str(data.get("source_type") or data.get("evidence_source") or "vendor_advisory"),
            source_reference=str(data.get("source_reference") or ""),
            auto_verifiable=bool(data.get("auto_verifiable", True)),
            extraction_method=str(data.get("extraction_method", "semantic_parser")),
            normalization_notes=str(data.get("normalization_notes", "")),
            evaluation_status=eval_st,
            evaluation_reason=str(data.get("evaluation_reason", "")),
            target_evidence_found=data.get("target_evidence_found"),
            configuration_evidence=list(data.get("configuration_evidence") or ([data["configuration_path"]] if data.get("configuration_path") else [])),
        )


# ============================================================
# LOGICAL EXPRESSION AST (AND, OR, NOT, LEAF)
# ============================================================

class LogicalOperator(str, Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"


@dataclass
class AndGroup:
    """
    Boolean AND node: requires all child expressions to be satisfied.
    """
    operands: List[Union[AndGroup, OrGroup, NotNode, ConditionNode]] = field(default_factory=list)
    group_id: str = field(default_factory=lambda: f"grp_and_{uuid.uuid4().hex[:8]}")
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "AND",
            "group_id": self.group_id,
            "description": self.description,
            "operands": [_serialize_ast_node(op) for op in self.operands]
        }


@dataclass
class OrGroup:
    """
    Boolean OR node: satisfied if at least one child expression is satisfied.
    """
    operands: List[Union[AndGroup, OrGroup, NotNode, ConditionNode]] = field(default_factory=list)
    group_id: str = field(default_factory=lambda: f"grp_or_{uuid.uuid4().hex[:8]}")
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "OR",
            "group_id": self.group_id,
            "description": self.description,
            "operands": [_serialize_ast_node(op) for op in self.operands]
        }


@dataclass
class NotNode:
    """
    Boolean NOT node: negates the child expression (3-valued logic).
    """
    operand: Union[AndGroup, OrGroup, NotNode, ConditionNode]
    node_id: str = field(default_factory=lambda: f"not_{uuid.uuid4().hex[:8]}")
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "NOT",
            "node_id": self.node_id,
            "description": self.description,
            "operand": _serialize_ast_node(self.operand)
        }


ASTNode = Union[AndGroup, OrGroup, NotNode, ConditionNode]


def _serialize_ast_node(node: ASTNode) -> Dict[str, Any]:
    if isinstance(node, ConditionNode):
        d = node.to_dict()
        d["node_type"] = "CONDITION"
        return d
    elif isinstance(node, (AndGroup, OrGroup, NotNode)):
        return node.to_dict()
    elif isinstance(node, dict):
        return node
    raise TypeError(f"Unknown AST node type: {type(node)}")


def deserialize_ast_node(data: Dict[str, Any]) -> ASTNode:
    """
    Recursively deserializes a dictionary into an ASTNode.
    """
    if not isinstance(data, dict):
        raise TypeError(f"Expected dict for AST node deserialization, got {type(data)}")

    node_type = str(data.get("node_type", "")).upper()

    if node_type == "AND":
        operands = [deserialize_ast_node(op) for op in data.get("operands", [])]
        return AndGroup(operands=operands, group_id=data.get("group_id", f"grp_and_{uuid.uuid4().hex[:8]}"), description=data.get("description", ""))

    elif node_type == "OR":
        operands = [deserialize_ast_node(op) for op in data.get("operands", [])]
        return OrGroup(operands=operands, group_id=data.get("group_id", f"grp_or_{uuid.uuid4().hex[:8]}"), description=data.get("description", ""))

    elif node_type == "NOT":
        op_data = data.get("operand", {})
        operand = deserialize_ast_node(op_data)
        return NotNode(operand=operand, node_id=data.get("node_id", f"not_{uuid.uuid4().hex[:8]}"), description=data.get("description", ""))

    else:
        # Defaults to ConditionNode leaf
        return ConditionNode.from_dict(data)


# ============================================================
# CONDITION TREE CONTAINER FOR A CVE
# ============================================================

@dataclass
class CVEConditionTree:
    """
    Top-level condition tree representing all documented conditions for a CVE:
    - environment_tree: LogicalExpression AST of environment prerequisites
    - attack_conditions: List of attacker capabilities / actions
    - impact_conditions: List of consequence requirements (e.g. file upload for RCE)
    - mitigations: List of known mitigations / workarounds
    - version_conditions: List of affected/fixed version conditions
    - unknown_conditions: Documented but uncertain conditions
    """
    cve_id: str
    environment_tree: Optional[ASTNode] = None
    attack_conditions: List[ConditionNode] = field(default_factory=list)
    impact_conditions: List[ConditionNode] = field(default_factory=list)
    mitigations: List[ConditionNode] = field(default_factory=list)
    version_conditions: List[ConditionNode] = field(default_factory=list)
    unknown_conditions: List[ConditionNode] = field(default_factory=list)

    def get_all_leaves(self, node: Optional[ASTNode] = None) -> List[ConditionNode]:
        """Collect all leaf ConditionNodes from the environment AST."""
        if node is None:
            node = self.environment_tree

        if node is None:
            return []

        if isinstance(node, ConditionNode):
            return [node]
        elif isinstance(node, (AndGroup, OrGroup)):
            res = []
            for op in node.operands:
                res.extend(self.get_all_leaves(op))
            return res
        elif isinstance(node, NotNode):
            return self.get_all_leaves(node.operand)
        return []

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete CVEConditionTree to dictionary."""
        return {
            "cve_id": self.cve_id,
            "environment_tree": _serialize_ast_node(self.environment_tree) if self.environment_tree else None,
            "attack_conditions": [c.to_dict() for c in self.attack_conditions],
            "impact_conditions": [c.to_dict() for c in self.impact_conditions],
            "mitigations": [c.to_dict() for c in self.mitigations],
            "version_conditions": [c.to_dict() for c in self.version_conditions],
            "unknown_conditions": [c.to_dict() for c in self.unknown_conditions],
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CVEConditionTree:
        """Deserialize CVEConditionTree from dictionary."""
        env_tree = None
        if data.get("environment_tree"):
            env_tree = deserialize_ast_node(data["environment_tree"])

        return cls(
            cve_id=data.get("cve_id", "UNKNOWN"),
            environment_tree=env_tree,
            attack_conditions=[ConditionNode.from_dict(d) for d in data.get("attack_conditions", [])],
            impact_conditions=[ConditionNode.from_dict(d) for d in data.get("impact_conditions", [])],
            mitigations=[ConditionNode.from_dict(d) for d in data.get("mitigations", [])],
            version_conditions=[ConditionNode.from_dict(d) for d in data.get("version_conditions", [])],
            unknown_conditions=[ConditionNode.from_dict(d) for d in data.get("unknown_conditions", [])],
        )

    @classmethod
    def from_json(cls, json_str: str) -> CVEConditionTree:
        return cls.from_dict(json.loads(json_str))
