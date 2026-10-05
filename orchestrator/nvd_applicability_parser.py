"""
Generic NVD / CPE Applicability Parser into Condition IR AST.

Ingests structured NVD configuration nodes (NVD 2.0 API and legacy schemas)
preserving hierarchical AND / OR relationships, running-on platform relationships,
and NEGATE semantics into a LogicalExpression AST without loss of structure.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from orchestrator.condition_ir import (
        AndGroup,
        ConditionCategory,
        ConditionNode,
        ConditionType,
        NotNode,
        Operator,
        OrGroup,
        TrustLevel,
        VerificationMethod,
    )
except ImportError:
    from condition_ir import (
        AndGroup,
        ConditionCategory,
        ConditionNode,
        ConditionType,
        NotNode,
        Operator,
        OrGroup,
        TrustLevel,
        VerificationMethod,
    )


def parse_cpe_uri(cpe_str: str) -> Dict[str, str]:
    """
    Parse CPE 2.3 or 2.2 URI into structured components:
    cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    res = {
        "part": "",
        "vendor": "",
        "product": "",
        "version": "",
        "update": "",
        "edition": "",
        "language": "",
        "sw_edition": "",
        "target_sw": "",
        "target_hw": "",
        "other": ""
    }
    if not cpe_str:
        return res

    clean_cpe = cpe_str.strip()
    if clean_cpe.startswith("cpe:2.3:"):
        tokens = clean_cpe.split(":")
        keys = ["cpe", "cpe_ver", "part", "vendor", "product", "version", "update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"]
        for i, val in enumerate(tokens[2:]):
            if i + 2 < len(keys):
                res[keys[i + 2]] = val.replace("\\", "")
    elif clean_cpe.startswith("cpe:/"):
        parts = clean_cpe[5:].split(":")
        if parts:
            res["part"] = parts[0]
        if len(parts) > 1:
            res["vendor"] = parts[1]
        if len(parts) > 2:
            res["product"] = parts[2]
        if len(parts) > 3:
            res["version"] = parts[3]

    return res


def cpe_to_condition_node(
    cpe_match: Dict[str, Any],
    source_url: str = "https://nvd.nist.gov"
) -> Tuple[ConditionCategory, ConditionNode]:
    """
    Converts a single cpeMatch dictionary into a typed ConditionNode.
    Distinguishes application versions from operating systems / platforms.
    """
    criteria = cpe_match.get("criteria") or cpe_match.get("cpe23Uri") or ""
    parsed = parse_cpe_uri(criteria)

    part = parsed.get("part", "a")
    vendor = parsed.get("vendor", "")
    product = parsed.get("product", "")
    version = parsed.get("version", "")
    vulnerable = bool(cpe_match.get("vulnerable", True))

    v_start_inc = cpe_match.get("versionStartIncluding")
    v_start_exc = cpe_match.get("versionStartExcluding")
    v_end_inc = cpe_match.get("versionEndIncluding")
    v_end_exc = cpe_match.get("versionEndExcluding")

    # Construct range string if bounds exist
    range_parts = []
    if v_start_inc:
        range_parts.append(f">= {v_start_inc}")
    elif v_start_exc:
        range_parts.append(f"> {v_start_exc}")
    if v_end_inc:
        range_parts.append(f"<= {v_end_inc}")
    elif v_end_exc:
        range_parts.append(f"< {v_end_exc}")

    range_str = ", ".join(range_parts) if range_parts else (version if version and version not in ("*", "-") else "all")

    if part == "o":  # Operating System / Platform
        os_name = product.replace("_", " ").title() if product else vendor.replace("_", " ").title()
        cond = ConditionNode(
            condition_id=f"cpe_os_{product or vendor}",
            condition_type=ConditionType.OS,
            subject=f"platform_{product or vendor}".lower(),
            attribute="operating_system",
            operator=Operator.EQUALS,
            value=product or vendor or "target_os",
            required=True,
            category=ConditionCategory.ENVIRONMENT,
            verification_method=VerificationMethod.PLATFORM_INSPECTOR,
            confidence="high",
            trust_level=TrustLevel.AUTHORITATIVE,
            evidence=f"NVD structured CPE match: {criteria}",
            source_url=source_url,
            source_type="nvd",
            source_reference=criteria,
            auto_verifiable=True,
            extraction_method="structured_data",
            normalization_notes=f"Extracted from NVD OS CPE: {criteria}"
        )
        return ConditionCategory.ENVIRONMENT, cond

    elif part == "h":  # Hardware / Architecture
        cond = ConditionNode(
            condition_id=f"cpe_arch_{product or vendor}",
            condition_type=ConditionType.ARCHITECTURE,
            subject=f"arch_{product or vendor}".lower(),
            attribute="hardware_architecture",
            operator=Operator.EQUALS,
            value=product or vendor,
            required=True,
            category=ConditionCategory.ENVIRONMENT,
            verification_method=VerificationMethod.PLATFORM_INSPECTOR,
            confidence="high",
            trust_level=TrustLevel.AUTHORITATIVE,
            evidence=f"NVD structured CPE match: {criteria}",
            source_url=source_url,
            source_type="nvd",
            source_reference=criteria,
            auto_verifiable=True,
            extraction_method="structured_data",
            normalization_notes=f"Extracted from NVD Hardware CPE: {criteria}"
        )
        return ConditionCategory.ENVIRONMENT, cond

    else:  # Application / Product Version
        cond = ConditionNode(
            condition_id=f"cpe_ver_{product or vendor}",
            condition_type=ConditionType.VERSION,
            subject="software_version_vulnerable",
            attribute=f"{vendor}:{product}",
            operator=Operator.WITHIN_RANGE if range_parts else Operator.EQUALS,
            value=range_str,
            required=True,
            category=ConditionCategory.VERSION,
            verification_method=VerificationMethod.VERSION_CHECK,
            confidence="high",
            trust_level=TrustLevel.AUTHORITATIVE,
            evidence=f"NVD structured CPE match: {criteria} (range: {range_str})",
            source_url=source_url,
            source_type="nvd",
            source_reference=criteria,
            auto_verifiable=True,
            extraction_method="structured_data",
            normalization_notes=f"Extracted from NVD Application CPE: {criteria}"
        )
        return ConditionCategory.VERSION, cond


def parse_nvd_node(
    node: Dict[str, Any],
    source_url: str = "https://nvd.nist.gov"
) -> Tuple[Optional[Any], List[ConditionNode]]:
    """
    Recursively parse a single NVD configuration node into ASTNode.
    Returns (env_ast_node, version_conditions).
    """
    operator = str(node.get("operator", "OR")).upper()
    negate = bool(node.get("negate", False))

    env_operands = []
    version_conditions = []

    # 1. Parse cpeMatch items in this node
    cpe_matches = node.get("cpeMatch", [])
    for cm in cpe_matches:
        cat, cond = cpe_to_condition_node(cm, source_url=source_url)
        if cat == ConditionCategory.VERSION:
            version_conditions.append(cond)
        else:
            env_operands.append(cond)

    # 2. Parse children nodes recursively (e.g. running-on relationships)
    children = node.get("children", [])
    for ch in children:
        ch_ast, ch_vers = parse_nvd_node(ch, source_url=source_url)
        if ch_ast:
            env_operands.append(ch_ast)
        version_conditions.extend(ch_vers)

    # 3. Assemble boolean group for environment operands
    if not env_operands:
        ast_res = None
    elif len(env_operands) == 1:
        ast_res = env_operands[0]
    else:
        if operator == "AND":
            ast_res = AndGroup(operands=env_operands, description="NVD AND configuration node")
        else:
            ast_res = OrGroup(operands=env_operands, description="NVD OR configuration node")

    # Apply negation if specified
    if negate and ast_res:
        ast_res = NotNode(operand=ast_res, description="NVD negated configuration node")

    return ast_res, version_conditions


def parse_nvd_configurations(
    configurations: Union[List[Dict[str, Any]], Dict[str, Any]],
    source_url: str = "https://nvd.nist.gov"
) -> Tuple[Optional[Any], List[ConditionNode]]:
    """
    Parse the entire NVD configurations block into (environment_ast, version_conditions).
    """
    if isinstance(configurations, dict):
        nodes = configurations.get("nodes", [])
    elif isinstance(configurations, list):
        nodes = []
        for item in configurations:
            if isinstance(item, dict):
                nodes.extend(item.get("nodes", [item]))
    else:
        return None, []

    env_roots = []
    all_versions = []

    for node in nodes:
        ast_node, vers = parse_nvd_node(node, source_url=source_url)
        if ast_node:
            env_roots.append(ast_node)
        all_versions.extend(vers)

    if not env_roots:
        final_ast = None
    elif len(env_roots) == 1:
        final_ast = env_roots[0]
    else:
        final_ast = OrGroup(operands=env_roots, description="NVD configuration top-level configurations")

    return final_ast, all_versions
