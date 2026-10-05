import json
import argparse
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from packaging.version import parse as parse_version

try:
    from orchestrator.cve_phase_b import EcosystemVersionComparator
except ImportError:
    try:
        from cve_phase_b import EcosystemVersionComparator
    except ImportError:
        EcosystemVersionComparator = None

_orchestrator_dir = Path(__file__).resolve().parent
_project_root = _orchestrator_dir.parent
DEFAULT_DB_PATH = _project_root / "data" / "cve_prerequisites.db"
DEFAULT_KNOWLEDGE_PATH = _orchestrator_dir / "cve_knowledge.json"

try:
    from orchestrator.condition_ir import (
        AndGroup,
        ASTNode,
        ConditionCategory,
        ConditionNode,
        ConditionType,
        CVEConditionTree,
        deserialize_ast_node,
        EvaluationStatus,
        NotNode,
        Operator,
        OrGroup,
        TrustLevel,
    )
except ImportError:
    from condition_ir import (
        AndGroup,
        ASTNode,
        ConditionCategory,
        ConditionNode,
        ConditionType,
        CVEConditionTree,
        deserialize_ast_node,
        EvaluationStatus,
        NotNode,
        Operator,
        OrGroup,
        TrustLevel,
    )


def generic_compare_versions(v1: str, v2: str, ecosystem: Optional[str] = None) -> int:
    """
    Compare two version strings deterministically using Phase B ecosystem comparator
    with fallbacks to Debian, SemVer, Maven, Python, and packaging.version.
    """
    if EcosystemVersionComparator is not None:
        if ecosystem and EcosystemVersionComparator.can_compare(ecosystem, str(v1), str(v2)):
            try:
                return EcosystemVersionComparator.compare(ecosystem, str(v1), str(v2))
            except Exception:
                pass

        # If versions contain letter suffixes in numbers (e.g. 1.0.1g, 1.0.1h), prioritize Debian comparator
        has_letters = bool(re.search(r"\d+[a-zA-Z]", str(v1)) or re.search(r"\d+[a-zA-Z]", str(v2)))
        eco_order = ["debian", "semver", "maven", "python"] if has_letters else ["semver", "debian", "maven", "python"]
        for eco in eco_order:
            if EcosystemVersionComparator.can_compare(eco, str(v1), str(v2)):
                try:
                    return EcosystemVersionComparator.compare(eco, str(v1), str(v2))
                except Exception:
                    continue

    try:
        pv1 = parse_version(str(v1))
        pv2 = parse_version(str(v2))
        if pv1 < pv2:
            return -1
        elif pv1 > pv2:
            return 1
        return 0
    except Exception:
        pass

    # Fallback component-by-component tokenized comparison
    t1 = re.findall(r"\d+|[a-zA-Z]+", str(v1))
    t2 = re.findall(r"\d+|[a-zA-Z]+", str(v2))
    for p1, p2 in zip(t1, t2):
        if p1.isdigit() and p2.isdigit():
            i1, i2 = int(p1), int(p2)
            if i1 != i2:
                return -1 if i1 < i2 else 1
        else:
            if p1 != p2:
                return -1 if p1 < p2 else 1
    if len(t1) != len(t2):
        return -1 if len(t1) < len(t2) else 1
    return 0


def is_version_affected(detected_str, range_str, fixed_dict=None, ecosystem: Optional[str] = None):
    """
    Deterministically check if a detected version falls within an affected range
    or is already patched using Phase B ecosystem comparison.
    """
    if not detected_str or not range_str:
        return "unknown", "Missing version or range"

    m = re.search(r"(\d+(\.\d+)*[a-zA-Z0-9\.\-]*)", str(detected_str))
    if not m:
        return "unknown", f"Could not parse detected version: {detected_str}"
    detected_clean = m.group(1).strip()

    # 1. Check fixed versions first
    if fixed_dict:
        fixed_vals = fixed_dict.values() if isinstance(fixed_dict, dict) else (
            fixed_dict if isinstance(fixed_dict, list) else [fixed_dict]
        )
        for fv in fixed_vals:
            fm = re.search(r"(\d+(\.\d+)*[a-zA-Z0-9\.\-]*)", str(fv))
            if fm:
                fix_v = fm.group(1).strip()
                try:
                    cmp_res = generic_compare_versions(detected_clean, fix_v, ecosystem=ecosystem)
                    # Check if same major/minor or direct >=
                    if cmp_res >= 0:
                        return "not_satisfied", f"Installed version {detected_clean} is >= fixed version {fix_v} (PATCHED)"
                except Exception:
                    pass

    # 1b. Compound comma-separated clauses (e.g. ">= 7.0.0, < 7.0.79")
    if "," in range_str:
        sub_ranges = [p.strip() for p in range_str.split(",") if p.strip()]
        if len(sub_ranges) > 1:
            reasons = []
            for sr in sub_ranges:
                status, reason = is_version_affected(detected_str, sr, fixed_dict=fixed_dict, ecosystem=ecosystem)
                if status != "satisfied":
                    return status, reason
                reasons.append(reason)
            return "satisfied", "; ".join(reasons)

    # 1c. Check 'A to B' range (e.g. "7.0.0 to 7.0.79")
    to_m = re.match(r"(.+?)\s+to\s+(.+)", range_str, re.I)
    if to_m:
        sm = re.search(r"(\d+(\.\d+)*[a-zA-Z0-9\.\-]*)", to_m.group(1))
        em = re.search(r"(\d+(\.\d+)*[a-zA-Z0-9\.\-]*)", to_m.group(2))
        if sm and em:
            v_start = sm.group(1).strip()
            v_end = em.group(1).strip()
            cmp_start = generic_compare_versions(detected_clean, v_start, ecosystem=ecosystem)
            cmp_end = generic_compare_versions(detected_clean, v_end, ecosystem=ecosystem)
            if cmp_start >= 0 and cmp_end <= 0:
                return "satisfied", f"Installed version {detected_clean} is within affected range {v_start} to {v_end}"
            else:
                return "not_satisfied", f"Installed version {detected_clean} is outside affected range {v_start} to {v_end}"

    # 2. Check 'A through B' range
    through_m = re.match(r"(.+?)\s+through\s+(.+)", range_str, re.I)
    if through_m:
        sm = re.search(r"(\d+(\.\d+)*[a-zA-Z0-9\.\-]*)", through_m.group(1))
        em = re.search(r"(\d+(\.\d+)*[a-zA-Z0-9\.\-]*)", through_m.group(2))
        if sm and em:
            v_start = sm.group(1).strip()
            v_end = em.group(1).strip()
            cmp_start = generic_compare_versions(detected_clean, v_start, ecosystem=ecosystem)
            cmp_end = generic_compare_versions(detected_clean, v_end, ecosystem=ecosystem)
            if cmp_start >= 0 and cmp_end <= 0:
                return "satisfied", f"Installed version {detected_clean} is within affected range {v_start} through {v_end}"
            else:
                return "not_satisfied", f"Installed version {detected_clean} is outside affected range {v_start} through {v_end}"

    # 3. Check '<= X' or '< X'
    lt_eq_m = re.match(r"<=\s*([a-zA-Z0-9\.\-]+)", range_str)
    if lt_eq_m:
        v_limit = lt_eq_m.group(1).strip()
        cmp_res = generic_compare_versions(detected_clean, v_limit, ecosystem=ecosystem)
        if cmp_res <= 0:
            return "satisfied", f"Installed version {detected_clean} is <= {v_limit}"
        return "not_satisfied", f"Installed version {detected_clean} is > {v_limit}"

    lt_m = re.match(r"<\s*([a-zA-Z0-9\.\-]+)", range_str)
    if lt_m:
        v_limit = lt_m.group(1).strip()
        cmp_res = generic_compare_versions(detected_clean, v_limit, ecosystem=ecosystem)
        if cmp_res < 0:
            return "satisfied", f"Installed version {detected_clean} is < {v_limit}"
        return "not_satisfied", f"Installed version {detected_clean} is >= {v_limit}"

    before_m = re.match(r"(?:[a-zA-Z0-9\.\-]+\s+)?before\s+([a-zA-Z0-9\.\-]+)", range_str, re.I)
    if before_m:
        v_limit = before_m.group(1).strip()
        cmp_res = generic_compare_versions(detected_clean, v_limit, ecosystem=ecosystem)
        if cmp_res < 0:
            return "satisfied", f"Installed version {detected_clean} is < {v_limit}"
        return "not_satisfied", f"Installed version {detected_clean} is >= {v_limit}"

    # 4. Check '>= X' or '> X'
    gt_eq_m = re.match(r">=\s*([a-zA-Z0-9\.\-]+)", range_str)
    if gt_eq_m:
        v_limit = gt_eq_m.group(1).strip()
        cmp_res = generic_compare_versions(detected_clean, v_limit, ecosystem=ecosystem)
        if cmp_res >= 0:
            return "satisfied", f"Installed version {detected_clean} is >= {v_limit}"
        return "not_satisfied", f"Installed version {detected_clean} is < {v_limit}"

    gt_m = re.match(r">\s*([a-zA-Z0-9\.\-]+)", range_str)
    if gt_m:
        v_limit = gt_m.group(1).strip()
        cmp_res = generic_compare_versions(detected_clean, v_limit, ecosystem=ecosystem)
        if cmp_res > 0:
            return "satisfied", f"Installed version {detected_clean} is > {v_limit}"
        return "not_satisfied", f"Installed version {detected_clean} is <= {v_limit}"

    # 5. Check '= X' or exact match
    eq_m = re.match(r"=?\s*([a-zA-Z0-9\.\-]+)$", range_str)
    if eq_m:
        v_limit = eq_m.group(1).strip()
        cmp_res = generic_compare_versions(detected_clean, v_limit, ecosystem=ecosystem)
        if cmp_res == 0:
            return "satisfied", f"Installed version {detected_clean} matches affected version {v_limit}"
        return "not_satisfied", f"Installed version {detected_clean} does not match {v_limit}"

    return "unknown", f"Unrecognized range format: {range_str}"


def resolve_affected_range_for_version(detected_version: Optional[str], range_str: str, evidence_texts: Optional[List[str]] = None) -> str:
    """
    Resolve or extract the effective affected range for the detected software version.
    Handles branch-specific vendor statements (e.g. '0.9.8 before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h')
    and cleans empty or placeholder range specifications.
    """
    clean_range = str(range_str).strip() if range_str else ""
    if clean_range.startswith("[") and clean_range.endswith("]"):
        clean_range = ""

    all_texts = ([clean_range] if clean_range else []) + (evidence_texts or [])

    # If detected_version has a major.minor branch, check if branch-specific statement exists
    if detected_version:
        m_det = re.match(r"^(\d+\.\d+(\.\d+)?)", str(detected_version))
        branch = m_det.group(1) if m_det else ""
        if branch:
            for ev in all_texts:
                if not ev:
                    continue
                m_branch = re.search(rf"\b{re.escape(branch)}\s+before\s+([a-zA-Z0-9\.\-]+)", ev, re.I)
                if m_branch:
                    return f"< {m_branch.group(1).strip()}"
                m_branch_lt = re.search(rf"\b{re.escape(branch)}\s*<\s*([a-zA-Z0-9\.\-]+)", ev, re.I)
                if m_branch_lt:
                    return f"< {m_branch_lt.group(1).strip()}"

    if clean_range and clean_range not in ("[]", "{}", "none", "null", "unknown", "all"):
        return clean_range

    if not detected_version or not evidence_texts:
        return ""

    for ev in evidence_texts:
        if not ev:
            continue
        # Generic 'before <limit>'
        m_before = re.search(r"\bbefore\s+([a-zA-Z0-9\.\-]+)", ev, re.I)
        if m_before:
            return f"< {m_before.group(1).strip()}"

    return ""


class CVEEvaluator:
    """
    Deterministic generic CVE prerequisite evaluator.

    The evaluator compares structured CVE prerequisites (from data/cve_prerequisites.db
    or an optional knowledge file) against the effective environment configuration
    collected by the existing Config Collector.
    """

    def __init__(
        self,
        knowledge_source: Union[Path, str, dict, None] = None,
        config_source: Union[Path, str, dict, None] = None,
        db_path: Union[Path, str, None] = None
    ):
        # Resolve SQLite database path
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH

        # Flexible invocation handling:
        # If knowledge_source was provided but config_source is None, check if it's actually config
        if knowledge_source is not None and config_source is None:
            if isinstance(knowledge_source, dict) and ("effective_configuration" in knowledge_source or "default_servlet" in knowledge_source):
                config_source = knowledge_source
                knowledge_source = None
            elif isinstance(knowledge_source, (str, Path)):
                p_str = str(knowledge_source).lower()
                if "config" in p_str:
                    config_source = knowledge_source
                    knowledge_source = None

        self.knowledge_file = Path(knowledge_source) if isinstance(knowledge_source, (str, Path)) else None
        self.config_file = Path(config_source) if isinstance(config_source, (str, Path)) else None

        self.knowledge = self.load_knowledge(knowledge_source)
        self.raw_configuration = self.load_raw_configuration(config_source)
        self.configuration = self.load_configuration(config_source)

    def load_knowledge(self, source: Union[Path, str, dict, None]) -> Dict[str, Any]:
        if source is None:
            return {}

        if isinstance(source, dict):
            return source

        p = Path(source)
        if not p.exists():
            return {}

        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_raw_configuration(self, source: Union[Path, str, dict, None]) -> Dict[str, Any]:
        if source is None:
            return {}

        if isinstance(source, dict):
            return source

        p = Path(source)
        if not p.exists():
            return {}

        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_configuration(self, source: Union[Path, str, dict, None]) -> Dict[str, Any]:
        data = self.load_raw_configuration(source)

        if isinstance(data, dict):
            # Current config_collector format
            if "effective_configuration" in data and isinstance(data["effective_configuration"], dict):
                return data["effective_configuration"]

            # Older format where effective configuration was stored directly
            if "default_servlet" in data:
                return data

            return data

        return {}

    def get_detected_version(self, product: Optional[str] = None) -> Optional[str]:
        """
        Dynamically extract detected target software version from any config structure
        without hardcoded vendor assumptions.
        """
        sources = [self.raw_configuration, self.configuration]

        # 1. Product-specific lookup if product name is provided
        if product:
            p_clean = str(product).lower().replace(" ", "_").replace("-", "_")
            candidates = [p_clean, str(product)] + [t for t in p_clean.split("_") if len(t) > 2]
            for src in sources:
                if not isinstance(src, dict):
                    continue
                for cand in candidates:
                    # Direct block match
                    block = src.get(cand)
                    if isinstance(block, dict) and block.get("version"):
                        return str(block["version"])
                    elif isinstance(block, (str, int, float)):
                        return str(block)

                    # Nested package/software container lookup
                    for container_key in ["packages", "software", "components", "dependencies"]:
                        c_block = src.get(container_key)
                        if isinstance(c_block, dict):
                            pkg = c_block.get(cand)
                            if isinstance(pkg, dict) and pkg.get("version"):
                                return str(pkg["version"])
                            elif isinstance(pkg, (str, int, float)):
                                return str(pkg)

        # 2. Generic version attributes
        for src in sources:
            if not isinstance(src, dict):
                continue
            for key in ["installed_version", "target_version", "software_version", "version"]:
                val = src.get(key)
                if val and isinstance(val, (str, int, float)):
                    return str(val)

        # 3. Dynamic search in nested component blocks
        for src in sources:
            if not isinstance(src, dict):
                continue
            for k, v in src.items():
                if isinstance(v, dict) and v.get("version") and k not in ("effective_configuration", "raw_configuration"):
                    return str(v["version"])

        return None

    def get_cve_prerequisites(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve structured prerequisites for a specific CVE from either:
        1. In-memory / loaded knowledge dictionary (cve_knowledge.json)
        2. SQLite prerequisite database (data/cve_prerequisites.db)

        Returns None if no prerequisite data is available for this CVE.
        """
        clean_cve = str(cve_id).strip().upper()

        # 1. Check in-memory / JSON knowledge if loaded
        if self.knowledge and clean_cve in self.knowledge:
            return self.knowledge[clean_cve]

        # 2. Query SQLite prerequisite database
        if self.db_path and self.db_path.exists():
            try:
                with sqlite3.connect(str(self.db_path), timeout=10.0) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    # Query master record
                    cursor.execute(
                        "SELECT summary, affected_versions, raw_record_json FROM cve_prerequisite_records WHERE cve_id = ?",
                        (clean_cve,)
                    )
                    master_row = cursor.fetchone()

                    # Also query individual prerequisites table
                    cursor.execute(
                        """
                        SELECT prerequisite_id, name, description, category, required,
                               expected_state, verification_method, trust_level, confidence,
                               evidence_source, evidence_url, evidence_text
                        FROM cve_prerequisites
                        WHERE cve_id = ?
                        ORDER BY id ASC
                        """,
                        (clean_cve,)
                    )
                    prereq_rows = cursor.fetchall()

                    if not master_row and not prereq_rows:
                        return None

                    raw_rec: Dict[str, Any] = {}
                    if master_row and master_row["raw_record_json"]:
                        try:
                            raw_rec = json.loads(master_row["raw_record_json"])
                        except Exception:
                            raw_rec = {}

                    summary = (master_row["summary"] if master_row else "") or raw_rec.get("summary", "")

                    affected_range = "unknown"
                    if master_row and master_row["affected_versions"]:
                        try:
                            aff_v = json.loads(master_row["affected_versions"])
                            if isinstance(aff_v, list) and aff_v:
                                affected_range = str(aff_v[0])
                            elif isinstance(aff_v, str):
                                affected_range = aff_v
                        except Exception:
                            affected_range = str(master_row["affected_versions"])
                    elif raw_rec.get("affected_versions"):
                        aff_v = raw_rec["affected_versions"]
                        affected_range = str(aff_v[0]) if isinstance(aff_v, list) and aff_v else str(aff_v)

                    conditions = []
                    raw_prereqs = raw_rec.get("prerequisites", [])
                    if raw_prereqs:
                        for p in raw_prereqs:
                            cond_name = p.get("name") or p.get("id")
                            if cond_name == "software_version_vulnerable":
                                continue
                            exp_state = p.get("expected_state")

                            if isinstance(exp_state, str):
                                if exp_state.lower() in ("true", "active", "enabled", "present"):
                                    req_val: Any = True
                                elif exp_state.lower() in ("false", "inactive", "disabled"):
                                    req_val = False
                                elif exp_state.lower() in ("must_be_identified", "must_be_established"):
                                    req_val = exp_state.lower()
                                else:
                                    req_val = exp_state
                            else:
                                req_val = exp_state if exp_state is not None else True

                            cfg_evidence = p.get("configuration_evidence")
                            if not cfg_evidence:
                                cfg_path = p.get("configuration_path")
                                cfg_evidence = [cfg_path] if cfg_path else [cond_name]

                            if cond_name in ("default_servlet_writes_enabled", "http_put_enabled") and "default_servlet.readonly" not in cfg_evidence:
                                cfg_evidence.append("default_servlet.readonly")

                            conditions.append({
                                "id": p.get("id") or cond_name,
                                "name": cond_name,
                                "description": p.get("description") or "",
                                "category": p.get("category") or "other",
                                "configuration_evidence": cfg_evidence,
                                "required_value": req_val,
                                "required": bool(p.get("required", True)),
                                "trust_level": p.get("trust_level", "authoritative"),
                                "verification_method": p.get("verification_method", "config_collector"),
                                "confidence": p.get("confidence", "high"),
                                "evidence": p.get("evidence", [])
                            })
                    elif prereq_rows:
                        for row in prereq_rows:
                            cond_name = row["name"]
                            if cond_name == "software_version_vulnerable":
                                continue
                            exp_state = row["expected_state"]

                            if isinstance(exp_state, str):
                                if exp_state.lower() in ("true", "active", "enabled", "present"):
                                    req_val = True
                                elif exp_state.lower() in ("false", "inactive", "disabled"):
                                    req_val = False
                                elif exp_state.lower() in ("must_be_identified", "must_be_established"):
                                    req_val = exp_state.lower()
                                else:
                                    req_val = exp_state
                            else:
                                req_val = exp_state if exp_state is not None else True

                            cfg_evidence = [cond_name]
                            if cond_name == "default_servlet_writes_enabled":
                                cfg_evidence = ["default_servlet.writes_enabled", "default_servlet.readonly"]
                            elif cond_name == "ajp_connector_active":
                                cfg_evidence = ["connectors", "ajp_connector"]

                            conditions.append({
                                "id": row["prerequisite_id"],
                                "name": cond_name,
                                "description": row["description"] or "",
                                "category": row["category"] or "other",
                                "configuration_evidence": cfg_evidence,
                                "required_value": req_val,
                                "required": bool(row["required"]) if "required" in row.keys() else True,
                                "trust_level": row["trust_level"] or "authoritative",
                                "verification_method": row["verification_method"] or "config_collector",
                                "confidence": row["confidence"] or "high",
                                "evidence_source": row["evidence_source"] or "",
                                "evidence_url": row["evidence_url"] or "",
                                "evidence_text": row["evidence_text"] or ""
                            })

                    return {
                        "cve_id": clean_cve,
                        "product": {
                            "vendor": "Target Software",
                            "name": "Software",
                            "component": "Component"
                        },
                        "affected_versions": {"range": affected_range},
                        "fixed_versions": {},
                        "severity": "HIGH",
                        "description": summary,
                        "conditions": {
                            "prerequisites": conditions
                        },
                        "unknown_conditions": raw_rec.get("unknown_conditions", []),
                        "remediation": raw_rec.get("remediation", []),
                        "sources": raw_rec.get("sources", [])
                    }
            except Exception:
                pass

        return None

    def evaluate_version_condition(self, cve):
        """
        Evaluate whether the detected environment version is affected by the CVE.
        """
        product = None
        if isinstance(cve.get("product"), dict):
            product = cve["product"].get("name") or cve["product"].get("vendor")
        elif isinstance(cve.get("product"), str):
            product = cve.get("product")

        detected_version = self.get_detected_version(product=product)
        affected_spec = cve.get("affected_versions", {})
        fixed_spec = cve.get("fixed_versions", {})
        if isinstance(affected_spec, dict):
            range_str = affected_spec.get("range", "")
        elif isinstance(affected_spec, list):
            boundary_cand = [v for v in affected_spec if any(k in str(v).lower() for k in ("before", "prior", "<", "<=", "through"))]
            range_str = boundary_cand[0] if boundary_cand else (affected_spec[0] if affected_spec else "")
        else:
            range_str = str(affected_spec) if affected_spec else ""

        # Collect evidence texts from version prerequisites, description, and summary
        ev_texts = []
        for p in cve.get("prerequisites", []):
            if p.get("category") == "version" or p.get("name") == "software_version_vulnerable":
                for ev in p.get("evidence", []):
                    if isinstance(ev, dict) and ev.get("evidence_text"):
                        ev_texts.append(ev["evidence_text"])
                if p.get("description"):
                    ev_texts.append(p["description"])
        if cve.get("description"):
            ev_texts.append(cve["description"])
        if cve.get("summary"):
            ev_texts.append(cve["summary"])

        range_str = resolve_affected_range_for_version(detected_version, range_str, ev_texts)

        if not detected_version:
            return {
                "name": "software_version_vulnerable",
                "display_name": "Software Version Vulnerable",
                "status": "unknown",
                "evaluation_status": "UNKNOWN",
                "required": True,
                "required_value": True,
                "verification_method": "version_check",
                "category": "version",
                "detected_version": None,
                "affected_range": range_str or "unspecified",
                "reason": "Target software version could not be detected from configuration"
            }

        if not range_str or range_str in ("all", "unknown"):
            return {
                "name": "software_version_vulnerable",
                "display_name": "Software Version Vulnerable",
                "status": "satisfied",
                "evaluation_status": "SATISFIED",
                "required": True,
                "required_value": True,
                "verification_method": "version_check",
                "category": "version",
                "detected_version": detected_version,
                "affected_range": range_str or "unspecified",
                "reason": f"Detected version {detected_version} matches target specification."
            }

        status, reason = is_version_affected(detected_version, range_str, fixed_spec)
        return {
            "name": "software_version_vulnerable",
            "display_name": "Software Version Vulnerable",
            "status": status,
            "evaluation_status": status.upper(),
            "required": True,
            "required_value": True,
            "verification_method": "version_check",
            "category": "version",
            "detected_version": detected_version,
            "affected_range": range_str,
            "reason": reason
        }

    # ---------------------------------------------------------
    # Legacy helper
    # ---------------------------------------------------------

    def load_json(self, path):
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ---------------------------------------------------------
    # Nested value lookup
    # ---------------------------------------------------------

    def get_value(self, data, path):
        current = data

        for part in path.split("."):
            if not isinstance(current, dict):
                return None, False

            if part not in current:
                return None, False

            current = current[part]

        return current, True

    # ---------------------------------------------------------
    # Evidence normalization
    # ---------------------------------------------------------

    def normalize_evidence_entry(self, entry):
        """
        Accept both legacy string evidence paths and the newer
        structured evidence format.

        Examples:

            "default_servlet.writes_enabled"

        or:

            {
                "path": "default_servlet.readonly",
                "transform": "boolean_not"
            }
        """

        if isinstance(entry, str):
            return {
                "path": entry,
                "transform": "identity"
            }

        if isinstance(entry, dict):
            path = entry.get("path")

            if not path:
                return None

            return {
                "path": path,
                "transform": entry.get("transform", "identity")
            }

        return None

    # ---------------------------------------------------------
    # Transform evidence value
    # ---------------------------------------------------------

    def transform_value(self, value, transform):
        """
        Convert raw configuration evidence into the semantic value
        required by the CVE condition.
        """

        if transform in (None, "", "identity", "none"):
            return value

        if transform in ("boolean_not", "not", "negate"):
            if isinstance(value, bool):
                return not value

            # A non-boolean value cannot safely be inverted.
            return None

        # Unknown transforms must not silently produce a result.
        return None

    # ---------------------------------------------------------
    # Determine whether evidence satisfies a requirement
    # ---------------------------------------------------------

    def check_evidence_value(self, value, required_value):
        # Missing / unresolved values
        if value is None:
            return "unknown"

        # Legacy collector value
        if value == "not_explicitly_configured":
            return "unknown"

        # Requirements that cannot be established from configuration alone.
        if required_value == "must_be_established":
            return "unknown"

        # Requirement is that something must exist.
        if required_value == "must_be_identified":
            if isinstance(value, list):
                return "satisfied" if len(value) > 0 else "not_satisfied"

            if isinstance(value, dict):
                return "satisfied" if len(value) > 0 else "not_satisfied"

            if isinstance(value, str):
                return "satisfied" if value.strip() else "not_satisfied"

            return "satisfied" if bool(value) else "not_satisfied"

        # Strict Type Safety Rule:
        # If evidence exists at the specified path but cannot be safely interpreted
        # as the expected type, treat this the same as missing evidence — return UNKNOWN,
        # never attempt a best-effort type coercion (e.g. finding a string or nested dict
        # where a scalar boolean was expected).
        if isinstance(required_value, bool):
            if isinstance(value, bool):
                return "satisfied" if value == required_value else "not_satisfied"
            if isinstance(value, (list, set)):
                return "satisfied" if (len(value) > 0) == required_value else "not_satisfied"
            # Unexpected type (string, dict/nested object, int, etc.)
            return "unknown"

        if isinstance(required_value, (int, float)) and not isinstance(required_value, bool):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return "unknown"
            return "satisfied" if value == required_value else "not_satisfied"

        if isinstance(required_value, str):
            req_clean = required_value.strip().lower()
            if isinstance(value, bool):
                if req_clean in ("true", "active", "enabled", "present", "allowed", "vulnerable_endpoints"):
                    return "satisfied" if value else "not_satisfied"
                elif req_clean in ("false", "inactive", "disabled", "denied"):
                    return "satisfied" if not value else "not_satisfied"
                return "unknown"

            if not isinstance(value, str):
                return "unknown"
            v_clean = value.strip().lower()
            if v_clean == req_clean or req_clean in v_clean:
                return "satisfied"
            return "not_satisfied"

        if isinstance(required_value, (list, dict)):
            if not isinstance(value, type(required_value)):
                return "unknown"
            return "satisfied" if value == required_value else "not_satisfied"

        # Normal exact comparison fallback.
        if value == required_value:
            return "satisfied"

        return "not_satisfied"

    # ---------------------------------------------------------
    # Legacy semantic fallback
    # ---------------------------------------------------------

    def infer_legacy_transform(self, condition, path):
        """
        Preserve compatibility with the existing CVE knowledge file.

        Older knowledge may list:

            configuration_evidence:
              - default_servlet.writes_enabled
              - default_servlet.readonly

        while using:

            required_value: true

        Semantically, readonly is the inverse of writes_enabled.

        If the condition itself clearly requires writes to be enabled,
        automatically interpret readonly as boolean_not.

        New knowledge can avoid this fallback by explicitly specifying:

            {
                "path": "default_servlet.readonly",
                "transform": "boolean_not"
            }
        """

        condition_name = str(condition.get("name", "")).lower()
        normalized_path = str(path).lower()

        if (
            ("writes" in condition_name or "write" in condition_name or "put" in condition_name)
            and (normalized_path.endswith("readonly") or normalized_path.endswith(".readonly"))
        ):
            return "boolean_not"

        return "identity"

    # ---------------------------------------------------------
    # Evaluate one CVE condition
    # ---------------------------------------------------------

    def evaluate_condition(self, condition):
        evidence_paths = condition.get("configuration_evidence", [])
        required_value = condition.get("required_value")
        if required_value is None and "value" in condition:
            required_value = condition["value"]

        evidence_results = []

        # Generic backend fallback for Operating System / Platform
        cond_type = str(condition.get("condition_type", "")).upper()
        cond_cat = str(condition.get("category", "")).lower()
        cond_name = str(condition.get("name") or condition.get("subject") or "").lower()

        if cond_type in ("OS", "PLATFORM") or cond_cat in ("operating_system", "platform") or cond_name.startswith("target_platform_"):
            os_val = None
            for p in ["environment.os", "os", "platform", "system.os", "host.os", "system_inventory.os"]:
                v, exists = self.get_value(self.configuration, p)
                if not exists and self.raw_configuration:
                    v, exists = self.get_value(self.raw_configuration, p)
                if exists and v is not None:
                    os_val = str(v).strip().lower()
                    break

            if os_val is not None:
                exp_os = str(required_value or condition.get("value") or "").strip().lower()
                if not exp_os or exp_os in ("true", "active", "enabled"):
                    if cond_name.startswith("target_platform_"):
                        exp_os = cond_name[len("target_platform_"):].strip().lower()
                st = "satisfied" if (exp_os and exp_os in os_val) else "not_satisfied"
                evidence_results.append({
                    "path": "environment.os",
                    "value": os_val,
                    "raw_value": os_val,
                    "transform": "identity",
                    "status": st,
                    "exists": True
                })

        if not evidence_paths and not evidence_results:
            cand_names = [p for p in [condition.get("name"), condition.get("subject"), condition.get("configuration_path")] if p]
            candidates = list(cand_names)
            prefixes = [
                "configuration", "environment", "relationships", "topology",
                "endpoint_inventory", "network", "network_context", "dependency_check",
                "dependencies", "service_inventory", "services"
            ]
            for p_item in cand_names:
                for prefix in prefixes:
                    candidates.append(f"{prefix}.{p_item}")
            if cond_type == "CLIENT_SERVER_RELATIONSHIP" or cond_cat == "client_server_relationship" or any("relationship" in str(x).lower() for x in cand_names):
                candidates.extend(["relationships.communication", "relationships.relationship", "communication", "relationship"])
            evidence_paths = list(dict.fromkeys(candidates))

        for raw_entry in evidence_paths:
            entry = self.normalize_evidence_entry(raw_entry)

            if entry is None:
                evidence_results.append(
                    {
                        "path": str(raw_entry),
                        "value": None,
                        "raw_value": None,
                        "transform": "invalid",
                        "status": "unknown"
                    }
                )
                continue

            path = entry["path"]
            transform = entry["transform"]

            # Compatibility with the existing knowledge file.
            if transform == "identity":
                transform = self.infer_legacy_transform(condition, path)

            raw_value, exists = self.get_value(
                self.configuration,
                path
            )
            if not exists and self.raw_configuration:
                raw_value, exists = self.get_value(
                    self.raw_configuration,
                    path
                )

            if not exists:
                evidence_results.append(
                    {
                        "path": path,
                        "value": None,
                        "raw_value": None,
                        "transform": transform,
                        "status": "unknown",
                        "exists": False
                    }
                )
                continue

            transformed_value = self.transform_value(
                raw_value,
                transform
            )

            # If a transform was requested but could not be applied,
            # do not pretend the evidence proves anything.
            if transformed_value is None and raw_value is not None:
                status = "unknown"
            else:
                status = self.check_evidence_value(
                    transformed_value,
                    required_value
                )

            evidence_results.append(
                {
                    "path": path,
                    "value": transformed_value,
                    "raw_value": raw_value,
                    "transform": transform,
                    "status": status,
                    "exists": True
                }
            )

        # -----------------------------------------------------
        # IMPORTANT:
        #
        # configuration_evidence entries are alternative ways
        # of proving the SAME condition.
        #
        # Example:
        #
        # writes_enabled = true
        #
        # OR
        #
        # readonly = false
        #
        # Either one is enough.
        # -----------------------------------------------------

        existing_evidence = [item for item in evidence_results if item.get("exists", False)]
        if not existing_evidence:
            final_status = "unknown"
        else:
            existing_statuses = [item["status"] for item in existing_evidence]
            if "satisfied" in existing_statuses:
                final_status = "satisfied"
            elif "unknown" in existing_statuses:
                final_status = "unknown"
            else:
                final_status = "not_satisfied"

        # Prerequisite Trust Level:
        # Derived prerequisites may never by themselves produce definitive not_satisfied.
        trust_level = str(condition.get("trust_level", "authoritative")).lower()
        if trust_level == "derived" and final_status == "not_satisfied":
            final_status = "unknown"

        # Select the strongest evidence.
        selected_evidence = None

        for item in evidence_results:
            if item["status"] == "satisfied":
                selected_evidence = item
                break

        if selected_evidence is None:
            for item in evidence_results:
                if item["status"] == "unknown":
                    selected_evidence = item
                    break

        if selected_evidence is None and evidence_results:
            selected_evidence = evidence_results[0]

        return {
            "condition_id": condition.get("id"),
            "name": condition.get("name"),
            "description": condition.get("description"),
            "required_value": required_value,
            "required": bool(condition.get("required", True)),
            "status": final_status,
            "evaluation_status": final_status.upper(),
            "trust_level": trust_level,
            "verification_method": condition.get("verification_method", "config_collector"),
            "category": condition.get("category", "configuration"),
            "selected_evidence": selected_evidence,
            "all_evidence": evidence_results
        }

    # ---------------------------------------------------------
    # Deterministic AST Evaluation (AND, OR, NOT, LEAF)
    # ---------------------------------------------------------

    def evaluate_ast_node(self, node: Any) -> Tuple[str, Dict[str, Any]]:
        """
        Deterministically evaluates an AST node (AndGroup, OrGroup, NotNode, ConditionNode, or dict)
        using 3-valued boolean logic:
            SATISFIED, NOT_SATISFIED, UNKNOWN
        Returns (status, detailed_result_dict).
        """
        if node is None:
            return "satisfied", {"status": "satisfied", "evaluation_status": "SATISFIED", "node_type": "EMPTY"}

        if hasattr(node, "to_dict"):
            node_dict = node.to_dict()
        elif isinstance(node, dict):
            node_dict = node
        else:
            return "unknown", {"status": "unknown", "evaluation_status": "UNKNOWN", "error": f"Invalid node type: {type(node)}"}

        node_type = str(node_dict.get("node_type", "CONDITION")).upper()

        if node_type == "AND":
            operands = node_dict.get("operands", [])
            evaluated_ops = []
            for op in operands:
                st, res = self.evaluate_ast_node(op)
                evaluated_ops.append(res)

            statuses = [op.get("status", "unknown").lower() for op in evaluated_ops]
            if not statuses:
                group_status = "satisfied"
            elif "not_satisfied" in statuses:
                group_status = "not_satisfied"
            elif "unknown" in statuses:
                group_status = "unknown"
            else:
                group_status = "satisfied"

            return group_status, {
                "node_type": "AND",
                "group_id": node_dict.get("group_id"),
                "status": group_status,
                "evaluation_status": group_status.upper(),
                "operands": evaluated_ops
            }

        elif node_type == "OR":
            operands = node_dict.get("operands", [])
            evaluated_ops = []
            for op in operands:
                st, res = self.evaluate_ast_node(op)
                evaluated_ops.append(res)

            statuses = [op.get("status", "unknown").lower() for op in evaluated_ops]
            if not statuses:
                group_status = "not_satisfied"
            elif "satisfied" in statuses:
                group_status = "satisfied"
            elif "unknown" in statuses:
                group_status = "unknown"
            elif all(s == "not_satisfied" for s in statuses):
                group_status = "not_satisfied"
            else:
                group_status = "unknown"

            return group_status, {
                "node_type": "OR",
                "group_id": node_dict.get("group_id"),
                "status": group_status,
                "evaluation_status": group_status.upper(),
                "operands": evaluated_ops
            }

        elif node_type == "NOT":
            op = node_dict.get("operand", {})
            st, res = self.evaluate_ast_node(op)
            child_st = res.get("status", "unknown").lower()
            if child_st == "satisfied":
                not_status = "not_satisfied"
            elif child_st == "not_satisfied":
                not_status = "satisfied"
            else:
                not_status = "unknown"

            return not_status, {
                "node_type": "NOT",
                "node_id": node_dict.get("node_id"),
                "status": not_status,
                "evaluation_status": not_status.upper(),
                "operand": res
            }

        else:
            cond_res = self.evaluate_condition(node_dict)
            st = cond_res.get("status", "unknown").lower()
            cond_res["node_type"] = "CONDITION"
            return st, cond_res

    # ---------------------------------------------------------
    # Evaluate condition group
    # ---------------------------------------------------------

    def evaluate_condition_group(self, conditions, version_condition=None):
        results = []

        if version_condition:
            results.append(version_condition)

        for condition in conditions:
            if condition.get("name") == "software_version_vulnerable" or condition.get("category") == "version":
                continue
            result = self.evaluate_condition(condition)
            results.append(result)

        # Only required conditions decide the group status
        required_results = [r for r in results if r.get("required", True) is not False]
        required_statuses = [r["status"] for r in required_results]

        if not required_statuses:
            group_status = "satisfied"
        elif "not_satisfied" in required_statuses:
            group_status = "not_satisfied"
        elif "unknown" in required_statuses:
            group_status = "unknown"
        else:
            group_status = "satisfied"

        return {
            "status": group_status,
            "conditions": results
        }

    # ---------------------------------------------------------
    # Evaluate CVE
    # ---------------------------------------------------------

    def evaluate_cve(self, cve_id: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        if isinstance(cve_id, dict):
            cve = cve_id
            clean_cve = str(cve.get("cve_id", "UNKNOWN")).strip().upper()
        else:
            clean_cve = str(cve_id).strip().upper()
            cve = self.get_cve_prerequisites(clean_cve)

        if not cve:
            detected_v = self.get_detected_version()
            return {
                "cve_id": clean_cve,
                "product": None,
                "detected_version": detected_v,
                "version_evaluation": {
                    "name": "software_version_vulnerable",
                    "display_name": "Software Version Vulnerable",
                    "status": "unknown",
                    "evaluation_status": "UNKNOWN",
                    "required": True,
                    "required_value": True,
                    "verification_method": "version_check",
                    "category": "version",
                    "detected_version": detected_v,
                    "affected_range": None,
                    "reason": "No CVE-specific prerequisite data is available."
                },
                "affected_versions": None,
                "fixed_versions": {},
                "vulnerability": None,
                "evaluation": {},
                "status": "unknown",
                "applicability_status": "UNKNOWN",
                "dynamic_validation_status": "NO_DYNAMIC_TEST_AVAILABLE",
                "reason": "No CVE-specific prerequisite data is available.",
                "remediation": None,
                "validation": None,
                "source": None,
                "environmental_conditions": [],
                "attack_conditions": []
            }

        version_condition = self.evaluate_version_condition(cve)
        version_condition["evaluation_status"] = version_condition["status"].upper()

        condition_groups = cve.get("conditions", {})
        if not condition_groups and "prerequisites" in cve:
            raw_prereqs = cve.get("prerequisites", [])
            formatted_conds = []
            for p in raw_prereqs:
                p_name = p.get("name") or p.get("id")
                # software_version_vulnerable is represented by version_condition
                if p_name == "software_version_vulnerable":
                    continue
                req_val = p.get("required_value")
                if req_val is None:
                    exp_state = str(p.get("expected_state", "")).lower()
                    if exp_state in ("true", "active", "enabled", "present", "allowed", "vulnerable_endpoints"):
                        req_val = True
                    elif exp_state in ("false", "inactive", "disabled", "denied"):
                        req_val = False
                    else:
                        req_val = exp_state or True

                cfg_ev = p.get("configuration_evidence")
                if not cfg_ev:
                    p_subj = p.get("subject")
                    names_to_check = [x for x in [p_name, p_subj, p.get("configuration_path")] if x]
                    candidates = []
                    for n in names_to_check:
                        candidates.append(n)
                        for prefix in ["configuration", "endpoint_inventory", "network_context", "network", "dependency_check", "dependencies", "service_inventory", "services", "environment"]:
                            candidates.append(f"{prefix}.{n}")
                    cfg_ev = list(dict.fromkeys(candidates))

                formatted_conds.append({
                    "id": p.get("id") or p_name,
                    "condition_id": p.get("condition_id") or p.get("id") or p_name,
                    "name": p_name,
                    "subject": p.get("subject") or p_name,
                    "display_name": p.get("display_name") or p_name,
                    "description": p.get("description", ""),
                    "category": p.get("category", "other"),
                    "configuration_evidence": cfg_ev,
                    "required_value": req_val,
                    "required": bool(p.get("required", True)),
                    "trust_level": p.get("trust_level", "authoritative"),
                    "verification_method": p.get("verification_method", "config_collector"),
                    "confidence": p.get("confidence", "high"),
                    "evidence": p.get("evidence", [])
                })
            condition_groups = {"prerequisites": formatted_conds}

        # Check for Generic Condition IR Environment AST
        env_tree = cve.get("environment_tree")
        if not env_tree and isinstance(cve.get("condition_tree"), dict):
            env_tree = cve["condition_tree"].get("environment_tree")
        if not env_tree and cve.get("condition_tree_json"):
            try:
                ct = json.loads(cve["condition_tree_json"])
                env_tree = ct.get("environment_tree")
            except Exception:
                env_tree = None

        if env_tree:
            ast_status, ast_eval = self.evaluate_ast_node(env_tree)
            ver_status = version_condition["status"].lower()

            # Flatten leaf conditions for backward-compatible consumption in reports and app
            def _extract_leaves(node_dict):
                leaves = []
                nt = str(node_dict.get("node_type", "CONDITION")).upper()
                if nt == "CONDITION":
                    leaves.append(node_dict)
                elif nt in ("AND", "OR"):
                    for op in node_dict.get("operands", []):
                        leaves.extend(_extract_leaves(op))
                elif nt == "NOT":
                    leaves.extend(_extract_leaves(node_dict.get("operand", {})))
                return leaves

            leaf_conds = _extract_leaves(ast_eval)
            all_cond_results = [version_condition] + leaf_conds

            # Combine version status and environment AST via 3-valued boolean AND:
            if ver_status == "not_satisfied" or ast_status == "not_satisfied":
                overall_status = "not_satisfied"
                if ver_status == "not_satisfied":
                    overall_reason = f"Prerequisites not satisfied: software_version_vulnerable ({version_condition.get('reason', '')})"
                else:
                    failed_leafs = [c.get("name") or c.get("condition_id") for c in leaf_conds if c.get("status") == "not_satisfied"]
                    if failed_leafs:
                        overall_reason = f"Prerequisites not satisfied: {', '.join(filter(None, set(failed_leafs)))}"
                    else:
                        overall_reason = "Prerequisites not satisfied in environment condition AST"
            elif ver_status == "unknown" or ast_status == "unknown":
                overall_status = "unknown"
                overall_reason = "Uncertain or missing evidence for required conditions"
            else:
                overall_status = "satisfied"
                overall_reason = "All environmental prerequisites and version conditions satisfied"

            evaluation = {
                "ast_evaluation": ast_eval,
                "prerequisites": {
                    "status": ast_status,
                    "conditions": all_cond_results
                }
            }
        else:
            evaluation = {}
            for group_name, conditions in condition_groups.items():
                evaluation[group_name] = self.evaluate_condition_group(
                    conditions,
                    version_condition=version_condition
                )

            # Compute overall prerequisite applicability status
            group_statuses = [g["status"] for g in evaluation.values()]

            if not group_statuses:
                overall_status = "unknown"
                overall_reason = "No prerequisite conditions defined for this CVE."
            elif "satisfied" in group_statuses:
                overall_status = "satisfied"
                satisfied_groups = [k for k, v in evaluation.items() if v["status"] == "satisfied"]
                overall_reason = f"Prerequisites satisfied for vector(s): {', '.join(satisfied_groups)}"
            elif all(s == "not_satisfied" for s in group_statuses):
                overall_status = "not_satisfied"
                failed_conditions = []
                for g in evaluation.values():
                    for c in g.get("conditions", []):
                        if c.get("status") == "not_satisfied":
                            failed_conditions.append(c.get("name", "unknown"))
                overall_reason = f"Prerequisites not satisfied: {', '.join(set(failed_conditions))}"
            else:
                overall_status = "unknown"
                unknown_conditions = []
                for g in evaluation.values():
                    for c in g.get("conditions", []):
                        if c.get("status") == "unknown":
                            unknown_conditions.append(c.get("name", "unknown"))
                overall_reason = f"Uncertain or missing evidence for: {', '.join(set(unknown_conditions))}"

        # Deterministic Applicability Status
        if overall_status == "satisfied":
            applicability_status = "APPLICABLE"
        elif overall_status == "not_satisfied":
            applicability_status = "NOT_APPLICABLE"
        else:
            applicability_status = "UNKNOWN"

        # Separate Dynamic Validation Status Layer
        attack_conds = cve.get("attack_conditions", [])
        has_dynamic_probe = any(
            a.get("verification_method") in ("dynamic_validation", "dynamic_test") or
            a.get("type") == "nuclei_dynamic_probe"
            for a in attack_conds
        ) or bool(cve.get("has_nuclei_template")) or bool(cve.get("dynamic_validation"))

        dynamic_validation_status = "NO_DYNAMIC_TEST_AVAILABLE"
        if has_dynamic_probe:
            dynamic_evidence = self.configuration.get("dynamic_validation") or self.raw_configuration.get("dynamic_validation")
            if isinstance(dynamic_evidence, dict):
                cve_dyn = dynamic_evidence.get(clean_cve)
                if cve_dyn is True or (isinstance(cve_dyn, dict) and cve_dyn.get("confirmed")):
                    dynamic_validation_status = "CONFIRMED"
                elif cve_dyn is False or (isinstance(cve_dyn, dict) and cve_dyn.get("confirmed") is False):
                    dynamic_validation_status = "NOT_DYNAMICALLY_CONFIRMED"
                else:
                    dynamic_validation_status = "UNDETERMINED"
            else:
                dynamic_validation_status = "UNDETERMINED"

        # Flatten evaluated environmental conditions
        env_conditions = []
        for g in evaluation.values():
            for c in g.get("conditions", []):
                env_conditions.append(c)

        return {
            "cve_id": clean_cve,
            "product": cve.get("product"),
            "detected_version": self.get_detected_version(
                product=(cve.get("product") or {}).get("name") if isinstance(cve.get("product"), dict) else None
            ),
            "version_evaluation": version_condition,
            "affected_versions": cve.get("affected_versions"),
            "fixed_versions": cve.get("fixed_versions"),
            "vulnerability": cve.get("vulnerability"),
            "evaluation": evaluation,
            "status": overall_status,
            "applicability_status": applicability_status,
            "dynamic_validation_status": dynamic_validation_status,
            "reason": overall_reason,
            "remediation": cve.get("remediation"),
            "validation": cve.get("validation"),
            "source": cve.get("source"),
            "unknown_conditions": cve.get("unknown_conditions", []),
            "environmental_conditions": env_conditions,
            "attack_conditions": attack_conds
        }

    # ---------------------------------------------------------
    # Print human-readable summary
    # ---------------------------------------------------------

    def print_summary(self, result: Dict[str, Any]):
        print()
        print("=" * 70)
        print("CVE PREREQUISITE & CONFIGURATION EVALUATION")
        print("=" * 70)

        print(f"CVE: {result['cve_id']}")
        v_eval = result.get("version_evaluation", {})
        print(f"Target Detected Version: {result.get('detected_version')} (Status: {v_eval.get('status', 'unknown').upper()})")
        if v_eval.get("reason"):
            print(f"Version Assessment: {v_eval.get('reason')}")

        if result.get("status"):
            print(f"Overall Prerequisite Status: {result['status'].upper()}")
            print(f"Assessment Reason: {result.get('reason', '')}")
        print()

        eval_groups = result.get("evaluation", {})
        if not eval_groups:
            print("No condition groups evaluated (prerequisite data unavailable).")

        for group_name, group in eval_groups.items():
            print(f"[{group_name}]")
            print(f"Overall status: {group['status']}")
            print()

            for condition in group["conditions"]:
                t_level = condition.get("trust_level", "authoritative")
                print(f"  {condition['name']} [{t_level.upper()}]")
                print(f"    Status: {condition['status']}")
                print(f"    Required: {condition['required_value']}")

                selected = condition.get("selected_evidence")

                if selected:
                    print(
                        f"    Selected evidence: "
                        f"{selected['path']}"
                    )

                    print(
                        f"      Raw value: "
                        f"{selected.get('raw_value')}"
                    )

                    print(
                        f"      Evaluated value: "
                        f"{selected['value']}"
                    )

                    print(
                        f"      Transform: "
                        f"{selected.get('transform')}"
                    )

                    print(
                        f"      Status: "
                        f"{selected['status']}"
                    )

                print()

        print("=" * 70)


# =============================================================
# MAIN
# =============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generic deterministic CVE prerequisite evaluator."
    )

    parser.add_argument(
        "--cve",
        required=True,
        help="CVE ID to evaluate"
    )

    parser.add_argument(
        "--config",
        required=True,
        help="Effective configuration JSON file from Config Collector"
    )

    parser.add_argument(
        "--knowledge",
        required=False,
        default=None,
        help="Optional CVE knowledge JSON file (defaults to data/cve_prerequisites.db)"
    )

    parser.add_argument(
        "--db",
        required=False,
        default=None,
        help="Optional path to cve_prerequisites.db"
    )

    parser.add_argument(
        "--output",
        default="cve-evaluation.json",
        help="Evaluation output JSON path"
    )

    args = parser.parse_args()

    evaluator = CVEEvaluator(
        knowledge_source=args.knowledge,
        config_source=args.config,
        db_path=args.db
    )

    result = evaluator.evaluate_cve(args.cve)

    evaluator.print_summary(result)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print()
    print(f"Full evaluation saved to: {output_path}")


if __name__ == "__main__":
    main()
